//! Syslog TCP listener with optional TLS (RFC 5425).
//!
//! TLS is enabled when both `COLLECTOR_TLS_CERT` and `COLLECTOR_TLS_KEY` are
//! set. Optional `COLLECTOR_TLS_CA` enables mutual TLS client authentication.
//!
//! Connection limiting: `COLLECTOR_TCP_MAX_CONNECTIONS` (default 2000) caps
//! concurrent TCP sessions via a semaphore; new connections are rejected when
//! the limit is reached rather than accepting and buffering indefinitely.

use std::{net::SocketAddr, sync::Arc};

use arc_swap::ArcSwap;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::{
    io::AsyncBufReadExt,
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
};
use tracing::{debug, error, info, warn};

use crate::metrics::CollectorMetrics;
use crate::multiline::{MultilineAccumulator, MultilineConfig};
use crate::parser::{parse_syslog, to_incoming_event};
use crate::ratelimit::SourceRateLimiter;

// ─── TLS config ───────────────────────────────────────────────────────────────

/// Rustls server-side TLS acceptor, built from PEM-encoded files.
pub fn build_tls_acceptor(
    cert_pem: &[u8],
    key_pem:  &[u8],
    ca_pem:   Option<&[u8]>,
) -> Result<Arc<tokio_rustls::TlsAcceptor>> {
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        server::WebPkiClientVerifier,
        RootCertStore, ServerConfig,
    };
    use rustls_pemfile::{certs, private_key};

    let server_certs: Vec<CertificateDer<'static>> = certs(&mut std::io::Cursor::new(cert_pem))
        .collect::<std::result::Result<_, _>>()
        .context("invalid TLS certificate PEM")?;

    let key: PrivateKeyDer<'static> =
        private_key(&mut std::io::Cursor::new(key_pem))
            .context("read TLS private key")?
            .context("no private key found in TLS key PEM")?;

    let config = if let Some(ca) = ca_pem {
        // Mutual TLS: clients must present a certificate signed by the CA
        let mut roots = RootCertStore::empty();
        for cert in certs(&mut std::io::Cursor::new(ca))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("invalid CA certificate PEM")?
        {
            roots.add(cert).context("add CA cert to root store")?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("build mTLS client verifier")?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certs, key)
            .context("build mTLS ServerConfig")?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(server_certs, key)
            .context("build TLS ServerConfig")?
    };

    Ok(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
}

// ─── Listener ─────────────────────────────────────────────────────────────────

/// `tls` is wrapped in an `ArcSwap` so it can be hot-reloaded at runtime via
/// SIGUSR1 without restarting the listener.  Each new connection loads the
/// current acceptor; existing connections are unaffected.
pub async fn run(
    bind:            SocketAddr,
    tenant_id:       Arc<String>,
    tx:              mpsc::Sender<Value>,
    max_msg_bytes:   usize,
    tls:             Option<Arc<ArcSwap<tokio_rustls::TlsAcceptor>>>,
    ml_cfg:          MultilineConfig,
    metrics:         Arc<CollectorMetrics>,
    max_connections: usize,
    rate_limiter:    Arc<SourceRateLimiter>,
    mut shutdown:    watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind TCP {bind}"))?;

    if tls.is_some() {
        info!(%bind, max_connections, "syslog TCP+TLS listener ready (RFC 5425, hot-reload via SIGUSR1)");
    } else {
        info!(%bind, max_connections, "syslog TCP listener ready (plain-text)");
    }

    let sem = Arc::new(Semaphore::new(max_connections));

    loop {
        let accept_res = tokio::select! {
            biased;
            _ = shutdown.changed() => { info!("TCP listener exiting on shutdown"); break; }
            r = listener.accept() => r,
        };
        match accept_res {
            Ok((stream, peer)) => {
                let ip        = peer.ip();
                let source_ip = ip.to_string();

                // Connection limit: try_acquire so we never block the accept loop
                let permit: OwnedSemaphorePermit = match Arc::clone(&sem).try_acquire_owned() {
                    Ok(p)  => p,
                    Err(_) => {
                        warn!(source_ip, max_connections, "TCP connection limit reached — dropping connection");
                        metrics.channel_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                };

                let tx2   = tx.clone();
                let tid   = Arc::clone(&tenant_id);
                let tls2: Option<Arc<tokio_rustls::TlsAcceptor>> =
                    tls.as_ref().map(|s| s.load_full());
                let m2    = Arc::clone(&metrics);
                let rl2   = Arc::clone(&rate_limiter);
                let ml_cfg2 = MultilineConfig {
                    pattern:    ml_cfg.pattern.as_ref()
                        .map(|r| regex::Regex::new(r.as_str()).unwrap()),
                    negate:     ml_cfg.negate,
                    max_lines:  ml_cfg.max_lines,
                    timeout_ms: ml_cfg.timeout_ms,
                };

                tokio::spawn(async move {
                    let _permit = permit; // released when this task ends
                    if let Err(err) = handle_conn(stream, source_ip, ip, tid, tx2, max_msg_bytes, tls2, ml_cfg2, m2, rl2).await {
                        debug!(%err, "TCP connection closed");
                    }
                });
            }
            Err(err) => error!(%err, "TCP accept error"),
        }
    }
    Ok(())
}

async fn handle_conn(
    stream:        TcpStream,
    source_ip:     String,
    source_ip_addr: std::net::IpAddr,
    tenant_id:     Arc<String>,
    tx:            mpsc::Sender<Value>,
    max_msg_bytes: usize,
    tls:           Option<Arc<tokio_rustls::TlsAcceptor>>,
    ml_cfg:        MultilineConfig,
    metrics:       Arc<CollectorMetrics>,
    rate_limiter:  Arc<SourceRateLimiter>,
) -> Result<()> {
    if let Some(acceptor) = tls {
        let tls_stream = acceptor.accept(stream).await.context("TLS handshake")?;
        process_lines(tls_stream, source_ip, source_ip_addr, tenant_id, tx, max_msg_bytes, ml_cfg, metrics, rate_limiter).await
    } else {
        process_lines(stream, source_ip, source_ip_addr, tenant_id, tx, max_msg_bytes, ml_cfg, metrics, rate_limiter).await
    }
}

async fn process_lines<S>(
    stream:         S,
    source_ip:      String,
    source_ip_addr: std::net::IpAddr,
    tenant_id:      Arc<String>,
    tx:             mpsc::Sender<Value>,
    max_msg_bytes:  usize,
    ml_cfg:         MultilineConfig,
    metrics:        Arc<CollectorMetrics>,
    rate_limiter:   Arc<SourceRateLimiter>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering::Relaxed;

    let reader = tokio::io::BufReader::new(stream);
    let mut lines = reader.lines();
    let mut acc = MultilineAccumulator::new(ml_cfg);

    while let Ok(Some(line)) = lines.next_line().await {
        // Hard-enforce maximum line size at a valid UTF-8 char boundary.
        let line = if line.len() > max_msg_bytes {
            let end = line.floor_char_boundary(max_msg_bytes);
            warn!(source_ip, bytes = line.len(), max = max_msg_bytes, "syslog TCP line truncated");
            metrics.parse_errors.fetch_add(1, Relaxed);
            line[..end].to_string()
        } else {
            line
        };
        if let Some(complete) = acc.feed(line) {
            if !rate_limiter.check(source_ip_addr) {
                metrics.rate_limit_drops.fetch_add(1, Relaxed);
                debug!(source_ip, "TCP syslog line rate-limited");
                continue;
            }
            match parse_syslog(complete.as_bytes(), &source_ip) {
                Some(msg) => {
                    let ev = to_incoming_event(&msg, &tenant_id);
                    metrics.tcp_received.fetch_add(1, Relaxed);
                    if tx.send(ev).await.is_err() {
                        return Ok(());
                    }
                }
                None => {
                    metrics.parse_errors.fetch_add(1, Relaxed);
                    debug!(source_ip, "could not parse TCP syslog line");
                }
            }
        }
    }

    // Flush any remaining buffered multiline event
    if let Some(complete) = acc.tick() {
        if let Some(msg) = parse_syslog(complete.as_bytes(), &source_ip) {
            let ev = to_incoming_event(&msg, &tenant_id);
            metrics.tcp_received.fetch_add(1, Relaxed);
            let _ = tx.send(ev).await;
        }
    }

    Ok(())
}
