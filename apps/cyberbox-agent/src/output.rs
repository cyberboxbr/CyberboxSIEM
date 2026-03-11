//! TCP output — connects to the collector, authenticates, writes events.
//!
//! ## Protocols
//! * `json`   — NDJSON: one JSON object per line.  Target: `COLLECTOR_JSON_TCP_BIND`.
//! * `syslog` — RFC 3164: `<PRI>TIMESTAMP HOSTNAME APP: MESSAGE\n`.
//!   Target: `COLLECTOR_TCP_BIND` or any syslog receiver.
//!
//! ## Enrollment token (JSON mode only)
//! When `token` is set the very first line sent on each new connection is an
//! auth handshake so the collector can identify and authenticate the agent:
//! ```json
//! {"cyberbox_auth":{"token":"<tok>","agent":"hostname","version":"0.1.0"}}
//! ```
//! The collector currently ignores unknown JSON lines; validation can be added
//! server-side later without changing the agent wire format.
//!
//! ## TLS (`--features tls`)
//! When `tls = true` in `agent.toml` the connection is wrapped in TLS using
//! `tokio-rustls`.  If `tls_ca` is set, only that CA is trusted.  Otherwise
//! the native OS trust store is loaded via `rustls-native-certs`.
//!
//! ## Resilience
//! A crash-safe disk-backed queue (`sled`) persists events while offline.
//! Oldest entries are evicted when the buffer is full.  On reconnect the queue
//! flushes before new events are written.  Events survive agent crashes.

use std::time::Duration;
#[cfg(feature = "tls")]
use std::{path::Path, sync::Arc};

use crate::disk_queue::DiskQueue;

use serde_json::Value;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::{mpsc, watch},
    time,
};
use tracing::{error, info, warn};

// ── Public config ─────────────────────────────────────────────────────────────

pub struct OutputConfig {
    pub host: String,
    pub port: u16,
    /// `"json"` or `"syslog"`
    pub protocol: String,
    pub tls: bool,
    pub tls_ca: Option<std::path::PathBuf>,
    /// Enrollment token — sent as first line per connection (JSON mode only)
    pub token: Option<String>,
    pub backoff_max_secs: u64,
    pub buffer_size: usize,
    pub hostname: String,
    pub app_name: String,
    pub tenant_id: String,
    /// Agent version string embedded in auth handshake
    pub version: String,
    /// Path for the disk-backed queue (sled database directory)
    pub queue_path: std::path::PathBuf,
}

// ── Unified connection wrapper ────────────────────────────────────────────────

enum Conn {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl Conn {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.write_all(data).await,
            #[cfg(feature = "tls")]
            Conn::Tls(s) => s.write_all(data).await,
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(
    mut rx: mpsc::Receiver<Value>,
    cfg: OutputConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let mut backoff_ms: u64 = 500;
    let backoff_max_ms = cfg.backoff_max_secs * 1000;

    let mut buf = match DiskQueue::open(&cfg.queue_path, cfg.buffer_size) {
        Ok(q) => q,
        Err(e) => {
            error!(%e, "failed to open disk queue — falling back to in-memory");
            // Create a temp dir as fallback
            let tmp = std::env::temp_dir().join("cyberbox-agent-queue-fallback");
            DiskQueue::open(&tmp, cfg.buffer_size).expect("cannot open fallback disk queue")
        }
    };

    'outer: loop {
        // ── Connect (plain or TLS) ────────────────────────────────────────────
        let conn = tokio::select! {
            biased;
            _ = shutdown.changed() => break 'outer,
            r = connect(&addr, &cfg) => r,
        };

        let mut conn = match conn {
            Ok(c) => {
                info!(%addr, tls = cfg.tls, "connected to collector");
                backoff_ms = 500;
                c
            }
            Err(e) => {
                warn!(%e, %addr, "cannot connect — retrying in {backoff_ms}ms");
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break 'outer,
                    _ = time::sleep(Duration::from_millis(backoff_ms)) => {}
                }
                backoff_ms = (backoff_ms * 2).min(backoff_max_ms);
                continue;
            }
        };

        // ── Enrollment token handshake (JSON mode) ────────────────────────────
        if cfg.protocol != "syslog" {
            if let Some(ref tok) = cfg.token {
                let handshake = format!(
                    "{{\"cyberbox_auth\":{{\"token\":\"{tok}\",\
                      \"agent\":\"{}\",\"version\":\"{}\"}}}}\n",
                    cfg.hostname, cfg.version
                );
                if conn.write_all(handshake.as_bytes()).await.is_err() {
                    backoff_ms = (backoff_ms * 2).min(backoff_max_ms);
                    continue;
                }
            }
        }

        // ── Flush disk queue ─────────────────────────────────────────────────
        while let Some(ev) = buf.pop() {
            let line = format_event(&ev, &cfg);
            if conn.write_all(line.as_bytes()).await.is_err() {
                let _ = buf.push(&ev);
                break;
            }
        }

        // ── Normal forward loop ───────────────────────────────────────────────
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break 'outer,
                ev = rx.recv() => {
                    match ev {
                        None => break 'outer,
                        Some(ev) => {
                            let line = format_event(&ev, &cfg);
                            if let Err(e) = conn.write_all(line.as_bytes()).await {
                                error!(%e, "collector write failed — buffering and reconnecting");
                                let _ = buf.push(&ev);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Drain rx into buffer while we back off
        while let Ok(ev) = rx.try_recv() {
            let _ = buf.push(&ev);
        }

        warn!(%addr, buffered = buf.len(), "reconnecting in {backoff_ms}ms");
        tokio::select! {
            biased;
            _ = shutdown.changed() => break 'outer,
            _ = time::sleep(Duration::from_millis(backoff_ms)) => {}
        }
        backoff_ms = (backoff_ms * 2).min(backoff_max_ms);
    }

    let remaining = buf.len();
    buf.flush();
    if remaining > 0 {
        info!(
            persisted = remaining,
            "output shutting down — events persisted to disk queue"
        );
    }
}

// ── Connection factory ────────────────────────────────────────────────────────

async fn connect(addr: &str, cfg: &OutputConfig) -> anyhow::Result<Conn> {
    #[cfg(feature = "tls")]
    if cfg.tls {
        let stream = connect_tls(addr, cfg.tls_ca.as_deref()).await?;
        return Ok(Conn::Tls(stream));
    }

    // Suppress unused warning when tls feature is disabled
    let _ = &cfg.tls_ca;

    Ok(Conn::Plain(TcpStream::connect(addr).await?))
}

#[cfg(feature = "tls")]
async fn connect_tls(
    addr: &str,
    tls_ca: Option<&Path>,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let mut root_store = RootCertStore::empty();

    if let Some(ca_path) = tls_ca {
        // Pin a specific CA (self-signed collector cert, internal PKI, etc.)
        let pem = std::fs::read(ca_path)
            .map_err(|e| anyhow::anyhow!("cannot read tls_ca {}: {e}", ca_path.display()))?;
        let mut reader = std::io::BufReader::new(pem.as_slice());
        for cert in rustls_pemfile::certs(&mut reader) {
            root_store.add(cert?)?;
        }
    } else {
        // Fall back to the OS native trust store
        let certs = rustls_native_certs::load_native_certs();
        for e in &certs.errors {
            warn!("native cert load warning: {e}");
        }
        for cert in certs.certs {
            let _ = root_store.add(cert); // ignore individual cert errors
        }
    }

    let tls_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let connector = TlsConnector::from(tls_cfg);
    let hostname = addr.split(':').next().unwrap_or(addr).to_string();
    let server_name = rustls::pki_types::ServerName::try_from(hostname)
        .map_err(|e| anyhow::anyhow!("invalid TLS hostname: {e}"))?;

    let tcp = TcpStream::connect(addr).await?;
    Ok(connector.connect(server_name, tcp).await?)
}

// ── Formatting ────────────────────────────────────────────────────────────────

fn format_event(ev: &Value, cfg: &OutputConfig) -> String {
    match cfg.protocol.as_str() {
        "syslog" => {
            // RFC 3164: <14> = user.info
            let ts = chrono::Utc::now().format("%-b %e %H:%M:%S");
            let msg = ev["raw_payload"]["message"]
                .as_str()
                .unwrap_or("(no message)");
            format!("<14>{ts} {} {}: {msg}\n", cfg.hostname, cfg.app_name)
        }
        _ => {
            // NDJSON — inject tenant_id if missing
            let mut ev2 = ev.clone();
            if ev2.get("tenant_id").is_none() {
                ev2["tenant_id"] = serde_json::json!(cfg.tenant_id);
            }
            let mut s = serde_json::to_string(&ev2).unwrap_or_default();
            s.push('\n');
            s
        }
    }
}
