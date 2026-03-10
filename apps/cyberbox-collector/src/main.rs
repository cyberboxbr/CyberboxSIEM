//! CyberboxSIEM — Log Collector
//!
//! Receives syslog (UDP + TCP, RFC 3164 + RFC 5424 + RFC 5425 TLS), CEF, LEEF,
//! tails log files, and on Windows subscribes to the Windows Event Log.
//! Also polls cloud sources (S3, Okta, O365) and accepts NetFlow v5/v9/IPFIX.
//! Events are batched, gzip-compressed, and forwarded to the CyberboxSIEM
//! ingest API with automatic exponential-backoff retry and a persistent disk
//! overflow queue.
//!
//! # Configuration (environment variables)
//!
//! | Variable                         | Default                        | Description                                         |
//! |----------------------------------|--------------------------------|-----------------------------------------------------|
//! | `COLLECTOR_API_URL`              | `http://127.0.0.1:8080`        | CyberboxSIEM API base URL                           |
//! | `COLLECTOR_TENANT_ID`            | `default`                      | Tenant that owns incoming events                    |
//! | `COLLECTOR_UDP_BIND`             | `0.0.0.0:514`                  | Syslog UDP listener address                         |
//! | `COLLECTOR_TCP_BIND`             | `0.0.0.0:601`                  | Syslog TCP listener address                         |
//! | `COLLECTOR_NETFLOW_BIND`         | *(empty)*                      | NetFlow/IPFIX UDP listener (empty = disabled)       |
//! | `COLLECTOR_BATCH_SIZE`           | `500`                          | Max events per API POST                             |
//! | `COLLECTOR_FLUSH_MS`             | `1000`                         | Max ms before a partial batch flushes               |
//! | `COLLECTOR_MAX_MSG_BYTES`        | `65536`                        | Max syslog datagram / TCP line size (hard-enforced) |
//! | `COLLECTOR_QUEUE_PATH`           | `collector-queue.jsonl`        | Disk overflow queue file path                       |
//! | `COLLECTOR_QUEUE_MAX_MB`         | `256`                          | Max disk queue size before dropping                 |
//! | `COLLECTOR_TLS_CERT`             | *(empty)*                      | Path to PEM cert for TCP TLS (RFC 5425)             |
//! | `COLLECTOR_TLS_KEY`              | *(empty)*                      | Path to PEM key for TCP TLS                         |
//! | `COLLECTOR_TLS_CA`               | *(empty)*                      | Path to CA cert for mutual TLS (optional)           |
//! | `COLLECTOR_TLS_RELOAD_BIND`      | *(empty)*                      | Bind addr for POST /reload-tls (empty = disabled)   |
//! | `COLLECTOR_TAIL_PATHS`           | *(empty)*                      | Comma-separated file paths to tail                  |
//! | `COLLECTOR_TAIL_POLL_MS`         | `500`                          | File tail poll interval in ms                       |
//! | `COLLECTOR_TAIL_BOOKMARK`        | `collector-tail.pos.json`      | Persistent read-position bookmark file              |
//! | `COLLECTOR_HEARTBEAT_SECS`       | `60`                           | Heartbeat interval (0 = disabled)                   |
//! | `COLLECTOR_WEL_CHANNELS`         | `Security,System,Application`  | Windows Event Log channels (Windows only)           |
//! | `COLLECTOR_ML_PATTERN`           | *(empty)*                      | Multiline regex pattern (empty = disabled)          |
//! | `COLLECTOR_ML_NEGATE`            | `false`                        | Multiline negate mode                               |
//! | `COLLECTOR_ML_MAX_LINES`         | `500`                          | Multiline max lines before force-flush              |
//! | `COLLECTOR_ML_TIMEOUT_MS`        | `2000`                         | Multiline silence timeout in ms                     |
//! | `COLLECTOR_VAULT_ADDR`           | *(empty)*                      | HashiCorp Vault URL (empty = disabled)              |
//! | `COLLECTOR_REMOTE_CONFIG_URL`    | *(empty)*                      | Remote config JSON endpoint (empty = disabled)      |
//! | `COLLECTOR_S3_ENABLED`           | `false`                        | Enable S3 CloudTrail polling                        |
//! | `COLLECTOR_OKTA_ENABLED`         | `false`                        | Enable Okta System Log polling                      |
//! | `COLLECTOR_O365_ENABLED`         | `false`                        | Enable O365 Management Activity polling             |
//! | `COLLECTOR_UDP_READERS`          | CPU cores                      | Parallel UDP recv tasks (multi-reader)              |
//! | `COLLECTOR_TCP_MAX_CONNECTIONS`  | `2000`                         | Max concurrent TCP sessions (semaphore)             |
//! | `COLLECTOR_SOURCE_RATE_EPS`      | `0`                            | Per-source-IP rate limit (0 = disabled)             |
//! | `COLLECTOR_SOURCE_RATE_BURST`    | `3`                            | Burst multiplier (× SOURCE_RATE_EPS)                |
//! | `COLLECTOR_JSON_UDP_BIND`        | *(empty)*                      | Raw JSON-over-UDP listener (empty = disabled)       |
//! | `COLLECTOR_JSON_TCP_BIND`        | *(empty)*                      | NDJSON-over-TCP listener (empty = disabled)         |
//! | `COLLECTOR_GELF_UDP_BIND`        | *(empty)*                      | GELF UDP listener (empty = disabled)                |
//! | `COLLECTOR_GELF_TCP_BIND`        | *(empty)*                      | GELF TCP listener (empty = disabled)                |
//! | `COLLECTOR_OTLP_HTTP_BIND`       | *(empty)*                      | OTLP HTTP/JSON receiver (empty = disabled)          |
//! | `COLLECTOR_FWD_CONCURRENCY`      | `4`                            | Concurrent forwarder HTTP POSTs in-flight           |
//! | `COLLECTOR_API_HMAC_SECRET`      | *(empty)*                      | HMAC-SHA256 key for `X-Cyberbox-Signature` header  |
//! | `COLLECTOR_HEALTHZ_BIND`         | *(empty)*                      | JSON /healthz endpoint bind address (disabled if empty) |
//! | `COLLECTOR_DLQ_PATH`             | *(empty)*                      | Dead-letter queue file for parse failures           |
//! | `COLLECTOR_DLQ_MAX_MB`           | `64`                           | Max DLQ file size before dropping new entries       |
//! | `COLLECTOR_KAFKA_BROKERS`        | `localhost:9092`               | Kafka broker list (kafka feature only)              |
//! | `COLLECTOR_KAFKA_TOPICS`         | *(empty)*                      | Kafka topics to consume (kafka feature only)        |
//! | `COLLECTOR_KAFKA_GROUP_ID`       | `cyberbox-collector`           | Kafka consumer group (kafka feature only)           |
//! | `COLLECTOR_KAFKA_OFFSET_RESET`   | `latest`                       | Kafka offset reset policy (kafka feature only)      |
//! | `RUST_LOG`                       | `cyberbox_collector=info`      | tracing filter                                      |

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;
use tokio::{sync::mpsc, time};
use tracing::{error, info, warn};

mod dlq;
mod forwarder;
mod healthz;
mod heartbeat;
mod metrics;
mod multiline;
mod parser;
mod ratelimit;
mod remote_config;
mod sources;
mod vault;

use forwarder::ForwarderConfig;
use metrics::CollectorMetrics;
use multiline::MultilineConfig;
use ratelimit::SourceRateLimiter;
use remote_config::SharedRuntimeConfig;

// ─── Config ───────────────────────────────────────────────────────────────────

struct Config {
    // Core
    api_url:        String,
    tenant_id:      String,
    udp_bind:       SocketAddr,
    tcp_bind:       SocketAddr,
    netflow_bind:   Option<SocketAddr>,
    batch_size:     usize,
    flush_ms:       u64,
    max_msg_bytes:  usize,
    // Disk queue
    queue_path:     PathBuf,
    queue_max_mb:   u64,
    // TLS
    tls_cert:       String,
    tls_key:        String,
    tls_ca:         String,
    /// HTTP endpoint for cross-platform TLS hot-reload (empty = disabled).
    tls_reload_bind: Option<SocketAddr>,
    // File tailing
    tail_paths:     Vec<PathBuf>,
    tail_poll_ms:   u64,
    tail_bookmark:  Option<PathBuf>,
    // Heartbeat
    heartbeat_secs: u64,
    // Windows Event Log
    wel_channels:   Vec<String>,
    // Multiline
    ml_pattern:     Option<String>,
    ml_negate:      bool,
    ml_max_lines:   usize,
    ml_timeout_ms:  u64,
    // UDP multi-reader
    udp_readers:    usize,
    // TCP connection limit
    tcp_max_conn:   usize,
    // Per-source-IP rate limiting
    source_rate_eps:   u64,
    source_rate_burst: u32,
    // JSON input sources
    json_udp_bind:  Option<SocketAddr>,
    json_tcp_bind:  Option<SocketAddr>,
    // GELF input sources
    gelf_udp_bind:   Option<SocketAddr>,
    gelf_tcp_bind:   Option<SocketAddr>,
    // OTLP HTTP receiver
    otlp_http_bind:  Option<SocketAddr>,
    // Forwarder concurrency
    fwd_concurrency: usize,
    // Forwarder HMAC signing
    api_hmac_secret: Option<String>,
    // Dead-letter queue
    dlq_path:        Option<PathBuf>,
    dlq_max_mb:      u64,
}

impl Config {
    fn from_env() -> Result<Self> {
        let tail_paths: Vec<PathBuf> = env_str("COLLECTOR_TAIL_PATHS", "")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();

        let wel_channels: Vec<String> = env_str("COLLECTOR_WEL_CHANNELS", "Security,System,Application")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let netflow_bind: Option<SocketAddr> = {
            let s = env_str("COLLECTOR_NETFLOW_BIND", "");
            if s.is_empty() { None } else { Some(s.parse().context("invalid COLLECTOR_NETFLOW_BIND")?) }
        };

        let ml_pattern = {
            let p = env_str("COLLECTOR_ML_PATTERN", "");
            if p.is_empty() { None } else { Some(p) }
        };

        let json_udp_bind: Option<SocketAddr> = {
            let s = env_str("COLLECTOR_JSON_UDP_BIND", "");
            if s.is_empty() { None } else { Some(s.parse().context("invalid COLLECTOR_JSON_UDP_BIND")?) }
        };
        let json_tcp_bind: Option<SocketAddr> = {
            let s = env_str("COLLECTOR_JSON_TCP_BIND", "");
            if s.is_empty() { None } else { Some(s.parse().context("invalid COLLECTOR_JSON_TCP_BIND")?) }
        };
        let gelf_udp_bind: Option<SocketAddr> = {
            let s = env_str("COLLECTOR_GELF_UDP_BIND", "");
            if s.is_empty() { None } else { Some(s.parse().context("invalid COLLECTOR_GELF_UDP_BIND")?) }
        };
        let gelf_tcp_bind: Option<SocketAddr> = {
            let s = env_str("COLLECTOR_GELF_TCP_BIND", "");
            if s.is_empty() { None } else { Some(s.parse().context("invalid COLLECTOR_GELF_TCP_BIND")?) }
        };
        let otlp_http_bind: Option<SocketAddr> = {
            let s = env_str("COLLECTOR_OTLP_HTTP_BIND", "");
            if s.is_empty() { None } else { Some(s.parse().context("invalid COLLECTOR_OTLP_HTTP_BIND")?) }
        };
        let tls_reload_bind: Option<SocketAddr> = {
            let s = env_str("COLLECTOR_TLS_RELOAD_BIND", "");
            if s.is_empty() { None } else { Some(s.parse().context("invalid COLLECTOR_TLS_RELOAD_BIND")?) }
        };

        // Tail bookmark: default to a sibling of the queue path, or the
        // explicit env var (empty string = disable bookmarking).
        let tail_bookmark: Option<PathBuf> = {
            let raw = env_str("COLLECTOR_TAIL_BOOKMARK", "collector-tail.pos.json");
            if raw.is_empty() { None } else { Some(PathBuf::from(raw)) }
        };

        let default_readers = std::thread::available_parallelism()
            .map(|n| n.get()).unwrap_or(4);

        Ok(Self {
            api_url:        env_str("COLLECTOR_API_URL",    "http://127.0.0.1:8080"),
            tenant_id:      env_str("COLLECTOR_TENANT_ID",  "default"),
            udp_bind:       env_str("COLLECTOR_UDP_BIND",   "0.0.0.0:514")
                            .parse().context("invalid COLLECTOR_UDP_BIND")?,
            tcp_bind:       env_str("COLLECTOR_TCP_BIND",   "0.0.0.0:601")
                            .parse().context("invalid COLLECTOR_TCP_BIND")?,
            netflow_bind,
            batch_size:     env_str("COLLECTOR_BATCH_SIZE", "500")
                            .parse().context("invalid COLLECTOR_BATCH_SIZE")?,
            flush_ms:       env_str("COLLECTOR_FLUSH_MS",   "1000")
                            .parse().context("invalid COLLECTOR_FLUSH_MS")?,
            max_msg_bytes:  env_str("COLLECTOR_MAX_MSG_BYTES", "65536")
                            .parse().context("invalid COLLECTOR_MAX_MSG_BYTES")?,
            queue_path:     PathBuf::from(env_str("COLLECTOR_QUEUE_PATH", "collector-queue.jsonl")),
            queue_max_mb:   env_str("COLLECTOR_QUEUE_MAX_MB", "256")
                            .parse().context("invalid COLLECTOR_QUEUE_MAX_MB")?,
            tls_cert:       env_str("COLLECTOR_TLS_CERT", ""),
            tls_key:        env_str("COLLECTOR_TLS_KEY",  ""),
            tls_ca:         env_str("COLLECTOR_TLS_CA",   ""),
            tls_reload_bind,
            tail_paths,
            tail_poll_ms:   env_str("COLLECTOR_TAIL_POLL_MS",    "500")
                            .parse().context("invalid COLLECTOR_TAIL_POLL_MS")?,
            tail_bookmark,
            heartbeat_secs: env_str("COLLECTOR_HEARTBEAT_SECS",  "60")
                            .parse().context("invalid COLLECTOR_HEARTBEAT_SECS")?,
            wel_channels,
            ml_pattern,
            ml_negate:      env_str("COLLECTOR_ML_NEGATE",      "false") == "true",
            ml_max_lines:   env_str("COLLECTOR_ML_MAX_LINES",   "500")
                            .parse().context("invalid COLLECTOR_ML_MAX_LINES")?,
            ml_timeout_ms:  env_str("COLLECTOR_ML_TIMEOUT_MS",  "2000")
                            .parse().context("invalid COLLECTOR_ML_TIMEOUT_MS")?,
            udp_readers:    env_str("COLLECTOR_UDP_READERS",    &default_readers.to_string())
                            .parse().context("invalid COLLECTOR_UDP_READERS")?,
            tcp_max_conn:   env_str("COLLECTOR_TCP_MAX_CONNECTIONS", "2000")
                            .parse().context("invalid COLLECTOR_TCP_MAX_CONNECTIONS")?,
            source_rate_eps:   env_str("COLLECTOR_SOURCE_RATE_EPS",   "0")
                            .parse().context("invalid COLLECTOR_SOURCE_RATE_EPS")?,
            source_rate_burst: env_str("COLLECTOR_SOURCE_RATE_BURST", "3")
                            .parse().context("invalid COLLECTOR_SOURCE_RATE_BURST")?,
            json_udp_bind,
            json_tcp_bind,
            gelf_udp_bind,
            gelf_tcp_bind,
            otlp_http_bind,
            fwd_concurrency: env_str("COLLECTOR_FWD_CONCURRENCY", "4")
                             .parse().context("invalid COLLECTOR_FWD_CONCURRENCY")?,
            api_hmac_secret: {
                let s = env_str("COLLECTOR_API_HMAC_SECRET", "");
                if s.is_empty() { None } else { Some(s) }
            },
            dlq_path: {
                let s = env_str("COLLECTOR_DLQ_PATH", "");
                if s.is_empty() { None } else { Some(PathBuf::from(s)) }
            },
            dlq_max_mb: env_str("COLLECTOR_DLQ_MAX_MB", "64")
                        .parse().context("invalid COLLECTOR_DLQ_MAX_MB")?,
        })
    }

    fn multiline_config(&self) -> Result<MultilineConfig> {
        let pattern = match &self.ml_pattern {
            Some(p) => Some(Regex::new(p).with_context(|| format!("invalid COLLECTOR_ML_PATTERN: {p}"))?),
            None    => None,
        };
        Ok(MultilineConfig {
            pattern,
            negate:     self.ml_negate,
            max_lines:  self.ml_max_lines,
            timeout_ms: self.ml_timeout_ms,
        })
    }
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

// ─── HTTP TLS reload server ────────────────────────────────────────────────────

/// Minimal HTTP server that accepts `POST /reload-tls` and atomically swaps
/// in freshly-read cert/key/CA.  Works on all platforms (no SIGUSR1 needed).
/// Bind to a loopback address to restrict access.
async fn serve_tls_reload(
    bind:      SocketAddr,
    swap:      Arc<arc_swap::ArcSwap<tokio_rustls::TlsAcceptor>>,
    cert_path: String,
    key_path:  String,
    ca_path:   String,
) {
    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(l)  => l,
        Err(e) => { error!(%e, %bind, "TLS reload server: bind failed"); return; }
    };
    info!(%bind, "TLS reload HTTP endpoint ready (POST /reload-tls)");

    loop {
        if let Ok((mut stream, peer)) = listener.accept().await {
            let swap2      = Arc::clone(&swap);
            let cert_path2 = cert_path.clone();
            let key_path2  = key_path.clone();
            let ca_path2   = ca_path.clone();

            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let mut req_buf = [0u8; 1024];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                let req = std::str::from_utf8(&req_buf[..n]).unwrap_or("");

                // Only handle POST /reload-tls — anything else gets 404.
                if !req.starts_with("POST /reload-tls") {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    return;
                }

                let result: anyhow::Result<()> = (|| async {
                    let cert = std::fs::read(&cert_path2)?;
                    let key  = std::fs::read(&key_path2)?;
                    let ca   = if !ca_path2.is_empty() {
                        Some(std::fs::read(&ca_path2)?)
                    } else {
                        None
                    };
                    let new_acceptor = sources::tcp::build_tls_acceptor(&cert, &key, ca.as_deref())?;
                    swap2.store(new_acceptor);
                    Ok(())
                })().await;

                match result {
                    Ok(()) => {
                        info!(from = %peer, "TLS certificate hot-reloaded via HTTP endpoint");
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                        ).await;
                    }
                    Err(e) => {
                        warn!(%e, "TLS reload failed — keeping existing certificate");
                        let body = format!("error: {e}");
                        let resp = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(), body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
            });
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cyberbox_collector=info".parse().unwrap()),
        )
        .init();

    // ── Vault secret injection (before any other config reads) ────────────────
    {
        let bootstrap_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        if let Err(err) = vault::load_secrets(&bootstrap_client).await {
            warn!(%err, "Vault secret loading failed — continuing with env vars");
        }
    }

    let cfg    = Config::from_env().context("invalid configuration")?;
    let ml_cfg = cfg.multiline_config()?;

    info!(
        api_url        = %cfg.api_url,
        tenant_id      = %cfg.tenant_id,
        udp            = %cfg.udp_bind,
        tcp            = %cfg.tcp_bind,
        netflow        = ?cfg.netflow_bind,
        batch_size     = cfg.batch_size,
        flush_ms       = cfg.flush_ms,
        queue_path     = %cfg.queue_path.display(),
        tls            = !cfg.tls_cert.is_empty(),
        tail_count     = cfg.tail_paths.len(),
        heartbeat_secs = cfg.heartbeat_secs,
        multiline      = cfg.ml_pattern.is_some(),
        "cyberbox-collector starting"
    );

    // ── HTTP client ───────────────────────────────────────────────────────────
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(8)
        .build()
        .context("build HTTP client")?;

    // ── Metrics ───────────────────────────────────────────────────────────────
    let metrics = CollectorMetrics::new(cfg.queue_path.clone());

    // Wire DLQ (optional — only if COLLECTOR_DLQ_PATH is set)
    if let Some(ref dlq_path) = cfg.dlq_path {
        let dlq = Arc::new(dlq::Dlq::new(dlq_path.clone(), cfg.dlq_max_mb));
        let _ = metrics.dlq.set(dlq);
        info!(path = %dlq_path.display(), max_mb = cfg.dlq_max_mb, "dead-letter queue enabled");
    }

    let start_time    = std::time::Instant::now();
    let drain_trigger = Arc::new(tokio::sync::Notify::new());
    {
        let m = Arc::clone(&metrics);
        tokio::spawn(metrics::serve(m));
    }
    {
        let m  = Arc::clone(&metrics);
        let dt = Arc::clone(&drain_trigger);
        tokio::spawn(healthz::serve(m, start_time, dt));
    }

    // ── Runtime config (remote override) ─────────────────────────────────────
    let runtime: SharedRuntimeConfig = remote_config::new_shared();
    {
        let rc2 = Arc::clone(&runtime);
        let cl2 = client.clone();
        tokio::spawn(remote_config::run(cl2, rc2));
    }

    // ── Shutdown signal (watch channel) ───────────────────────────────────────
    // Cloud tasks subscribe to this; it flips to `true` on Ctrl-C / SIGTERM
    // so they exit their poll loops cleanly without leaking threads.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── Event channel ─────────────────────────────────────────────────────────
    let (tx, rx) = mpsc::channel::<Value>(cfg.batch_size * 8);
    let tenant_id = Arc::new(cfg.tenant_id.clone());

    // ── Channel depth sampler (updates gauge every second) ────────────────────
    {
        let tx_sample = tx.clone();
        let m_depth   = Arc::clone(&metrics);
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            let mut interval = time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let depth = (tx_sample.max_capacity() - tx_sample.capacity()) as u64;
                m_depth.channel_depth.store(depth, Relaxed);
            }
        });
    }

    // ── Per-source-IP rate limiter ────────────────────────────────────────────
    let rate_limiter = Arc::new(SourceRateLimiter::new(cfg.source_rate_eps, cfg.source_rate_burst));
    if cfg.source_rate_eps > 0 {
        info!(eps = cfg.source_rate_eps, burst = cfg.source_rate_burst, "per-source-IP rate limiting enabled");
        let rl = Arc::clone(&rate_limiter);
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60));
            loop { interval.tick().await; rl.cleanup(); }
        });
    }

    // ── Forwarder (gzip + disk queue + retry) ─────────────────────────────────
    let channel_capacity = cfg.batch_size * 8; // matches mpsc::channel capacity below
    let fwd_cfg = ForwarderConfig {
        api_url:          cfg.api_url.clone(),
        tenant_id:        cfg.tenant_id.clone(),
        batch_size:       cfg.batch_size,
        flush_ms:         cfg.flush_ms,
        queue_path:       cfg.queue_path.clone(),
        queue_max_mb:     cfg.queue_max_mb,
        concurrency:      cfg.fwd_concurrency,
        channel_capacity,
        hmac_secret:      cfg.api_hmac_secret.clone(),
        drain_trigger:    Arc::clone(&drain_trigger),
    };
    let fwd_handle = tokio::spawn(forwarder::run(rx, fwd_cfg, client.clone(), Some(Arc::clone(&runtime)), Arc::clone(&metrics)));

    // ── UDP listener (multi-reader) ───────────────────────────────────────────
    {
        let tx2  = tx.clone();
        let tid  = Arc::clone(&tenant_id);
        let bind = cfg.udp_bind;
        let max  = cfg.max_msg_bytes;
        let m    = Arc::clone(&metrics);
        let rl   = Arc::clone(&rate_limiter);
        let rdr  = cfg.udp_readers;
        let sd = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(err) = sources::udp::run(bind, rdr, tid, tx2, max, m, rl, sd).await {
                error!(%err, "UDP listener failed");
            }
        });
    }

    // ── TLS acceptor (shared by TCP, GELF, JSON sources) ─────────────────────
    // Wrapped in ArcSwap so hot-reload (SIGUSR1 on Unix, HTTP on all platforms)
    // swaps the acceptor atomically without touching existing connections.
    let tls_swap: Option<Arc<arc_swap::ArcSwap<tokio_rustls::TlsAcceptor>>> =
        if !cfg.tls_cert.is_empty() && !cfg.tls_key.is_empty() {
            let cert = std::fs::read(&cfg.tls_cert)
                .with_context(|| format!("read TLS cert {}", cfg.tls_cert))?;
            let key = std::fs::read(&cfg.tls_key)
                .with_context(|| format!("read TLS key {}", cfg.tls_key))?;
            let ca = if !cfg.tls_ca.is_empty() {
                Some(std::fs::read(&cfg.tls_ca)
                    .with_context(|| format!("read TLS CA {}", cfg.tls_ca))?)
            } else {
                None
            };
            let mode = if ca.is_some() { "mTLS" } else { "TLS" };
            info!(mode, cert = %cfg.tls_cert, "TCP listener using {mode}");
            let acceptor = sources::tcp::build_tls_acceptor(&cert, &key, ca.as_deref())?;
            Some(Arc::new(arc_swap::ArcSwap::from(acceptor)))
        } else {
            None
        };

    // ── SIGUSR1: hot-reload TLS certificate (Unix only) ───────────────────────
    #[cfg(unix)]
    if let Some(ref swap) = tls_swap {
        let swap2     = Arc::clone(swap);
        let cert_path = cfg.tls_cert.clone();
        let key_path  = cfg.tls_key.clone();
        let ca_path   = cfg.tls_ca.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sig = match signal(SignalKind::user_defined1()) {
                Ok(s)  => s,
                Err(e) => { error!(%e, "SIGUSR1 handler setup failed"); return; }
            };
            loop {
                sig.recv().await;
                info!("SIGUSR1: reloading TLS certificate");
                let cert = std::fs::read(&cert_path);
                let key  = std::fs::read(&key_path);
                let ca   = if !ca_path.is_empty() { std::fs::read(&ca_path).ok() } else { None };
                match (cert, key) {
                    (Ok(c), Ok(k)) => {
                        match sources::tcp::build_tls_acceptor(&c, &k, ca.as_deref()) {
                            Ok(new_acceptor) => {
                                swap2.store(new_acceptor);
                                info!("TLS certificate hot-reloaded via SIGUSR1");
                            }
                            Err(e) => error!(%e, "TLS hot-reload failed — keeping existing cert"),
                        }
                    }
                    _ => error!("TLS hot-reload: could not read cert/key files"),
                }
            }
        });
    }

    // ── HTTP TLS reload endpoint (cross-platform; enabled by COLLECTOR_TLS_RELOAD_BIND) ──
    if let (Some(reload_bind), Some(ref swap)) = (cfg.tls_reload_bind, &tls_swap) {
        let swap2     = Arc::clone(swap);
        let cert_path = cfg.tls_cert.clone();
        let key_path  = cfg.tls_key.clone();
        let ca_path   = cfg.tls_ca.clone();
        tokio::spawn(serve_tls_reload(reload_bind, swap2, cert_path, key_path, ca_path));
    } else if cfg.tls_reload_bind.is_some() {
        warn!("COLLECTOR_TLS_RELOAD_BIND is set but TLS is not configured — reload endpoint disabled");
    }

    // ── TCP syslog listener ───────────────────────────────────────────────────
    {
        let tx2   = tx.clone();
        let tid   = Arc::clone(&tenant_id);
        let bind  = cfg.tcp_bind;
        let max   = cfg.max_msg_bytes;
        let m     = Arc::clone(&metrics);
        let ml    = MultilineConfig {
            pattern:    ml_cfg.pattern.as_ref()
                .map(|r| Regex::new(r.as_str()).unwrap()),
            negate:     ml_cfg.negate,
            max_lines:  ml_cfg.max_lines,
            timeout_ms: ml_cfg.timeout_ms,
        };
        let tls2    = tls_swap.as_ref().map(Arc::clone);
        let max_conn = cfg.tcp_max_conn;
        let rl       = Arc::clone(&rate_limiter);
        let sd = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(err) = sources::tcp::run(bind, tid, tx2, max, tls2, ml, m, max_conn, rl, sd).await {
                error!(%err, "TCP listener failed");
            }
        });
    }

    // ── NetFlow v5/v9/IPFIX listener ──────────────────────────────────────────
    if let Some(nf_bind) = cfg.netflow_bind {
        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant_id);
        let m   = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(err) = sources::netflow::run(nf_bind, tid, tx2, m).await {
                error!(%err, "NetFlow listener failed");
            }
        });
    }

    // ── File tailing (with multiline + persistent bookmark) ───────────────────
    if !cfg.tail_paths.is_empty() {
        let tx2       = tx.clone();
        let tid       = Arc::clone(&tenant_id);
        let paths     = cfg.tail_paths.clone();
        let poll_ms   = cfg.tail_poll_ms;
        let bookmark  = cfg.tail_bookmark.clone();
        let ml        = MultilineConfig {
            pattern:    ml_cfg.pattern.as_ref()
                .map(|r| Regex::new(r.as_str()).unwrap()),
            negate:     ml_cfg.negate,
            max_lines:  ml_cfg.max_lines,
            timeout_ms: ml_cfg.timeout_ms,
        };
        let _sd = shutdown_rx.clone(); // tail exits when tx closes; watch clone keeps shutdown channel alive
        tokio::spawn(sources::tail::run(paths, poll_ms, tid, tx2, ml, bookmark));
    }

    // ── Windows Event Log ─────────────────────────────────────────────────────
    #[cfg(windows)]
    {
        let tx2      = tx.clone();
        let tid      = Arc::clone(&tenant_id);
        let channels = cfg.wel_channels.clone();
        tokio::spawn(sources::wineventlog::run(channels, tid, tx2));
    }

    // ── Cloud source polling (S3, Okta, O365) — graceful shutdown wired in ───
    {
        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant_id);
        let cl2 = client.clone();
        let m   = Arc::clone(&metrics);
        let sd  = shutdown_rx.clone();
        tokio::spawn(sources::cloud::spawn_all(cl2, tid, tx2, m, sd));
    }

    // ── Heartbeat ─────────────────────────────────────────────────────────────
    {
        let tx2      = tx.clone();
        let tid      = Arc::clone(&tenant_id);
        let interval = cfg.heartbeat_secs;
        let sd = shutdown_rx.clone();
        tokio::spawn(heartbeat::run(interval, tid, tx2, sd));
    }

    // ── JSON input sources ────────────────────────────────────────────────────
    if let Some(j_udp) = cfg.json_udp_bind {
        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant_id);
        let m   = Arc::clone(&metrics);
        let sd = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(err) = sources::json_input::run_udp(j_udp, tid, tx2, m, sd).await {
                error!(%err, "JSON UDP listener failed");
            }
        });
    }
    if let Some(j_tcp) = cfg.json_tcp_bind {
        let tx2  = tx.clone();
        let tid  = Arc::clone(&tenant_id);
        let m    = Arc::clone(&metrics);
        let tls2 = tls_swap.as_ref().map(Arc::clone);
        let sd = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(err) = sources::json_input::run_tcp(j_tcp, tid, tx2, m, tls2, sd).await {
                error!(%err, "JSON TCP listener failed");
            }
        });
    }

    // ── GELF input sources ────────────────────────────────────────────────────
    if let Some(g_udp) = cfg.gelf_udp_bind {
        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant_id);
        let m   = Arc::clone(&metrics);
        let sd = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(err) = sources::gelf::run_udp(g_udp, tid, tx2, m, sd).await {
                error!(%err, "GELF UDP listener failed");
            }
        });
    }
    if let Some(g_tcp) = cfg.gelf_tcp_bind {
        let tx2  = tx.clone();
        let tid  = Arc::clone(&tenant_id);
        let m    = Arc::clone(&metrics);
        let tls2 = tls_swap.as_ref().map(Arc::clone);
        let sd = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(err) = sources::gelf::run_tcp(g_tcp, tid, tx2, m, tls2, sd).await {
                error!(%err, "GELF TCP listener failed");
            }
        });
    }

    // ── OTLP HTTP receiver ────────────────────────────────────────────────────
    if let Some(otlp_bind) = cfg.otlp_http_bind {
        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant_id);
        let m   = Arc::clone(&metrics);
        let sd = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(err) = sources::otlp::run(otlp_bind, tid, tx2, m, sd).await {
                error!(%err, "OTLP HTTP receiver failed");
            }
        });
    }

    // ── Kafka consumer (optional — compiled only with --features kafka) ────────
    #[cfg(feature = "kafka")]
    {
        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant_id);
        let m   = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(err) = sources::kafka::run(tid, tx2, m).await {
                error!(%err, "Kafka consumer failed");
            }
        });
    }

    // ── Wait for Ctrl-C / SIGTERM, then drain gracefully ─────────────────────
    tokio::signal::ctrl_c().await.context("signal handler")?;
    info!("shutdown signal received — signalling cloud tasks and draining forwarder…");

    // Signal all cloud tasks to exit their poll loops.
    let _ = shutdown_tx.send(true);

    // Close the ingest channel so the forwarder exits after flushing.
    drop(tx);

    // Wait up to 30 s for the forwarder to flush remaining events and close.
    match time::timeout(Duration::from_secs(30), fwd_handle).await {
        Ok(_)  => info!("forwarder drained — collector stopped"),
        Err(_) => warn!("forwarder drain timeout (30 s) — forcing shutdown"),
    }
    Ok(())
}
