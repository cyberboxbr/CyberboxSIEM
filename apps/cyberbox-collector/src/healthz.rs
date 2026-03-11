//! Lightweight JSON health endpoint for the collector.
//!
//! Serves `GET /healthz` (and any path, for simplicity) on
//! `COLLECTOR_HEALTHZ_BIND` (default empty = disabled).
//!
//! ## Response fields
//! | Field | Type | Description |
//! |---|---|---|
//! | `status` | `"ok"` | Always "ok" while the process is running |
//! | `version` | string | Crate version from Cargo.toml |
//! | `uptime_secs` | u64 | Seconds since collector start |
//! | `events_received` | object | Per-source counters |
//! | `events_dropped` | object | Drop counters by reason |
//! | `events_forwarded` | u64 | Successfully delivered to the API |
//! | `batches_ok` | u64 | Successful API batch POSTs |
//! | `batches_err` | u64 | Failed API batch POSTs |
//! | `channel_depth` | u64 | Current ingest channel queue depth |
//! | `last_batch_secs_ago` | u64 | Seconds since the last successful batch |
//! | `queue_bytes` | u64 | Disk overflow queue file size |

use std::{net::SocketAddr, sync::Arc, time::Instant};

use tokio::sync::Notify;
use tracing::{error, info};

use crate::metrics::CollectorMetrics;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Serve the healthz + management endpoint.  Returns immediately if
/// `COLLECTOR_HEALTHZ_BIND` is empty or unset.
///
/// Endpoints:
/// - `GET  /healthz`   — JSON health/metrics snapshot
/// - `POST /drain-dlq` — trigger immediate disk queue drain (202 Accepted)
pub async fn serve(metrics: Arc<CollectorMetrics>, start: Instant, drain_trigger: Arc<Notify>) {
    let bind_str = std::env::var("COLLECTOR_HEALTHZ_BIND").unwrap_or_default();

    if bind_str.is_empty() {
        return;
    }

    let bind: SocketAddr = match bind_str.parse() {
        Ok(a) => a,
        Err(e) => {
            error!(%e, "invalid COLLECTOR_HEALTHZ_BIND — healthz disabled");
            return;
        }
    };

    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            error!(%e, %bind, "failed to bind healthz listener");
            return;
        }
    };
    info!(%bind, "collector healthz endpoint ready (GET /healthz)");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let m = Arc::clone(&metrics);
            let trigger = Arc::clone(&drain_trigger);
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut rbuf = [0u8; 512];
                let n = tokio::io::AsyncReadExt::read(&mut stream, &mut rbuf)
                    .await
                    .unwrap_or(0);
                let req = std::str::from_utf8(&rbuf[..n]).unwrap_or("");

                let resp = if req.starts_with("POST /drain-dlq") {
                    trigger.notify_one();
                    info!("drain-dlq requested via healthz endpoint");
                    "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                } else {
                    // GET /healthz or anything else → return health JSON
                    let body = build_body(&m, start);
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    }
}

fn build_body(m: &CollectorMetrics, start: Instant) -> String {
    use std::sync::atomic::Ordering::Relaxed;

    let uptime = start.elapsed().as_secs();

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last_batch = m.last_batch_epoch_secs.load(Relaxed);
    let last_batch_secs_ago = if last_batch == 0 {
        u64::MAX
    } else {
        now_epoch.saturating_sub(last_batch)
    };

    let queue_bytes = std::fs::metadata(&m.queue_path)
        .map(|meta| meta.len())
        .unwrap_or(0);

    serde_json::json!({
        "status":  "ok",
        "version": VERSION,
        "uptime_secs": uptime,
        "events_received": {
            "udp":       m.udp_received.load(Relaxed),
            "tcp":       m.tcp_received.load(Relaxed),
            "file":      m.file_received.load(Relaxed),
            "netflow":   m.netflow_received.load(Relaxed),
            "cloud":     m.cloud_received.load(Relaxed),
            "gelf_udp":  m.gelf_udp_received.load(Relaxed),
            "gelf_tcp":  m.gelf_tcp_received.load(Relaxed),
            "json_udp":  m.json_udp_received.load(Relaxed),
            "json_tcp":  m.json_tcp_received.load(Relaxed),
            "otlp":      m.otlp_received.load(Relaxed),
            "kafka":     m.kafka_received.load(Relaxed),
        },
        "events_dropped": {
            "channel_full": m.channel_drops.load(Relaxed),
            "parse_error":  m.parse_errors.load(Relaxed),
            "rate_limited": m.rate_limit_drops.load(Relaxed),
        },
        "events_forwarded":   m.events_forwarded.load(Relaxed),
        "batches_ok":         m.batches_ok.load(Relaxed),
        "batches_err":        m.batches_err.load(Relaxed),
        "channel_depth":      m.channel_depth.load(Relaxed),
        "last_batch_secs_ago": last_batch_secs_ago,
        "queue_bytes":        queue_bytes,
    })
    .to_string()
}
