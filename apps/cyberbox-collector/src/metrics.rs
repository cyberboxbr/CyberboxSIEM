//! Collector-side Prometheus metrics.
//!
//! Exposes a `/metrics` endpoint on `COLLECTOR_METRICS_BIND` (default
//! `0.0.0.0:9091`) in the Prometheus text format.  Prometheus or any compatible
//! scraper can poll it; no external crate is required — we hand-roll the text
//! format with standard atomic counters.
//!
//! # Counters exposed
//! | Metric | Labels | Description |
//! |---|---|---|
//! | `collector_events_received_total` | `source` | Events parsed and queued per source |
//! | `collector_events_dropped_total` | `reason` | Events discarded (channel_full, parse_error) |
//! | `collector_batches_sent_total` | `status` | API POST results (ok / err) |
//! | `collector_events_forwarded_total` | — | Events successfully sent to the API |
//! | `collector_queue_bytes` | — | Current disk overflow queue file size (gauge) |

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock,
    },
};

use tracing::{error, info};

// ─── Latency histogram ────────────────────────────────────────────────────────

/// Fixed upper bounds in milliseconds (le= labels in Prometheus).
const BOUNDS: [u64; 12] = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000];
/// Number of finite bounds + 1 (+Inf bucket at index 12).
const NUM_BUCKETS: usize = BOUNDS.len() + 1;

/// Lightweight cumulative histogram using atomic counters.
///
/// Each call to `observe(ms)` increments every bucket whose upper bound
/// is ≥ `ms` (i.e. the values are stored cumulatively, matching the
/// Prometheus histogram wire format directly).
pub struct LatencyHistogram {
    /// `buckets[i]` = count of observations with value ≤ BOUNDS[i].
    /// `buckets[NUM_BUCKETS-1]` = +Inf = total count.
    buckets: [AtomicU64; NUM_BUCKETS],
    sum_ms: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_ms: AtomicU64::new(0),
        }
    }
}

impl LatencyHistogram {
    pub fn observe(&self, ms: u64) {
        let r = Ordering::Relaxed;
        self.sum_ms.fetch_add(ms, r);
        for (i, &bound) in BOUNDS.iter().enumerate() {
            if ms <= bound {
                self.buckets[i].fetch_add(1, r);
            }
        }
        // +Inf always
        self.buckets[NUM_BUCKETS - 1].fetch_add(1, r);
    }

    /// Render as Prometheus histogram lines (no HELP/TYPE header — caller adds those).
    pub fn render_buckets(&self, name: &str) -> String {
        let r = Ordering::Relaxed;
        let mut out = String::new();
        for (i, &bound) in BOUNDS.iter().enumerate() {
            let v = self.buckets[i].load(r);
            out.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {v}\n"));
        }
        let inf = self.buckets[NUM_BUCKETS - 1].load(r);
        let sum = self.sum_ms.load(r);
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {inf}\n"));
        out.push_str(&format!("{name}_sum {sum}\n"));
        out.push_str(&format!("{name}_count {inf}\n"));
        out
    }
}

// ─── Counter struct ───────────────────────────────────────────────────────────

pub struct CollectorMetrics {
    // Events received per source
    pub udp_received: AtomicU64,
    pub tcp_received: AtomicU64,
    pub file_received: AtomicU64,
    pub netflow_received: AtomicU64,
    pub cloud_received: AtomicU64,
    pub heartbeat_sent: AtomicU64,
    // Granular per-protocol counters
    pub gelf_udp_received: AtomicU64,
    pub gelf_tcp_received: AtomicU64,
    pub json_udp_received: AtomicU64,
    pub json_tcp_received: AtomicU64,
    pub otlp_received: AtomicU64,

    // Drops / errors
    pub channel_drops: AtomicU64,
    pub parse_errors: AtomicU64,
    pub rate_limit_drops: AtomicU64,

    // Forwarder
    pub batches_ok: AtomicU64,
    pub batches_err: AtomicU64,
    pub events_forwarded: AtomicU64,

    // Kafka consumer
    pub kafka_received: AtomicU64,

    // Ingest channel depth (sampled by a background task in main.rs)
    pub channel_depth: AtomicU64,

    // Epoch seconds of the last successful API batch (0 = never)
    pub last_batch_epoch_secs: AtomicU64,

    // API batch POST latency histogram (milliseconds)
    pub batch_latency: LatencyHistogram,

    // Queue size (read at scrape time from disk)
    pub queue_path: PathBuf,

    // Optional dead-letter queue — set once in main.rs before sources start.
    pub dlq: OnceLock<Arc<crate::dlq::Dlq>>,
}

impl CollectorMetrics {
    pub fn new(queue_path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            udp_received: AtomicU64::new(0),
            tcp_received: AtomicU64::new(0),
            file_received: AtomicU64::new(0),
            netflow_received: AtomicU64::new(0),
            cloud_received: AtomicU64::new(0),
            heartbeat_sent: AtomicU64::new(0),
            gelf_udp_received: AtomicU64::new(0),
            gelf_tcp_received: AtomicU64::new(0),
            json_udp_received: AtomicU64::new(0),
            json_tcp_received: AtomicU64::new(0),
            otlp_received: AtomicU64::new(0),
            channel_drops: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            rate_limit_drops: AtomicU64::new(0),
            batches_ok: AtomicU64::new(0),
            batches_err: AtomicU64::new(0),
            events_forwarded: AtomicU64::new(0),
            kafka_received: AtomicU64::new(0),
            channel_depth: AtomicU64::new(0),
            last_batch_epoch_secs: AtomicU64::new(0),
            batch_latency: LatencyHistogram::default(),
            queue_path,
            dlq: OnceLock::new(),
        })
    }

    /// Render Prometheus text exposition format.
    pub fn render(&self) -> String {
        let r = Ordering::Relaxed;

        let udp = self.udp_received.load(r);
        let tcp = self.tcp_received.load(r);
        let file = self.file_received.load(r);
        let netflow = self.netflow_received.load(r);
        let cloud = self.cloud_received.load(r);
        let hb = self.heartbeat_sent.load(r);
        let gelf_udp = self.gelf_udp_received.load(r);
        let gelf_tcp = self.gelf_tcp_received.load(r);
        let json_udp = self.json_udp_received.load(r);
        let json_tcp = self.json_tcp_received.load(r);
        let otlp = self.otlp_received.load(r);
        let kafka = self.kafka_received.load(r);
        let drops = self.channel_drops.load(r);
        let perr = self.parse_errors.load(r);
        let rldrops = self.rate_limit_drops.load(r);
        let bok = self.batches_ok.load(r);
        let berr = self.batches_err.load(r);
        let fwd = self.events_forwarded.load(r);
        let depth = self.channel_depth.load(r);
        let last_batch = self.last_batch_epoch_secs.load(r);
        let latency_buckets = self
            .batch_latency
            .render_buckets("collector_batch_latency_ms");
        let qbytes = std::fs::metadata(&self.queue_path)
            .map(|m| m.len())
            .unwrap_or(0);

        format!(
            "# HELP collector_events_received_total Total events received per source\n\
             # TYPE collector_events_received_total counter\n\
             collector_events_received_total{{source=\"udp\"}} {udp}\n\
             collector_events_received_total{{source=\"tcp\"}} {tcp}\n\
             collector_events_received_total{{source=\"file\"}} {file}\n\
             collector_events_received_total{{source=\"netflow\"}} {netflow}\n\
             collector_events_received_total{{source=\"cloud\"}} {cloud}\n\
             collector_events_received_total{{source=\"heartbeat\"}} {hb}\n\
             collector_events_received_total{{source=\"gelf_udp\"}} {gelf_udp}\n\
             collector_events_received_total{{source=\"gelf_tcp\"}} {gelf_tcp}\n\
             collector_events_received_total{{source=\"json_udp\"}} {json_udp}\n\
             collector_events_received_total{{source=\"json_tcp\"}} {json_tcp}\n\
             collector_events_received_total{{source=\"otlp\"}} {otlp}\n\
             collector_events_received_total{{source=\"kafka\"}} {kafka}\n\
             # HELP collector_events_dropped_total Events discarded before forwarding\n\
             # TYPE collector_events_dropped_total counter\n\
             collector_events_dropped_total{{reason=\"channel_full\"}} {drops}\n\
             collector_events_dropped_total{{reason=\"parse_error\"}} {perr}\n\
             collector_events_dropped_total{{reason=\"rate_limited\"}} {rldrops}\n\
             # HELP collector_batches_sent_total API batch POST results\n\
             # TYPE collector_batches_sent_total counter\n\
             collector_batches_sent_total{{status=\"ok\"}} {bok}\n\
             collector_batches_sent_total{{status=\"error\"}} {berr}\n\
             # HELP collector_events_forwarded_total Events successfully delivered to the API\n\
             # TYPE collector_events_forwarded_total counter\n\
             collector_events_forwarded_total {fwd}\n\
             # HELP collector_ingest_channel_depth Current events queued in the ingest channel\n\
             # TYPE collector_ingest_channel_depth gauge\n\
             collector_ingest_channel_depth {depth}\n\
             # HELP collector_queue_bytes Disk overflow queue file size in bytes\n\
             # TYPE collector_queue_bytes gauge\n\
             collector_queue_bytes {qbytes}\n\
             # HELP collector_last_batch_epoch_seconds Unix timestamp of the last successful API batch\n\
             # TYPE collector_last_batch_epoch_seconds gauge\n\
             collector_last_batch_epoch_seconds {last_batch}\n\
             # HELP collector_batch_latency_ms Histogram of API batch POST latency in milliseconds\n\
             # TYPE collector_batch_latency_ms histogram\n\
             {latency_buckets}"
        )
    }
}

// ─── HTTP server ──────────────────────────────────────────────────────────────

/// Serve Prometheus `/metrics` on `COLLECTOR_METRICS_BIND` (default
/// `0.0.0.0:9091`). Returns immediately if the env var is set to empty string.
pub async fn serve(metrics: Arc<CollectorMetrics>) {
    let bind_str =
        std::env::var("COLLECTOR_METRICS_BIND").unwrap_or_else(|_| "0.0.0.0:9091".to_string());

    if bind_str.is_empty() {
        return;
    }

    let bind: SocketAddr = match bind_str.parse() {
        Ok(a) => a,
        Err(e) => {
            error!(%e, "invalid COLLECTOR_METRICS_BIND — metrics disabled");
            return;
        }
    };

    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            error!(%e, %bind, "failed to bind metrics listener");
            return;
        }
    };
    info!(%bind, "collector metrics endpoint ready (GET /metrics)");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let m = Arc::clone(&metrics);
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                // Read request (we don't need to parse it — respond to anything)
                let mut rbuf = [0u8; 512];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut rbuf).await;

                let body = m.render();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    }
}
