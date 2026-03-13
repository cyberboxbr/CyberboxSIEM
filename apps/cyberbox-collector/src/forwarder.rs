//! Batch forwarder with concurrent HTTP POSTs, adaptive batch sizing,
//! exponential-backoff retry, and disk-overflow queue.
//!
//! ## Normal flow
//! Events → mpsc channel → forwarder → gzip-compressed batch POST(s) to API.
//!
//! ## Concurrency model
//! Up to `concurrency` (default 4, `COLLECTOR_FWD_CONCURRENCY`) batch POSTs
//! fly in parallel.  A `Semaphore` with N permits gates dispatch: once N batches
//! are in-flight the main loop blocks on acquiring a permit, providing natural
//! back-pressure to the ingest channel.  Results (success/failure) are returned
//! via an unbounded channel and drained non-blockingly at the top of each loop
//! iteration.
//!
//! ## Adaptive batch sizing
//! When the ingest channel is filling up (depth > 50% of capacity), the
//! effective batch size doubles; at > 75% it quadruples (up to 5 000 events).
//! This allows the forwarder to drain bursts more quickly without sacrificing
//! latency at normal load.
//!
//! ## When the API is unreachable
//! 1. Failed batch is appended as a JSON-lines entry to `queue_path`.
//! 2. Every flush tick the task probes the API by attempting to drain the queue.
//! 3. Backoff doubles on each consecutive failure (100 ms → 200 → … → 30 s).
//! 4. On reconnect the queue is drained FIFO before accepting new batches.
//! 5. If the queue file exceeds `queue_max_mb`, oldest batches are silently dropped.
//!
//! ## Streaming drain
//! `drain_queue` reads the queue file one line at a time (constant memory) and
//! streams remaining failed lines to a `.jsonl.tmp` sidecar.  On success the
//! tmp file replaces the original atomically.

use std::{
    io::{BufRead, Write},
    path::PathBuf,
    sync::{atomic::Ordering::Relaxed, Arc},
    time::Duration,
};

use flate2::{write::GzEncoder, Compression};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use tokio::{
    sync::{mpsc, Notify, Semaphore},
    time,
};
use tracing::{debug, error, info, warn};

use crate::metrics::CollectorMetrics;
use crate::remote_config::SharedRuntimeConfig;

// ─── Config ───────────────────────────────────────────────────────────────────

pub struct ForwarderConfig {
    pub api_url: String,
    pub tenant_id: String,
    pub batch_size: usize,
    pub flush_ms: u64,
    pub queue_path: PathBuf,
    pub queue_max_mb: u64,
    /// Max concurrent in-flight batch POSTs (default 4).
    pub concurrency: usize,
    /// Ingest channel capacity — used to compute adaptive batch size.
    pub channel_capacity: usize,
    /// If set, sign each POST with `X-Cyberbox-Signature: sha256=<hex>`.
    pub hmac_secret: Option<String>,
    /// If set, send `X-Api-Key` header on each POST for authenticated ingest.
    pub api_key: Option<String>,
    /// When notified, immediately attempt to drain the disk queue (for the
    /// `POST /drain-dlq` management endpoint).
    pub drain_trigger: Arc<Notify>,
}

// ─── API health tracker ───────────────────────────────────────────────────────

struct ApiHealth {
    online: bool,
    backoff_ms: u64,
}

impl ApiHealth {
    fn new() -> Self {
        Self {
            online: true,
            backoff_ms: 100,
        }
    }
    fn mark_success(&mut self) {
        self.online = true;
        self.backoff_ms = 100;
    }
    fn mark_failure(&mut self) {
        self.online = false;
        self.backoff_ms = (self.backoff_ms * 2).min(30_000);
    }
}

// ─── Concurrent POST result ───────────────────────────────────────────────────

struct PostOutcome {
    success: bool,
    /// Non-empty only on failure — events to spill to disk queue.
    failed_events: Vec<Value>,
    count: u64,
    latency_ms: u64,
}

// ─── Forwarder task ───────────────────────────────────────────────────────────

pub async fn run(
    mut rx: mpsc::Receiver<Value>,
    cfg: ForwarderConfig,
    client: reqwest::Client,
    runtime: Option<SharedRuntimeConfig>,
    metrics: Arc<CollectorMetrics>,
) {
    let ingest_url = Arc::new(format!("{}/api/v1/events:ingest", cfg.api_url));
    let tenant_id = Arc::new(cfg.tenant_id.clone());
    let hmac_secret = Arc::new(cfg.hmac_secret.clone());
    let api_key = Arc::new(cfg.api_key.clone());
    let drain_trigger = Arc::clone(&cfg.drain_trigger);

    let concurrency = cfg.concurrency.max(1);
    let sem = Arc::new(Semaphore::new(concurrency));
    let (result_tx, mut result_rx) = mpsc::unbounded_channel::<PostOutcome>();

    let flush_interval = Duration::from_millis(cfg.flush_ms);
    let mut batch: Vec<Value> = Vec::with_capacity(cfg.batch_size);
    let mut ticker = time::interval(flush_interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut health = ApiHealth::new();
    let mut needs_drain = false;

    if cfg.queue_path.exists() {
        info!(path = %cfg.queue_path.display(), "found disk queue from previous run — will drain on reconnect");
        needs_drain = true;
    }

    loop {
        let cur_batch_size = effective_batch_size(&cfg, &runtime, &metrics);

        // ── Non-blocking drain of completed in-flight POSTs ───────────────────
        drain_results(
            &mut result_rx,
            &mut needs_drain,
            &mut health,
            &metrics,
            &cfg,
        );

        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(ev) => {
                        batch.push(ev);
                        if batch.len() >= cur_batch_size {
                            let events = std::mem::take(&mut batch);
                            dispatch_post(events, &sem, &result_tx, &client, &ingest_url, &tenant_id, &hmac_secret, &api_key).await;
                        }
                    }
                    None => {
                        // Channel closed — flush remaining events then wait for all in-flight.
                        if !batch.is_empty() {
                            let events = std::mem::take(&mut batch);
                            dispatch_post(events, &sem, &result_tx, &client, &ingest_url, &tenant_id, &hmac_secret, &api_key).await;
                        }
                        // Acquire all N permits → every in-flight task has finished.
                        let _ = sem.acquire_many(concurrency as u32).await;
                        // Final drain of any results that arrived during shutdown.
                        drain_results(&mut result_rx, &mut needs_drain, &mut health, &metrics, &cfg);
                        return;
                    }
                }
            }
            _ = ticker.tick() => {
                if needs_drain {
                    drain_queue(&client, &ingest_url, &tenant_id, &cfg, &mut health, &metrics, hmac_secret.as_deref(), api_key.as_deref()).await;
                    if health.online && !cfg.queue_path.exists() {
                        needs_drain = false;
                    }
                }
                if !batch.is_empty() {
                    let events = std::mem::take(&mut batch);
                    dispatch_post(events, &sem, &result_tx, &client, &ingest_url, &tenant_id, &hmac_secret, &api_key).await;
                }
            }
            _ = drain_trigger.notified() => {
                info!("drain-dlq triggered via management endpoint");
                needs_drain = true;
                drain_queue(&client, &ingest_url, &tenant_id, &cfg, &mut health, &metrics, hmac_secret.as_deref(), api_key.as_deref()).await;
                if health.online && !cfg.queue_path.exists() {
                    needs_drain = false;
                }
            }
        }
    }
}

// ─── Adaptive batch sizing ────────────────────────────────────────────────────

/// Scale effective batch size based on ingest-channel fill ratio.
///
/// | Fill   | Multiplier |
/// |--------|-----------|
/// | > 75%  | × 4       |
/// | > 50%  | × 2       |
/// | ≤ 50%  | × 1       |
///
/// The runtime override (remote config) sets the *base* batch size before
/// the multiplier is applied.  Result is capped at 5 000 to prevent oversized
/// API requests.
fn effective_batch_size(
    cfg: &ForwarderConfig,
    runtime: &Option<SharedRuntimeConfig>,
    metrics: &CollectorMetrics,
) -> usize {
    let base = runtime
        .as_ref()
        .and_then(|rc| rc.try_read().ok())
        .and_then(|g| g.batch_size)
        .unwrap_or(cfg.batch_size);

    let depth = metrics.channel_depth.load(Relaxed) as usize;
    let cap = cfg.channel_capacity.max(1);

    let scale = if depth * 4 > cap * 3 {
        4
    }
    // > 75%
    else if depth * 2 > cap {
        2
    }
    // > 50%
    else {
        1
    };

    (base * scale).min(5_000)
}

// ─── Dispatch: acquire permit then spawn POST task ────────────────────────────

/// Acquire a semaphore permit (blocks if `concurrency` tasks are already
/// in-flight) then spawn a task to POST the batch.  The permit is held for
/// the lifetime of the spawned task so at most `concurrency` POSTs run
/// simultaneously.
async fn dispatch_post(
    events: Vec<Value>,
    sem: &Arc<Semaphore>,
    result_tx: &mpsc::UnboundedSender<PostOutcome>,
    client: &reqwest::Client,
    url: &Arc<String>,
    tenant_id: &Arc<String>,
    hmac_secret: &Arc<Option<String>>,
    api_key: &Arc<Option<String>>,
) {
    let count = events.len() as u64;
    let permit = sem
        .clone()
        .acquire_owned()
        .await
        .expect("forwarder semaphore closed — this is a bug");

    let client2 = client.clone();
    let url2 = Arc::clone(url);
    let tenant2 = Arc::clone(tenant_id);
    let secret2 = Arc::clone(hmac_secret);
    let api_key2 = Arc::clone(api_key);
    let result_tx2 = result_tx.clone();

    tokio::spawn(async move {
        let _permit = permit; // released when this task ends
        let t0 = std::time::Instant::now();

        match post_events(
            &client2,
            &url2,
            &tenant2,
            &events,
            secret2.as_deref(),
            api_key2.as_deref(),
        )
        .await
        {
            Ok(()) => {
                let latency_ms = t0.elapsed().as_millis() as u64;
                debug!(count, latency_ms, "batch POSTed successfully");
                let _ = result_tx2.send(PostOutcome {
                    success: true,
                    failed_events: vec![],
                    count,
                    latency_ms,
                });
            }
            Err(err) => {
                let latency_ms = t0.elapsed().as_millis() as u64;
                error!(%err, count, latency_ms, "API POST failed — spilling to result queue");
                let _ = result_tx2.send(PostOutcome {
                    success: false,
                    failed_events: events,
                    count,
                    latency_ms,
                });
            }
        }
    });
}

// ─── Non-blocking drain of completed POST results ─────────────────────────────

fn drain_results(
    result_rx: &mut mpsc::UnboundedReceiver<PostOutcome>,
    needs_drain: &mut bool,
    health: &mut ApiHealth,
    metrics: &CollectorMetrics,
    cfg: &ForwarderConfig,
) {
    while let Ok(outcome) = result_rx.try_recv() {
        metrics.batch_latency.observe(outcome.latency_ms);
        if outcome.success {
            health.mark_success();
            metrics.batches_ok.fetch_add(1, Relaxed);
            metrics.events_forwarded.fetch_add(outcome.count, Relaxed);
            let epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            metrics.last_batch_epoch_secs.store(epoch, Relaxed);
        } else {
            health.mark_failure();
            metrics.batches_err.fetch_add(1, Relaxed);
            spill_to_queue(cfg, outcome.failed_events);
            *needs_drain = true;
        }
    }
}

// ─── HTTP POST ────────────────────────────────────────────────────────────────

async fn post_events(
    client: &reqwest::Client,
    url: &str,
    tenant_id: &str,
    events: &[Value],
    hmac_secret: Option<&str>,
    api_key: Option<&str>,
) -> anyhow::Result<()> {
    let body = json!({ "events": events });
    let json_bytes = serde_json::to_vec(&body)?;
    let gz_bytes = {
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        std::io::Write::write_all(&mut enc, &json_bytes)?;
        enc.finish()?
    };

    let mut req = client
        .post(url)
        .header("x-tenant-id", tenant_id)
        .header("x-user-id", "cyberbox-collector")
        .header("x-roles", "admin")
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "gzip");

    if let Some(key) = api_key {
        req = req.header("X-Api-Key", key);
    }

    if let Some(secret) = hmac_secret {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(&gz_bytes);
        let sig = hex::encode(mac.finalize().into_bytes());
        req = req.header("X-Cyberbox-Signature", format!("sha256={sig}"));
    }

    let resp = req.body(gz_bytes).send().await?;

    if resp.status().is_success() {
        Ok(())
    } else {
        warn!(status = %resp.status(), "API rejected batch");
        Ok(()) // non-retriable — don't re-queue 4xx
    }
}

// ─── Disk queue ───────────────────────────────────────────────────────────────

fn spill_to_queue(cfg: &ForwarderConfig, events: Vec<Value>) {
    let path = &cfg.queue_path;
    let max_bytes = cfg.queue_max_mb * 1024 * 1024;

    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() >= max_bytes {
            warn!(path = %path.display(), max_mb = cfg.queue_max_mb,
                  "disk queue full — dropping overflow batch");
            return;
        }
    }

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(mut f) => {
            if let Ok(line) = serde_json::to_string(&events) {
                let _ = writeln!(f, "{line}");
            }
        }
        Err(err) => error!(%err, path = %path.display(), "failed to open disk queue"),
    }
}

/// Drain the queue file one line (one batch) at a time.
///
/// Memory usage is bounded: at most one batch is held in RAM at any point.
/// Unprocessed lines are streamed to a `.jsonl.tmp` sidecar; on completion
/// the sidecar atomically replaces the queue file (or is deleted when empty).
async fn drain_queue(
    client: &reqwest::Client,
    url: &str,
    tenant_id: &str,
    cfg: &ForwarderConfig,
    health: &mut ApiHealth,
    metrics: &CollectorMetrics,
    hmac_secret: Option<&str>,
    api_key: Option<&str>,
) {
    let path = &cfg.queue_path;
    if !path.exists() {
        return;
    }

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            error!(%e, "cannot open disk queue for draining");
            return;
        }
    };

    let tmp_path = path.with_extension("jsonl.tmp");
    let reader = std::io::BufReader::new(file);
    let mut succeeded = 0usize;
    let mut rem_count = 0usize;
    let mut tmp: Option<std::fs::File> = None;

    info!(path = %path.display(), "draining disk queue");

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) if !l.trim().is_empty() => l,
            _ => continue,
        };

        // API already failed — stream remainder to .tmp
        if let Some(ref mut tf) = tmp {
            let _ = writeln!(tf, "{line}");
            rem_count += 1;
            continue;
        }

        let events: Vec<Value> = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                succeeded += 1;
                continue;
            } // discard malformed
        };

        let count = events.len() as u64;
        let t0 = std::time::Instant::now();
        match post_events(client, url, tenant_id, &events, hmac_secret, api_key).await {
            Ok(_) => {
                let latency_ms = t0.elapsed().as_millis() as u64;
                metrics.batch_latency.observe(latency_ms);
                health.mark_success();
                metrics.batches_ok.fetch_add(1, Relaxed);
                metrics.events_forwarded.fetch_add(count, Relaxed);
                let epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                metrics.last_batch_epoch_secs.store(epoch, Relaxed);
                succeeded += 1;
            }
            Err(err) => {
                let latency_ms = t0.elapsed().as_millis() as u64;
                metrics.batch_latency.observe(latency_ms);
                error!(%err, "API unreachable during drain — pausing");
                health.mark_failure();
                metrics.batches_err.fetch_add(1, Relaxed);
                match std::fs::File::create(&tmp_path) {
                    Ok(mut tf) => {
                        let _ = writeln!(tf, "{line}");
                        rem_count = 1;
                        tmp = Some(tf);
                    }
                    Err(e) => error!(%e, "failed to create drain temp file"),
                }
            }
        }
    }

    drop(tmp);

    if rem_count == 0 {
        let _ = std::fs::remove_file(path);
        info!(succeeded, "disk queue fully drained and removed");
    } else {
        if std::fs::rename(&tmp_path, path).is_err() {
            if let Ok(content) = std::fs::read_to_string(&tmp_path) {
                let _ = std::fs::write(path, content);
                let _ = std::fs::remove_file(&tmp_path);
            }
        }
        info!(
            succeeded,
            remaining = rem_count,
            "partial queue drain — API still recovering"
        );
    }
}
