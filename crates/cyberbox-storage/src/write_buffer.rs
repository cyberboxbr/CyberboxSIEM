//! Application-level write buffer for ClickHouse event persistence.
//!
//! Decouples the ingest hot-path from ClickHouse I/O:
//!
//!  ┌─────────────────┐  try_send (non-blocking)  ┌─────────────────────────┐
//!  │  Ingest handler │ ────────────────────────►  │  mpsc channel (bounded) │
//!  └─────────────────┘                            └──────────┬──────────────┘
//!                                                            │ recv
//!                                                  ┌─────────▼────────────────┐
//!                                                  │  Background flush task   │
//!                                                  │  batch_size OR interval  │
//!                                                  └─────────┬────────────────┘
//!                                                            │ INSERT JSONEachRow
//!                                                  ┌─────────▼────────────────┐
//!                                                  │       ClickHouse         │
//!                                                  └──────────────────────────┘
//!
//! Key properties:
//! - `send_events()` is non-blocking (~1 µs).  The caller is never blocked
//!   waiting for a ClickHouse INSERT to complete.
//! - The background task flushes when `batch_size` events are buffered OR
//!   the `flush_interval_ms` timer fires, whichever comes first.
//! - Failed flushes are retried with exponential backoff + jitter up to
//!   `max_retries`.  After that the batch is dead-lettered (logged + metric).
//! - When the channel is full (ClickHouse is consistently behind), new events
//!   are dropped and a metric is incremented — the ingest handler can observe
//!   this to return HTTP 429 for sustained overload.

use std::sync::Arc;
use std::time::Duration;

use metrics::{counter, gauge};
use tokio::sync::mpsc;

use cyberbox_core::AppConfig;
use cyberbox_models::EventEnvelope;

use crate::traits::EventStore;
use crate::ClickHouseEventStore;

// ─── Configuration ────────────────────────────────────────────────────────────

/// Tuning parameters for the write buffer.  All fields have production-safe
/// defaults via [`WriteBufferConfig::from_app_config`].
#[derive(Debug, Clone)]
pub struct WriteBufferConfig {
    /// Flush when the accumulated batch reaches this many events.
    pub batch_size: usize,
    /// Flush at least this often (ms), even if `batch_size` is not reached.
    pub flush_interval_ms: u64,
    /// Bounded channel capacity.  When full, `send_events` starts dropping —
    /// this is the backpressure signal for the ingest path.
    pub channel_capacity: usize,
    /// Maximum flush retry attempts before dead-lettering the batch.
    pub max_retries: u32,
    /// Base delay (ms) for exponential backoff between retries.
    pub retry_backoff_base_ms: u64,
    /// Max additional jitter (ms) added to each retry delay.
    pub retry_backoff_jitter_ms: u64,
}

impl WriteBufferConfig {
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self {
            batch_size: config.clickhouse_sink_batch_size.max(1),
            // Enforce a minimum interval so we don't busy-loop at tiny values.
            flush_interval_ms: config.clickhouse_sink_flush_interval_ms.max(50),
            // Channel holds 20× the batch size by default — enough to absorb
            // burst spikes without losing events.
            channel_capacity: config
                .clickhouse_sink_batch_size
                .saturating_mul(20)
                .max(1_000),
            max_retries: config.clickhouse_sink_max_retries.max(1),
            retry_backoff_base_ms: config.clickhouse_sink_retry_backoff_base_ms,
            retry_backoff_jitter_ms: config.clickhouse_sink_retry_backoff_jitter_ms,
        }
    }
}

// ─── Write Buffer ─────────────────────────────────────────────────────────────

/// Wraps `ClickHouseEventStore` with an async, bounded write buffer.
///
/// `ClickHouseWriteBuffer` is `Clone` — the internal `mpsc::Sender` is cheap to
/// clone and all clones share the same background flush worker.  This means
/// `AppState::clone()` (called when axum dispatches requests) is safe and free.
#[derive(Clone)]
pub struct ClickHouseWriteBuffer {
    sender: mpsc::Sender<EventEnvelope>,
    channel_capacity: usize,
}

impl ClickHouseWriteBuffer {
    /// Start the background flush task and return a handle to the buffer.
    ///
    /// Must be called from within a Tokio async context (e.g. `main`).
    pub fn start(store: Arc<ClickHouseEventStore>, config: WriteBufferConfig) -> Self {
        let cap = config.channel_capacity;
        let (tx, rx) = mpsc::channel(cap);
        tokio::spawn(flush_loop(rx, store, config));
        Self {
            sender: tx,
            channel_capacity: cap,
        }
    }

    /// Returns `true` when ≥ 90 % of the channel is full.
    ///
    /// Call this **before** doing any per-request work so that an overloaded
    /// ClickHouse sink causes an immediate HTTP 429 rather than silently dropping
    /// events after they have already been stored in memory.
    pub fn is_overloaded(&self) -> bool {
        // Overloaded when remaining capacity < 10 % of total channel capacity,
        // i.e. fewer than one batch worth of slots are free
        // (channel_capacity = batch_size × 20, so / 20 ≈ one batch).
        self.sender.capacity() < self.channel_capacity / 10
    }

    /// Send a batch of events to the buffer.  Non-blocking.
    ///
    /// Returns the number of events dropped because the channel was full.
    /// The caller should treat a non-zero return as a backpressure signal.
    pub fn send_events(&self, events: &[EventEnvelope]) -> usize {
        let mut dropped = 0usize;
        for event in events {
            if self.sender.try_send(event.clone()).is_err() {
                dropped += 1;
            }
        }

        // Update the live pending gauge regardless of drops.
        let pending = self
            .channel_capacity
            .saturating_sub(self.sender.capacity()) as f64;
        gauge!("cyberbox_clickhouse_write_buffer_pending").set(pending);

        if dropped > 0 {
            counter!("cyberbox_clickhouse_write_buffer_events_dropped_total")
                .increment(dropped as u64);
            tracing::warn!(
                dropped,
                "ClickHouse write buffer full — events dropped (ClickHouse backpressure)"
            );
        }

        dropped
    }
}

// ─── Background flush task ────────────────────────────────────────────────────

async fn flush_loop(
    mut rx: mpsc::Receiver<EventEnvelope>,
    store: Arc<ClickHouseEventStore>,
    config: WriteBufferConfig,
) {
    let mut batch: Vec<EventEnvelope> = Vec::with_capacity(config.batch_size);
    let flush_interval = Duration::from_millis(config.flush_interval_ms);
    let mut interval = tokio::time::interval(flush_interval);
    // Skip missed ticks instead of firing a burst of catches-up after a slow flush.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tracing::info!(
        batch_size = config.batch_size,
        flush_interval_ms = config.flush_interval_ms,
        channel_capacity = config.channel_capacity,
        max_retries = config.max_retries,
        "ClickHouse write buffer flush task started"
    );

    loop {
        tokio::select! {
            // Prioritise draining the channel over the timer so we don't flush
            // tiny batches while data is still arriving quickly.
            biased;

            msg = rx.recv() => {
                match msg {
                    Some(event) => {
                        batch.push(event);
                        // Drain additional queued events without yielding so we
                        // fill the batch efficiently under sustained load.
                        while batch.len() < config.batch_size {
                            match rx.try_recv() {
                                Ok(e) => batch.push(e),
                                Err(_) => break,
                            }
                        }
                        if batch.len() >= config.batch_size {
                            flush_with_retry(&mut batch, &store, &config).await;
                        }
                    }
                    None => {
                        // The sender side was dropped (process shutting down).
                        // Flush whatever remains so we don't lose buffered events.
                        if !batch.is_empty() {
                            tracing::info!(
                                remaining = batch.len(),
                                "ClickHouse write buffer: channel closed, flushing remaining events"
                            );
                            flush_with_retry(&mut batch, &store, &config).await;
                        }
                        tracing::info!("ClickHouse write buffer flush task exiting");
                        return;
                    }
                }
            }

            _ = interval.tick() => {
                if !batch.is_empty() {
                    flush_with_retry(&mut batch, &store, &config).await;
                }
            }
        }
    }
}

async fn flush_with_retry(
    batch: &mut Vec<EventEnvelope>,
    store: &Arc<ClickHouseEventStore>,
    config: &WriteBufferConfig,
) {
    let batch_len = batch.len();
    let mut attempt = 0u32;

    loop {
        match store.insert_events(batch).await {
            Ok(()) => {
                counter!("cyberbox_clickhouse_write_buffer_events_flushed_total")
                    .increment(batch_len as u64);
                counter!("cyberbox_clickhouse_write_buffer_batches_flushed_total").increment(1);
                tracing::debug!(batch_size = batch_len, "ClickHouse write buffer: batch flushed");
                batch.clear();
                return;
            }
            Err(err) => {
                attempt += 1;
                if attempt >= config.max_retries {
                    tracing::error!(
                        batch_size = batch_len,
                        attempts = attempt,
                        error = %err,
                        "ClickHouse write buffer: max retries exhausted — batch dead-lettered"
                    );
                    counter!("cyberbox_clickhouse_write_buffer_events_dead_lettered_total")
                        .increment(batch_len as u64);
                    batch.clear();
                    return;
                }

                // Exponential backoff capped at 2^6 × base, with deterministic
                // jitter derived from the wall-clock sub-second nanoseconds.
                // Avoids a rand crate dependency while still spreading retries.
                let backoff_ms = config
                    .retry_backoff_base_ms
                    .saturating_mul(1u64 << (attempt - 1).min(6));
                let jitter_ms = if config.retry_backoff_jitter_ms > 0 {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos() as u64
                        % config.retry_backoff_jitter_ms
                } else {
                    0
                };

                tracing::warn!(
                    attempt,
                    max_retries = config.max_retries,
                    retry_after_ms = backoff_ms + jitter_ms,
                    error = %err,
                    "ClickHouse write buffer: flush failed, retrying"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms + jitter_ms)).await;
            }
        }
    }
}

