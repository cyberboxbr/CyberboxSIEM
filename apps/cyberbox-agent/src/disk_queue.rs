//! Crash-safe disk-backed FIFO queue using `sled`.
//!
//! Events are persisted as JSON under monotonic u64 keys.  On startup, any
//! events remaining from a previous crash are drained first.  A configurable
//! max-size evicts the oldest entries on overflow.
//!
//! The queue is designed for single-producer / single-consumer use inside the
//! output module.

use serde_json::Value;
use tracing::{info, warn};

pub struct DiskQueue {
    tree: sled::Tree,
    db: sled::Db,
    max: usize,
    seq: u64,
}

impl DiskQueue {
    /// Open (or create) a queue backed by a sled database at `path`.
    pub fn open(path: &std::path::Path, max_size: usize) -> anyhow::Result<Self> {
        let db = sled::open(path)?;
        let tree = db.open_tree("event_queue")?;

        // Resume sequence counter from last key
        let seq = tree
            .last()
            .ok()
            .flatten()
            .map(|(k, _)| u64::from_be_bytes(k.as_ref().try_into().unwrap_or([0; 8])) + 1)
            .unwrap_or(0);

        let len = tree.len();
        if len > 0 {
            info!(pending = len, "disk queue opened with persisted events");
        }

        Ok(Self {
            tree,
            db,
            max: max_size,
            seq,
        })
    }

    /// Push an event to the back of the queue, evicting the oldest if full.
    pub fn push(&mut self, event: &Value) -> anyhow::Result<()> {
        // Evict oldest when at capacity
        while self.tree.len() >= self.max {
            if let Some(Ok((k, _))) = self.tree.iter().next() {
                self.tree.remove(k)?;
            } else {
                break;
            }
        }

        let key = self.seq.to_be_bytes();
        let val = serde_json::to_vec(event)?;
        self.tree.insert(key, val)?;
        self.seq += 1;
        Ok(())
    }

    /// Pop the oldest event from the front, or `None` if empty.
    pub fn pop(&mut self) -> Option<Value> {
        let (k, v) = self.tree.iter().next()?.ok()?;
        self.tree.remove(k).ok()?;
        serde_json::from_slice(&v).ok()
    }

    /// Number of events currently in the queue.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Flush to disk (sled auto-flushes but this is explicit for shutdown).
    pub fn flush(&self) {
        if let Err(e) = self.db.flush() {
            warn!(%e, "disk queue flush failed");
        }
    }
}
