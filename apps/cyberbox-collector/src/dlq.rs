//! Dead-letter queue (DLQ) for events that fail to parse.
//!
//! Parse failures in the GELF and JSON input sources are written here as
//! JSON-lines so that operators can inspect and replay them later.
//!
//! The DLQ is optional: if `COLLECTOR_DLQ_PATH` is not set the feature is
//! disabled and `CollectorMetrics::dlq` is never initialised.  All call-sites
//! guard with `metrics.dlq.get().map(|d| d.write(...))`.
//!
//! ## File format
//! One JSON object per line:
//! ```json
//! {"ts":"2025-01-01T00:00:00Z","source":"gelf_udp","source_ip":"10.0.0.1","raw":"..."}
//! ```
//!
//! ## Size cap
//! When the file exceeds `COLLECTOR_DLQ_MAX_MB` (default 64 MiB) new entries
//! are silently dropped (the DLQ itself is never rotated — operators are
//! expected to drain it).

use std::{io::Write, path::PathBuf, sync::Mutex};

use tracing::error;

pub struct Dlq {
    path: PathBuf,
    max_bytes: u64,
    /// Serialise concurrent writes so we don't interleave partial lines.
    lock: Mutex<()>,
}

impl Dlq {
    pub fn new(path: PathBuf, max_mb: u64) -> Self {
        Self {
            path,
            max_bytes: max_mb * 1024 * 1024,
            lock: Mutex::new(()),
        }
    }

    /// Append one failed-parse entry to the DLQ file.
    ///
    /// * `source`    — source protocol label, e.g. `"gelf_udp"`
    /// * `source_ip` — peer IP address as string
    /// * `raw`       — the raw bytes that could not be parsed
    pub fn write(&self, source: &str, source_ip: &str, raw: &[u8]) {
        // Enforce size cap before acquiring the lock to avoid blocking callers
        // when the DLQ is full.
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() >= self.max_bytes {
                return;
            }
        }

        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());

        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                let ts = chrono::Utc::now().to_rfc3339();
                let raw_str = String::from_utf8_lossy(raw);
                let entry = serde_json::json!({
                    "ts":        ts,
                    "source":    source,
                    "source_ip": source_ip,
                    "raw":       raw_str,
                });
                if let Ok(line) = serde_json::to_string(&entry) {
                    let _ = writeln!(f, "{line}");
                }
            }
            Err(e) => error!(
                err  = %e,
                path = %self.path.display(),
                "failed to open DLQ file for writing"
            ),
        }
    }
}
