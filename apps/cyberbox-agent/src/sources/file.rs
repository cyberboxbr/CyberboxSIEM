//! File-tail source.
//!
//! Polls one or more file paths every `poll_ms` milliseconds, emitting new
//! lines as they appear.  Read positions are persisted to a JSON bookmark file
//! so the agent survives restarts without re-sending old data.
//!
//! Log rotation is handled gracefully: if the current file size is smaller than
//! the saved offset (i.e. the file was truncated/replaced), reading restarts
//! from byte 0.

use std::{
    collections::HashMap,
    io::{BufRead as _, BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};
use tracing::warn;

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(
    paths: Vec<PathBuf>,
    poll_ms: u64,
    bookmark_path: PathBuf,
    tenant_id: String,
    hostname: String,
    tx: mpsc::Sender<Value>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut bookmarks = load_bookmarks(&bookmark_path);

    // On first start, seek to end of each existing file (don't replay history)
    for p in &paths {
        let key = p.to_string_lossy().to_string();
        if let std::collections::hash_map::Entry::Vacant(e) = bookmarks.entry(key) {
            if let Ok(meta) = std::fs::metadata(p) {
                e.insert(meta.len());
            }
        }
    }

    let mut ticker = tokio::time::interval(Duration::from_millis(poll_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                save_bookmarks(&bookmark_path, &bookmarks);
                return;
            }
            _ = ticker.tick() => {}
        }

        for p in &paths {
            poll_file(p, &mut bookmarks, &tenant_id, &hostname, &tx).await;
        }

        save_bookmarks(&bookmark_path, &bookmarks);
    }
}

// ── Per-file polling ──────────────────────────────────────────────────────────

async fn poll_file(
    path: &Path,
    bookmarks: &mut HashMap<String, u64>,
    tenant_id: &str,
    hostname: &str,
    tx: &mpsc::Sender<Value>,
) {
    let key = path.to_string_lossy().to_string();

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return, // file may not exist yet
    };

    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let saved = *bookmarks.get(&key).unwrap_or(&0);
    // Handle log rotation: if file shrank, restart from zero
    let offset = if size < saved { 0 } else { saved };

    let mut reader = BufReader::new(file);
    if reader.seek(SeekFrom::Start(offset)).is_err() {
        return;
    }

    let mut new_offset = offset;
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(n) => {
                new_offset += n as u64;
                let msg = line
                    .trim_end_matches('\n')
                    .trim_end_matches('\r')
                    .to_string();
                if msg.is_empty() {
                    continue;
                }
                let ev = json!({
                    "tenant_id":  tenant_id,
                    "source":     "file",
                    "event_time": Utc::now().to_rfc3339(),
                    "raw_payload": {
                        "hostname": hostname,
                        "path":     key,
                        "message":  msg,
                    }
                });
                if tx.send(ev).await.is_err() {
                    return; // receiver dropped → shutdown
                }
            }
            Err(e) => {
                warn!(%e, path = %path.display(), "read error");
                break;
            }
        }
    }

    bookmarks.insert(key, new_offset);
}

// ── Bookmark persistence ──────────────────────────────────────────────────────

fn load_bookmarks(path: &Path) -> HashMap<String, u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_bookmarks(path: &Path, bm: &HashMap<String, u64>) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(s) = serde_json::to_string(bm) {
        let _ = std::fs::write(path, s);
    }
}
