//! Poll-based log file tailer with persistent read-position bookmarks.
//!
//! Each new line is parsed as syslog if it starts with `<`; otherwise it is
//! treated as a plain-text event.
//!
//! # Persistent positions
//! On startup the tailer loads read positions from a JSON bookmark file
//! (`COLLECTOR_TAIL_BOOKMARK`, default `collector-tail.pos.json`) so that
//! a restart replays only unread lines rather than starting from EOF.
//! Positions are written back after every successful poll cycle; if the file
//! cannot be written, a warning is logged and tailing continues normally.
//!
//! # Rotation detection
//! When the file is shorter than the last known position the reader resets to
//! offset 0 (the file was truncated or rotated). The bookmark is updated
//! immediately after a rotation is detected.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncSeekExt},
    sync::mpsc,
    time,
};
use tracing::{debug, info, warn};

use crate::multiline::{MultilineAccumulator, MultilineConfig};
use crate::parser::{parse_syslog, to_incoming_event};

// ─── Bookmark I/O ─────────────────────────────────────────────────────────────

/// Load saved file positions from `bookmark_path`.  Missing keys are silently
/// ignored; a missing file returns an empty map (first-run).
fn load_bookmark(bookmark_path: &PathBuf) -> HashMap<PathBuf, u64> {
    let text = match std::fs::read_to_string(bookmark_path) {
        Ok(t) => t,
        Err(_) => return HashMap::new(), // file missing = first run
    };
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&text).unwrap_or_default();
    map.into_iter()
        .filter_map(|(k, v)| v.as_u64().map(|pos| (PathBuf::from(k), pos)))
        .collect()
}

/// Persist positions to `bookmark_path`. Writes atomically via a temp file.
fn save_bookmark(bookmark_path: &PathBuf, positions: &HashMap<PathBuf, u64>) {
    let map: serde_json::Map<String, serde_json::Value> = positions
        .iter()
        .map(|(p, &pos)| (p.display().to_string(), serde_json::Value::from(pos)))
        .collect();

    let tmp = bookmark_path.with_extension("pos.tmp");
    let json =
        serde_json::to_string(&serde_json::Value::Object(map)).unwrap_or_else(|_| "{}".to_string());
    if let Err(e) = std::fs::write(&tmp, &json) {
        warn!(%e, path = %bookmark_path.display(), "tail: failed to write bookmark");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, bookmark_path) {
        warn!(%e, path = %bookmark_path.display(), "tail: failed to rename bookmark temp file");
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

pub async fn run(
    paths: Vec<PathBuf>,
    poll_ms: u64,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    ml_cfg: MultilineConfig,
    bookmark_path: Option<PathBuf>,
) {
    if paths.is_empty() {
        return;
    }

    info!(count = paths.len(), bookmark = ?bookmark_path, "file tail started");

    // One accumulator per path
    let mut accumulators: HashMap<PathBuf, MultilineAccumulator> = paths
        .iter()
        .map(|p| {
            let cfg = MultilineConfig {
                pattern: ml_cfg
                    .pattern
                    .as_ref()
                    .map(|r| regex::Regex::new(r.as_str()).unwrap()),
                negate: ml_cfg.negate,
                max_lines: ml_cfg.max_lines,
                timeout_ms: ml_cfg.timeout_ms,
            };
            (p.clone(), MultilineAccumulator::new(cfg))
        })
        .collect();

    // Load saved positions (if any).
    let saved = bookmark_path
        .as_ref()
        .map(load_bookmark)
        .unwrap_or_default();
    let mut positions: HashMap<PathBuf, u64> = HashMap::new();

    // Initialise positions: saved bookmark wins; otherwise seek to current EOF
    // so we don't replay historic lines on first run.
    for path in &paths {
        if let Some(&saved_pos) = saved.get(path) {
            debug!(path = %path.display(), pos = saved_pos, "tail: restored bookmark position");
            positions.insert(path.clone(), saved_pos);
        } else if let Ok(meta) = std::fs::metadata(path) {
            positions.insert(path.clone(), meta.len());
        }
    }

    let mut interval = time::interval(Duration::from_millis(poll_ms));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        // Flush any multiline events that have timed out.
        for path in &paths {
            if let Some(acc) = accumulators.get_mut(path) {
                if let Some(complete) = acc.tick() {
                    let ev = parse_line(&complete, path, &tenant_id);
                    if tx.send(ev).await.is_err() {
                        return;
                    }
                }
            }
        }

        for path in &paths {
            if let Err(err) =
                tail_once(path, &tenant_id, &tx, &mut positions, &mut accumulators).await
            {
                debug!(%err, path = %path.display(), "tail error");
            }
        }

        // Persist positions after every poll cycle.
        if let Some(ref bp) = bookmark_path {
            save_bookmark(bp, &positions);
        }
    }
}

// ─── Per-file tail ────────────────────────────────────────────────────────────

async fn tail_once(
    path: &PathBuf,
    tenant_id: &str,
    tx: &mpsc::Sender<Value>,
    positions: &mut HashMap<PathBuf, u64>,
    accumulators: &mut HashMap<PathBuf, MultilineAccumulator>,
) -> Result<()> {
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => return Ok(()), // file doesn't exist yet — normal
    };

    let file_len = meta.len();
    let pos = positions.entry(path.clone()).or_insert(file_len);

    // Detect rotation: file is shorter than our last position
    if file_len < *pos {
        info!(path = %path.display(), old_pos = *pos, "file rotation detected — resetting to start");
        *pos = 0;
    }

    if file_len == *pos {
        return Ok(());
    }

    let mut file = tokio::fs::File::open(path).await?;
    file.seek(std::io::SeekFrom::Start(*pos)).await?;
    let mut reader = tokio::io::BufReader::new(file);

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            continue;
        }

        let acc = accumulators.get_mut(path);
        let complete = if let Some(a) = acc {
            a.feed(trimmed.to_string())
        } else {
            Some(trimmed.to_string())
        };

        if let Some(text) = complete {
            let ev = parse_line(&text, path, tenant_id);
            if tx.send(ev).await.is_err() {
                return Ok(());
            }
        }
    }

    // Update tracked position to the actual file offset after reading.
    *pos = reader
        .into_inner()
        .seek(std::io::SeekFrom::Current(0))
        .await?;

    Ok(())
}

// ─── Line parsing ─────────────────────────────────────────────────────────────

fn parse_line(line: &str, path: &Path, tenant_id: &str) -> Value {
    if line.starts_with('<') {
        if let Some(msg) = parse_syslog(line.as_bytes(), "127.0.0.1") {
            return to_incoming_event(&msg, tenant_id);
        }
    }
    plain_text_event(line, path, tenant_id)
}

fn plain_text_event(line: &str, path: &Path, tenant_id: &str) -> Value {
    json!({
        "tenant_id":  tenant_id,
        "source":     "file",
        "event_time": chrono::Utc::now().to_rfc3339(),
        "raw_payload": {
            "message":    line,
            "source_file": path.display().to_string(),
            "hostname":   hostname_or_default(),
            "severity":   6,
            "severity_name": "info",
            "facility":   1,
            "facility_name": "user",
        }
    })
}

fn hostname_or_default() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}
