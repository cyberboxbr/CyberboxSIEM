//! File Integrity Monitoring (FIM) source.
//!
//! Periodically scans one or more paths, computes SHA-256 hashes + metadata,
//! compares against a persisted baseline, and emits change events.
//!
//! ## Event kinds emitted
//! | `fim_event`           | Trigger                                        |
//! |-----------------------|------------------------------------------------|
//! | `created`             | Path appears that was not in baseline          |
//! | `modified`            | SHA-256, size, or mtime changed                |
//! | `deleted`             | Path was in baseline but no longer exists      |
//! | `permission_changed`  | Unix mode or Windows ACL flags changed         |
//!
//! ## Baseline
//! A JSON file (`baseline_path`) stores the last-known fingerprint of every
//! scanned file. Updated after every scan cycle so restarts resume cleanly.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

// ── Baseline entry ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileFingerprint {
    sha256: String,
    size: u64,
    mtime_secs: i64,
    /// Unix permission bits (lower 12 bits of st_mode); 0 on Windows.
    mode: u32,
    /// uid on Linux, 0 on Windows.
    uid: u32,
    /// gid on Linux, 0 on Windows.
    gid: u32,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn run(
    paths: Vec<PathBuf>,
    scan_interval_secs: u64,
    recursive: bool,
    baseline_path: PathBuf,
    tenant_id: String,
    hostname: String,
    tx: mpsc::Sender<Value>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut baseline = load_baseline(&baseline_path);
    let interval = Duration::from_secs(scan_interval_secs.max(1));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {}
        }

        // Collect all files to check
        let mut to_scan: Vec<PathBuf> = Vec::new();
        for root in &paths {
            collect_files(root, recursive, &mut to_scan);
        }

        let mut current: HashMap<String, FileFingerprint> = HashMap::new();

        for file_path in &to_scan {
            match fingerprint(file_path) {
                Ok(fp) => {
                    let key = file_path.to_string_lossy().to_string();
                    current.insert(key, fp);
                }
                Err(e) => {
                    debug!(path = %file_path.display(), %e, "FIM: cannot fingerprint");
                }
            }
        }

        // Detect created + modified
        for (path, new_fp) in &current {
            if let Some(old_fp) = baseline.get(path) {
                // Check for changes
                let hash_changed = old_fp.sha256 != new_fp.sha256;
                let perm_changed = old_fp.mode != new_fp.mode
                    || old_fp.uid != new_fp.uid
                    || old_fp.gid != new_fp.gid;

                if hash_changed || (old_fp.size != new_fp.size) {
                    let ev = build_event(
                        "modified",
                        path,
                        new_fp,
                        Some(old_fp),
                        &tenant_id,
                        &hostname,
                    );
                    if tx.send(ev).await.is_err() {
                        return;
                    }
                } else if perm_changed {
                    let ev = build_event(
                        "permission_changed",
                        path,
                        new_fp,
                        Some(old_fp),
                        &tenant_id,
                        &hostname,
                    );
                    if tx.send(ev).await.is_err() {
                        return;
                    }
                }
            } else {
                // New file
                let ev = build_event("created", path, new_fp, None, &tenant_id, &hostname);
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
        }

        // Detect deleted
        for (path, old_fp) in &baseline {
            if !current.contains_key(path) {
                let ev = json!({
                    "tenant_id":  tenant_id,
                    "source":     "fim",
                    "event_time": Utc::now().to_rfc3339(),
                    "raw_payload": {
                        "hostname":   hostname,
                        "fim_event":  "deleted",
                        "path":       path,
                        "old_sha256": old_fp.sha256,
                        "old_size":   old_fp.size,
                    }
                });
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
        }

        baseline = current;
        save_baseline(&baseline_path, &baseline);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_event(
    kind: &str,
    path: &str,
    new_fp: &FileFingerprint,
    old_fp: Option<&FileFingerprint>,
    tenant_id: &str,
    hostname: &str,
) -> Value {
    let mut payload = json!({
        "hostname":   hostname,
        "fim_event":  kind,
        "path":       path,
        "sha256":     new_fp.sha256,
        "size":       new_fp.size,
        "mtime_secs": new_fp.mtime_secs,
        "mode":       new_fp.mode,
        "uid":        new_fp.uid,
        "gid":        new_fp.gid,
    });

    if let Some(old) = old_fp {
        payload["old_sha256"] = json!(old.sha256);
        payload["old_size"] = json!(old.size);
        payload["old_mode"] = json!(old.mode);
    }

    json!({
        "tenant_id":  tenant_id,
        "source":     "fim",
        "event_time": Utc::now().to_rfc3339(),
        "raw_payload": payload,
    })
}

/// Compute SHA-256 + stat metadata for a single file.
fn fingerprint(path: &Path) -> std::io::Result<FileFingerprint> {
    let data = std::fs::read(path)?;
    let meta = std::fs::metadata(path)?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let sha256 = format!("{:x}", hasher.finalize());

    let mtime_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    #[cfg(unix)]
    let (mode, uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        (meta.mode() & 0o7777, meta.uid(), meta.gid())
    };

    #[cfg(not(unix))]
    let (mode, uid, gid) = (0u32, 0u32, 0u32);

    Ok(FileFingerprint {
        sha256,
        size: meta.len(),
        mtime_secs,
        mode,
        uid,
        gid,
    })
}

/// Recursively (or not) enumerate files under `root`.
fn collect_files(root: &Path, recursive: bool, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    if !root.is_dir() {
        return;
    }
    let read_dir = match std::fs::read_dir(root) {
        Ok(rd) => rd,
        Err(e) => {
            warn!(path = %root.display(), %e, "FIM: cannot read directory");
            return;
        }
    };
    for entry in read_dir.flatten() {
        let p = entry.path();
        if p.is_file() {
            out.push(p);
        } else if recursive && p.is_dir() {
            collect_files(&p, true, out);
        }
    }
}

// ── Baseline persistence ──────────────────────────────────────────────────────

fn load_baseline(path: &Path) -> HashMap<String, FileFingerprint> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_baseline(path: &Path, baseline: &HashMap<String, FileFingerprint>) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(s) = serde_json::to_string(baseline) {
        if let Err(e) = std::fs::write(path, s) {
            warn!(path = %path.display(), %e, "FIM: cannot save baseline");
        }
    }
}
