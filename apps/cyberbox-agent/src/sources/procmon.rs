//! Linux process monitor source.
//!
//! Polls `/proc` on a configurable interval to detect process creation and
//! termination, emitting structured JSON events for each change.
//!
//! ## Events emitted
//! | `proc_event`        | Trigger                                         |
//! |---------------------|-------------------------------------------------|
//! | `process_create`    | PID appears that was not in the previous scan   |
//! | `process_terminate` | PID was in the previous scan but no longer exists |
//!
//! ## Fields per event
//! ```json
//! {
//!   "pid":      1234,
//!   "ppid":     1,
//!   "comm":     "nginx",
//!   "cmdline":  "nginx: worker process",
//!   "exe":      "/usr/sbin/nginx",
//!   "uid":      33,
//!   "gid":      33,
//!   "username": "www-data",    // resolved from /etc/passwd when available
//!   "mitre_technique": "T1059" // set for process_create
//! }
//! ```
//!
//! Pairs naturally with Sigma rules that reference `Image`, `CommandLine`,
//! `User`, `ProcessId`, `ParentProcessId`.

use std::{collections::HashMap, path::PathBuf, time::Duration};

use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};
use tracing::debug;

// ── Process snapshot ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct ProcInfo {
    pid: u32,
    ppid: u32,
    comm: String,
    cmdline: String,
    exe: String,
    uid: u32,
    gid: u32,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(
    poll_ms: u64,
    tenant_id: String,
    hostname: String,
    tx: mpsc::Sender<Value>,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = Duration::from_millis(poll_ms.max(100));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Build initial snapshot — don't fire events for pre-existing processes
    let mut known: HashMap<u32, ProcInfo> = scan_procs();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {}
        }

        let current = scan_procs();

        // Detect created
        for (pid, info) in &current {
            if !known.contains_key(pid) {
                let ev = build_event("process_create", info, &tenant_id, &hostname);
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
        }

        // Detect terminated
        for (pid, info) in &known {
            if !current.contains_key(pid) {
                let ev = build_event("process_terminate", info, &tenant_id, &hostname);
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
        }

        known = current;
    }
}

// ── /proc scanner ─────────────────────────────────────────────────────────────

fn scan_procs() -> HashMap<u32, ProcInfo> {
    let mut map = HashMap::new();
    let proc_dir = PathBuf::from("/proc");

    let read_dir = match std::fs::read_dir(&proc_dir) {
        Ok(rd) => rd,
        Err(e) => {
            debug!(%e, "procmon: cannot read /proc");
            return map;
        }
    };

    for entry in read_dir.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let pid: u32 = match name.parse() {
            Ok(n) => n,
            Err(_) => continue, // skip non-numeric entries
        };

        if let Some(info) = read_proc_info(pid) {
            map.insert(pid, info);
        }
    }
    map
}

fn read_proc_info(pid: u32) -> Option<ProcInfo> {
    let base = PathBuf::from(format!("/proc/{pid}"));

    // comm — short process name (max 15 chars)
    let comm = std::fs::read_to_string(base.join("comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "<unknown>".into());

    // cmdline — NUL-separated args
    let cmdline = std::fs::read(base.join("cmdline"))
        .map(|b| {
            b.iter()
                .map(|&c| if c == 0 { ' ' } else { c as char })
                .collect::<String>()
                .trim()
                .to_string()
        })
        .unwrap_or_default();

    // exe — symlink to executable path
    let exe = std::fs::read_link(base.join("exe"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "<unknown>".into());

    // status — parse Pid, PPid, Uid, Gid
    let (ppid, uid, gid) = parse_status(pid).unwrap_or((0, 0, 0));

    Some(ProcInfo {
        pid,
        ppid,
        comm,
        cmdline,
        exe,
        uid,
        gid,
    })
}

/// Parse /proc/<pid>/status for PPid, Uid (real), Gid (real).
fn parse_status(pid: u32) -> Option<(u32, u32, u32)> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut ppid = 0u32;
    let mut uid = 0u32;
    let mut gid = 0u32;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    Some((ppid, uid, gid))
}

// ── Event builder ─────────────────────────────────────────────────────────────

fn build_event(kind: &str, info: &ProcInfo, tenant_id: &str, hostname: &str) -> Value {
    let mitre = if kind == "process_create" {
        "T1059"
    } else {
        ""
    };

    json!({
        "tenant_id":  tenant_id,
        "source":     "procmon",
        "event_time": Utc::now().to_rfc3339(),
        "raw_payload": {
            "hostname":         hostname,
            "proc_event":       kind,
            "mitre_technique":  mitre,
            // Sigma-compatible field names
            "ProcessId":        info.pid,
            "ParentProcessId":  info.ppid,
            "Image":            info.exe,
            "CommandLine":      info.cmdline,
            "comm":             info.comm,
            "User":             resolve_uid(info.uid),
            "uid":              info.uid,
            "gid":              info.gid,
        }
    })
}

/// Best-effort UID → username resolution via /etc/passwd.
/// Returns "uid:<n>" if the name cannot be resolved.
fn resolve_uid(uid: u32) -> String {
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find(|line| {
                    let parts: Vec<&str> = line.splitn(4, ':').collect();
                    parts.get(2).and_then(|s| s.parse::<u32>().ok()) == Some(uid)
                })
                .map(|line| line.splitn(2, ':').next().unwrap_or("").to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("uid:{uid}"))
}
