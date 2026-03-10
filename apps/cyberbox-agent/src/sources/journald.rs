//! Linux journald source via `journalctl --follow --output=json`.
//!
//! Spawns `journalctl` as a child process and streams its JSON output line by
//! line.  If journalctl exits unexpectedly (e.g. due to a log rotation), the
//! source restarts it with a short backoff.
//!
//! No C dependencies — plain subprocess approach.

use std::{process::Stdio, time::Duration};

use chrono::Utc;
use serde_json::{json, Map, Value};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::{mpsc, watch},
    time,
};
use tracing::{error, info, warn};

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(
    units:        Vec<String>,
    tenant_id:    String,
    hostname:     String,
    tx:           mpsc::Sender<Value>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let mut cmd = Command::new("journalctl");
        cmd.args(["--follow", "--output=json", "--lines=0"]);
        for u in &units {
            cmd.args(["-u", u.as_str()]);
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::null());

        let mut child = match cmd.spawn() {
            Ok(c)  => c,
            Err(e) => {
                error!(%e, "failed to spawn journalctl");
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => return,
                    _ = time::sleep(Duration::from_secs(5)) => {}
                }
                continue;
            }
        };

        let stdout = child.stdout.take().expect("journalctl stdout");
        let mut lines = BufReader::new(stdout).lines();

        info!(?units, "journald source started");

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    let _ = child.kill().await;
                    return;
                }
                line = lines.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            if let Some(ev) = parse_line(&line, &tenant_id, &hostname) {
                                if tx.send(ev).await.is_err() { return; }
                            }
                        }
                        Ok(None) => break, // journalctl exited
                        Err(e) => {
                            warn!(%e, "journalctl read error");
                            break;
                        }
                    }
                }
            }
        }

        let _ = child.wait().await;
        warn!("journalctl exited — restarting in 2s");
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = time::sleep(Duration::from_secs(2)) => {}
        }
    }
}

// ── Parse a journalctl JSON line ──────────────────────────────────────────────

fn parse_line(line: &str, tenant_id: &str, hostname: &str) -> Option<Value> {
    let j: Value = serde_json::from_str(line).ok()?;

    // MESSAGE can be a string or a byte-array
    let message = match j.get("MESSAGE") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::Array(bytes)) => {
            // byte array — decode as UTF-8
            let raw: Vec<u8> = bytes.iter()
                .filter_map(|b| b.as_u64().map(|n| n as u8))
                .collect();
            String::from_utf8_lossy(&raw).into_owned()
        }
        _ => return None,
    };

    let unit    = str_field(&j, "_SYSTEMD_UNIT");
    let comm    = str_field(&j, "_COMM");
    let pid     = str_field(&j, "_PID");
    let host    = j["_HOSTNAME"].as_str().unwrap_or(hostname).to_string();
    let prio    = j["PRIORITY"].as_str()
        .and_then(|p| p.parse::<u8>().ok())
        .unwrap_or(6);

    // Collect any extra structured fields as a map
    let mut extra = Map::new();
    for key in ["_EXE", "_CMDLINE", "_TRANSPORT", "SYSLOG_IDENTIFIER",
                "SYSLOG_PID", "_BOOT_ID", "_MACHINE_ID"] {
        if let Some(v) = j.get(key).and_then(Value::as_str) {
            extra.insert(key.to_string(), Value::String(v.to_string()));
        }
    }

    Some(json!({
        "tenant_id":  tenant_id,
        "source":     "syslog",
        "event_time": Utc::now().to_rfc3339(),
        "raw_payload": {
            "hostname":      host,
            "app_name":      if !unit.is_empty() { unit } else { comm },
            "pid":           pid,
            "message":       message,
            "severity":      prio,
            "severity_name": severity_name(prio),
            "facility":      1,
            "facility_name": "user",
            "extra":         Value::Object(extra),
        }
    }))
}

fn str_field(j: &Value, key: &str) -> String {
    j[key].as_str().unwrap_or("").to_string()
}

fn severity_name(p: u8) -> &'static str {
    match p {
        0 => "emergency", 1 => "alert",  2 => "critical", 3 => "error",
        4 => "warning",   5 => "notice", 6 => "info",      7 => "debug",
        _ => "debug",
    }
}
