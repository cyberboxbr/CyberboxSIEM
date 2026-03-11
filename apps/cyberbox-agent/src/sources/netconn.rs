//! Network connections source (Linux only).
//!
//! Polls `/proc/net/tcp` and `/proc/net/tcp6` to detect new network
//! connections, emitting events for each newly established connection.
//! Zero dependencies — no libpcap, no raw sockets, no elevated privileges.
//!
//! ## Events emitted
//! | `net_event`        | Trigger                                    |
//! |--------------------|--------------------------------------------|
//! | `connection_open`  | New ESTABLISHED connection detected        |
//! | `connection_close` | Previously seen connection no longer exists |
//! | `listening_open`   | New LISTEN socket detected                 |
//! | `listening_close`  | Previously seen listener no longer exists   |
//!
//! ## Fields
//! ```json
//! {
//!   "local_ip": "10.0.0.5",
//!   "local_port": 443,
//!   "remote_ip": "192.168.1.100",
//!   "remote_port": 52341,
//!   "protocol": "tcp",
//!   "state": "ESTABLISHED",
//!   "pid": 1234,            // when available (requires /proc/<pid>/fd scan)
//!   "Image": "/usr/bin/nginx",
//!   "uid": 33,
//!   "inode": 12345
//! }
//! ```
//!
//! Pairs with Sigma rules for C2 detection (unusual outbound connections),
//! lateral movement (new internal connections), and data exfiltration.

use std::collections::HashSet;
use std::time::Duration;

use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};
use tracing::debug;

// -- Connection key for dedup -------------------------------------------------

#[derive(Clone, Hash, Eq, PartialEq)]
struct ConnKey {
    local_ip:    String,
    local_port:  u16,
    remote_ip:   String,
    remote_port: u16,
    state:       u8,
    inode:       u64,
}

struct ConnInfo {
    key:  ConnKey,
    uid:  u32,
}

// -- Entry point --------------------------------------------------------------

pub async fn run(
    poll_ms:   u64,
    tenant_id: String,
    hostname:  String,
    tx:        mpsc::Sender<Value>,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = Duration::from_millis(poll_ms.max(200));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Build initial snapshot — don't fire events for pre-existing connections
    let mut known: HashSet<ConnKey> = scan_connections()
        .into_iter()
        .map(|c| c.key)
        .collect();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {}
        }

        let current = scan_connections();
        let current_keys: HashSet<ConnKey> = current.iter().map(|c| c.key.clone()).collect();

        // Detect new connections
        for conn in &current {
            if !known.contains(&conn.key) {
                let kind = match conn.key.state {
                    0x0A => "listening_open",    // LISTEN
                    0x01 => "connection_open",   // ESTABLISHED
                    _    => continue,            // skip transient states
                };
                let ev = build_event(kind, &conn, &tenant_id, &hostname);
                if tx.send(ev).await.is_err() { return; }
            }
        }

        // Detect closed connections
        for key in &known {
            if !current_keys.contains(key) {
                let kind = match key.state {
                    0x0A => "listening_close",
                    0x01 => "connection_close",
                    _    => continue,
                };
                let ev = build_close_event(kind, key, &tenant_id, &hostname);
                if tx.send(ev).await.is_err() { return; }
            }
        }

        known = current_keys;
    }
}

// -- /proc/net parser ---------------------------------------------------------

fn scan_connections() -> Vec<ConnInfo> {
    let mut result = Vec::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                if let Some(conn) = parse_proc_net_line(line) {
                    result.push(conn);
                }
            }
        }
    }
    result
}

fn parse_proc_net_line(line: &str) -> Option<ConnInfo> {
    // Format: sl  local_address rem_address   st tx_queue:rx_queue ... uid ... inode
    // Example: 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 ... 33 ... 12345
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 { return None; }

    let local   = parse_addr(parts[1])?;
    let remote  = parse_addr(parts[2])?;
    let state   = u8::from_str_radix(parts[3], 16).ok()?;
    let uid     = parts[7].parse::<u32>().unwrap_or(0);
    let inode   = parts[9].parse::<u64>().unwrap_or(0);

    // Only track ESTABLISHED and LISTEN states
    if state != 0x01 && state != 0x0A {
        return None;
    }

    Some(ConnInfo {
        key: ConnKey {
            local_ip:    local.0,
            local_port:  local.1,
            remote_ip:   remote.0,
            remote_port: remote.1,
            state,
            inode,
        },
        uid,
    })
}

fn parse_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return None; }

    let port = u16::from_str_radix(parts[1], 16).ok()?;
    let ip_hex = parts[0];

    let ip = if ip_hex.len() == 8 {
        // IPv4: little-endian u32
        let n = u32::from_str_radix(ip_hex, 16).ok()?;
        format!(
            "{}.{}.{}.{}",
            n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff
        )
    } else if ip_hex.len() == 32 {
        // IPv6: 4 groups of 4 bytes (little-endian within each group)
        let mut groups = Vec::new();
        for i in 0..4 {
            let chunk = &ip_hex[i*8..(i+1)*8];
            let n = u32::from_str_radix(chunk, 16).ok()?;
            let swapped = n.swap_bytes();
            groups.push(format!("{:04x}:{:04x}", (swapped >> 16) & 0xffff, swapped & 0xffff));
        }
        // Check if it's an IPv4-mapped IPv6
        if ip_hex.starts_with("0000000000000000FFFF0000") || ip_hex.starts_with("0000000000000000ffff0000") {
            let v4_hex = &ip_hex[24..32];
            let n = u32::from_str_radix(v4_hex, 16).ok()?;
            format!(
                "{}.{}.{}.{}",
                n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff
            )
        } else {
            groups.join(":")
        }
    } else {
        return None;
    };

    Some((ip, port))
}

fn state_name(state: u8) -> &'static str {
    match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _    => "UNKNOWN",
    }
}

// -- Resolve inode to PID/exe (best effort) -----------------------------------

fn resolve_inode_to_process(inode: u64) -> (u32, String) {
    if inode == 0 {
        return (0, String::new());
    }

    let target = format!("socket:[{inode}]");
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return (0, String::new()),
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{pid}/fd");
        if let Ok(fds) = std::fs::read_dir(&fd_dir) {
            for fd in fds.flatten() {
                if let Ok(link) = std::fs::read_link(fd.path()) {
                    if link.to_string_lossy() == target {
                        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default();
                        return (pid, exe);
                    }
                }
            }
        }
    }
    (0, String::new())
}

// -- Event builders -----------------------------------------------------------

fn build_event(kind: &str, conn: &ConnInfo, tenant_id: &str, hostname: &str) -> Value {
    let (pid, exe) = resolve_inode_to_process(conn.key.inode);
    let mitre = if kind == "connection_open" { "T1071" } else { "" };

    json!({
        "tenant_id":  tenant_id,
        "source":     "netconn",
        "event_time": Utc::now().to_rfc3339(),
        "raw_payload": {
            "hostname":         hostname,
            "net_event":        kind,
            "protocol":         "tcp",
            "state":            state_name(conn.key.state),
            "local_ip":         conn.key.local_ip,
            "local_port":       conn.key.local_port,
            "remote_ip":        conn.key.remote_ip,
            "remote_port":      conn.key.remote_port,
            "DestinationIp":    conn.key.remote_ip,
            "DestinationPort":  conn.key.remote_port,
            "SourceIp":         conn.key.local_ip,
            "SourcePort":       conn.key.local_port,
            "ProcessId":        pid,
            "Image":            exe,
            "uid":              conn.uid,
            "inode":            conn.key.inode,
            "mitre_technique":  mitre,
        }
    })
}

fn build_close_event(kind: &str, key: &ConnKey, tenant_id: &str, hostname: &str) -> Value {
    json!({
        "tenant_id":  tenant_id,
        "source":     "netconn",
        "event_time": Utc::now().to_rfc3339(),
        "raw_payload": {
            "hostname":         hostname,
            "net_event":        kind,
            "protocol":         "tcp",
            "state":            state_name(key.state),
            "local_ip":         key.local_ip,
            "local_port":       key.local_port,
            "remote_ip":        key.remote_ip,
            "remote_port":      key.remote_port,
            "DestinationIp":    key.remote_ip,
            "DestinationPort":  key.remote_port,
            "SourceIp":         key.local_ip,
            "SourcePort":       key.local_port,
        }
    })
}
