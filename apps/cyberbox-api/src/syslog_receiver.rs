//! Syslog UDP and TCP receiver.
//!
//! Listens for RFC 3164 / RFC 5424 syslog datagrams or streams, converts each
//! message to an [`IncomingEvent`] with `source = EventSource::Syslog`, then
//! feeds it through the standard normalize → enrich → detect → ClickHouse pipeline.
//!
//! ```text
//!  UDP :5514 ──────────────────────────────────────────┐
//!                                                       ▼
//!  TCP :5514 (newline-framed) ─► line buffer ─► parse_syslog_line()
//!                                                       │
//!                                               IncomingEvent { source: Syslog, ... }
//!                                                       │
//!                                            normalize_to_ocsf()
//!                                                       │
//!                                         in-memory store + write buffer
//! ```
//!
//! Parsing strategy:
//!  1. Try RFC 5424 (`<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID …`)
//!  2. Fall back to RFC 3164 (`<PRI>MONTH DD HH:MM:SS HOSTNAME TAG: MSG`)
//!  3. If neither matches, store the raw line as `{"msg": "<raw>"}`.

use std::net::SocketAddr;

use chrono::Utc;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};

use cyberbox_core::{normalize::{attach_enrichment, normalize_to_ocsf}, parsers::parse_log_line, AppConfig};
use cyberbox_models::{EventSource, IncomingEvent};
use cyberbox_storage::EventStore;

use crate::state::AppState;

// ─── Public entry-point ────────────────────────────────────────────────────────

/// Start the syslog UDP and/or TCP listeners as background Tokio tasks.
///
/// Each listener converts incoming messages to events, normalises them, stores
/// them in the in-memory store, and (if enabled) sends them to the ClickHouse
/// write buffer.  Detection rule evaluation is NOT run on the syslog path —
/// the in-process scheduler picks up new events on its next tick, matching the
/// same flow as Kafka-less ingest.
pub fn start(state: AppState, config: &AppConfig) {
    let tenant_id = config.syslog_default_tenant_id.clone();

    if config.syslog_udp_enabled {
        let bind = format!("{}:{}", config.syslog_bind_addr, config.syslog_udp_port);
        tracing::info!(bind, "syslog UDP listener started");
        let state_udp = state.clone();
        let tenant_udp = tenant_id.clone();
        let bind_udp = bind.clone();
        tokio::spawn(async move {
            if let Err(err) = run_udp(state_udp, &bind_udp, &tenant_udp).await {
                tracing::error!(error = %err, bind = %bind_udp, "syslog UDP listener failed");
            }
        });
    }

    if config.syslog_tcp_enabled {
        let bind = format!("{}:{}", config.syslog_bind_addr, config.syslog_tcp_port);
        tracing::info!(bind, "syslog TCP listener started");
        let state_tcp = state.clone();
        let tenant_tcp = tenant_id.clone();
        let bind_tcp = bind.clone();
        tokio::spawn(async move {
            if let Err(err) = run_tcp(state_tcp, &bind_tcp, &tenant_tcp).await {
                tracing::error!(error = %err, bind = %bind_tcp, "syslog TCP listener failed");
            }
        });
    }
}

// ─── UDP listener ─────────────────────────────────────────────────────────────

async fn run_udp(state: AppState, bind: &str, tenant_id: &str) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(bind).await?;
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, _peer) = sock.recv_from(&mut buf).await?;
        let line = std::str::from_utf8(&buf[..n]).unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        process_line(&state, tenant_id, line).await;
    }
}

// ─── TCP listener ─────────────────────────────────────────────────────────────

async fn run_tcp(state: AppState, bind: &str, tenant_id: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let state_conn = state.clone();
        let tenant_conn = tenant_id.to_string();
        tokio::spawn(async move {
            handle_tcp_connection(state_conn, stream, peer, &tenant_conn).await;
        });
    }
}

async fn handle_tcp_connection(
    state: AppState,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    tenant_id: &str,
) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        process_line(&state, tenant_id, &line).await;
    }
    tracing::debug!(%peer, "syslog TCP connection closed");
}

// ─── Line processing ──────────────────────────────────────────────────────────

async fn process_line(state: &AppState, tenant_id: &str, line: &str) {
    let payload = parse_syslog_line(line);

    let incoming = IncomingEvent {
        tenant_id: tenant_id.to_string(),
        source: EventSource::Syslog,
        raw_payload: payload,
        event_time: Utc::now(),
    };

    let envelope = {
        let env = normalize_to_ocsf(&incoming);
        if let Some(enricher) = &state.geoip_enricher {
            attach_enrichment(env, vec![], enricher.enrich_event(&incoming.raw_payload))
        } else {
            env
        }
    };

    // Store in in-memory store for scheduler / search.
    if let Err(err) = state.storage.insert_events(&[envelope.clone()]).await {
        tracing::warn!(error = %err, "syslog: in-memory store insert failed");
    }

    // Forward to ClickHouse write buffer if enabled.
    if let Some(write_buffer) = &state.clickhouse_write_buffer {
        let dropped = write_buffer.send_events(&[envelope]);
        if dropped > 0 {
            tracing::warn!(dropped, tenant_id, "syslog: write buffer full — event dropped");
        }
    }
}

// ─── Syslog parser ────────────────────────────────────────────────────────────

/// Parse a single syslog line into a JSON payload.
///
/// Attempts RFC 5424 first, then RFC 3164, then CEF/LEEF/KV via the structured
/// log parser, then falls back to a plain `msg` object.
fn parse_syslog_line(line: &str) -> serde_json::Value {
    if let Some(parsed) = try_parse_rfc5424(line) {
        return parsed;
    }
    if let Some(parsed) = try_parse_rfc3164(line) {
        return parsed;
    }
    // Try structured formats (CEF, LEEF, KV, JSON) before falling back to raw msg.
    parse_log_line(line)
}

/// RFC 5424: `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`
fn try_parse_rfc5424(line: &str) -> Option<serde_json::Value> {
    // Must start with `<NNN>` priority
    if !line.starts_with('<') {
        return None;
    }
    let close = line.find('>')?;
    let pri_str = &line[1..close];
    let pri: u32 = pri_str.parse().ok()?;
    let rest = &line[close + 1..];

    // Version digit immediately after `>`
    let mut fields = rest.splitn(8, ' ');
    let version = fields.next()?;
    if version != "1" {
        return None; // Not RFC 5424
    }
    let timestamp = fields.next().unwrap_or("-");
    let hostname = fields.next().unwrap_or("-");
    let app_name = fields.next().unwrap_or("-");
    let proc_id = fields.next().unwrap_or("-");
    let msg_id = fields.next().unwrap_or("-");
    let _structured = fields.next().unwrap_or("-");
    let msg = fields.next().unwrap_or("").trim_start_matches("BOM");

    let facility = pri / 8;
    let severity = pri % 8;

    Some(json!({
        "syslog_format":  "rfc5424",
        "facility":       facility,
        "severity":       severity,
        "timestamp":      if timestamp == "-" { serde_json::Value::Null } else { json!(timestamp) },
        "hostname":       if hostname == "-" { serde_json::Value::Null } else { json!(hostname) },
        "app_name":       if app_name == "-" { serde_json::Value::Null } else { json!(app_name) },
        "proc_id":        if proc_id == "-" { serde_json::Value::Null } else { json!(proc_id) },
        "msg_id":         if msg_id == "-" { serde_json::Value::Null } else { json!(msg_id) },
        "msg":            msg,
    }))
}

/// RFC 3164: `<PRI>MONTH DD HH:MM:SS HOSTNAME TAG[PID]: MSG`
fn try_parse_rfc3164(line: &str) -> Option<serde_json::Value> {
    if !line.starts_with('<') {
        return None;
    }
    let close = line.find('>')?;
    let pri_str = &line[1..close];
    let pri: u32 = pri_str.parse().ok()?;
    let rest = line[close + 1..].trim();

    // Expect at least: MONTH DD HH:MM:SS HOSTNAME
    let mut parts = rest.splitn(5, ' ');
    let month = parts.next()?;
    let day = parts.next()?;
    let time = parts.next()?;
    let hostname = parts.next()?;
    let remainder = parts.next().unwrap_or("").trim();

    // tag[pid]: msg  OR  tag: msg
    let (tag, msg) = if let Some(colon) = remainder.find(':') {
        let tag = remainder[..colon].trim();
        let msg = remainder[colon + 1..].trim();
        (tag, msg)
    } else {
        ("", remainder)
    };

    let timestamp_str = format!("{month} {day} {time}");
    let facility = pri / 8;
    let severity = pri % 8;

    Some(json!({
        "syslog_format":  "rfc3164",
        "facility":       facility,
        "severity":       severity,
        "timestamp":      timestamp_str,
        "hostname":       hostname,
        "tag":            tag,
        "msg":            msg,
    }))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5424_parses_correctly() {
        let line = "<34>1 2024-01-15T10:00:00Z myhost myapp 1234 - - An application message";
        let parsed = parse_syslog_line(line);
        assert_eq!(parsed["syslog_format"], "rfc5424");
        assert_eq!(parsed["hostname"], "myhost");
        assert_eq!(parsed["app_name"], "myapp");
        assert_eq!(parsed["msg"], "An application message");
        assert_eq!(parsed["facility"], 4); // 34 / 8 = 4
        assert_eq!(parsed["severity"], 2); // 34 % 8 = 2
    }

    #[test]
    fn rfc3164_parses_correctly() {
        let line = "<13>Jan 15 10:00:00 myhost sshd[1234]: Failed password for root";
        let parsed = parse_syslog_line(line);
        assert_eq!(parsed["syslog_format"], "rfc3164");
        assert_eq!(parsed["hostname"], "myhost");
        assert_eq!(parsed["msg"], "Failed password for root");
        assert_eq!(parsed["facility"], 1); // 13 / 8 = 1
        assert_eq!(parsed["severity"], 5); // 13 % 8 = 5
    }

    #[test]
    fn fallback_returns_raw_msg() {
        let line = "not a syslog line at all";
        let parsed = parse_syslog_line(line);
        assert_eq!(parsed["msg"], line);
    }

    #[test]
    fn rfc5424_null_fields_for_nilvalue() {
        let line = "<34>1 - - - - - - hello world";
        let parsed = parse_syslog_line(line);
        assert_eq!(parsed["hostname"], serde_json::Value::Null);
        assert_eq!(parsed["timestamp"], serde_json::Value::Null);
    }
}
