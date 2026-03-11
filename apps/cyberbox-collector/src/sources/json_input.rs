//! Raw JSON / NDJSON input sources.
//!
//! Accepts structured JSON events directly — no syslog framing required.
//! Useful for Filebeat, Fluent Bit, Vector, or any shipper that can POST/send
//! JSON.
//!
//! # UDP (one JSON object per datagram)
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_JSON_UDP_BIND` | *(empty)* | Bind address (disabled if empty) |
//!
//! # TCP (newline-delimited JSON — NDJSON / JSON Lines)
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_JSON_TCP_BIND` | *(empty)* | Bind address (disabled if empty) |
//!
//! TLS (and mutual TLS when `COLLECTOR_TLS_CA` is set) is shared with the
//! syslog TCP listener — the same cert / key / CA are reused.  The `tls`
//! parameter is an `ArcSwap` so SIGUSR1 hot-reload applies automatically.
//!
//! ## Event format
//! Each JSON object is wrapped as:
//! ```json
//! { "tenant_id": "...", "source": "<source_field_or_json>", "event_time": "...", "raw_payload": {...} }
//! ```
//! Fields `source` and `event_time` are taken from the incoming JSON if present;
//! otherwise defaulted to `"json_udp"` / `"json_tcp"` and `Utc::now()`.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use chrono::Utc;
use serde_json::{json, Value};
use tokio::{
    io::AsyncBufReadExt,
    net::{TcpListener, UdpSocket},
    sync::{mpsc, watch},
};
use tracing::{debug, error, info, warn};

use crate::metrics::CollectorMetrics;

// ─── UDP JSON source ──────────────────────────────────────────────────────────

pub async fn run_udp(
    bind: SocketAddr,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    use tokio::sync::mpsc::error::TrySendError;

    let sock = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("bind JSON UDP {bind}"))?;
    info!(%bind, "JSON UDP listener ready (one JSON object per datagram)");

    let mut buf = vec![0u8; 65_535];
    loop {
        let res = tokio::select! {
            biased;
            _ = shutdown.changed() => { info!("JSON UDP listener exiting on shutdown"); break; }
            r = sock.recv_from(&mut buf) => r,
        };
        match res {
            Ok((len, peer)) => {
                let source_ip = peer.ip().to_string();
                match serde_json::from_slice::<Value>(&buf[..len]) {
                    Ok(payload) if payload.is_object() => {
                        let ev = wrap_json(payload, &tenant_id, &source_ip, "json_udp");
                        match tx.try_send(ev) {
                            Ok(_) => {
                                metrics.json_udp_received.fetch_add(1, Relaxed);
                            }
                            Err(TrySendError::Full(_)) => {
                                metrics.channel_drops.fetch_add(1, Relaxed);
                                debug!(source_ip, "JSON UDP event dropped — channel full");
                            }
                            Err(TrySendError::Closed(_)) => return Ok(()),
                        }
                    }
                    Ok(_) => {
                        metrics.parse_errors.fetch_add(1, Relaxed);
                        if let Some(dlq) = metrics.dlq.get() {
                            dlq.write("json_udp", &source_ip, &buf[..len]);
                        }
                        debug!(
                            source_ip,
                            "JSON UDP datagram is not a JSON object — skipping"
                        );
                    }
                    Err(e) => {
                        metrics.parse_errors.fetch_add(1, Relaxed);
                        if let Some(dlq) = metrics.dlq.get() {
                            dlq.write("json_udp", &source_ip, &buf[..len]);
                        }
                        debug!(source_ip, err = %e, "JSON UDP datagram parse error");
                    }
                }
            }
            Err(err) => error!(%err, "JSON UDP recv_from error"),
        }
    }
    Ok(())
}

// ─── TCP NDJSON source ────────────────────────────────────────────────────────

/// `tls` is loaded per-connection from the `ArcSwap`, allowing SIGUSR1
/// hot-reload without restarting the listener.  Pass `None` for plain-text.
pub async fn run_tcp(
    bind: SocketAddr,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
    tls: Option<Arc<ArcSwap<tokio_rustls::TlsAcceptor>>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind JSON TCP {bind}"))?;

    if tls.is_some() {
        info!(%bind, "JSON TCP listener ready (NDJSON, TLS/mTLS — hot-reload via SIGUSR1)");
    } else {
        info!(%bind, "JSON TCP listener ready (newline-delimited JSON / NDJSON, plain-text)");
    }

    loop {
        let accept_res = tokio::select! {
            biased;
            _ = shutdown.changed() => { info!("JSON TCP listener exiting on shutdown"); break; }
            r = listener.accept() => r,
        };
        match accept_res {
            Ok((stream, peer)) => {
                let source_ip = peer.ip().to_string();
                let tx2 = tx.clone();
                let tid = Arc::clone(&tenant_id);
                let m = Arc::clone(&metrics);
                // Atomically snapshot the current TLS acceptor for this connection.
                let tls2: Option<Arc<tokio_rustls::TlsAcceptor>> =
                    tls.as_ref().map(|s| s.load_full());

                tokio::spawn(async move {
                    let result = if let Some(acceptor) = tls2 {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                process_ndjson(tls_stream, source_ip.clone(), tid, tx2, m).await
                            }
                            Err(e) => {
                                debug!(source_ip, err = %e, "JSON TCP TLS handshake failed");
                                return;
                            }
                        }
                    } else {
                        process_ndjson(stream, source_ip.clone(), tid, tx2, m).await
                    };
                    if let Err(e) = result {
                        debug!(source_ip, %e, "JSON TCP connection closed");
                    }
                });
            }
            Err(err) => error!(%err, "JSON TCP accept error"),
        }
    }
    Ok(())
}

async fn process_ndjson<S>(
    stream: S,
    source_ip: String,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering::Relaxed;

    let reader = tokio::io::BufReader::new(stream);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<Value>(trimmed) {
            Ok(payload) if payload.is_object() => {
                let ev = wrap_json(payload, &tenant_id, &source_ip, "json_tcp");
                metrics.json_tcp_received.fetch_add(1, Relaxed);
                if tx.send(ev).await.is_err() {
                    return Ok(());
                }
            }
            Ok(_) => {
                metrics.parse_errors.fetch_add(1, Relaxed);
                if let Some(dlq) = metrics.dlq.get() {
                    dlq.write("json_tcp", &source_ip, trimmed.as_bytes());
                }
                warn!(source_ip, "JSON TCP line is not a JSON object — skipping");
            }
            Err(e) => {
                metrics.parse_errors.fetch_add(1, Relaxed);
                if let Some(dlq) = metrics.dlq.get() {
                    dlq.write("json_tcp", &source_ip, trimmed.as_bytes());
                }
                debug!(source_ip, err = %e, "JSON TCP line parse error");
            }
        }
    }
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn wrap_json(mut payload: Value, tenant_id: &str, source_ip: &str, default_source: &str) -> Value {
    let source = payload
        .as_object_mut()
        .and_then(|m| m.remove("source"))
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| default_source.to_string());

    let event_time = payload
        .as_object()
        .and_then(|m| {
            m.get("event_time")
                .or_else(|| m.get("timestamp"))
                .or_else(|| m.get("@timestamp"))
        })
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    json!({
        "tenant_id":  tenant_id,
        "source":     source,
        "event_time": event_time,
        "raw_payload": {
            "message":   payload,
            "source_ip": source_ip,
        }
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    #[test]
    fn wrap_json_extracts_source_and_timestamp() {
        let payload = serde_json::json!({
            "source": "beats",
            "@timestamp": "2026-01-01T00:00:00Z",
            "msg": "hello",
        });
        let out = wrap_json(payload, "tenant1", "1.2.3.4", "json_udp");
        assert_eq!(out["source"], "beats");
        assert_eq!(out["event_time"], "2026-01-01T00:00:00Z");
        assert_eq!(out["tenant_id"], "tenant1");
    }

    #[test]
    fn wrap_json_defaults_when_fields_absent() {
        let payload = serde_json::json!({"data": 42});
        let out = wrap_json(payload, "t", "1.1.1.1", "json_tcp");
        assert_eq!(out["source"], "json_tcp");
        assert!(out["event_time"].as_str().unwrap().contains('T'));
    }

    /// End-to-end plain-text NDJSON round-trip (no TLS).
    #[tokio::test]
    async fn roundtrip_ndjson_plaintext() {
        let (tx, mut rx) = mpsc::channel(16);
        let metrics = CollectorMetrics::new("test-json-queue.jsonl".into());
        let tenant = Arc::new("acme".to_string());

        // Bind on OS-assigned port.
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_addr = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();

        // Minimal accept loop that reuses process_ndjson directly.
        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant);
        let m = Arc::clone(&metrics);
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let ip = peer.ip().to_string();
                        let tx3 = tx2.clone();
                        let tid2 = Arc::clone(&tid);
                        let m2 = Arc::clone(&m);
                        tokio::spawn(async move {
                            let _ = process_ndjson(stream, ip, tid2, tx3, m2).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let mut stream = TcpStream::connect(bound_addr).await.unwrap();
        stream
            .write_all(b"{\"source\":\"filebeat\",\"msg\":\"hello\"}\n")
            .await
            .unwrap();

        let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .expect("timeout waiting for event")
            .expect("channel closed");

        assert_eq!(ev["tenant_id"], "acme");
        assert_eq!(ev["source"], "filebeat");
        assert_eq!(ev["raw_payload"]["message"]["msg"], "hello");

        handle.abort();
    }
}
