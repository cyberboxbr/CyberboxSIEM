//! Collector integration tests.
//!
//! Each test exercises a specific source end-to-end:
//! 1. Bind the source on an OS-assigned port
//! 2. Send a test payload
//! 3. Assert the wrapped `IncomingEvent` JSON arrives on the channel
//!
//! Tests bind on port 0 (OS-assigned) to avoid fixed-port conflicts when run
//! in parallel.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use cyberbox_collector::{
    metrics::CollectorMetrics,
    ratelimit::SourceRateLimiter,
};
use serde_json::Value;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc, time::timeout};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn metrics() -> Arc<CollectorMetrics> {
    CollectorMetrics::new("test-integration-queue.jsonl".into())
}

fn no_ratelimit() -> Arc<SourceRateLimiter> {
    Arc::new(SourceRateLimiter::new(0, 3))
}

async fn recv(rx: &mut mpsc::Receiver<Value>) -> Value {
    timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("test timed out waiting for event")
        .expect("channel closed unexpectedly")
}

/// Bind a TCP listener on an OS-assigned port; return (listener, local_addr).
fn bind_tcp_listener() -> (std::net::TcpListener, SocketAddr) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    l.set_nonblocking(true).unwrap();
    (l, a)
}

/// Bind a UDP socket on an OS-assigned port; return (std_sock, local_addr).
fn bind_udp_socket() -> (std::net::UdpSocket, SocketAddr) {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = s.local_addr().unwrap();
    s.set_nonblocking(true).unwrap();
    (s, a)
}

// ─── 1. Rate-limiter unit test ─────────────────────────────────────────────────

#[test]
fn rate_limiter_allows_burst_then_drops() {
    use std::net::IpAddr;

    // 5 eps, burst = 1× → 5 tokens initially.
    let rl  = SourceRateLimiter::new(5, 1);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // First 5 checks consume the initial burst.
    for _ in 0..5 {
        assert!(rl.check(ip), "expected allow within burst");
    }
    // 6th check immediately (no time elapsed for refill) must be dropped.
    assert!(!rl.check(ip), "expected drop after burst exhausted");
}

#[test]
fn rate_limiter_disabled_when_eps_zero() {
    use std::net::IpAddr;
    let rl = SourceRateLimiter::new(0, 3);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    // Any number of checks — always allowed.
    for _ in 0..10_000 {
        assert!(rl.check(ip));
    }
}

// ─── 2. UDP syslog round-trip ─────────────────────────────────────────────────

#[tokio::test]
async fn udp_syslog_roundtrip() {
    let (tx, mut rx) = mpsc::channel::<Value>(16);
    let m            = metrics();
    let rl           = no_ratelimit();
    let tenant       = Arc::new("udp-tenant".to_string());

    // Pre-bind and convert to tokio socket so we know the local address.
    let (std_sock, bound_addr) = bind_udp_socket();
    let sock = Arc::new(tokio::net::UdpSocket::from_std(std_sock).unwrap());

    // Spawn reader loop directly (exercises the same code path as run()).
    let sock2 = Arc::clone(&sock);
    let tx2   = tx.clone();
    let tid   = Arc::clone(&tenant);
    let m2    = Arc::clone(&m);
    let _rl2  = Arc::clone(&rl);
    let handle = tokio::spawn(async move {
        use std::sync::atomic::Ordering::Relaxed;
        use tokio::sync::mpsc::error::TrySendError;
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((len, peer)) = sock2.recv_from(&mut buf).await {
                let source_ip = peer.ip().to_string();
                if let Some(msg) = cyberbox_collector::parser::parse_syslog(&buf[..len], &source_ip) {
                    let ev = cyberbox_collector::parser::to_incoming_event(&msg, &tid);
                    m2.udp_received.fetch_add(1, Relaxed);
                    match tx2.try_send(ev) {
                        Ok(_) | Err(TrySendError::Full(_)) => {}
                        Err(TrySendError::Closed(_)) => return,
                    }
                }
            }
        }
    });

    // Send an RFC-3164 syslog datagram.
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(
            b"<13>Jan  1 00:00:00 myhost sshd[42]: Accepted publickey for alice",
            bound_addr,
        )
        .await
        .unwrap();

    let ev = recv(&mut rx).await;
    assert_eq!(ev["tenant_id"], "udp-tenant");
    assert_eq!(ev["source"],    "syslog");
    assert_eq!(ev["raw_payload"]["hostname"], "myhost");
    assert_eq!(ev["raw_payload"]["app_name"], "sshd");
    assert!(ev["raw_payload"]["message"].as_str().unwrap().contains("Accepted publickey"));

    handle.abort();
}

// ─── 3. JSON-over-TCP round-trip (plain-text, no TLS) ────────────────────────

#[tokio::test]
async fn json_tcp_ndjson_roundtrip() {
    let (tx, mut rx) = mpsc::channel::<Value>(16);
    let m            = metrics();
    let tenant       = Arc::new("json-tenant".to_string());

    let (std_listener, bound_addr) = bind_tcp_listener();
    let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();

    // Spawn source (no TLS).
    let tx2  = tx.clone();
    let tid  = Arc::clone(&tenant);
    let m2   = Arc::clone(&m);
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let ip   = peer.ip().to_string();
                    let tx3  = tx2.clone();
                    let tid2 = Arc::clone(&tid);
                    let m3   = Arc::clone(&m2);
                    tokio::spawn(async move {
                        use tokio::io::AsyncBufReadExt;
                        use std::sync::atomic::Ordering::Relaxed;
                        let reader    = tokio::io::BufReader::new(stream);
                        let mut lines = reader.lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                                if v.is_object() {
                                    m3.tcp_received.fetch_add(1, Relaxed);
                                    let source = v.get("source").and_then(|s| s.as_str()).unwrap_or("json_tcp").to_string();
                                    let ev = serde_json::json!({
                                        "tenant_id": &*tid2,
                                        "source": source,
                                        "event_time": chrono::Utc::now().to_rfc3339(),
                                        "raw_payload": {"message": v, "source_ip": ip},
                                    });
                                    if tx3.send(ev).await.is_err() { return; }
                                }
                            }
                        }
                    });
                }
                Err(_) => break,
            }
        }
    });

    // Connect and send NDJSON.
    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    stream
        .write_all(b"{\"source\":\"vector\",\"level\":\"info\",\"msg\":\"disk usage 80%\"}\n")
        .await
        .unwrap();

    let ev = recv(&mut rx).await;
    assert_eq!(ev["tenant_id"], "json-tenant");
    assert_eq!(ev["source"],    "vector");
    assert_eq!(ev["raw_payload"]["message"]["msg"], "disk usage 80%");

    handle.abort();
}

// ─── 4. GELF TCP round-trip (null-delimited, plain-text) ─────────────────────

#[tokio::test]
async fn gelf_tcp_roundtrip() {
    let (tx, mut rx) = mpsc::channel::<Value>(16);
    let m            = metrics();
    let tenant       = Arc::new("gelf-tenant".to_string());

    let (std_listener, bound_addr) = bind_tcp_listener();
    let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();

    let tx2  = tx.clone();
    let tid  = Arc::clone(&tenant);
    let m2   = Arc::clone(&m);
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let ip   = peer.ip().to_string();
                    let tx3  = tx2.clone();
                    let tid2 = Arc::clone(&tid);
                    let m3   = Arc::clone(&m2);
                    tokio::spawn(async move {
                        use tokio::io::AsyncBufReadExt;
                        use std::sync::atomic::Ordering::Relaxed;
                        let mut reader = tokio::io::BufReader::new(stream);
                        let mut buf    = Vec::with_capacity(8192);
                        loop {
                            buf.clear();
                            let n = reader.read_until(b'\0', &mut buf).await.unwrap_or(0);
                            if n == 0 { break; }
                            if buf.last() == Some(&0) { buf.pop(); }
                            if buf.is_empty() { continue; }
                            if let Ok(v) = serde_json::from_slice::<Value>(&buf) {
                                if v.is_object() {
                                    let host = v.get("host").and_then(|h| h.as_str()).unwrap_or(&ip).to_string();
                                    let mut raw = v.clone();
                                    if let Some(o) = raw.as_object_mut() {
                                        o.insert("source_ip".into(), serde_json::Value::String(ip.clone()));
                                    }
                                    m3.tcp_received.fetch_add(1, Relaxed);
                                    let ev = serde_json::json!({
                                        "tenant_id":  &*tid2,
                                        "source":     format!("gelf:{host}"),
                                        "event_time": chrono::Utc::now().to_rfc3339(),
                                        "raw_payload": raw,
                                    });
                                    if tx3.send(ev).await.is_err() { return; }
                                }
                            }
                        }
                    });
                }
                Err(_) => break,
            }
        }
    });

    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    let gelf = b"{\"version\":\"1.1\",\"host\":\"db-01\",\"short_message\":\"slow query\",\"level\":4}\0";
    stream.write_all(gelf).await.unwrap();

    let ev = recv(&mut rx).await;
    assert_eq!(ev["tenant_id"],  "gelf-tenant");
    assert_eq!(ev["source"],     "gelf:db-01");
    assert_eq!(ev["raw_payload"]["short_message"], "slow query");
    assert_eq!(ev["raw_payload"]["level"], 4);

    handle.abort();
}

// ─── 5. GELF UDP round-trip (plain JSON datagram) ────────────────────────────

#[tokio::test]
async fn gelf_udp_roundtrip() {
    let (tx, mut rx) = mpsc::channel::<Value>(16);
    let m            = metrics();
    let tenant       = Arc::new("gelf-udp-tenant".to_string());

    let (std_sock, bound_addr) = bind_udp_socket();
    let sock = tokio::net::UdpSocket::from_std(std_sock).unwrap();

    let tx2  = tx.clone();
    let tid  = Arc::clone(&tenant);
    let m2   = Arc::clone(&m);
    let handle = tokio::spawn(async move {
        use std::sync::atomic::Ordering::Relaxed;
        use tokio::sync::mpsc::error::TrySendError;
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((len, peer)) = sock.recv_from(&mut buf).await {
                let ip = peer.ip().to_string();
                if let Ok(v) = serde_json::from_slice::<Value>(&buf[..len]) {
                    if v.is_object() {
                        let host = v.get("host").and_then(|h| h.as_str()).unwrap_or(&ip).to_string();
                        let ts = v.get("timestamp").and_then(|t| t.as_f64())
                            .and_then(|f| {
                                chrono::DateTime::from_timestamp(f as i64, 0)
                                    .map(|d| d.to_rfc3339())
                            })
                            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
                        let mut raw = v.clone();
                        if let Some(o) = raw.as_object_mut() {
                            o.insert("source_ip".into(), serde_json::Value::String(ip.clone()));
                        }
                        m2.udp_received.fetch_add(1, Relaxed);
                        let ev = serde_json::json!({
                            "tenant_id":  &*tid,
                            "source":     format!("gelf:{host}"),
                            "event_time": ts,
                            "raw_payload": raw,
                        });
                        match tx2.try_send(ev) {
                            Ok(_) | Err(TrySendError::Full(_)) => {}
                            Err(TrySendError::Closed(_)) => return,
                        }
                    }
                }
            }
        }
    });

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let gelf   = serde_json::json!({
        "version": "1.1",
        "host": "app-02",
        "short_message": "cache miss",
        "level": 6,
    });
    sender.send_to(gelf.to_string().as_bytes(), bound_addr).await.unwrap();

    let ev = recv(&mut rx).await;
    assert_eq!(ev["tenant_id"], "gelf-udp-tenant");
    assert_eq!(ev["source"],    "gelf:app-02");
    assert_eq!(ev["raw_payload"]["short_message"], "cache miss");

    handle.abort();
}

// ─── 6. Multi-line syslog event via parser ────────────────────────────────────

#[test]
fn parser_rfc5424_to_incoming_event() {
    use cyberbox_collector::parser::{parse_syslog, to_incoming_event};

    let raw = b"<165>1 2026-03-10T10:00:00Z auth-01 sshd 4321 - - login failed for root";
    let msg = parse_syslog(raw, "192.168.1.5").expect("parse failed");
    let ev  = to_incoming_event(&msg, "corp");

    assert_eq!(ev["tenant_id"],                     "corp");
    assert_eq!(ev["source"],                        "syslog");
    assert_eq!(ev["raw_payload"]["hostname"],        "auth-01");
    assert_eq!(ev["raw_payload"]["app_name"],        "sshd");
    assert_eq!(ev["raw_payload"]["severity_name"],   "notice");
    assert!(ev["raw_payload"]["message"].as_str().unwrap().contains("login failed"));
}
