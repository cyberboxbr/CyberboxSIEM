//! GELF (Graylog Extended Log Format) 1.1 input sources.
//!
//! Reference: <https://go2docs.graylog.org/5-0/getting_in_log_data/gelf.html>
//!
//! # UDP
//! Each datagram may be:
//! - Plain UTF-8 JSON (`{…}`)
//! - Gzip-compressed JSON (magic `0x1f 0x8b`)
//! - Zlib-compressed JSON (magic `0x78 0x??`)
//! - Chunked GELF (magic `0x1e 0x0f`) — up to 128 chunks, reassembled in memory
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_GELF_UDP_BIND` | *(empty)* | Bind address (disabled if empty) |
//!
//! # TCP
//! Messages are null-byte (`\0`) terminated.  TLS is shared with the syslog
//! TCP listener — pass the same `ArcSwap<TlsAcceptor>` used for port 601.
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_GELF_TCP_BIND` | *(empty)* | Bind address (disabled if empty) |
//!
//! ## Event format
//! ```json
//! {
//!   "tenant_id": "...",
//!   "source":    "gelf:<host>",
//!   "event_time": "<ISO-8601>",
//!   "raw_payload": { /* all GELF fields */ , "source_ip": "..." }
//! }
//! ```

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio::{
    io::AsyncBufReadExt,
    net::{TcpListener, UdpSocket},
    sync::{mpsc, watch},
};
use tracing::{debug, error, info, warn};

use crate::metrics::CollectorMetrics;

// ─── Chunk reassembly ─────────────────────────────────────────────────────────

const GELF_CHUNK_MAGIC: [u8; 2] = [0x1e, 0x0f];
/// Stale incomplete chunk assemblies are evicted after this many seconds.
const CHUNK_TTL_SECS: u64 = 5;
/// GELF spec: max 128 chunks per message.
const MAX_CHUNKS: usize = 128;

struct ChunkBuffer {
    count: u8,
    received: u8,
    chunks: Vec<Option<Vec<u8>>>,
    created_at: Instant,
}

type ChunkMap = Arc<Mutex<HashMap<[u8; 8], ChunkBuffer>>>;

/// Try to reassemble a chunked GELF datagram.
/// Returns `Some(assembled_bytes)` when all chunks have arrived, `None` otherwise.
fn handle_chunk(map: &ChunkMap, data: &[u8]) -> Option<Vec<u8>> {
    // Header: 2 magic + 8 id + 1 seq_num + 1 seq_count = 12 bytes minimum
    if data.len() < 12 {
        return None;
    }

    let mut id = [0u8; 8];
    id.copy_from_slice(&data[2..10]);
    let seq_num = data[10] as usize;
    let seq_count = data[11];
    let payload = data[12..].to_vec();

    if seq_count == 0 || seq_count as usize > MAX_CHUNKS || seq_num >= seq_count as usize {
        return None;
    }

    let mut map = map.lock().unwrap_or_else(|e| e.into_inner());

    let buf = map.entry(id).or_insert_with(|| ChunkBuffer {
        count: seq_count,
        received: 0,
        chunks: vec![None; seq_count as usize],
        created_at: Instant::now(),
    });

    if buf.chunks[seq_num].is_none() {
        buf.chunks[seq_num] = Some(payload);
        buf.received += 1;
    }

    if buf.received == buf.count {
        let assembled: Vec<u8> = buf
            .chunks
            .iter()
            .filter_map(|c| c.as_deref())
            .flat_map(|c| c.iter().copied())
            .collect();
        map.remove(&id);
        return Some(assembled);
    }
    None
}

/// Evict partial chunk assemblies older than `CHUNK_TTL_SECS`.
fn evict_stale_chunks(map: &ChunkMap) {
    if let Ok(mut m) = map.try_lock() {
        let now = Instant::now();
        m.retain(|_, buf| now.duration_since(buf.created_at).as_secs() < CHUNK_TTL_SECS);
    }
}

// ─── Decompression ────────────────────────────────────────────────────────────

/// Decompress gzip / zlib payloads; return plain bytes unchanged otherwise.
fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::{GzDecoder, ZlibDecoder};
    use std::io::Read;

    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        // Gzip
        let mut out = Vec::new();
        GzDecoder::new(data).read_to_end(&mut out).ok()?;
        Some(out)
    } else if data.len() >= 2 && data[0] == 0x78 && matches!(data[1], 0x01 | 0x5e | 0x9c | 0xda) {
        // Zlib
        let mut out = Vec::new();
        ZlibDecoder::new(data).read_to_end(&mut out).ok()?;
        Some(out)
    } else {
        // Plain
        Some(data.to_vec())
    }
}

// ─── Wrap GELF payload into IncomingEvent shape ───────────────────────────────

fn wrap_gelf(payload: Value, tenant_id: &str, source_ip: &str) -> Value {
    let obj = payload.as_object();

    // `host` is GELF-required; fall back to source IP.
    let host = obj
        .and_then(|o| o.get("host"))
        .and_then(|v| v.as_str())
        .unwrap_or(source_ip);

    // `timestamp` is seconds-since-epoch (float).
    let event_time = obj
        .and_then(|o| o.get("timestamp"))
        .and_then(|v| v.as_f64())
        .and_then(|ts| {
            let secs = ts as i64;
            let nanos = ((ts - secs as f64) * 1_000_000_000.0) as u32;
            DateTime::from_timestamp(secs, nanos).map(|dt| dt.to_rfc3339())
        })
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let mut raw = payload.clone();
    if let Some(obj) = raw.as_object_mut() {
        obj.insert(
            "source_ip".to_string(),
            Value::String(source_ip.to_string()),
        );
    }

    json!({
        "tenant_id":   tenant_id,
        "source":      format!("gelf:{host}"),
        "event_time":  event_time,
        "raw_payload": raw,
    })
}

/// Parse raw bytes as a GELF JSON object; emit to channel on success.
fn emit_gelf(
    data: &[u8],
    source_ip: &str,
    tenant_id: &str,
    tx: &mpsc::Sender<Value>,
    metrics: &CollectorMetrics,
) {
    use std::sync::atomic::Ordering::Relaxed;

    match serde_json::from_slice::<Value>(data) {
        Ok(payload) if payload.is_object() => {
            let ev = wrap_gelf(payload, tenant_id, source_ip);
            // Prefer try_send for UDP (non-blocking); fall back to best-effort.
            use tokio::sync::mpsc::error::TrySendError;
            match tx.try_send(ev) {
                Ok(_) => {
                    metrics.gelf_udp_received.fetch_add(1, Relaxed);
                }
                Err(TrySendError::Full(_)) => {
                    metrics.channel_drops.fetch_add(1, Relaxed);
                    debug!(source_ip, "GELF event dropped — channel full");
                }
                Err(TrySendError::Closed(_)) => {}
            }
        }
        Ok(_) => {
            metrics.parse_errors.fetch_add(1, Relaxed);
            if let Some(dlq) = metrics.dlq.get() {
                dlq.write("gelf_udp", source_ip, data);
            }
            debug!(source_ip, "GELF payload is not a JSON object");
        }
        Err(e) => {
            metrics.parse_errors.fetch_add(1, Relaxed);
            if let Some(dlq) = metrics.dlq.get() {
                dlq.write("gelf_udp", source_ip, data);
            }
            debug!(source_ip, err = %e, "GELF JSON parse error");
        }
    }
}

// ─── UDP source ───────────────────────────────────────────────────────────────

pub async fn run_udp(
    bind: SocketAddr,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let sock = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("bind GELF UDP {bind}"))?;
    info!(%bind, "GELF UDP listener ready");

    let chunks: ChunkMap = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 65_535];
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => { info!("GELF UDP listener exiting on shutdown"); break; }
            res = sock.recv_from(&mut buf) => {
                match res {
                    Ok((len, peer)) => {
                        let source_ip = peer.ip().to_string();
                        let data      = &buf[..len];

                        // Chunked GELF?
                        if data.len() >= 2 && data[..2] == GELF_CHUNK_MAGIC {
                            if let Some(assembled) = handle_chunk(&chunks, data) {
                                if let Some(decompressed) = decompress(&assembled) {
                                    emit_gelf(&decompressed, &source_ip, &tenant_id, &tx, &metrics);
                                }
                            }
                            continue;
                        }

                        // Plain or compressed JSON
                        match decompress(data) {
                            Some(plain) => emit_gelf(&plain, &source_ip, &tenant_id, &tx, &metrics),
                            None => {
                                use std::sync::atomic::Ordering::Relaxed;
                                metrics.parse_errors.fetch_add(1, Relaxed);
                                debug!(source_ip, "GELF UDP decompression failed");
                            }
                        }
                    }
                    Err(err) => error!(%err, "GELF UDP recv_from error"),
                }
            }
            _ = tick.tick() => {
                evict_stale_chunks(&chunks);
            }
        }
    }
    Ok(())
}

// ─── TCP source ───────────────────────────────────────────────────────────────

/// `tls` is per-connection hot-reloaded from the `ArcSwap`.  Pass `None` for
/// plain-text.
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
        .with_context(|| format!("bind GELF TCP {bind}"))?;

    if tls.is_some() {
        info!(%bind, "GELF TCP listener ready (null-delimited, TLS/mTLS)");
    } else {
        info!(%bind, "GELF TCP listener ready (null-byte-delimited JSON)");
    }

    loop {
        let accept_res = tokio::select! {
            biased;
            _ = shutdown.changed() => { info!("GELF TCP listener exiting on shutdown"); break; }
            r = listener.accept() => r,
        };
        match accept_res {
            Ok((stream, peer)) => {
                let source_ip = peer.ip().to_string();
                let tx2 = tx.clone();
                let tid = Arc::clone(&tenant_id);
                let m = Arc::clone(&metrics);
                let tls2: Option<Arc<tokio_rustls::TlsAcceptor>> =
                    tls.as_ref().map(|s| s.load_full());

                tokio::spawn(async move {
                    let result = if let Some(acceptor) = tls2 {
                        match acceptor.accept(stream).await {
                            Ok(ts) => process_gelf_tcp(ts, source_ip.clone(), tid, tx2, m).await,
                            Err(e) => {
                                debug!(source_ip, err = %e, "GELF TCP TLS handshake failed");
                                return;
                            }
                        }
                    } else {
                        process_gelf_tcp(stream, source_ip.clone(), tid, tx2, m).await
                    };
                    if let Err(e) = result {
                        debug!(source_ip, %e, "GELF TCP connection closed");
                    }
                });
            }
            Err(err) => error!(%err, "GELF TCP accept error"),
        }
    }
    Ok(())
}

/// Read null-byte–terminated GELF messages from `stream`.
async fn process_gelf_tcp<S>(
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

    let mut reader = tokio::io::BufReader::new(stream);
    let mut buf = Vec::with_capacity(8192);

    loop {
        buf.clear();
        // read_until includes the delimiter; GELF messages end with \0.
        let n = reader.read_until(b'\0', &mut buf).await?;
        if n == 0 {
            break;
        } // EOF

        // Strip the trailing null byte.
        if buf.last() == Some(&0) {
            buf.pop();
        }
        if buf.is_empty() {
            continue;
        }

        match serde_json::from_slice::<Value>(&buf) {
            Ok(payload) if payload.is_object() => {
                let ev = wrap_gelf(payload, &tenant_id, &source_ip);
                metrics.gelf_tcp_received.fetch_add(1, Relaxed);
                if tx.send(ev).await.is_err() {
                    return Ok(());
                }
            }
            Ok(_) => {
                metrics.parse_errors.fetch_add(1, Relaxed);
                if let Some(dlq) = metrics.dlq.get() {
                    dlq.write("gelf_tcp", &source_ip, &buf);
                }
                warn!(source_ip, "GELF TCP message is not a JSON object");
            }
            Err(e) => {
                metrics.parse_errors.fetch_add(1, Relaxed);
                if let Some(dlq) = metrics.dlq.get() {
                    dlq.write("gelf_tcp", &source_ip, &buf);
                }
                debug!(source_ip, err = %e, "GELF TCP JSON parse error");
            }
        }
    }
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    // ── wrap_gelf ─────────────────────────────────────────────────────────────

    #[test]
    fn wrap_gelf_maps_host_and_time() {
        let payload = serde_json::json!({
            "version": "1.1",
            "host": "web-01",
            "short_message": "disk full",
            "timestamp": 1_700_000_000.5_f64,
        });
        let ev = wrap_gelf(payload, "t1", "10.0.0.1");
        assert_eq!(ev["tenant_id"], "t1");
        assert!(ev["source"].as_str().unwrap().starts_with("gelf:web-01"));
        assert!(ev["event_time"].as_str().unwrap().contains('T'));
        assert_eq!(ev["raw_payload"]["source_ip"], "10.0.0.1");
        assert_eq!(ev["raw_payload"]["host"], "web-01");
    }

    #[test]
    fn wrap_gelf_falls_back_to_source_ip_for_host() {
        let payload = serde_json::json!({"version":"1.1","short_message":"hi"});
        let ev = wrap_gelf(payload, "t", "1.2.3.4");
        assert_eq!(ev["source"], "gelf:1.2.3.4");
    }

    // ── decompress ────────────────────────────────────────────────────────────

    #[test]
    fn decompress_plain_json_unchanged() {
        let data = b"{\"a\":1}";
        assert_eq!(decompress(data).unwrap(), data);
    }

    #[test]
    fn decompress_gzip_json() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(b"{\"b\":2}").unwrap();
        let compressed = enc.finish().unwrap();
        let out = decompress(&compressed).unwrap();
        assert_eq!(out, b"{\"b\":2}");
    }

    // ── chunk reassembly ──────────────────────────────────────────────────────

    #[test]
    fn chunk_reassembly_two_chunks() {
        let map: ChunkMap = Arc::new(Mutex::new(HashMap::new()));
        let id = [0xAAu8; 8];

        // Build chunk 0
        let mut c0 = vec![0x1e, 0x0f];
        c0.extend_from_slice(&id);
        c0.push(0); // seq_num
        c0.push(2); // seq_count
        c0.extend_from_slice(b"{\"a\":");

        // Build chunk 1
        let mut c1 = vec![0x1e, 0x0f];
        c1.extend_from_slice(&id);
        c1.push(1); // seq_num
        c1.push(2); // seq_count
        c1.extend_from_slice(b"1}");

        assert!(handle_chunk(&map, &c0).is_none());
        let assembled = handle_chunk(&map, &c1).unwrap();
        assert_eq!(assembled, b"{\"a\":1}");
        // Buffer should be cleaned up after assembly.
        assert!(map.lock().unwrap().is_empty());
    }

    // ── GELF TCP round-trip ───────────────────────────────────────────────────

    #[tokio::test]
    async fn roundtrip_gelf_tcp_null_delimited() {
        let (tx, mut rx) = mpsc::channel(16);
        let metrics = CollectorMetrics::new("test-gelf-queue.jsonl".into());
        let tenant = Arc::new("gelf-tenant".to_string());

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_addr = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();

        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant);
        let m = Arc::clone(&metrics);
        let handle = tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let ip = peer.ip().to_string();
                let tx3 = tx2.clone();
                let tid2 = Arc::clone(&tid);
                let m2 = Arc::clone(&m);
                tokio::spawn(async move {
                    let _ = process_gelf_tcp(stream, ip, tid2, tx3, m2).await;
                });
            }
        });

        let mut stream = TcpStream::connect(bound_addr).await.unwrap();
        let gelf_msg = b"{\"version\":\"1.1\",\"host\":\"srv01\",\"short_message\":\"test msg\",\"level\":6}\0";
        stream.write_all(gelf_msg).await.unwrap();

        let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .expect("timeout waiting for GELF event")
            .expect("channel closed");

        assert_eq!(ev["tenant_id"], "gelf-tenant");
        assert_eq!(ev["source"], "gelf:srv01");
        assert_eq!(ev["raw_payload"]["short_message"], "test msg");
        assert_eq!(ev["raw_payload"]["level"], 6);

        handle.abort();
    }

    // ── GELF UDP round-trip ───────────────────────────────────────────────────

    #[tokio::test]
    async fn roundtrip_gelf_udp_plain() {
        let (tx, mut rx) = mpsc::channel(16);
        let metrics = CollectorMetrics::new("test-gelf-udp-queue.jsonl".into());
        let tenant = Arc::new("gelf-udp-tenant".to_string());

        // Bind source on OS-assigned port.
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bound_addr = std_sock.local_addr().unwrap();
        std_sock.set_nonblocking(true).unwrap();
        let sock = UdpSocket::from_std(std_sock).unwrap();

        let chunks: ChunkMap = Arc::new(Mutex::new(HashMap::new()));
        let tx2 = tx.clone();
        let tid = Arc::clone(&tenant);
        let m = Arc::clone(&metrics);

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
                let source_ip = peer.ip().to_string();
                let data = &buf[..len];
                if data.len() >= 2 && data[..2] == GELF_CHUNK_MAGIC {
                    if let Some(assembled) = handle_chunk(&chunks, data) {
                        if let Some(plain) = decompress(&assembled) {
                            emit_gelf(&plain, &source_ip, &tid, &tx2, &m);
                        }
                    }
                } else if let Some(plain) = decompress(data) {
                    emit_gelf(&plain, &source_ip, &tid, &tx2, &m);
                }
            }
        });

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gelf = serde_json::json!({
            "version": "1.1",
            "host": "udp-host",
            "short_message": "udp gelf test",
        });
        sender
            .send_to(gelf.to_string().as_bytes(), bound_addr)
            .await
            .unwrap();

        let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .expect("timeout waiting for GELF UDP event")
            .expect("channel closed");

        assert_eq!(ev["tenant_id"], "gelf-udp-tenant");
        assert_eq!(ev["source"], "gelf:udp-host");
        assert_eq!(ev["raw_payload"]["short_message"], "udp gelf test");

        handle.abort();
    }
}
