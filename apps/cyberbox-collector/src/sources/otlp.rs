//! OpenTelemetry Protocol (OTLP) HTTP/JSON receiver.
//!
//! Listens for OTLP over HTTP using the JSON encoding (content-type
//! `application/json`).  No gRPC or protobuf dependencies are required.
//!
//! Handles:
//!   `POST /v1/logs`    — ExportLogsServiceRequest
//!   `POST /v1/traces`  — ExportTraceServiceRequest
//!   `POST /v1/metrics` — ExportMetricsServiceRequest (passed through as-is)
//!
//! Each log record produces one `IncomingEvent`.  Each span produces one event.
//! Each resource metric batch (one `resourceMetrics` element) produces one event
//! so high-cardinality metric series are not exploded into thousands of events.
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_OTLP_HTTP_BIND` | *(empty)* | Bind address (empty = disabled) |

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Map, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
};
use tracing::{debug, error, info, warn};

use crate::metrics::CollectorMetrics;

/// Maximum accepted request body (10 MiB).
const MAX_BODY: usize = 10 * 1024 * 1024;

// ─── Entry point ──────────────────────────────────────────────────────────────

pub async fn run(
    bind: SocketAddr,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind OTLP HTTP {bind}"))?;

    info!(%bind, "OTLP HTTP receiver ready (POST /v1/logs, /v1/traces, /v1/metrics)");

    loop {
        let accept_res = tokio::select! {
            biased;
            _ = shutdown.changed() => { info!("OTLP HTTP receiver exiting on shutdown"); break; }
            r = listener.accept() => r,
        };
        match accept_res {
            Ok((stream, peer)) => {
                let source_ip = peer.ip().to_string();
                let tx2 = tx.clone();
                let tid = Arc::clone(&tenant_id);
                let m = Arc::clone(&metrics);
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, source_ip.clone(), tid, tx2, m).await {
                        debug!(source_ip, err = %e, "OTLP HTTP connection error");
                    }
                });
            }
            Err(err) => error!(%err, "OTLP HTTP accept error"),
        }
    }
    Ok(())
}

// ─── HTTP connection handler ──────────────────────────────────────────────────

async fn handle_conn(
    stream: TcpStream,
    source_ip: String,
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // Handle multiple requests on the same connection (HTTP/1.1 keep-alive).
    loop {
        // ── Request line ──────────────────────────────────────────────────────
        let mut req_line = String::new();
        let n = reader.read_line(&mut req_line).await?;
        if n == 0 {
            break;
        } // connection closed

        let mut tokens = req_line.trim().splitn(3, ' ');
        let method = tokens.next().unwrap_or("").to_string();
        let path = tokens.next().unwrap_or("").to_string();

        // ── Headers ───────────────────────────────────────────────────────────
        let mut content_length: Option<usize> = None;
        loop {
            let mut hdr = String::new();
            reader.read_line(&mut hdr).await?;
            let h = hdr.trim();
            if h.is_empty() {
                break;
            }
            let lower = h.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().ok();
            }
        }

        // ── Body ──────────────────────────────────────────────────────────────
        let body_len = content_length.unwrap_or(0).min(MAX_BODY);
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            reader.read_exact(&mut body).await?;
        }

        // Non-POST requests get 405.
        if method != "POST" {
            writer.write_all(
                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ).await?;
            break;
        }

        // ── Dispatch ──────────────────────────────────────────────────────────
        let n = process_body(&path, &body, &source_ip, &tenant_id, &tx, &metrics).await;
        debug!(source_ip, path, events = n, "OTLP request processed");

        // Return minimal success response (empty partialSuccess = all accepted).
        let resp_body = b"{}";
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\r\n",
            resp_body.len()
        );
        writer.write_all(resp.as_bytes()).await?;
        writer.write_all(resp_body).await?;
    }
    Ok(())
}

// ─── Body dispatch ────────────────────────────────────────────────────────────

async fn process_body(
    path: &str,
    body: &[u8],
    source_ip: &str,
    tenant_id: &str,
    tx: &mpsc::Sender<Value>,
    metrics: &CollectorMetrics,
) -> usize {
    use std::sync::atomic::Ordering::Relaxed;

    if body.is_empty() {
        return 0;
    }

    let root: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            metrics.parse_errors.fetch_add(1, Relaxed);
            warn!(source_ip, path, err = %e, "OTLP JSON parse error");
            return 0;
        }
    };

    match path {
        "/v1/logs" => emit_logs(&root, source_ip, tenant_id, tx, metrics).await,
        "/v1/traces" => emit_traces(&root, source_ip, tenant_id, tx, metrics).await,
        "/v1/metrics" => emit_metrics(&root, source_ip, tenant_id, tx, metrics).await,
        other => {
            debug!(
                source_ip,
                path = other,
                "OTLP HTTP: unknown path — ignoring"
            );
            0
        }
    }
}

// ─── OTLP attribute helpers ───────────────────────────────────────────────────

/// Convert an OTLP `attributes` array into a flat JSON map.
/// Keys with `'.'` are preserved as-is (e.g. `"service.name"`).
fn extract_attributes(attrs: &Value) -> Map<String, Value> {
    let mut map = Map::new();
    if let Some(arr) = attrs.as_array() {
        for attr in arr {
            if let Some(key) = attr["key"].as_str() {
                map.insert(key.to_string(), extract_any_value(&attr["value"]));
            }
        }
    }
    map
}

/// Convert an OTLP `AnyValue` JSON node to a plain serde_json `Value`.
fn extract_any_value(v: &Value) -> Value {
    if let Some(s) = v.get("stringValue").and_then(|s| s.as_str()) {
        return Value::String(s.to_string());
    }
    if let Some(i) = v.get("intValue").and_then(|i| i.as_i64()) {
        return json!(i);
    }
    // intValue sometimes arrives as a JSON string in some SDKs
    if let Some(s) = v.get("intValue").and_then(|i| i.as_str()) {
        if let Ok(i) = s.parse::<i64>() {
            return json!(i);
        }
    }
    if let Some(d) = v.get("doubleValue").and_then(|d| d.as_f64()) {
        return json!(d);
    }
    if let Some(b) = v.get("boolValue").and_then(|b| b.as_bool()) {
        return json!(b);
    }
    // arrayValue / kvlistValue — stringify
    Value::String(v.to_string())
}

/// Parse OTLP nanosecond epoch (string or number) to RFC-3339.
fn otlp_nanos_to_rfc3339(v: &Value) -> String {
    let ns = v
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| v.as_u64());

    ns.and_then(|ns| {
        let secs = (ns / 1_000_000_000) as i64;
        let nanos = (ns % 1_000_000_000) as u32;
        chrono::DateTime::from_timestamp(secs, nanos)
    })
    .map(|dt| dt.to_rfc3339())
    .unwrap_or_else(|| Utc::now().to_rfc3339())
}

// ─── Log record emission ──────────────────────────────────────────────────────

async fn emit_logs(
    root: &Value,
    source_ip: &str,
    tenant_id: &str,
    tx: &mpsc::Sender<Value>,
    metrics: &CollectorMetrics,
) -> usize {
    use std::sync::atomic::Ordering::Relaxed;
    let mut count = 0usize;

    let resource_logs = match root["resourceLogs"].as_array() {
        Some(a) => a,
        None => return 0,
    };

    'outer: for rl in resource_logs {
        let res_attrs = extract_attributes(&rl["resource"]["attributes"]);
        let service_name = res_attrs
            .get("service.name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let scope_logs = match rl["scopeLogs"].as_array() {
            Some(a) => a,
            None => continue,
        };

        for sl in scope_logs {
            let scope_name = sl["scope"]["name"].as_str().unwrap_or("").to_string();

            let records = match sl["logRecords"].as_array() {
                Some(a) => a,
                None => continue,
            };

            for lr in records {
                let event_time = otlp_nanos_to_rfc3339(
                    lr.get("timeUnixNano")
                        .or_else(|| lr.get("observedTimeUnixNano"))
                        .unwrap_or(&Value::Null),
                );

                let severity_text = lr["severityText"].as_str().unwrap_or("INFO").to_string();
                let severity_number = lr["severityNumber"].as_u64().unwrap_or(9);

                // Body can be a string AnyValue or a plain string field.
                let body = lr["body"]["stringValue"]
                    .as_str()
                    .unwrap_or_else(|| lr["body"].as_str().unwrap_or(""))
                    .to_string();

                let rec_attrs = extract_attributes(&lr["attributes"]);

                let mut raw = Map::new();
                raw.insert("message".into(), Value::String(body));
                raw.insert("severity_text".into(), Value::String(severity_text));
                raw.insert("severity_number".into(), json!(severity_number));
                raw.insert("service_name".into(), Value::String(service_name.clone()));
                raw.insert("scope_name".into(), Value::String(scope_name.clone()));
                raw.insert("source_ip".into(), Value::String(source_ip.to_string()));
                raw.insert("protocol".into(), Value::String("otlp".into()));
                if let Some(tid) = lr["traceId"].as_str() {
                    raw.insert("trace_id".into(), Value::String(tid.to_string()));
                }
                if let Some(sid) = lr["spanId"].as_str() {
                    raw.insert("span_id".into(), Value::String(sid.to_string()));
                }
                // Resource attributes (prefixed to avoid collision)
                for (k, v) in &res_attrs {
                    raw.insert(format!("resource_{}", k.replace('.', "_")), v.clone());
                }
                // Record-level attributes (dot-to-underscore for field names)
                for (k, v) in &rec_attrs {
                    raw.entry(k.replace('.', "_")).or_insert_with(|| v.clone());
                }

                let ev = json!({
                    "tenant_id":  tenant_id,
                    "source":     format!("otlp:{service_name}"),
                    "event_time": event_time,
                    "raw_payload": Value::Object(raw),
                });

                metrics.otlp_received.fetch_add(1, Relaxed);
                if tx.send(ev).await.is_err() {
                    break 'outer;
                }
                count += 1;
            }
        }
    }
    count
}

// ─── Trace span emission ──────────────────────────────────────────────────────

async fn emit_traces(
    root: &Value,
    source_ip: &str,
    tenant_id: &str,
    tx: &mpsc::Sender<Value>,
    metrics: &CollectorMetrics,
) -> usize {
    use std::sync::atomic::Ordering::Relaxed;
    let mut count = 0usize;

    let resource_spans = match root["resourceSpans"].as_array() {
        Some(a) => a,
        None => return 0,
    };

    'outer: for rs in resource_spans {
        let res_attrs = extract_attributes(&rs["resource"]["attributes"]);
        let service_name = res_attrs
            .get("service.name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let scope_spans = match rs["scopeSpans"].as_array() {
            Some(a) => a,
            None => continue,
        };

        for ss in scope_spans {
            let scope_name = ss["scope"]["name"].as_str().unwrap_or("").to_string();

            let spans = match ss["spans"].as_array() {
                Some(a) => a,
                None => continue,
            };

            for span in spans {
                let event_time = otlp_nanos_to_rfc3339(&span["startTimeUnixNano"]);
                let span_name = span["name"].as_str().unwrap_or("").to_string();
                let kind = span["kind"].as_u64().unwrap_or(0);
                let status_code = span["status"]["code"].as_u64().unwrap_or(0);
                let span_attrs = extract_attributes(&span["attributes"]);

                let mut raw = Map::new();
                raw.insert(
                    "message".into(),
                    Value::String(format!("span: {span_name}")),
                );
                raw.insert("span_name".into(), Value::String(span_name));
                raw.insert("span_kind".into(), json!(kind));
                raw.insert("status_code".into(), json!(status_code));
                raw.insert("service_name".into(), Value::String(service_name.clone()));
                raw.insert("scope_name".into(), Value::String(scope_name.clone()));
                raw.insert("source_ip".into(), Value::String(source_ip.to_string()));
                raw.insert("protocol".into(), Value::String("otlp_trace".into()));
                if let Some(tid) = span["traceId"].as_str() {
                    raw.insert("trace_id".into(), Value::String(tid.to_string()));
                }
                if let Some(sid) = span["spanId"].as_str() {
                    raw.insert("span_id".into(), Value::String(sid.to_string()));
                }
                for (k, v) in &res_attrs {
                    raw.insert(format!("resource_{}", k.replace('.', "_")), v.clone());
                }
                for (k, v) in &span_attrs {
                    raw.entry(k.replace('.', "_")).or_insert_with(|| v.clone());
                }

                let ev = json!({
                    "tenant_id":  tenant_id,
                    "source":     format!("otlp_trace:{service_name}"),
                    "event_time": event_time,
                    "raw_payload": Value::Object(raw),
                });

                metrics.otlp_received.fetch_add(1, Relaxed);
                if tx.send(ev).await.is_err() {
                    break 'outer;
                }
                count += 1;
            }
        }
    }
    count
}

// ─── Metric batch emission ────────────────────────────────────────────────────

/// Emits one event per `resourceMetrics` element (one per service/resource
/// combination).  High-cardinality metric series are NOT exploded into
/// individual data-point events — the full OTLP JSON tree is passed through
/// as `raw_payload.metrics_data` for downstream storage.
async fn emit_metrics(
    root: &Value,
    source_ip: &str,
    tenant_id: &str,
    tx: &mpsc::Sender<Value>,
    metrics: &CollectorMetrics,
) -> usize {
    use std::sync::atomic::Ordering::Relaxed;
    let mut count = 0usize;

    let resource_metrics = match root["resourceMetrics"].as_array() {
        Some(a) => a,
        None => return 0,
    };

    for rm in resource_metrics {
        let res_attrs = extract_attributes(&rm["resource"]["attributes"]);
        let service_name = res_attrs
            .get("service.name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let mut raw = Map::new();
        raw.insert("service_name".into(), Value::String(service_name.clone()));
        raw.insert("source_ip".into(), Value::String(source_ip.to_string()));
        raw.insert("protocol".into(), Value::String("otlp_metrics".into()));
        raw.insert("metrics_data".into(), rm.clone());
        for (k, v) in &res_attrs {
            raw.insert(format!("resource_{}", k.replace('.', "_")), v.clone());
        }

        let ev = json!({
            "tenant_id":  tenant_id,
            "source":     format!("otlp_metrics:{service_name}"),
            "event_time": Utc::now().to_rfc3339(),
            "raw_payload": Value::Object(raw),
        });

        metrics.otlp_received.fetch_add(1, Relaxed);
        if tx.send(ev).await.is_err() {
            break;
        }
        count += 1;
    }
    count
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    fn make_log_request() -> Vec<u8> {
        let body = serde_json::json!({
            "resourceLogs": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "my-service"}}
                    ]
                },
                "scopeLogs": [{
                    "scope": {"name": "my-lib", "version": "1.0"},
                    "logRecords": [{
                        "timeUnixNano": "1700000000000000000",
                        "severityNumber": 9,
                        "severityText": "INFO",
                        "body": {"stringValue": "hello from otlp"},
                        "attributes": [
                            {"key": "request.id", "value": {"stringValue": "abc123"}}
                        ],
                        "traceId": "aabbccdd00000000",
                        "spanId":  "00001111"
                    }]
                }]
            }]
        })
        .to_string();
        let body_bytes = body.as_bytes();
        format!(
            "POST /v1/logs HTTP/1.1\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
            body_bytes.len()
        ).into_bytes().into_iter().chain(body_bytes.iter().copied()).collect()
    }

    #[tokio::test]
    async fn otlp_logs_roundtrip() {
        let (tx, mut rx) = mpsc::channel(16);
        let metrics = CollectorMetrics::new("test-otlp-queue.jsonl".into());
        let tenant = Arc::new("otlp-tenant".to_string());

        // Bind on OS-assigned port.
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_addr = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();

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
                            let _ = handle_conn(stream, ip, tid2, tx3, m2).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let mut stream = TcpStream::connect(bound_addr).await.unwrap();
        stream.write_all(&make_log_request()).await.unwrap();

        let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .expect("timeout waiting for OTLP event")
            .expect("channel closed");

        assert_eq!(ev["tenant_id"], "otlp-tenant");
        assert_eq!(ev["source"], "otlp:my-service");
        assert_eq!(ev["raw_payload"]["message"], "hello from otlp");
        assert_eq!(ev["raw_payload"]["severity_text"], "INFO");
        assert_eq!(ev["raw_payload"]["service_name"], "my-service");
        assert_eq!(ev["raw_payload"]["resource_service_name"], "my-service");
        assert_eq!(ev["raw_payload"]["trace_id"], "aabbccdd00000000");
        // request.id attribute → request_id in raw_payload
        assert_eq!(ev["raw_payload"]["request_id"], "abc123");

        handle.abort();
    }

    #[tokio::test]
    async fn otlp_unknown_path_returns_empty() {
        let (tx, _rx) = mpsc::channel(16);
        let metrics = CollectorMetrics::new("test-otlp2-queue.jsonl".into());
        let body = b"{}";
        let n = process_body("/v1/unknown", body, "1.2.3.4", "t", &tx, &metrics).await;
        assert_eq!(n, 0);
    }

    #[test]
    fn extract_attributes_handles_all_types() {
        let attrs = serde_json::json!([
            {"key": "str",  "value": {"stringValue": "hello"}},
            {"key": "num",  "value": {"intValue": "42"}},
            {"key": "dbl",  "value": {"doubleValue": 3.14}},
            {"key": "bool", "value": {"boolValue": true}},
        ]);
        let map = extract_attributes(&attrs);
        assert_eq!(map["str"], Value::String("hello".into()));
        assert_eq!(map["num"], json!(42i64));
        assert_eq!(map["bool"], json!(true));
    }

    #[test]
    fn otlp_nanos_parses_string_and_number() {
        let s = otlp_nanos_to_rfc3339(&json!("1700000000000000000"));
        assert!(s.starts_with("2023"));
        let n = otlp_nanos_to_rfc3339(&json!(1700000000000000000u64));
        assert!(n.starts_with("2023"));
    }
}
