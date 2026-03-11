//! Kafka consumer source.
//!
//! Subscribes to one or more Kafka topics and injects each message into the
//! collector ingest pipeline as a structured event.  The payload is parsed in
//! this order:
//!
//! 1. JSON object  → used directly as `raw_payload`
//! 2. Syslog line  → parsed by `crate::parser::parse_syslog` → structured event
//! 3. Plain text   → wrapped as `{"message": "<text>"}` in `raw_payload`
//!
//! This module is compiled only when the `kafka` feature is enabled.
//!
//! ## Configuration (environment variables)
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_KAFKA_BROKERS`      | `localhost:9092` | Comma-separated broker list |
//! | `COLLECTOR_KAFKA_TOPICS`       | *(required)*     | Comma-separated topic list   |
//! | `COLLECTOR_KAFKA_GROUP_ID`     | `cyberbox-collector` | Consumer group ID       |
//! | `COLLECTOR_KAFKA_OFFSET_RESET` | `latest`         | `earliest` or `latest`       |

use std::sync::Arc;

use anyhow::{Context, Result};
use rdkafka::{
    config::ClientConfig,
    consumer::{Consumer, StreamConsumer},
    message::Message,
};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::metrics::CollectorMetrics;
use crate::parser::parse_syslog;

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

pub async fn run(
    tenant_id: Arc<String>,
    tx: mpsc::Sender<Value>,
    metrics: Arc<CollectorMetrics>,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;

    let brokers = env_str("COLLECTOR_KAFKA_BROKERS", "localhost:9092");
    let topics_str = env_str("COLLECTOR_KAFKA_TOPICS", "");
    let group_id = env_str("COLLECTOR_KAFKA_GROUP_ID", "cyberbox-collector");
    let offset_reset = env_str("COLLECTOR_KAFKA_OFFSET_RESET", "latest");

    if topics_str.is_empty() {
        warn!("COLLECTOR_KAFKA_TOPICS is not set — Kafka consumer disabled");
        return Ok(());
    }

    let topics: Vec<&str> = topics_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("group.id", &group_id)
        .set("auto.offset.reset", &offset_reset)
        .set("enable.auto.commit", "true")
        .set("auto.commit.interval.ms", "5000")
        .set("session.timeout.ms", "30000")
        .create()
        .context("create Kafka StreamConsumer")?;

    let topic_refs: Vec<&str> = topics.iter().map(|s| *s).collect();
    consumer
        .subscribe(&topic_refs)
        .context("subscribe to Kafka topics")?;

    info!(brokers = %brokers, topics = %topics_str, group = %group_id, "Kafka consumer started");

    loop {
        match consumer.recv().await {
            Err(e) => {
                error!(err = %e, "Kafka consumer error");
                // Back off briefly before retrying to avoid tight error loops.
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Ok(msg) => {
                let payload_bytes = match msg.payload() {
                    Some(b) => b,
                    None => {
                        debug!("Kafka message with empty payload — skipping");
                        continue;
                    }
                };

                let source_ip = msg.topic().to_string(); // use topic as "source"
                let ev = parse_kafka_payload(payload_bytes, &tenant_id, &source_ip);

                match tx.try_send(ev) {
                    Ok(_) => {
                        metrics.kafka_received.fetch_add(1, Relaxed);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        metrics.channel_drops.fetch_add(1, Relaxed);
                        debug!(topic = msg.topic(), "Kafka event dropped — channel full");
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        info!("ingest channel closed — Kafka consumer exiting");
                        return Ok(());
                    }
                }
            }
        }
    }
}

fn parse_kafka_payload(bytes: &[u8], tenant_id: &str, topic: &str) -> Value {
    // 1. Try JSON object
    if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
        if v.is_object() {
            return json!({
                "tenant_id":   tenant_id,
                "source":      format!("kafka:{topic}"),
                "event_time":  chrono::Utc::now().to_rfc3339(),
                "raw_payload": v,
            });
        }
    }

    // 2. Try syslog
    let text = String::from_utf8_lossy(bytes);
    if let Ok(msg) = parse_syslog(text.trim(), "0.0.0.0") {
        return msg.to_incoming_event(tenant_id);
    }

    // 3. Plain text fallback
    json!({
        "tenant_id":  tenant_id,
        "source":     format!("kafka:{topic}"),
        "event_time": chrono::Utc::now().to_rfc3339(),
        "raw_payload": { "message": text.trim() },
    })
}
