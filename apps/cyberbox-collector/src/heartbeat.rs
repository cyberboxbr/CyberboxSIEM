//! Periodic heartbeat publisher.
//!
//! Sends a synthetic `heartbeat` event every `interval_secs` seconds so the
//! API's `GET /api/v1/sources` shows the collector as `active` even during
//! quiet periods. Disabled when `interval_secs == 0`.

use std::{sync::Arc, time::Duration};

use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};
use tracing::debug;

pub async fn run(
    interval_secs: u64,
    tenant_id:     Arc<String>,
    tx:            mpsc::Sender<Value>,
    mut shutdown:  watch::Receiver<bool>,
) {
    if interval_secs == 0 { return; }

    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {}
        }

        let ev = json!({
            "tenant_id":  *tenant_id,
            "source":     "syslog",
            "event_time": Utc::now().to_rfc3339(),
            "raw_payload": {
                "hostname":       hostname(),
                "app_name":       "cyberbox-collector",
                "message":        "heartbeat",
                "severity":       6,
                "severity_name":  "info",
                "facility":       1,
                "facility_name":  "user",
                "source_ip":      "127.0.0.1",
                "syslog_version": "synthetic",
                "event_type":     "heartbeat",
            }
        });

        if tx.send(ev).await.is_err() { return; }
        debug!("heartbeat sent");
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "cyberbox-collector".to_string())
}
