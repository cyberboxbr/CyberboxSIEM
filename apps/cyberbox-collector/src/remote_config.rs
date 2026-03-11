//! Remote configuration polling.
//!
//! Fetches a JSON document from `COLLECTOR_REMOTE_CONFIG_URL` every
//! `COLLECTOR_REMOTE_CONFIG_POLL_SECS` seconds and applies supported
//! runtime-overridable settings without requiring a restart.
//!
//! # Overridable at runtime
//! `batch_size`, `flush_ms`, `heartbeat_secs`, `tail_poll_ms`
//!
//! # Not overridable (require restart)
//! Bind addresses, TLS certificates, WEL channels, cloud source credentials.

use std::{sync::Arc, time::Duration};

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// ─── Runtime config ───────────────────────────────────────────────────────────

/// Subset of Config that can be updated at runtime without restart.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeConfig {
    pub batch_size: Option<usize>,
    pub flush_ms: Option<u64>,
    pub heartbeat_secs: Option<u64>,
    #[allow(dead_code)]
    pub tail_poll_ms: Option<u64>,
}

pub type SharedRuntimeConfig = Arc<RwLock<RuntimeConfig>>;

pub fn new_shared() -> SharedRuntimeConfig {
    Arc::new(RwLock::new(RuntimeConfig::default()))
}

// ─── Polling task ─────────────────────────────────────────────────────────────

/// Polls `COLLECTOR_REMOTE_CONFIG_URL` every `COLLECTOR_REMOTE_CONFIG_POLL_SECS`
/// seconds and writes new settings into `shared`.
/// Returns immediately (no-op) when `COLLECTOR_REMOTE_CONFIG_URL` is not set.
pub async fn run(client: reqwest::Client, shared: SharedRuntimeConfig) {
    let url = match std::env::var("COLLECTOR_REMOTE_CONFIG_URL")
        .ok()
        .filter(|s| !s.is_empty())
    {
        Some(u) => u,
        None => return,
    };

    let poll_secs: u64 = std::env::var("COLLECTOR_REMOTE_CONFIG_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    info!(url, poll_secs, "remote config polling enabled");

    let mut interval = tokio::time::interval(Duration::from_secs(poll_secs));
    interval.tick().await; // skip first tick (apply on second tick)

    loop {
        interval.tick().await;
        match fetch_config(&client, &url).await {
            Ok(new_cfg) => {
                let mut w = shared.write().await;
                let old = w.clone();
                *w = new_cfg.clone();
                drop(w);

                // Log any changed fields
                if new_cfg.batch_size != old.batch_size {
                    info!(value = ?new_cfg.batch_size, "remote config: batch_size updated");
                }
                if new_cfg.flush_ms != old.flush_ms {
                    info!(value = ?new_cfg.flush_ms, "remote config: flush_ms updated");
                }
                if new_cfg.heartbeat_secs != old.heartbeat_secs {
                    info!(value = ?new_cfg.heartbeat_secs, "remote config: heartbeat_secs updated");
                }
                debug!("remote config refreshed");
            }
            Err(err) => warn!(%err, "failed to fetch remote config"),
        }
    }
}

async fn fetch_config(client: &reqwest::Client, url: &str) -> anyhow::Result<RuntimeConfig> {
    let cfg: RuntimeConfig = client
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(cfg)
}
