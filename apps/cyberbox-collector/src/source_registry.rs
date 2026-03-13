//! Auto-registration of syslog sources as agents in the CyberboxSIEM API.
//!
//! When the collector receives syslog messages from a device, the
//! [`SourceRegistry`] records the source IP and hostname. A background task
//! periodically registers new sources via `POST /api/v1/agents/register` and
//! sends heartbeats for all known sources, so they appear in the Agent Fleet
//! page alongside real agents.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use reqwest::Client;
use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// How often the background task runs (seconds).
const TICK_INTERVAL_SECS: u64 = 30;

/// Sources not seen for this duration are considered stale (offline).
const STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// Per-source bookkeeping entry.
struct SourceEntry {
    /// Hostname extracted from the syslog message (best-effort).
    hostname: String,
    /// When this source was first observed.
    #[allow(dead_code)]
    first_seen: Instant,
    /// When the last syslog message was received from this source.
    last_seen: Instant,
    /// Whether we have successfully called `/agents/register` for this source.
    registered: bool,
}

/// Lock-free registry of syslog sources observed by the collector.
///
/// The hot-path method [`observe`] is called from the UDP/TCP receive loops and
/// performs only a DashMap insert/update — no blocking, no I/O.
///
/// A separate background task ([`run`]) handles the HTTP registration and
/// heartbeat calls on a 30-second interval.
pub struct SourceRegistry {
    sources: DashMap<String, SourceEntry>,
}

impl Default for SourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceRegistry {
    pub fn new() -> Self {
        Self {
            sources: DashMap::new(),
        }
    }

    /// Record a syslog message from `source_ip` with the parsed `hostname`.
    ///
    /// This is called on every successfully parsed syslog message in the UDP
    /// and TCP receive loops. It must be non-blocking.
    pub fn observe(&self, source_ip: &str, hostname: &str) {
        let now = Instant::now();
        self.sources
            .entry(source_ip.to_string())
            .and_modify(|e| {
                e.last_seen = now;
                // Update hostname if the new one is more informative (not the
                // raw IP or empty).
                if !hostname.is_empty() && hostname != source_ip {
                    e.hostname = hostname.to_string();
                }
            })
            .or_insert_with(|| SourceEntry {
                hostname: if hostname.is_empty() {
                    source_ip.to_string()
                } else {
                    hostname.to_string()
                },
                first_seen: now,
                last_seen: now,
                registered: false,
            });
    }

    /// Background loop: register new sources and heartbeat all known sources.
    pub async fn run(
        self: Arc<Self>,
        client: Client,
        api_url: String,
        tenant_id: String,
        mut shutdown: watch::Receiver<bool>,
        api_key: Option<String>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(TICK_INTERVAL_SECS));
        // First tick fires immediately — skip it so we give sources time to appear.
        interval.tick().await;

        info!(
            "source registry background task started (interval={}s)",
            TICK_INTERVAL_SECS
        );

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    info!("source registry exiting on shutdown");
                    break;
                }
                _ = interval.tick() => {
                    self.tick(&client, &api_url, &tenant_id, api_key.as_deref()).await;
                }
            }
        }
    }

    async fn tick(&self, client: &Client, api_url: &str, tenant_id: &str, api_key: Option<&str>) {
        let now = Instant::now();

        // Collect entries to process (avoid holding DashMap refs across await).
        let entries: Vec<(String, String, bool, bool)> = self
            .sources
            .iter()
            .map(|entry| {
                let source_ip = entry.key().clone();
                let hostname = entry.value().hostname.clone();
                let registered = entry.value().registered;
                let stale = now.duration_since(entry.value().last_seen) > STALE_AFTER;
                (source_ip, hostname, registered, stale)
            })
            .collect();

        for (source_ip, hostname, registered, stale) in entries {
            let agent_id = format!("syslog-{source_ip}");

            // Register if not yet done.
            if !registered {
                match self
                    .register(client, api_url, tenant_id, &agent_id, &hostname, api_key)
                    .await
                {
                    Ok(()) => {
                        // Mark as registered.
                        if let Some(mut entry) = self.sources.get_mut(&source_ip) {
                            entry.registered = true;
                        }
                        info!(source_ip, hostname, "syslog source registered as agent");
                    }
                    Err(e) => {
                        warn!(source_ip, %e, "failed to register syslog source — will retry");
                    }
                }
            }

            // Send heartbeat for active (non-stale) sources that are registered.
            if !stale {
                if let Err(e) = self.heartbeat(client, api_url, tenant_id, &agent_id, api_key).await {
                    debug!(source_ip, %e, "heartbeat failed for syslog source");
                }
            }
        }
    }

    async fn register(
        &self,
        client: &Client,
        api_url: &str,
        tenant_id: &str,
        agent_id: &str,
        hostname: &str,
        api_key: Option<&str>,
    ) -> Result<(), reqwest::Error> {
        let url = format!("{api_url}/api/v1/agents/register");
        let body = json!({
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "hostname": hostname,
            "os": "syslog",
            "version": "collector-detected",
        });

        let mut req = client
            .post(&url)
            .header("x-tenant-id", tenant_id)
            .header("x-user-id", "cyberbox-collector")
            .header("x-roles", "ingestor");

        if let Some(key) = api_key {
            req = req.header("X-Api-Key", key);
        }

        let resp = req
            .json(&body)
            .send()
            .await?;

        // Treat any 2xx as success; 409 (already registered) is also fine.
        let status = resp.status();
        if status.is_success() || status.as_u16() == 409 {
            Ok(())
        } else {
            // Log and consume the body to release the connection.
            let body_text = resp.text().await.unwrap_or_default();
            warn!(
                %status, body = %body_text,
                "unexpected status from agent register"
            );
            // Don't return an error for non-retriable statuses — mark
            // registered on next cycle if the API recovers.
            Ok(())
        }
    }

    async fn heartbeat(
        &self,
        client: &Client,
        api_url: &str,
        tenant_id: &str,
        agent_id: &str,
        api_key: Option<&str>,
    ) -> Result<(), reqwest::Error> {
        let url = format!("{api_url}/api/v1/agents/{agent_id}/heartbeat");

        let mut req = client
            .post(&url)
            .header("x-tenant-id", tenant_id)
            .header("x-user-id", "cyberbox-collector")
            .header("x-roles", "ingestor");

        if let Some(key) = api_key {
            req = req.header("X-Api-Key", key);
        }

        let resp = req
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            debug!(
                %status, body = %body_text, agent_id,
                "heartbeat response was not 2xx"
            );
        }

        Ok(())
    }
}
