//! Auto-registration of syslog sources as agents in the CyberboxSIEM API.
//!
//! When the collector receives syslog messages from a device, the
//! [`SourceRegistry`] records the hostname and source IP. A background task
//! periodically registers new sources via `POST /api/v1/agents/register` and
//! sends heartbeats for all known sources, so they appear in the Agent Fleet
//! page alongside real agents.
//!
//! Sources are keyed by **hostname** (not source IP), so multiple devices
//! behind the same NAT gateway appear as separate agents.

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
    /// Source IP address of the syslog sender.
    source_ip: String,
    /// When this source was first observed.
    #[allow(dead_code)]
    first_seen: Instant,
    /// When the last syslog message was received from this source.
    last_seen: Instant,
    /// Whether we have successfully called `/agents/register` for this source.
    registered: bool,
    /// Auto-detected platform type.
    platform: String,
    /// A sample app_name or provider for device-type detection.
    sample_app: String,
}

/// Lock-free registry of syslog sources observed by the collector.
///
/// The hot-path method [`observe`] is called from the UDP/TCP receive loops and
/// performs only a DashMap insert/update — no blocking, no I/O.
///
/// A separate background task ([`run`]) handles the HTTP registration and
/// heartbeat calls on a 30-second interval.
pub struct SourceRegistry {
    /// Keyed by hostname (not source IP).
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
    /// `app_name` is the syslog app-name field (e.g. "filterlog", "cyberbox-agent",
    /// "sshd") used to auto-detect the device/OS type.
    ///
    /// This is called on every successfully parsed syslog message in the UDP
    /// and TCP receive loops. It must be non-blocking.
    pub fn observe(&self, source_ip: &str, hostname: &str, app_name: &str) {
        let key = if hostname.is_empty() || hostname == source_ip {
            source_ip.to_string()
        } else {
            hostname.to_string()
        };

        let now = Instant::now();
        self.sources
            .entry(key)
            .and_modify(|e| {
                e.last_seen = now;
                if !source_ip.is_empty() {
                    e.source_ip = source_ip.to_string();
                }
                // Update platform detection with new evidence
                if !app_name.is_empty() && e.sample_app.is_empty() {
                    e.sample_app = app_name.to_string();
                    e.platform = detect_platform(hostname, app_name);
                }
            })
            .or_insert_with(|| {
                let platform = detect_platform(hostname, app_name);
                SourceEntry {
                    source_ip: source_ip.to_string(),
                    first_seen: now,
                    last_seen: now,
                    registered: false,
                    platform,
                    sample_app: app_name.to_string(),
                }
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
        let entries: Vec<(String, String, String, bool, bool)> = self
            .sources
            .iter()
            .map(|entry| {
                let hostname = entry.key().clone();
                let source_ip = entry.value().source_ip.clone();
                let platform = entry.value().platform.clone();
                let registered = entry.value().registered;
                let stale = now.duration_since(entry.value().last_seen) > STALE_AFTER;
                (hostname, source_ip, platform, registered, stale)
            })
            .collect();

        for (hostname, source_ip, platform, registered, stale) in entries {
            let agent_id = format!("syslog-{hostname}");

            // Register if not yet done.
            if !registered {
                match self
                    .register(
                        client, api_url, tenant_id, &agent_id, &hostname, &source_ip, &platform,
                        api_key,
                    )
                    .await
                {
                    Ok(()) => {
                        if let Some(mut entry) = self.sources.get_mut(&hostname) {
                            entry.registered = true;
                        }
                        info!(
                            hostname,
                            source_ip, platform, "syslog source registered as agent"
                        );
                    }
                    Err(e) => {
                        warn!(hostname, %e, "failed to register syslog source — will retry");
                    }
                }
            }

            // Send heartbeat for active (non-stale) sources that are registered.
            if !stale {
                if let Err(e) = self
                    .heartbeat(client, api_url, tenant_id, &agent_id, api_key)
                    .await
                {
                    debug!(hostname, %e, "heartbeat failed for syslog source");
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn register(
        &self,
        client: &Client,
        api_url: &str,
        tenant_id: &str,
        agent_id: &str,
        hostname: &str,
        source_ip: &str,
        platform: &str,
        api_key: Option<&str>,
    ) -> Result<(), reqwest::Error> {
        let url = format!("{api_url}/api/v1/agents/register");
        let body = json!({
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "hostname": hostname,
            "os": platform,
            "version": "collector-detected",
            "ip": source_ip,
        });

        let mut req = client
            .post(&url)
            .header("x-tenant-id", tenant_id)
            .header("x-user-id", "cyberbox-collector")
            .header("x-roles", "ingestor");

        if let Some(key) = api_key {
            req = req.header("X-Api-Key", key);
        }

        let resp = req.json(&body).send().await?;

        let status = resp.status();
        if status.is_success() || status.as_u16() == 409 {
            Ok(())
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            warn!(
                %status, body = %body_text,
                "unexpected status from agent register"
            );
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

        let resp = req.send().await?;

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

/// Auto-detect platform/device type from hostname and syslog app_name.
fn detect_platform(hostname: &str, app_name: &str) -> String {
    let h = hostname.to_lowercase();
    let a = app_name.to_lowercase();

    // Firewall / network devices
    if a.contains("filterlog") || h.contains("opnsense") {
        return "firewall".to_string();
    }
    if h.contains("pfsense") || a.contains("pf") && a.contains("log") {
        return "firewall".to_string();
    }
    if h.contains("fortinet") || h.contains("fortigate") || a.contains("fortigate") {
        return "firewall".to_string();
    }
    if h.contains("paloalto") || h.contains("pan-os") || a.contains("threat") && a.contains("log") {
        return "firewall".to_string();
    }
    if h.contains("sophos") || h.contains("utm") || a.contains("sophosxg") {
        return "firewall".to_string();
    }
    if h.contains("mikrotik") || a.contains("routeros") {
        return "router".to_string();
    }
    if h.contains("unifi") || h.contains("ubnt") || a.contains("ubnt") {
        return "network".to_string();
    }

    // Windows
    if a.contains("cyberbox-agent") || a.contains("microsoft-windows") {
        return "windows".to_string();
    }
    if h.contains("server-") || h.contains("win-") || h.contains(".local") {
        return "windows".to_string();
    }
    if a.contains("mssql") || a.contains("iis") || a.contains("exchange") {
        return "windows".to_string();
    }

    // Linux
    if a.contains("sshd")
        || a.contains("sudo")
        || a.contains("systemd")
        || a.contains("cron")
        || a.contains("kernel")
    {
        return "linux".to_string();
    }
    if a.contains("nginx") || a.contains("apache") || a.contains("httpd") {
        return "linux".to_string();
    }
    if a.contains("docker") || a.contains("containerd") {
        return "linux".to_string();
    }

    // Generic syslog
    "syslog".to_string()
}
