//! Auto-registration of syslog sources as agents in the CyberboxSIEM API.
//!
//! When the collector receives syslog messages from a device, the
//! [`SourceRegistry`] records the hostname and source IP. A background task
//! periodically registers new sources via `POST /api/v1/agents/register` and
//! sends heartbeats for all known sources, so they appear in the Agent Fleet
//! page alongside real agents.
//!
//! Platform detection uses an evidence-scoring system that accumulates signals
//! from multiple syslog messages (app_name, message content, hostname patterns)
//! and picks the platform with the highest confidence after enough evidence.

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

/// Minimum evidence score before we lock in a platform detection.
const CONFIDENCE_THRESHOLD: i32 = 3;

// ── Platform scoring ─────────────────────────────────────────────────────────

#[derive(Default)]
struct PlatformScores {
    windows: i32,
    linux: i32,
    firewall: i32,
    router: i32,
    network: i32,
    macos: i32,
    messages_seen: u32,
    locked: bool,
}

impl PlatformScores {
    fn best(&self) -> &'static str {
        let candidates = [
            (self.firewall, "firewall"),
            (self.router, "router"),
            (self.network, "network"),
            (self.windows, "windows"),
            (self.linux, "linux"),
            (self.macos, "macos"),
        ];
        candidates
            .iter()
            .max_by_key(|(score, _)| *score)
            .filter(|(score, _)| *score > 0)
            .map(|(_, name)| *name)
            .unwrap_or("syslog")
    }

    fn is_confident(&self) -> bool {
        let best_score = [
            self.windows,
            self.linux,
            self.firewall,
            self.router,
            self.network,
            self.macos,
        ]
        .into_iter()
        .max()
        .unwrap_or(0);
        best_score >= CONFIDENCE_THRESHOLD
    }

    /// Ingest evidence from one syslog message.
    fn observe(&mut self, hostname: &str, app_name: &str, message: &str) {
        if self.locked {
            return;
        }
        self.messages_seen += 1;

        let h = hostname.to_lowercase();
        let a = app_name.to_lowercase();
        let m_lower;
        // Only lowercase message if we need it (avoid allocation on hot path)
        let m = if message.len() < 4096 {
            m_lower = message.to_lowercase();
            m_lower.as_str()
        } else {
            m_lower = message[..4096].to_lowercase();
            m_lower.as_str()
        };

        // ── Firewall / network device signals ────────────────────────
        if a == "filterlog" {
            self.firewall += 10;
        }
        if h.contains("opnsense") || h.contains("pfsense") {
            self.firewall += 10;
        }
        if a.contains("fortigate") || h.contains("fortinet") || h.contains("fortigate") {
            self.firewall += 10;
        }
        if h.contains("paloalto") || h.contains("pan-os") {
            self.firewall += 10;
        }
        if h.contains("sophos") || a.contains("sophosxg") {
            self.firewall += 10;
        }
        if h.contains("mikrotik") || a.contains("routeros") {
            self.router += 10;
        }
        if h.contains("unifi") || h.contains("ubnt") || a.contains("ubnt") {
            self.network += 10;
        }
        if a.contains("haproxy") || a.contains("keepalived") {
            self.network += 3;
        }
        // Cisco
        if h.contains("cisco") || a.contains("cisco") || a == "%asa" || a == "%fwsm" {
            self.firewall += 10;
        }
        if m.contains("%asa-") || m.contains("%fwsm-") || m.contains("%pix-") {
            self.firewall += 8;
        }
        if m.contains("%sec-") || m.contains("%sys-") || m.contains("%link-") {
            self.network += 5;
        }
        if a.contains("ios") && (m.contains("%") || h.contains("switch") || h.contains("router")) {
            self.network += 5;
        }
        // Juniper
        if h.contains("juniper") || h.contains("junos") || a.contains("junos") {
            self.firewall += 8;
        }
        if m.contains("rt_flow") || m.contains("rt_ids") {
            self.firewall += 6;
        }
        // Check Point
        if a.contains("checkpoint") || m.contains("smartdefense") || m.contains("fw-1") {
            self.firewall += 8;
        }
        // WatchGuard
        if h.contains("watchguard") || a.contains("watchguard") || m.contains("firebox") {
            self.firewall += 8;
        }

        // ── Windows signals (strong) ─────────────────────────────────
        if a.contains("microsoft-windows") {
            self.windows += 10;
        }
        if m.contains("microsoft-windows-sysmon") {
            self.windows += 10;
        }
        if m.contains("eventid") && (m.contains("security") || m.contains("system")) {
            self.windows += 5;
        }
        if m.contains("c:\\") || m.contains("\\windows\\") {
            self.windows += 4;
        }
        if a.contains("mssql") || a.contains("iis") || a.contains("exchange") {
            self.windows += 8;
        }
        if a.contains("winlogbeat") || a.contains("nxlog") {
            self.windows += 8;
        }
        if m.contains("powershell") || m.contains("cmd.exe") || m.contains(".exe") {
            self.windows += 2;
        }

        // ── Windows signals (hostname hints) ─────────────────────────
        if h.contains("win-") || h.contains("desktop-") {
            self.windows += 3;
        }
        if h.ends_with(".local") {
            self.windows += 1; // weak — macOS also uses .local
            self.macos += 1;
        }

        // ── Linux signals (strong) ───────────────────────────────────
        if a == "sshd" || a == "sudo" || a == "su" {
            self.linux += 5;
        }
        if a == "systemd" || a.starts_with("systemd-") {
            self.linux += 8;
        }
        if a == "cron" || a == "crond" || a == "anacron" {
            self.linux += 5;
        }
        if a == "kernel" || a.starts_with("kernel:") {
            self.linux += 5;
        }
        if a.contains("auditd") || a == "audit" {
            self.linux += 6;
        }
        if a == "nginx" || a == "apache2" || a == "httpd" {
            self.linux += 3;
        }
        if a == "docker" || a == "containerd" || a == "podman" {
            self.linux += 4;
        }
        if a == "kubelet" || a == "kube-apiserver" || a == "kube-proxy" || a == "etcd" {
            self.linux += 6;
        }
        if m.contains("kubernetes") || m.contains("k8s.io/") || m.contains("kube-system") {
            self.linux += 3;
        }
        if a == "calico" || a == "cilium" || a == "flannel" || a == "coredns" {
            self.linux += 4;
        }
        if a == "postfix" || a.contains("dovecot") || a == "rsyslogd" {
            self.linux += 4;
        }
        if m.contains("/var/log/") || m.contains("/etc/") || m.contains("/usr/") {
            self.linux += 3;
        }
        if m.contains("\x1b[") || m.contains("\\033[") {
            // ANSI escape codes — typical of Linux agent/app logs
            self.linux += 2;
        }

        // ── macOS signals ────────────────────────────────────────────
        if a == "sandboxd" || a == "loginwindow" || a.contains("coreaudio") {
            self.macos += 8;
        }
        if m.contains("com.apple.") {
            self.macos += 5;
        }

        // ── cyberbox-agent — neutral, check message for hints ────────
        if a == "cyberbox-agent" {
            // The agent itself is cross-platform; look at message content
            if m.contains("windows") || m.contains(".exe") || m.contains("sysmon") {
                self.windows += 2;
            }
            if m.contains("linux") || m.contains("/var/") || m.contains("systemd") {
                self.linux += 2;
            }
            // If hostname looks like a Windows server name
            if h.starts_with("server-") || h.starts_with("win-") || h.starts_with("desktop-") {
                self.windows += 2;
            }
        }

        // Lock after enough evidence
        if self.messages_seen >= 5 && self.is_confident() {
            self.locked = true;
        }
    }
}

// ── Source entry ──────────────────────────────────────────────────────────────

/// Per-source bookkeeping entry.
struct SourceEntry {
    source_ip: String,
    #[allow(dead_code)]
    first_seen: Instant,
    last_seen: Instant,
    registered: bool,
    scores: PlatformScores,
}

impl SourceEntry {
    fn platform(&self) -> &'static str {
        self.scores.best()
    }
}

// ── Source registry ──────────────────────────────────────────────────────────

/// Lock-free registry of syslog sources observed by the collector.
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

    /// Record a syslog message. Called on every parsed message — must be non-blocking.
    pub fn observe(&self, source_ip: &str, hostname: &str, app_name: &str, message: &str) {
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
                e.scores.observe(hostname, app_name, message);
            })
            .or_insert_with(|| {
                let mut scores = PlatformScores::default();
                scores.observe(hostname, app_name, message);
                SourceEntry {
                    source_ip: source_ip.to_string(),
                    first_seen: now,
                    last_seen: now,
                    registered: false,
                    scores,
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

        let entries: Vec<(String, String, String, bool, bool)> = self
            .sources
            .iter()
            .map(|entry| {
                let hostname = entry.key().clone();
                let source_ip = entry.value().source_ip.clone();
                let platform = entry.value().platform().to_string();
                let registered = entry.value().registered;
                let stale = now.duration_since(entry.value().last_seen) > STALE_AFTER;
                (hostname, source_ip, platform, registered, stale)
            })
            .collect();

        for (hostname, source_ip, platform, registered, stale) in entries {
            let agent_id = format!("syslog-{hostname}");

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
    ) -> Result<(), String> {
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

        let resp = req.json(&body).send().await.map_err(|e| e.to_string())?;

        let status = resp.status();
        if status.is_success() || status.as_u16() == 409 {
            Ok(())
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            let msg = format!("register returned {status}: {body_text}");
            warn!(agent_id, hostname, error = %msg, "agent register failed — will retry next tick");
            Err(msg)
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
