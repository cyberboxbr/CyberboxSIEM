//! `agent.toml` configuration types.

use std::path::PathBuf;
use serde::Deserialize;

// ── Top-level ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    pub collector: CollectorConfig,
    pub agent:     AgentMeta,
    #[serde(default)]
    pub source:    Vec<SourceConfig>,
}

// ── Collector output ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct CollectorConfig {
    /// Hostname or IP of the collector
    pub host: String,

    /// TCP port (default: 7514 for JSON, 601 for syslog)
    #[serde(default = "default_port")]
    pub port: u16,

    /// Output wire format: `"json"` (NDJSON) or `"syslog"` (RFC3164)
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// Enable TLS (requires `--features tls` build)
    #[serde(default)]
    pub tls: bool,

    /// Optional CA certificate path to pin (PEM). When absent, native OS trust
    /// store is used (requires `--features tls`).
    pub tls_ca: Option<PathBuf>,

    /// Enrollment token sent as the first line on each new connection so the
    /// collector can authenticate agents:
    ///   `{"cyberbox_auth":{"token":"…","agent":"hostname","version":"0.1.0"}}`
    /// The collector silently ignores this line today — validation is a future
    /// feature. Set via config or `CYBERBOX_AGENT_TOKEN` env var.
    pub token: Option<String>,

    /// Reconnect backoff ceiling in seconds
    #[serde(default = "default_backoff_max")]
    pub backoff_max_secs: u64,

    /// In-memory ring buffer capacity (events) while offline
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_port()         -> u16    { 7514 }
fn default_protocol()     -> String { "json".into() }
fn default_backoff_max()  -> u64    { 30 }
fn default_buffer_size()  -> usize  { 10_000 }

// ── Agent identity ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct AgentMeta {
    /// Tenant ID forwarded with every event
    pub tenant_id: String,

    /// Override auto-detected hostname
    pub hostname: Option<String>,

    /// App-name used in syslog-mode RFC3164 messages
    #[serde(default = "default_app_name")]
    pub app_name: String,
}

fn default_app_name() -> String { "cyberbox-agent".into() }

// ── Sources ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceConfig {
    /// Tail one or more log files
    File {
        paths:         Vec<String>,
        #[serde(default = "default_poll_ms")]
        poll_ms:       u64,
        #[serde(default = "default_bookmark")]
        bookmark_path: String,
    },
    /// Windows Event Log channels (Windows only)
    Wineventlog {
        #[serde(default = "default_wel_channels")]
        channels: Vec<String>,
    },
    /// Linux systemd journal (via `journalctl`)
    Journald {
        /// Filter to specific units (empty = all)
        #[serde(default)]
        #[allow(dead_code)]  // used on Linux only
        units: Vec<String>,
    },
}

fn default_poll_ms() -> u64 { 500 }
fn default_bookmark() -> String { "cyberbox-agent.bookmark.json".into() }
fn default_wel_channels() -> Vec<String> {
    vec!["Security".into(), "System".into(), "Application".into()]
}

// ── Load from file ────────────────────────────────────────────────────────────

pub fn load(path: &std::path::Path) -> anyhow::Result<AgentConfig> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", path.display()))?;
    toml::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("invalid config {}: {e}", path.display()))
}
