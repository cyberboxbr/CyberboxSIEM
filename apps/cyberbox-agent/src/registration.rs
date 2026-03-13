//! Agent registration and heartbeat with cyberbox-api.
//!
//! On startup, sends `POST /api/v1/agents/register` to identify this agent.
//! Then loops every `heartbeat_secs` sending `POST /api/v1/agents/:id/heartbeat`
//! so the API can track which agents are active/stale/offline.
//!
//! All requests are best-effort: failures are logged but do not stop the agent.

use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{error, info, warn};

pub struct RegistrationConfig {
    pub api_url: String,
    pub token: Option<String>,
    pub heartbeat_secs: u64,
    /// Used as a stable agent identifier (UUID or hostname-based string)
    pub agent_id: String,
    pub hostname: String,
    pub tenant_id: String,
    pub version: String,
    /// Path of the active agent.toml — used to write pending config updates.
    pub config_path: std::path::PathBuf,
    /// Notify main loop that config has been updated and should be reloaded.
    pub reload_tx: Option<watch::Sender<bool>>,
}

pub async fn run(cfg: RegistrationConfig, mut shutdown: watch::Receiver<bool>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let os = std::env::consts::OS.to_string();

    // ── Register ──────────────────────────────────────────────────────────────
    let reg_url = format!(
        "{}/api/v1/agents/register",
        cfg.api_url.trim_end_matches('/')
    );
    let body = json!({
        "agent_id":  cfg.agent_id,
        "tenant_id": cfg.tenant_id,
        "hostname":  cfg.hostname,
        "os":        os,
        "version":   cfg.version,
    });

    let mut req = client.post(&reg_url).json(&body);
    if let Some(ref tok) = cfg.token {
        req = req.bearer_auth(tok);
    }
    match req.send().await {
        Ok(r) if r.status().is_success() => {
            info!(agent_id = %cfg.agent_id, "agent registered with API");
        }
        Ok(r) => {
            warn!(status = %r.status(), "agent registration returned non-2xx — continuing");
        }
        Err(e) => {
            warn!(%e, "agent registration failed — continuing without API tracking");
        }
    }

    // ── Heartbeat loop ────────────────────────────────────────────────────────
    let hb_url = format!(
        "{}/api/v1/agents/{}/heartbeat",
        cfg.api_url.trim_end_matches('/'),
        cfg.agent_id,
    );
    let interval = Duration::from_secs(cfg.heartbeat_secs.max(5));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {}
        }

        let mut req = client.post(&hb_url);
        if let Some(ref tok) = cfg.token {
            req = req.bearer_auth(tok);
        }
        match req.send().await {
            Err(e) => error!(%e, "heartbeat failed"),
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                // Agent unknown after API restart — re-register
                warn!("heartbeat returned 404 — re-registering agent");
                let mut rr = client.post(&reg_url).json(&body);
                if let Some(ref tok) = cfg.token {
                    rr = rr.bearer_auth(tok);
                }
                match rr.send().await {
                    Ok(r) if r.status().is_success() => {
                        info!(agent_id = %cfg.agent_id, "agent re-registered after 404");
                    }
                    Ok(r) => warn!(status = %r.status(), "re-registration failed"),
                    Err(e) => warn!(%e, "re-registration request failed"),
                }
            }
            Ok(resp) => {
                // Check for queued config delivery
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    // Config push from API
                    if let Some(toml_str) = body.get("pending_config").and_then(|v| v.as_str()) {
                        apply_pending_config(toml_str, &cfg.config_path, &cfg.reload_tx);
                    }
                    // Self-update check
                    if let Some(ver) = body.get("latest_version").and_then(|v| v.as_str()) {
                        if crate::updater::is_newer(env!("CARGO_PKG_VERSION"), ver) {
                            info!(
                                latest = ver,
                                "newer version available -- attempting self-update"
                            );
                            match crate::updater::self_update(ver).await {
                                Ok(true) => info!(ver, "self-update complete -- restart to apply"),
                                Ok(false) => {}
                                Err(e) => warn!(%e, "self-update failed"),
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Write a pending config to disk and signal a live reload if the watch
/// channel is available.
fn apply_pending_config(
    toml_str: &str,
    config_path: &std::path::Path,
    reload_tx: &Option<watch::Sender<bool>>,
) {
    match std::fs::write(config_path, toml_str) {
        Ok(()) => {
            info!(path = %config_path.display(), "pending config written to disk");
            if let Some(tx) = reload_tx {
                let _ = tx.send(true);
                info!("signalled live config reload");
            }
        }
        Err(e) => {
            error!(path = %config_path.display(), %e, "failed to write pending config");
        }
    }
}
