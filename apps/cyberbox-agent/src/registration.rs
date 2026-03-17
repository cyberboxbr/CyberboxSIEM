//! Agent enrollment, registration, heartbeat, and credential rotation with
//! cyberbox-api.
//!
//! The agent uses a one-time enrollment token to obtain a rotating machine
//! credential and signed device certificate, then authenticates register /
//! heartbeat / rotate-secret calls with `x-agent-id`, `x-tenant-id`,
//! `x-agent-secret`, and `x-agent-cert` headers.
//!
//! All requests are best-effort: failures are logged but do not stop the agent.

use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use tokio::sync::watch;
use tracing::{error, info, warn};

pub struct RegistrationConfig {
    pub api_url: String,
    pub token: Option<String>,
    pub enrollment_token: Option<String>,
    pub agent_secret: Option<String>,
    pub device_certificate: Option<String>,
    pub heartbeat_secs: u64,
    pub credential_rotation_secs: u64,
    /// Used as a stable agent identifier (UUID or hostname-based string)
    pub agent_id: String,
    pub hostname: String,
    pub tenant_id: String,
    pub version: String,
    /// Path of the active agent.toml - used to write pending config updates.
    pub config_path: std::path::PathBuf,
    /// Notify main loop that config has been updated and should be reloaded.
    pub reload_tx: Option<watch::Sender<bool>>,
}

#[derive(Debug, Deserialize)]
struct EnrollResponse {
    agent_secret: String,
    device_certificate: Option<String>,
    credential_version: u64,
}

#[derive(Debug, Deserialize)]
struct RotateResponse {
    agent_secret: String,
    device_certificate: Option<String>,
    credential_version: u64,
}

#[derive(Debug, Clone)]
struct MachineCredentials {
    agent_secret: String,
    device_certificate: String,
}

pub async fn run(cfg: RegistrationConfig, mut shutdown: watch::Receiver<bool>) {
    if cfg.token.is_some() {
        warn!("api.token is deprecated for agent control-plane auth and is ignored");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let os = std::env::consts::OS.to_string();
    let mut credentials = match ensure_agent_credentials(&client, &cfg, &os).await {
        Some(credentials) => credentials,
        None => {
            warn!("agent API configured but no machine credential is available");
            return;
        }
    };
    let mut last_rotation = Instant::now();

    let reg_url = format!(
        "{}/api/v1/agents/register",
        cfg.api_url.trim_end_matches('/')
    );
    let hb_url = format!(
        "{}/api/v1/agents/{}/heartbeat",
        cfg.api_url.trim_end_matches('/'),
        cfg.agent_id,
    );
    let rotate_url = format!(
        "{}/api/v1/agents/{}/rotate-secret",
        cfg.api_url.trim_end_matches('/'),
        cfg.agent_id,
    );
    let register_body = json!({
        "agent_id":  cfg.agent_id,
        "tenant_id": cfg.tenant_id,
        "hostname":  cfg.hostname,
        "os":        os,
        "version":   cfg.version,
    });

    if register_agent_with_secret(&client, &cfg, &reg_url, &register_body, &credentials)
        .await
        .is_err()
    {
        warn!("agent registration failed - continuing without API tracking");
    }

    let interval = Duration::from_secs(cfg.heartbeat_secs.max(5));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {}
        }

        if cfg.credential_rotation_secs > 0
            && last_rotation.elapsed() >= Duration::from_secs(cfg.credential_rotation_secs)
        {
            if let Some(rotated) =
                rotate_machine_secret(&client, &cfg, &rotate_url, &credentials).await
            {
                credentials = rotated;
                last_rotation = Instant::now();
            }
        }

        let req = with_machine_auth(client.post(&hb_url), &cfg, &credentials);
        match req.send().await {
            Err(err) => error!(%err, "heartbeat failed"),
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                warn!("heartbeat returned 404 - re-registering agent");
                let _ = register_agent_with_secret(
                    &client,
                    &cfg,
                    &reg_url,
                    &register_body,
                    &credentials,
                )
                .await;
            }
            Ok(resp)
                if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                    || resp.status() == reqwest::StatusCode::FORBIDDEN =>
            {
                warn!(status = %resp.status(), "heartbeat rejected - machine credential may be invalid or revoked");
            }
            Ok(resp) => {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(toml_str) = body.get("pending_config").and_then(|v| v.as_str()) {
                        apply_pending_config(toml_str, &cfg.config_path, &cfg.reload_tx);
                    }
                    if let Some(ver) = body.get("latest_version").and_then(|v| v.as_str()) {
                        if crate::updater::is_newer(env!("CARGO_PKG_VERSION"), ver) {
                            info!(
                                latest = ver,
                                "newer version available -- attempting self-update"
                            );
                            match crate::updater::self_update(ver).await {
                                Ok(true) => info!(ver, "self-update complete -- restart to apply"),
                                Ok(false) => {}
                                Err(err) => warn!(%err, "self-update failed"),
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn ensure_agent_credentials(
    client: &reqwest::Client,
    cfg: &RegistrationConfig,
    os: &str,
) -> Option<MachineCredentials> {
    if let (Some(agent_secret), Some(device_certificate)) = (
        cfg.agent_secret.clone(),
        cfg.device_certificate.clone(),
    ) {
        return Some(MachineCredentials {
            agent_secret,
            device_certificate,
        });
    }

    let enrollment_token = match cfg.enrollment_token.clone() {
        Some(token) => token,
        None => {
            warn!(
                "api.agent_secret / api.device_certificate are incomplete and no api.enrollment_token was provided"
            );
            return None;
        }
    };

    let enroll_url = format!("{}/api/v1/agents/enroll", cfg.api_url.trim_end_matches('/'));
    let body = json!({
        "enrollment_token": enrollment_token,
        "agent_id": cfg.agent_id,
        "tenant_id": cfg.tenant_id,
        "hostname": cfg.hostname,
        "os": os,
        "version": cfg.version,
    });

    match client.post(&enroll_url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<EnrollResponse>().await {
            Ok(enrolled) => {
                let Some(device_certificate) = enrolled.device_certificate else {
                    warn!("enrollment succeeded but response omitted device_certificate");
                    return None;
                };
                info!(
                    agent_id = %cfg.agent_id,
                    credential_version = enrolled.credential_version,
                    "agent enrolled with API"
                );
                let credentials = MachineCredentials {
                    agent_secret: enrolled.agent_secret,
                    device_certificate,
                };
                persist_agent_credentials(&cfg.config_path, &credentials);
                Some(credentials)
            }
            Err(err) => {
                warn!(%err, "enrollment succeeded but response body could not be parsed");
                None
            }
        },
        Ok(resp) => {
            warn!(status = %resp.status(), "agent enrollment returned non-2xx");
            None
        }
        Err(err) => {
            warn!(%err, "agent enrollment request failed");
            None
        }
    }
}

async fn register_agent_with_secret(
    client: &reqwest::Client,
    cfg: &RegistrationConfig,
    reg_url: &str,
    body: &serde_json::Value,
    credentials: &MachineCredentials,
) -> Result<(), ()> {
    let req = with_machine_auth(client.post(reg_url).json(body), cfg, credentials);
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            info!(agent_id = %cfg.agent_id, "agent registered with API");
            Ok(())
        }
        Ok(resp) => {
            warn!(status = %resp.status(), "agent registration returned non-2xx");
            Err(())
        }
        Err(err) => {
            warn!(%err, "agent registration request failed");
            Err(())
        }
    }
}

async fn rotate_machine_secret(
    client: &reqwest::Client,
    cfg: &RegistrationConfig,
    rotate_url: &str,
    credentials: &MachineCredentials,
) -> Option<MachineCredentials> {
    let req = with_machine_auth(client.post(rotate_url), cfg, credentials);
    match req.send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<RotateResponse>().await {
            Ok(rotated) => {
                let Some(device_certificate) = rotated.device_certificate else {
                    warn!("credential rotation succeeded but response omitted device_certificate");
                    return None;
                };
                info!(
                    agent_id = %cfg.agent_id,
                    credential_version = rotated.credential_version,
                    "agent machine credential rotated"
                );
                let credentials = MachineCredentials {
                    agent_secret: rotated.agent_secret,
                    device_certificate,
                };
                persist_agent_credentials(&cfg.config_path, &credentials);
                Some(credentials)
            }
            Err(err) => {
                warn!(%err, "credential rotation succeeded but response body could not be parsed");
                None
            }
        },
        Ok(resp) => {
            warn!(status = %resp.status(), "credential rotation returned non-2xx");
            None
        }
        Err(err) => {
            warn!(%err, "credential rotation request failed");
            None
        }
    }
}

fn with_machine_auth(
    req: reqwest::RequestBuilder,
    cfg: &RegistrationConfig,
    credentials: &MachineCredentials,
) -> reqwest::RequestBuilder {
    req.header("x-agent-id", &cfg.agent_id)
        .header("x-tenant-id", &cfg.tenant_id)
        .header("x-agent-secret", &credentials.agent_secret)
        .header("x-agent-cert", &credentials.device_certificate)
}

fn persist_agent_credentials(config_path: &std::path::Path, credentials: &MachineCredentials) {
    let raw = match std::fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(err) => {
            warn!(path = %config_path.display(), %err, "failed to read config for secret persistence");
            return;
        }
    };

    // Use targeted string manipulation so that comments and formatting are
    // preserved (toml::to_string_pretty would strip them).
    let rendered = upsert_api_credentials(
        &raw,
        &credentials.agent_secret,
        &credentials.device_certificate,
    );

    // Atomic write: write to a temp file next to the target, then rename.
    let tmp_path = config_path.with_extension("toml.tmp");
    if let Err(err) = std::fs::write(&tmp_path, &rendered) {
        warn!(path = %tmp_path.display(), %err, "failed to write tmp config for secret persistence");
        return;
    }
    if let Err(err) = std::fs::rename(&tmp_path, config_path) {
        warn!(path = %config_path.display(), %err, "failed to rename tmp config into place");
        // Best-effort cleanup of the orphaned tmp file.
        let _ = std::fs::remove_file(&tmp_path);
    }
}

/// Insert or update `agent_secret` and `device_certificate` inside the `[api]`
/// section of a TOML config string **without** full parse/reserialize, so that
/// comments and whitespace are preserved.
fn upsert_api_credentials(raw: &str, agent_secret: &str, device_certificate: &str) -> String {
    // Escape the values for TOML string literals (handle backslashes and quotes).
    let secret_line = format!("agent_secret = \"{}\"", toml_escape(agent_secret));
    let cert_line = format!("device_certificate = \"{}\"", toml_escape(device_certificate));

    // Find the `[api]` section header.
    let lines: Vec<&str> = raw.lines().collect();
    let api_header_idx = lines.iter().position(|line| {
        let trimmed = line.trim();
        trimmed == "[api]"
    });

    match api_header_idx {
        Some(header_idx) => {
            // Determine the range of lines belonging to the [api] section (up to
            // the next section header or EOF).
            let section_end = lines
                .iter()
                .enumerate()
                .skip(header_idx + 1)
                .find_map(|(i, line)| {
                    let trimmed = line.trim();
                    if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
                        Some(i)
                    } else {
                        None
                    }
                })
                .unwrap_or(lines.len());

            // Rebuild the section: keep non-target lines, upsert our two keys.
            let mut result_lines: Vec<String> = Vec::with_capacity(lines.len() + 2);

            // Lines before and including [api] header.
            for line in &lines[..=header_idx] {
                result_lines.push(line.to_string());
            }

            let mut wrote_secret = false;
            let mut wrote_cert = false;

            for line in &lines[header_idx + 1..section_end] {
                let trimmed = line.trim();
                if trimmed.starts_with("agent_secret") && trimmed.contains('=') {
                    result_lines.push(secret_line.clone());
                    wrote_secret = true;
                } else if trimmed.starts_with("device_certificate") && trimmed.contains('=') {
                    result_lines.push(cert_line.clone());
                    wrote_cert = true;
                } else {
                    result_lines.push(line.to_string());
                }
            }

            // Append any keys we didn't replace.
            if !wrote_secret {
                result_lines.push(secret_line);
            }
            if !wrote_cert {
                result_lines.push(cert_line);
            }

            // Remaining lines (next sections).
            for line in &lines[section_end..] {
                result_lines.push(line.to_string());
            }

            let mut out = result_lines.join("\n");
            // Preserve the original trailing newline if present.
            if raw.ends_with('\n') && !out.ends_with('\n') {
                out.push('\n');
            }
            out
        }
        None => {
            // No [api] section exists — append one.
            let mut out = raw.to_string();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
            out.push_str("[api]\n");
            out.push_str(&secret_line);
            out.push('\n');
            out.push_str(&cert_line);
            out.push('\n');
            out
        }
    }
}

/// Escape a string value for embedding inside TOML double quotes.
fn toml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Write a pending config to disk and signal a live reload if the watch
/// channel is available.  Uses write-to-temp-then-rename for atomicity.
fn apply_pending_config(
    toml_str: &str,
    config_path: &std::path::Path,
    reload_tx: &Option<watch::Sender<bool>>,
) {
    let tmp_path = config_path.with_extension("toml.tmp");
    if let Err(err) = std::fs::write(&tmp_path, toml_str) {
        error!(path = %tmp_path.display(), %err, "failed to write tmp pending config");
        return;
    }
    match std::fs::rename(&tmp_path, config_path) {
        Ok(()) => {
            info!(path = %config_path.display(), "pending config written to disk");
            if let Some(tx) = reload_tx {
                let _ = tx.send(true);
                info!("signalled live config reload");
            }
        }
        Err(err) => {
            error!(path = %config_path.display(), %err, "failed to rename tmp pending config into place");
            let _ = std::fs::remove_file(&tmp_path);
        }
    }
}
