//! HashiCorp Vault secret loader.
//!
//! On collector startup, fetches secrets from one or more Vault KV v2 paths
//! and injects them as environment variables. This replaces hard-coded
//! credentials in `COLLECTOR_*` env vars with Vault-managed secrets.
//!
//! # Authentication
//!
//! | Method | Variables |
//! |---|---|
//! | Static token | `COLLECTOR_VAULT_TOKEN` |
//! | AppRole | `COLLECTOR_VAULT_ROLE_ID` + `COLLECTOR_VAULT_SECRET_ID` |
//!
//! # Configuration
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `COLLECTOR_VAULT_ADDR` | *(empty)* | Vault server URL — set to enable |
//! | `COLLECTOR_VAULT_TOKEN` | *(empty)* | Static Vault token |
//! | `COLLECTOR_VAULT_ROLE_ID` | *(empty)* | AppRole role_id |
//! | `COLLECTOR_VAULT_SECRET_ID` | *(empty)* | AppRole secret_id |
//! | `COLLECTOR_VAULT_MOUNT` | `secret` | KV v2 mount path |
//! | `COLLECTOR_VAULT_PATHS` | *(empty)* | Comma-separated KV secret paths to load |
//! | `COLLECTOR_VAULT_NAMESPACE` | *(empty)* | Enterprise namespace header |

use anyhow::{bail, Context, Result};
use tracing::{debug, info, warn};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Load secrets from Vault and inject them as process environment variables.
/// Returns immediately (no-op) when `COLLECTOR_VAULT_ADDR` is not set.
pub async fn load_secrets(client: &reqwest::Client) -> Result<()> {
    let addr = match std::env::var("COLLECTOR_VAULT_ADDR")
        .ok()
        .filter(|s| !s.is_empty())
    {
        Some(a) => a,
        None => return Ok(()), // Vault not configured
    };

    let paths_raw = std::env::var("COLLECTOR_VAULT_PATHS").unwrap_or_default();
    let paths: Vec<&str> = paths_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if paths.is_empty() {
        warn!("COLLECTOR_VAULT_ADDR is set but COLLECTOR_VAULT_PATHS is empty — nothing to load");
        return Ok(());
    }

    let mount = std::env::var("COLLECTOR_VAULT_MOUNT").unwrap_or_else(|_| "secret".into());
    let namespace = std::env::var("COLLECTOR_VAULT_NAMESPACE")
        .ok()
        .filter(|s| !s.is_empty());

    // Authenticate
    let token = authenticate(client, &addr, namespace.as_deref())
        .await
        .context("Vault authentication failed")?;

    info!(addr, paths = paths.len(), "loading secrets from Vault");

    // Load each path
    let mut loaded = 0usize;
    for path in paths {
        match read_kv2(client, &addr, &mount, path, &token, namespace.as_deref()).await {
            Ok(secrets) => {
                for (k, v) in &secrets {
                    // Safety: only set vars whose keys look like valid env var names
                    if k.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        // SAFETY: single-threaded at startup; no other threads read env yet
                        unsafe {
                            std::env::set_var(k, v);
                        }
                        debug!(key = k, "secret injected");
                        loaded += 1;
                    }
                }
            }
            Err(err) => warn!(path, %err, "failed to read Vault secret"),
        }
    }

    info!(loaded, "Vault secrets loaded");
    Ok(())
}

// ─── Authentication ───────────────────────────────────────────────────────────

async fn authenticate(
    client: &reqwest::Client,
    addr: &str,
    namespace: Option<&str>,
) -> Result<String> {
    // Static token
    if let Some(tok) = std::env::var("COLLECTOR_VAULT_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return Ok(tok);
    }

    // AppRole
    let role_id = std::env::var("COLLECTOR_VAULT_ROLE_ID").unwrap_or_default();
    let secret_id = std::env::var("COLLECTOR_VAULT_SECRET_ID").unwrap_or_default();

    if role_id.is_empty() {
        bail!("no Vault credentials: set COLLECTOR_VAULT_TOKEN or COLLECTOR_VAULT_ROLE_ID + COLLECTOR_VAULT_SECRET_ID");
    }

    let url = format!("{addr}/v1/auth/approle/login");
    let body = serde_json::json!({ "role_id": role_id, "secret_id": secret_id });

    let mut req = client.post(&url).json(&body);
    if let Some(ns) = namespace {
        req = req.header("X-Vault-Namespace", ns);
    }

    let resp: serde_json::Value = req.send().await?.error_for_status()?.json().await?;

    resp["auth"]["client_token"]
        .as_str()
        .map(|s| s.to_string())
        .context("Vault AppRole response missing auth.client_token")
}

// ─── KV v2 read ───────────────────────────────────────────────────────────────

async fn read_kv2(
    client: &reqwest::Client,
    addr: &str,
    mount: &str,
    path: &str,
    token: &str,
    namespace: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let url = format!("{addr}/v1/{mount}/data/{path}");

    let mut req = client.get(&url).header("X-Vault-Token", token);
    if let Some(ns) = namespace {
        req = req.header("X-Vault-Namespace", ns);
    }

    let resp: serde_json::Value = req.send().await?.error_for_status()?.json().await?;

    let data = resp
        .get("data")
        .and_then(|d| d.get("data"))
        .and_then(|d| d.as_object())
        .context("unexpected Vault KV v2 response shape")?;

    let pairs = data
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect();

    Ok(pairs)
}
