/// Lightweight JSON-file persistence for in-memory state that must survive restarts.
///
/// Saves/loads two files under `state_dir`:
///   - `threat_intel_feeds.json` — feed configurations
///   - `rbac_store.json`         — per-tenant RBAC overrides
///
/// All operations are best-effort: failures are logged as warnings and never panic.
use std::collections::HashMap;
use std::path::Path;

use dashmap::DashMap;
use uuid::Uuid;

use cyberbox_auth::Role;
use cyberbox_core::threatintel::ThreatIntelFeed;

const FEEDS_FILE: &str = "threat_intel_feeds.json";
const RBAC_FILE: &str = "rbac_store.json";

// ── Feeds ─────────────────────────────────────────────────────────────────────

/// Persist all feed configs to `<state_dir>/threat_intel_feeds.json`.
pub fn save_feeds(feeds: &DashMap<Uuid, ThreatIntelFeed>, state_dir: &str) {
    if state_dir.is_empty() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(state_dir) {
        tracing::warn!(error = %e, dir = state_dir, "persist: cannot create state dir");
        return;
    }
    let path = Path::new(state_dir).join(FEEDS_FILE);
    let data: Vec<ThreatIntelFeed> = feeds.iter().map(|e| e.value().clone()).collect();
    match serde_json::to_string_pretty(&data) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!(error = %e, ?path, "persist: failed to write feeds file");
            }
        }
        Err(e) => tracing::warn!(error = %e, "persist: failed to serialize feeds"),
    }
}

/// Load feed configs from `<state_dir>/threat_intel_feeds.json` into `feeds`.
pub fn load_feeds(feeds: &DashMap<Uuid, ThreatIntelFeed>, state_dir: &str) {
    if state_dir.is_empty() {
        return;
    }
    let path = Path::new(state_dir).join(FEEDS_FILE);
    if !path.exists() {
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(json) => match serde_json::from_str::<Vec<ThreatIntelFeed>>(&json) {
            Ok(items) => {
                let count = items.len();
                for feed in items {
                    feeds.insert(feed.feed_id, feed);
                }
                tracing::info!(count, "persist: loaded threat intel feeds");
            }
            Err(e) => tracing::warn!(error = %e, "persist: failed to parse feeds file"),
        },
        Err(e) => tracing::warn!(error = %e, "persist: failed to read feeds file"),
    }
}

// ── RBAC ──────────────────────────────────────────────────────────────────────

/// Persist all RBAC overrides to `<state_dir>/rbac_store.json`.
pub fn save_rbac(store: &DashMap<String, Vec<Role>>, state_dir: &str) {
    if state_dir.is_empty() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(state_dir) {
        tracing::warn!(error = %e, dir = state_dir, "persist: cannot create state dir");
        return;
    }
    let path = Path::new(state_dir).join(RBAC_FILE);
    let data: HashMap<String, Vec<Role>> =
        store.iter().map(|e| (e.key().clone(), e.value().clone())).collect();
    match serde_json::to_string_pretty(&data) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!(error = %e, ?path, "persist: failed to write rbac file");
            }
        }
        Err(e) => tracing::warn!(error = %e, "persist: failed to serialize rbac store"),
    }
}

/// Load RBAC overrides from `<state_dir>/rbac_store.json` into `store`.
pub fn load_rbac(store: &DashMap<String, Vec<Role>>, state_dir: &str) {
    if state_dir.is_empty() {
        return;
    }
    let path = Path::new(state_dir).join(RBAC_FILE);
    if !path.exists() {
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(json) => match serde_json::from_str::<HashMap<String, Vec<Role>>>(&json) {
            Ok(items) => {
                let count = items.len();
                for (key, roles) in items {
                    store.insert(key, roles);
                }
                tracing::info!(count, "persist: loaded RBAC assignments");
            }
            Err(e) => tracing::warn!(error = %e, "persist: failed to parse rbac file"),
        },
        Err(e) => tracing::warn!(error = %e, "persist: failed to read rbac file"),
    }
}
