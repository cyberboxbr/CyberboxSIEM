//! STIX/TAXII 2.1 threat intelligence feed ingestion.
//!
//! Downloads STIX bundles from TAXII 2.1 collection endpoints and extracts
//! Indicator objects into named lookup tables for use with the `|lookup` Sigma
//! modifier.
//!
//! ## Supported STIX indicator patterns
//!
//! | Pattern | Extracted value | Example |
//! |---------|-----------------|---------|
//! | `[ipv4-addr:value = 'X.X.X.X']` | IPv4 address | `1.2.3.4` |
//! | `[ipv6-addr:value = 'X::X']` | IPv6 address | `2001:db8::1` |
//! | `[domain-name:value = 'evil.com']` | Domain name | `evil.com` |
//! | `[url:value = 'http://...']` | URL | `http://evil.com/c2` |
//! | `[file:hashes.MD5 = 'abc...']` | File hash | `abc123...` |
//! | `[file:hashes.'SHA-256' = '...']` | File hash | `sha256...` |
//!
//! Multiple patterns of the same type are merged into a single lookup table.
//!
//! ## Usage
//! ```no_run
//! use cyberbox_core::threatintel::{ThreatIntelFeed, FeedSyncResult};
//! use cyberbox_core::LookupStore;
//! use std::sync::Arc;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let store = Arc::new(LookupStore::new());
//! let feed = ThreatIntelFeed {
//!     feed_id: uuid::Uuid::new_v4(),
//!     name: "abuse.ch".to_string(),
//!     taxii_url: "https://example.taxii.server/api/v21/collections/indicators/objects/".to_string(),
//!     api_key: None,
//!     target_table: "ioc_ips".to_string(),
//!     indicator_types: vec!["ipv4-addr".to_string()],
//!     enabled: true,
//!     auto_sync_interval_secs: 0,
//!     last_synced_at: None,
//! };
//! let result = feed.sync(&store, &reqwest::Client::new()).await?;
//! println!("Added {} IOCs", result.indicators_added);
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::LookupStore;

// ─── Feed configuration ────────────────────────────────────────────────────────

/// A configured TAXII 2.1 threat intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeed {
    pub feed_id: Uuid,
    /// Human-readable name shown in the UI.
    pub name: String,
    /// TAXII 2.1 collection objects URL, e.g.
    /// `https://host/api/v21/collections/<id>/objects/`
    pub taxii_url: String,
    /// Optional bearer token / API key sent in `Authorization: Bearer <key>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Name of the lookup table to populate with extracted indicators.
    pub target_table: String,
    /// STIX object types to extract, e.g. `["ipv4-addr", "domain-name"]`.
    /// Empty = extract all supported types.
    #[serde(default)]
    pub indicator_types: Vec<String>,
    pub enabled: bool,
    /// Automatic sync interval in seconds. `0` = manual sync only.
    #[serde(default)]
    pub auto_sync_interval_secs: u64,
    /// Timestamp of the last successful automatic sync (updated in-place by scheduler).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Result of a single feed synchronisation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSyncResult {
    pub feed_id: Uuid,
    pub feed_name: String,
    pub indicators_added: usize,
    pub errors: Vec<String>,
    pub synced_at: chrono::DateTime<chrono::Utc>,
}

impl ThreatIntelFeed {
    /// Download the TAXII collection and merge extracted IOCs into `lookup_store`.
    ///
    /// Uses `reqwest` for HTTP.  Fails gracefully — network/parse errors are
    /// recorded in `FeedSyncResult::errors` rather than returning `Err`.
    pub async fn sync(
        &self,
        lookup_store: &Arc<LookupStore>,
        client: &reqwest::Client,
    ) -> anyhow::Result<FeedSyncResult> {
        let errors = Vec::new();

        let response = {
            let mut req = client
                .get(&self.taxii_url)
                .header("Accept", "application/taxii+json;version=2.1");
            if let Some(key) = &self.api_key {
                req = req.bearer_auth(key);
            }
            match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("HTTP request failed: {e}");
                    tracing::warn!(feed = %self.name, error = %msg);
                    return Ok(FeedSyncResult {
                        feed_id: self.feed_id,
                        feed_name: self.name.clone(),
                        indicators_added: 0,
                        errors: vec![msg],
                        synced_at: chrono::Utc::now(),
                    });
                }
            }
        };

        let body: Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("JSON decode failed: {e}");
                tracing::warn!(feed = %self.name, error = %msg);
                return Ok(FeedSyncResult {
                    feed_id: self.feed_id,
                    feed_name: self.name.clone(),
                    indicators_added: 0,
                    errors: vec![msg],
                    synced_at: chrono::Utc::now(),
                });
            }
        };

        // TAXII response may be a bundle object or a list of objects
        let objects = extract_stix_objects(&body);
        let mut indicators: Vec<String> = Vec::new();

        for obj in &objects {
            // Only process STIX Indicator objects (type = "indicator")
            if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
                continue;
            }
            if let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) {
                let extracted = extract_ioc_values(pattern, &self.indicator_types);
                indicators.extend(extracted);
            }
        }

        let count = indicators.len();
        if count > 0 {
            lookup_store.add_entries(&self.target_table, indicators);
            tracing::info!(
                feed = %self.name,
                table = %self.target_table,
                indicators_added = count,
                "TAXII feed synced"
            );
        }

        Ok(FeedSyncResult {
            feed_id: self.feed_id,
            feed_name: self.name.clone(),
            indicators_added: count,
            errors,
            synced_at: chrono::Utc::now(),
        })
    }
}

// ─── STIX pattern extraction ──────────────────────────────────────────────────

/// Extract the STIX objects array from a TAXII response body.
/// Handles both envelope format `{"objects": [...]}` and plain arrays.
fn extract_stix_objects(body: &Value) -> Vec<Value> {
    if let Some(objects) = body.get("objects").and_then(|o| o.as_array()) {
        return objects.clone();
    }
    if let Some(arr) = body.as_array() {
        return arr.clone();
    }
    vec![]
}

/// Extract IOC string values from a STIX pattern expression.
///
/// Supports:
/// - `[ipv4-addr:value = 'X.X.X.X']`
/// - `[ipv6-addr:value = 'X::X']`
/// - `[domain-name:value = 'evil.com']`
/// - `[url:value = 'http://...']`
/// - `[file:hashes.MD5 = 'abc']` / `[file:hashes.'SHA-256' = 'abc']`
///
/// If `allowed_types` is non-empty, only patterns for those STIX types are extracted.
pub fn extract_ioc_values(pattern: &str, allowed_types: &[String]) -> Vec<String> {
    let mut values = Vec::new();

    // Each `[type:path = 'value']` clause
    for clause in split_pattern_clauses(pattern) {
        let clause = clause.trim().trim_start_matches('[').trim_end_matches(']');

        // Determine STIX type from clause start
        let stix_type = clause
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        if !allowed_types.is_empty()
            && !allowed_types
                .iter()
                .any(|t| t.to_ascii_lowercase() == stix_type)
        {
            continue;
        }

        // Extract the quoted value after `=`
        if let Some(val) = extract_quoted_value(clause) {
            values.push(val);
        }
    }

    values
}

/// Split a STIX pattern like `[A = 'x'] AND [B = 'y']` into individual clauses.
fn split_pattern_clauses(pattern: &str) -> Vec<&str> {
    // Simple split on "] AND [" or "] OR ["
    // For production use a proper STIX pattern parser; this covers the common case.
    let mut clauses = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '[' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            ']' => {
                depth -= 1;
                if depth == 0 {
                    clauses.push(&pattern[start..=i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    if clauses.is_empty() {
        clauses.push(pattern);
    }
    clauses
}

/// Extract the string value from a `field = 'value'` or `field = "value"` expression.
fn extract_quoted_value(clause: &str) -> Option<String> {
    let eq = clause.find('=')?;
    let after_eq = clause[eq + 1..].trim();
    // Strip surrounding quotes (single or double)
    let val = if (after_eq.starts_with('\'') && after_eq.ends_with('\''))
        || (after_eq.starts_with('"') && after_eq.ends_with('"'))
    {
        after_eq[1..after_eq.len() - 1].to_string()
    } else {
        after_eq.trim_matches('\'').trim_matches('"').to_string()
    };
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ipv4() {
        let pattern = "[ipv4-addr:value = '1.2.3.4']";
        let vals = extract_ioc_values(pattern, &[]);
        assert_eq!(vals, vec!["1.2.3.4"]);
    }

    #[test]
    fn extracts_domain() {
        let pattern = "[domain-name:value = 'evil.com']";
        let vals = extract_ioc_values(pattern, &[]);
        assert_eq!(vals, vec!["evil.com"]);
    }

    #[test]
    fn extracts_hash() {
        let pattern = "[file:hashes.MD5 = 'aabbccdd']";
        let vals = extract_ioc_values(pattern, &[]);
        assert_eq!(vals, vec!["aabbccdd"]);
    }

    #[test]
    fn filters_by_allowed_type() {
        let pattern = "[ipv4-addr:value = '1.2.3.4']";
        // Only allow domain-name — IPv4 should be excluded
        let vals = extract_ioc_values(pattern, &["domain-name".to_string()]);
        assert!(vals.is_empty());
    }

    #[test]
    fn compound_pattern_or() {
        let pattern = "[ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'evil.com']";
        let vals = extract_ioc_values(pattern, &[]);
        assert!(vals.contains(&"1.2.3.4".to_string()));
        assert!(vals.contains(&"evil.com".to_string()));
    }

    #[test]
    fn extract_stix_objects_from_envelope() {
        let body = serde_json::json!({
            "type": "bundle",
            "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '9.9.9.9']"},
                {"type": "malware", "name": "BadActor"}
            ]
        });
        let objects = extract_stix_objects(&body);
        assert_eq!(objects.len(), 2);
    }
}
