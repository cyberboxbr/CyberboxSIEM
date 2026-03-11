//! Rule pack import/sync — shared logic used by both the API endpoint and
//! the startup auto-import.

use std::collections::HashSet;

use serde::Serialize;
use uuid::Uuid;

use cyberbox_auth::AuthContext;
use cyberbox_core::CyberboxError;
use cyberbox_models::{DetectionMode, DetectionRule, Severity};
use cyberbox_storage::RuleStore;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub imported: usize,
    pub updated: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruned: Option<usize>,
}

/// Import all `.yml` / `.yaml` Sigma rule files from `dir` into the store.
///
/// - `prune`: if true, disables rules that exist in the DB but not on disk.
pub async fn import_rules_from_dir(
    auth: &AuthContext,
    state: &AppState,
    dir: &str,
    prune: bool,
) -> Result<ImportResult, CyberboxError> {
    let dir_path = std::path::Path::new(dir);
    if !dir_path.is_dir() {
        return Err(CyberboxError::BadRequest(format!(
            "path is not a directory: {dir}"
        )));
    }

    let mut imported = 0usize;
    let mut updated = 0usize;
    let mut skipped = 0usize;
    let mut errors = Vec::new();
    let mut seen_ids = HashSet::new();

    let entries: Vec<_> = std::fs::read_dir(dir_path)
        .map_err(|e| CyberboxError::BadRequest(format!("cannot read directory: {e}")))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_lowercase();
            name.ends_with(".yml") || name.ends_with(".yaml")
        })
        .collect();

    for entry in entries {
        let file_path = entry.path();
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let content = match std::fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{file_name}: read error: {e}"));
                continue;
            }
        };

        let rule_id = extract_rule_id_from_yaml(&content).unwrap_or_else(Uuid::new_v4);
        seen_ids.insert(rule_id);

        let severity = extract_severity_from_yaml(&content);

        let compiled_plan = match state.sigma_compiler.compile(&content) {
            Ok(p) => p,
            Err(e) => {
                errors.push(format!("{file_name}: compile error: {e}"));
                continue;
            }
        };

        let existing = state.storage.get_rule(&auth.tenant_id, rule_id).await.ok();

        if let Some(ref ex) = existing {
            if ex.sigma_source == content {
                skipped += 1;
                continue;
            }
        }

        let rule = DetectionRule {
            rule_id,
            tenant_id: auth.tenant_id.clone(),
            sigma_source: content,
            compiled_plan,
            schedule_or_stream: DetectionMode::Stream,
            schedule: None,
            severity,
            enabled: true,
            scheduler_health: None,
            threshold_count: None,
            threshold_group_by: None,
            suppression_window_secs: None,
        };

        match state.storage.upsert_rule(rule).await {
            Ok(_) => {
                if existing.is_some() {
                    updated += 1;
                } else {
                    imported += 1;
                }
            }
            Err(e) => {
                errors.push(format!("{file_name}: storage error: {e}"));
            }
        }
    }

    let pruned = if prune {
        let mut count = 0;
        let all_rules = state
            .storage
            .list_rules(&auth.tenant_id)
            .await
            .unwrap_or_default();
        for rule in &all_rules {
            if rule.enabled && !seen_ids.contains(&rule.rule_id) {
                let mut disabled = rule.clone();
                disabled.enabled = false;
                let _ = state.storage.upsert_rule(disabled).await;
                count += 1;
            }
        }
        Some(count)
    } else {
        None
    };

    // Refresh rule cache
    let fresh = state
        .storage
        .list_rules(&auth.tenant_id)
        .await
        .unwrap_or_default();
    state.stream_rule_cache.refresh(&auth.tenant_id, fresh);

    Ok(ImportResult {
        imported,
        updated,
        skipped,
        errors,
        pruned,
    })
}

/// Extract `id:` field from Sigma YAML.
pub fn extract_rule_id_from_yaml(yaml: &str) -> Option<Uuid> {
    for line in yaml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("id:") {
            let id_str = rest.trim().trim_matches(|c| c == '\'' || c == '"');
            return Uuid::parse_str(id_str).ok();
        }
    }
    None
}

/// Extract `level:` field from Sigma YAML.
pub fn extract_severity_from_yaml(yaml: &str) -> Severity {
    for line in yaml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("level:") {
            return match rest.trim().to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                "informational" | "info" => Severity::Low,
                _ => Severity::Medium,
            };
        }
    }
    Severity::Medium
}
