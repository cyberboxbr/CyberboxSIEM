//! In-process scheduled-rule executor for the noop (in-memory) ingest path.
//!
//! Mirrors the logic in `cyberbox-worker`'s `run_scheduled_detection_tick` but
//! operates against `InMemoryStore` instead of ClickHouse, so scheduled rules
//! work end-to-end in local/test/dev deployments with no external dependencies.
//!
//! Two entry points:
//! - `run_tick(state)` — execute one scheduler pass; called by the HTTP handler
//!   (`POST /api/v1/scheduler/tick`) and by the background loop.
//! - `run_scheduler_loop(state, tick_secs)` — spawned as a background Tokio task
//!   in `main.rs` when Kafka is disabled.

use std::collections::HashMap;

use chrono::Utc;
use metrics::gauge;
use cyberbox_core::CyberboxError;
use cyberbox_models::{AlertStatus, CaseRecord, CaseStatus, RuleScheduleConfig, RuleSchedulerHealth, Severity};
use cyberbox_storage::{AlertStore, CaseStore, sla_due_at};

use crate::state::AppState;

const DEFAULT_RULE_INTERVAL_SECONDS: u32 = 30;
const DEFAULT_RULE_LOOKBACK_SECONDS: u32 = 300;
const EVENTS_PER_RULE_LIMIT: usize = 500;

pub struct SchedulerTickResult {
    pub rules_scanned: usize,
    pub alerts_emitted: usize,
}

/// Execute one pass of the scheduled-rule loop.
///
/// For each enabled scheduled rule the function:
/// 1. Skips the rule if its configured interval has not yet elapsed.
/// 2. Scans `[watermark, now]` (or `[now - lookback, now]` on first run).
/// 3. Evaluates every event through the detection engine.
/// 4. Creates / merges alerts for matches.
/// 5. Updates health counters and persists the watermark.
pub async fn run_tick(state: &AppState) -> Result<SchedulerTickResult, CyberboxError> {
    let rules = state.storage.list_all_scheduled_rules();
    let now = Utc::now();
    let mut alerts_emitted = 0usize;

    for rule in &rules {
        let schedule = rule.schedule.clone().unwrap_or(RuleScheduleConfig {
            interval_seconds: DEFAULT_RULE_INTERVAL_SECONDS,
            lookback_seconds: DEFAULT_RULE_LOOKBACK_SECONDS,
        });

        // Skip if the rule's own interval hasn't elapsed since last run.
        if let Some(last_run) = state.storage.get_watermark(rule.rule_id) {
            let elapsed = now.signed_duration_since(last_run).num_seconds();
            if elapsed < schedule.interval_seconds as i64 {
                let mut health = state
                    .storage
                    .get_rule_scheduler_health(&rule.tenant_id, rule.rule_id);
                health.skipped_by_interval_count =
                    health.skipped_by_interval_count.saturating_add(1);
                let _ = state
                    .storage
                    .upsert_rule_scheduler_health(&rule.tenant_id, rule.rule_id, &health)
                    .await;
                continue;
            }
        }

        let started = std::time::Instant::now();
        let mut match_count = 0u64;
        let mut error_count = 0u64;

        // Scan from the last watermark, or fall back to `now - lookback` on first run.
        let from = state.storage.get_watermark(rule.rule_id).unwrap_or_else(|| {
            now - chrono::Duration::seconds(schedule.lookback_seconds as i64)
        });

        let events =
            state
                .storage
                .list_events_in_range(&rule.tenant_id, from, now, EVENTS_PER_RULE_LIMIT);

        for event in &events {
            let result = state.rule_executor.evaluate(rule, event);
            if !result.matched {
                continue;
            }
            match_count += 1;

            if let Some(alert) = state
                .rule_executor
                .maybe_build_alert(rule, event, format!("event:{}", event.event_id))
            {
                if let Err(err) = state.storage.suppress_or_create_alert(alert).await {
                    tracing::warn!(
                        tenant_id = %rule.tenant_id,
                        rule_id = %rule.rule_id,
                        error = %err,
                        "scheduled rule: failed to persist alert"
                    );
                    error_count = error_count.saturating_add(1);
                } else {
                    alerts_emitted += 1;
                }
            }
        }

        let run_duration_seconds = started.elapsed().as_secs_f64();
        let health = RuleSchedulerHealth {
            run_count: state
                .storage
                .get_rule_scheduler_health(&rule.tenant_id, rule.rule_id)
                .run_count
                .saturating_add(1),
            match_count: state
                .storage
                .get_rule_scheduler_health(&rule.tenant_id, rule.rule_id)
                .match_count
                .saturating_add(match_count),
            error_count: state
                .storage
                .get_rule_scheduler_health(&rule.tenant_id, rule.rule_id)
                .error_count
                .saturating_add(error_count),
            skipped_by_interval_count: state
                .storage
                .get_rule_scheduler_health(&rule.tenant_id, rule.rule_id)
                .skipped_by_interval_count,
            last_run_duration_seconds: run_duration_seconds,
        };
        let _ = state
            .storage
            .upsert_rule_scheduler_health(&rule.tenant_id, rule.rule_id, &health)
            .await;

        state.storage.upsert_watermark(rule.rule_id, now);

        tracing::debug!(
            tenant_id = %rule.tenant_id,
            rule_id = %rule.rule_id,
            events_scanned = events.len(),
            match_count,
            alerts_emitted,
            run_duration_seconds,
            "scheduled rule tick completed"
        );
    }

    // ── TAXII auto-sync ───────────────────────────────────────────────────────
    // For each enabled feed with auto_sync_interval_secs > 0, check if it is
    // due for a sync and spawn a background task if so. last_synced_at is
    // updated in-place so the next tick won't re-trigger prematurely.
    let now_utc = Utc::now();
    let feed_ids_to_sync: Vec<uuid::Uuid> = state
        .threat_intel_feeds
        .iter()
        .filter_map(|entry| {
            let f = entry.value();
            if !f.enabled || f.auto_sync_interval_secs == 0 {
                return None;
            }
            let due = f.last_synced_at
                .map(|t| (now_utc - t).num_seconds() >= f.auto_sync_interval_secs as i64)
                .unwrap_or(true);
            if due { Some(f.feed_id) } else { None }
        })
        .collect();

    for feed_id in feed_ids_to_sync {
        if let Some(mut entry) = state.threat_intel_feeds.get_mut(&feed_id) {
            entry.last_synced_at = Some(now_utc);
            let feed_clone = entry.clone();
            let lookup = std::sync::Arc::clone(&state.lookup_store);
            let http = state.http_client.clone();
            tokio::spawn(async move {
                match feed_clone.sync(&lookup, &http).await {
                    Ok(r) => tracing::info!(
                        feed_id = %r.feed_id,
                        feed_name = %r.feed_name,
                        indicators_added = r.indicators_added,
                        "TAXII auto-sync completed"
                    ),
                    Err(e) => tracing::warn!(
                        feed_id = %feed_id,
                        error = %e,
                        "TAXII auto-sync failed"
                    ),
                }
            });
        }
    }

    // ── SLA breach monitoring ─────────────────────────────────────────────────
    // Collect unique tenant IDs from scheduled rules to check SLA breaches per tenant.
    let tenants: std::collections::HashSet<String> =
        rules.iter().map(|r| r.tenant_id.clone()).collect();
    for tenant_id in &tenants {
        if let Ok(breaches) = state.storage.list_sla_breaches(tenant_id).await {
            if !breaches.is_empty() {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    breach_count = breaches.len(),
                    "SLA breach: {} open case(s) past deadline",
                    breaches.len()
                );
            }
            gauge!("cyberbox_case_sla_breaches", "tenant" => tenant_id.clone())
                .set(breaches.len() as f64);
        }
    }

    // ── Alert auto-grouping into cases ────────────────────────────────────────
    // For each tenant, group open/in-progress alerts by rule_id. When a rule
    // produces >= AUTO_GROUP_THRESHOLD alerts, auto-create or update a case
    // that bundles them. This surfaces alert storms without analyst triage.
    const AUTO_GROUP_THRESHOLD: usize = 3;
    for tenant_id in &tenants {
        if let Ok(alerts) = state.storage.list_alerts(tenant_id).await {
            // Map rule_id → [alert_id] for open/in-progress, non-suppressed alerts.
            let mut by_rule: HashMap<uuid::Uuid, Vec<uuid::Uuid>> = HashMap::new();
            for alert in &alerts {
                if matches!(alert.status, AlertStatus::Open | AlertStatus::InProgress) {
                    by_rule.entry(alert.rule_id).or_default().push(alert.alert_id);
                }
            }

            for (rule_id, alert_ids) in by_rule {
                if alert_ids.len() < AUTO_GROUP_THRESHOLD {
                    continue;
                }

                // Check if a case already groups these alerts (by tag "auto:rule:<rule_id>").
                let tag = format!("auto:rule:{rule_id}");
                let existing_case = state.storage
                    .list_cases(tenant_id)
                    .await
                    .ok()
                    .and_then(|cases| cases.into_iter().find(|c| {
                        c.tags.contains(&tag)
                            && !matches!(c.status, CaseStatus::Closed | CaseStatus::Resolved)
                    }));

                let now_utc = Utc::now();
                if let Some(mut case) = existing_case {
                    // Merge newly seen alert IDs into existing case.
                    let mut updated = false;
                    for aid in &alert_ids {
                        if !case.alert_ids.contains(aid) {
                            case.alert_ids.push(*aid);
                            updated = true;
                        }
                    }
                    if updated {
                        case.updated_at = now_utc;
                        let _ = state.storage.upsert_case(case).await;
                    }
                } else {
                    // Create a new auto-grouped case.
                    let severity = Severity::Medium;
                    let new_case = CaseRecord {
                        case_id: uuid::Uuid::new_v4(),
                        tenant_id: tenant_id.clone(),
                        title: format!("Auto-grouped: rule {rule_id} ({} alerts)", alert_ids.len()),
                        description: format!(
                            "Automatically grouped {} open alerts triggered by rule {}.",
                            alert_ids.len(), rule_id
                        ),
                        status: CaseStatus::Open,
                        severity: severity.clone(),
                        alert_ids,
                        assignee: None,
                        created_by: "scheduler".to_string(),
                        created_at: now_utc,
                        updated_at: now_utc,
                        sla_due_at: Some(sla_due_at(&severity, now_utc)),
                        closed_at: None,
                        tags: vec![tag],
                    };
                    let _ = state.storage.upsert_case(new_case).await;
                    tracing::info!(
                        tenant_id = %tenant_id,
                        rule_id = %rule_id,
                        "alert auto-grouping: new case created"
                    );
                }
            }
        }
    }

    // ── Scheduled digest report ───────────────────────────────────────────────
    if state.report_interval_secs > 0 {
        let should_report = {
            let last = state.last_report_sent_at.lock().unwrap_or_else(|e| e.into_inner());
            last.map(|t| t.elapsed().as_secs() >= state.report_interval_secs)
                .unwrap_or(true)
        };
        if should_report {
            let mut open_alerts = 0usize;
            let mut total_alerts = 0usize;
            let mut open_cases = 0usize;
            let mut sla_breaches_count = 0usize;
            for tenant_id in &tenants {
                if let Ok(alerts) = state.storage.list_alerts(tenant_id).await {
                    total_alerts += alerts.len();
                    open_alerts += alerts.iter()
                        .filter(|a| matches!(a.status, AlertStatus::Open | AlertStatus::InProgress))
                        .count();
                }
                if let Ok(cases) = state.storage.list_cases(tenant_id).await {
                    open_cases += cases.iter()
                        .filter(|c| matches!(c.status, CaseStatus::Open | CaseStatus::InProgress))
                        .count();
                }
                if let Ok(b) = state.storage.list_sla_breaches(tenant_id).await {
                    sla_breaches_count += b.len();
                }
            }
            let period = format!("{}s interval", state.report_interval_secs);
            if let Err(e) = state.teams_notifier
                .send_digest(&period, open_alerts, total_alerts, open_cases, sla_breaches_count)
                .await
            {
                tracing::warn!(error = %e, "scheduled digest send failed");
            } else {
                *state.last_report_sent_at.lock().unwrap_or_else(|e| e.into_inner())
                    = Some(std::time::Instant::now());
                tracing::info!("scheduled digest sent");
            }
        }
    }

    Ok(SchedulerTickResult {
        rules_scanned: rules.len(),
        alerts_emitted,
    })
}

/// Background scheduler loop — spawned from `main.rs` in noop/in-memory mode.
pub async fn run_scheduler_loop(state: AppState, tick_secs: u64) {
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(tick_secs.max(1)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    tracing::info!(tick_secs, "in-memory scheduler loop started");

    loop {
        interval.tick().await;
        match run_tick(&state).await {
            Ok(result) => {
                if result.rules_scanned > 0 {
                    tracing::info!(
                        rules_scanned = result.rules_scanned,
                        alerts_emitted = result.alerts_emitted,
                        "in-memory scheduler tick completed"
                    );
                }
            }
            Err(err) => {
                tracing::error!(error = %err, "in-memory scheduler tick failed");
            }
        }
    }
}
