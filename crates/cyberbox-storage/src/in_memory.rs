use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde_json::{json, Value};
use uuid::Uuid;

use cyberbox_core::CyberboxError;
use cyberbox_models::{
    AlertRecord, AlertStatus, AssignAlertRequest, AuditLogRecord, CaseRecord, CaseStatus,
    CloseAlertRequest, DetectionMode, DetectionRule, EventEnvelope, RuleSchedulerHealth,
    RuleVersion, SearchQueryRequest, SearchQueryResponse, Severity, UpdateCaseRequest,
};

use crate::traits::{AlertStore, CaseStore, EventStore, RuleStore};

/// Maximum events retained per tenant. Oldest entries are evicted automatically
/// on each `insert_events` call to prevent unbounded in-memory growth.
const MAX_EVENTS_PER_TENANT: usize = 500_000;

#[derive(Clone, Default)]
pub struct InMemoryStore {
    /// Per-tenant time-ordered event store.
    /// Key: (event_time, event_id) ensures chronological ordering and uniqueness.
    /// Range queries via `BTreeMap::range()` are O(log n + k) vs the previous O(n) Vec scan.
    events: Arc<DashMap<String, BTreeMap<(DateTime<Utc>, Uuid), EventEnvelope>>>,
    rules: Arc<DashMap<(String, Uuid), DetectionRule>>,
    alerts: Arc<DashMap<(String, Uuid), AlertRecord>>,
    /// Secondary dedupe index: (tenant_id, dedupe_key) → alert_id of open/in-progress alert.
    /// Allows `suppress_or_create_alert` to skip the O(n) `list_alerts()` scan.
    alert_dedupe_index: Arc<DashMap<(String, String), Uuid>>,
    audits: Arc<DashMap<String, Vec<AuditLogRecord>>>,
    rule_scheduler_health: Arc<DashMap<(String, Uuid), RuleSchedulerHealth>>,
    /// Scheduler watermarks: rule_id → last-run timestamp (in-process only, not persisted).
    watermarks: Arc<DashMap<Uuid, DateTime<Utc>>>,
    /// Incident cases: (tenant_id, case_id) → CaseRecord.
    cases: Arc<DashMap<(String, Uuid), CaseRecord>>,
    /// Rule version history: (tenant_id, rule_id) → ordered list of RuleVersion snapshots.
    rule_versions: Arc<DashMap<(String, Uuid), Vec<RuleVersion>>>,
}

impl InMemoryStore {
    /// Remove all events for a tenant from the in-memory store.
    /// Returns the number of events removed.
    pub fn clear_tenant_events(&self, tenant_id: &str) -> u64 {
        let removed = self
            .events
            .remove(tenant_id)
            .map(|(_, tree)| tree.len() as u64)
            .unwrap_or(0);
        tracing::info!(
            tenant_id,
            deleted_rows = removed,
            "GDPR purge: tenant events cleared from in-memory store"
        );
        removed
    }

    pub async fn append_audit_log(&self, audit: AuditLogRecord) -> Result<(), CyberboxError> {
        self.audits
            .entry(audit.tenant_id.clone())
            .and_modify(|tenant_logs| tenant_logs.push(audit.clone()))
            .or_insert_with(|| vec![audit]);
        Ok(())
    }

    pub async fn list_audit_logs(
        &self,
        tenant_id: &str,
        action: Option<&str>,
        entity_type: Option<&str>,
        actor: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        cursor: Option<(DateTime<Utc>, Uuid)>,
        limit: usize,
    ) -> Result<Vec<AuditLogRecord>, CyberboxError> {
        let mut audits = self
            .audits
            .get(tenant_id)
            .map(|value| value.clone())
            .unwrap_or_default();

        audits.retain(|entry| {
            if let Some(filter) = action {
                if entry.action != filter {
                    return false;
                }
            }
            if let Some(filter) = entity_type {
                if entry.entity_type != filter {
                    return false;
                }
            }
            if let Some(filter) = actor {
                if entry.actor != filter {
                    return false;
                }
            }
            if let Some(start) = from {
                if entry.timestamp < start {
                    return false;
                }
            }
            if let Some(end) = to {
                if entry.timestamp > end {
                    return false;
                }
            }
            if let Some((cursor_timestamp, cursor_id)) = cursor {
                let entry_ms = entry.timestamp.timestamp_millis();
                let cursor_ms = cursor_timestamp.timestamp_millis();
                if entry_ms > cursor_ms {
                    return false;
                }
                if entry_ms == cursor_ms && entry.audit_id >= cursor_id {
                    return false;
                }
            }
            true
        });
        audits.sort_by(|a, b| {
            b.timestamp
                .timestamp_millis()
                .cmp(&a.timestamp.timestamp_millis())
                .then_with(|| b.audit_id.cmp(&a.audit_id))
        });
        audits.truncate(limit.max(1));
        Ok(audits)
    }

    pub async fn upsert_rule_scheduler_health(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
        health: &RuleSchedulerHealth,
    ) -> Result<(), CyberboxError> {
        self.rule_scheduler_health
            .insert((tenant_id.to_string(), rule_id), health.clone());
        Ok(())
    }

    pub async fn list_rule_scheduler_health(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<(Uuid, RuleSchedulerHealth)>, CyberboxError> {
        let rows = self
            .rule_scheduler_health
            .iter()
            .filter_map(|entry| {
                let ((health_tenant_id, rule_id), health) = entry.pair();
                (health_tenant_id == tenant_id).then(|| (*rule_id, health.clone()))
            })
            .collect();
        Ok(rows)
    }

    /// Return the existing health record for a rule, or a zeroed default.
    pub fn get_rule_scheduler_health(&self, tenant_id: &str, rule_id: Uuid) -> RuleSchedulerHealth {
        self.rule_scheduler_health
            .get(&(tenant_id.to_string(), rule_id))
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Return all enabled scheduled rules across every tenant.
    pub fn list_all_scheduled_rules(&self) -> Vec<DetectionRule> {
        self.rules
            .iter()
            .filter_map(|entry| {
                let (_, rule) = entry.pair();
                if rule.enabled && matches!(rule.schedule_or_stream, DetectionMode::Scheduled) {
                    Some(rule.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return events for `tenant_id` whose `event_time` falls in `[from, to]`, up to `limit`.
    /// O(log n + k) via BTreeMap range scan rather than O(n) full Vec scan.
    pub fn list_events_in_range(
        &self,
        tenant_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: usize,
    ) -> Vec<EventEnvelope> {
        let lo = (from, Uuid::nil());
        let hi = (to, Uuid::max());
        self.events
            .get(tenant_id)
            .map(|tree| {
                tree.range(lo..=hi)
                    .map(|(_, ev)| ev.clone())
                    .take(limit)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Persist the last-run timestamp for a scheduled rule.
    pub fn upsert_watermark(&self, rule_id: Uuid, last_run_at: DateTime<Utc>) {
        self.watermarks.insert(rule_id, last_run_at);
    }

    /// Retrieve the last-run timestamp for a scheduled rule, if any.
    pub fn get_watermark(&self, rule_id: Uuid) -> Option<DateTime<Utc>> {
        self.watermarks.get(&rule_id).map(|v| *v)
    }
}

#[async_trait]
impl EventStore for InMemoryStore {
    async fn insert_events(&self, events: &[EventEnvelope]) -> Result<(), CyberboxError> {
        // Group by tenant so each DashMap shard is locked at most once per tenant,
        // regardless of how many events are in the batch.
        let mut by_tenant: std::collections::HashMap<&str, Vec<&EventEnvelope>> =
            std::collections::HashMap::new();
        for event in events {
            by_tenant.entry(&event.tenant_id).or_default().push(event);
        }

        for (tenant_id, tenant_events) in by_tenant {
            self.events
                .entry(tenant_id.to_string())
                .and_modify(|tree| {
                    for event in &tenant_events {
                        tree.insert((event.event_time, event.event_id), (*event).clone());
                    }
                    // Evict oldest entries if the tenant store exceeds the retention cap.
                    while tree.len() > MAX_EVENTS_PER_TENANT {
                        tree.pop_first();
                    }
                })
                .or_insert_with(|| {
                    tenant_events
                        .iter()
                        .map(|e| ((e.event_time, e.event_id), (*e).clone()))
                        .collect()
                });
        }
        Ok(())
    }

    async fn search(
        &self,
        query: &SearchQueryRequest,
    ) -> Result<SearchQueryResponse, CyberboxError> {
        let lo = (query.time_range.start, Uuid::nil());
        let hi = (query.time_range.end, Uuid::max());

        let filtered: Vec<Value> = self
            .events
            .get(&query.tenant_id)
            .map(|tree| {
                tree.range(lo..=hi)
                    .map(|(_, event)| {
                        json!({
                            "event_id": event.event_id,
                            "event_time": event.event_time,
                            "source": event.source,
                            "raw_payload": event.raw_payload,
                            "ocsf_record": event.ocsf_record,
                            "enrichment": event.enrichment,
                            "integrity_hash": event.integrity_hash,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let page_size = query.pagination.page_size.max(1);
        let start = pagination_offset(query.pagination.page, page_size) as usize;
        let total = filtered.len() as u64;
        let end = start + page_size as usize;
        let rows: Vec<Value> = filtered
            .iter()
            .skip(start)
            .take(page_size as usize)
            .cloned()
            .collect();
        let has_more = end < filtered.len();
        let next_page = query.pagination.page.max(1) + 1;

        Ok(SearchQueryResponse {
            rows,
            total,
            has_more,
            next_cursor: has_more.then(|| next_page.to_string()),
        })
    }
}

fn pagination_offset(page: u32, page_size: u32) -> u64 {
    if page <= 1 {
        return 0;
    }

    page.saturating_sub(1).saturating_mul(page_size) as u64
}

#[cfg(test)]
mod tests {
    use super::pagination_offset;

    #[test]
    fn pagination_offset_uses_one_based_pages() {
        assert_eq!(pagination_offset(0, 10), 0);
        assert_eq!(pagination_offset(1, 10), 0);
        assert_eq!(pagination_offset(2, 10), 10);
    }
}

impl InMemoryStore {
    /// Return all saved versions for a rule, ordered ascending (oldest first).
    pub fn list_rule_versions(&self, tenant_id: &str, rule_id: Uuid) -> Vec<RuleVersion> {
        self.rule_versions
            .get(&(tenant_id.to_string(), rule_id))
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Return a specific version snapshot, or `None` if not found.
    pub fn get_rule_version(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
        version: u32,
    ) -> Option<RuleVersion> {
        self.rule_versions
            .get(&(tenant_id.to_string(), rule_id))
            .and_then(|v| v.iter().find(|rv| rv.version == version).cloned())
    }
}

#[async_trait]
impl RuleStore for InMemoryStore {
    async fn upsert_rule(&self, rule: DetectionRule) -> Result<DetectionRule, CyberboxError> {
        // Record an immutable version snapshot before inserting.
        let key = (rule.tenant_id.clone(), rule.rule_id);
        let next_version = self
            .rule_versions
            .get(&key)
            .map(|v| v.len() as u32 + 1)
            .unwrap_or(1);
        let snapshot = RuleVersion {
            rule_id: rule.rule_id,
            tenant_id: rule.tenant_id.clone(),
            version: next_version,
            sigma_source: rule.sigma_source.clone(),
            compiled_plan: rule.compiled_plan.clone(),
            severity: rule.severity.clone(),
            created_at: Utc::now(),
        };
        self.rule_versions
            .entry(key)
            .and_modify(|v| v.push(snapshot.clone()))
            .or_insert_with(|| vec![snapshot]);

        self.rules
            .insert((rule.tenant_id.clone(), rule.rule_id), rule.clone());
        Ok(rule)
    }

    async fn list_rules(&self, tenant_id: &str) -> Result<Vec<DetectionRule>, CyberboxError> {
        let health_map: std::collections::HashMap<Uuid, RuleSchedulerHealth> = self
            .list_rule_scheduler_health(tenant_id)
            .await?
            .into_iter()
            .collect();
        let rules = self
            .rules
            .iter()
            .filter_map(|entry| {
                let ((rule_tenant_id, _), rule) = entry.pair();
                (rule_tenant_id == tenant_id).then(|| {
                    let mut rule = rule.clone();
                    rule.scheduler_health = health_map.get(&rule.rule_id).cloned();
                    rule
                })
            })
            .collect();

        Ok(rules)
    }

    async fn get_rule(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
    ) -> Result<DetectionRule, CyberboxError> {
        self.rules
            .get(&(tenant_id.to_string(), rule_id))
            .map(|rule| rule.clone())
            .ok_or(CyberboxError::NotFound)
    }

    async fn delete_rule(&self, tenant_id: &str, rule_id: Uuid) -> Result<(), CyberboxError> {
        self.rules
            .remove(&(tenant_id.to_string(), rule_id))
            .map(|_| ())
            .ok_or(CyberboxError::NotFound)
    }
}

#[async_trait]
impl AlertStore for InMemoryStore {
    async fn upsert_alert(&self, alert: AlertRecord) -> Result<AlertRecord, CyberboxError> {
        // Keep dedupe index in sync: open/in-progress alerts are indexed; closed ones are not.
        let idx_key = (
            alert.tenant_id.clone(),
            alert.routing_state.dedupe_key.clone(),
        );
        if matches!(alert.status, AlertStatus::Open | AlertStatus::InProgress) {
            self.alert_dedupe_index.insert(idx_key, alert.alert_id);
        } else {
            self.alert_dedupe_index.remove(&idx_key);
        }
        self.alerts
            .insert((alert.tenant_id.clone(), alert.alert_id), alert.clone());
        Ok(alert)
    }

    async fn list_alerts(&self, tenant_id: &str) -> Result<Vec<AlertRecord>, CyberboxError> {
        Ok(self
            .alerts
            .iter()
            .filter_map(|entry| {
                let ((alert_tenant_id, _), alert) = entry.pair();
                (alert_tenant_id == tenant_id).then(|| alert.clone())
            })
            .collect())
    }

    async fn acknowledge(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        _actor: &str,
    ) -> Result<AlertRecord, CyberboxError> {
        let key = (tenant_id.to_string(), alert_id);
        let mut entry = self.alerts.get_mut(&key).ok_or(CyberboxError::NotFound)?;
        entry.status = AlertStatus::Acknowledged;
        entry.last_seen = Utc::now();

        Ok(entry.clone())
    }

    async fn assign(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        assignment: &AssignAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        let key = (tenant_id.to_string(), alert_id);
        let mut entry = self.alerts.get_mut(&key).ok_or(CyberboxError::NotFound)?;
        entry.assignee = Some(assignment.assignee.clone());
        entry.status = AlertStatus::InProgress;
        entry.last_seen = Utc::now();

        Ok(entry.clone())
    }

    async fn close(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        request: &CloseAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        let key = (tenant_id.to_string(), alert_id);
        let mut entry = self.alerts.get_mut(&key).ok_or(CyberboxError::NotFound)?;
        entry.status = AlertStatus::Closed;
        entry.resolution = Some(request.resolution.clone());
        entry.close_note = request.note.clone();
        entry.last_seen = Utc::now();
        // Remove from dedupe index so future events create a fresh alert.
        let idx_key = (
            tenant_id.to_string(),
            entry.routing_state.dedupe_key.clone(),
        );
        drop(entry);
        self.alert_dedupe_index.remove(&idx_key);
        Ok(self.alerts.get(&key).unwrap().clone())
    }

    /// O(1) deduplication via the secondary dedupe index — replaces the O(n) `list_alerts` scan
    /// in the default trait implementation.
    async fn suppress_or_create_alert(
        &self,
        alert: AlertRecord,
    ) -> Result<AlertRecord, CyberboxError> {
        let idx_key = (
            alert.tenant_id.clone(),
            alert.routing_state.dedupe_key.clone(),
        );

        if let Some(existing_id) = self.alert_dedupe_index.get(&idx_key).map(|v| *v) {
            let alert_key = (alert.tenant_id.clone(), existing_id);
            if let Some(mut existing) = self.alerts.get_mut(&alert_key) {
                if matches!(existing.status, AlertStatus::Open | AlertStatus::InProgress) {
                    existing.last_seen = alert.last_seen;
                    existing.hit_count += 1;
                    for ev in &alert.evidence_refs {
                        if !existing.evidence_refs.contains(ev) {
                            existing.evidence_refs.push(ev.clone());
                        }
                    }
                    return Ok(existing.clone());
                }
            }
            // Stale index entry (alert was closed) — remove it and fall through to create.
            self.alert_dedupe_index.remove(&idx_key);
        }

        // No open alert found — create a new one (also updates the index via upsert_alert).
        self.upsert_alert(alert).await
    }
}

// ─── SLA helpers ──────────────────────────────────────────────────────────────

/// Compute the SLA response deadline from severity and case creation time.
/// Deadlines: Critical 15 min · High 1 h · Medium 4 h · Low 24 h.
pub fn sla_due_at(severity: &Severity, created_at: DateTime<Utc>) -> DateTime<Utc> {
    let minutes: i64 = match severity {
        Severity::Critical => 15,
        Severity::High => 60,
        Severity::Medium => 240,
        Severity::Low => 1440,
    };
    created_at + chrono::Duration::minutes(minutes)
}

// ─── CaseStore impl ───────────────────────────────────────────────────────────

#[async_trait]
impl CaseStore for InMemoryStore {
    async fn upsert_case(&self, case: CaseRecord) -> Result<CaseRecord, CyberboxError> {
        self.cases
            .insert((case.tenant_id.clone(), case.case_id), case.clone());
        Ok(case)
    }

    async fn get_case(&self, tenant_id: &str, case_id: Uuid) -> Result<CaseRecord, CyberboxError> {
        self.cases
            .get(&(tenant_id.to_string(), case_id))
            .map(|r| r.clone())
            .ok_or(CyberboxError::NotFound)
    }

    async fn list_cases(&self, tenant_id: &str) -> Result<Vec<CaseRecord>, CyberboxError> {
        let mut cases: Vec<CaseRecord> = self
            .cases
            .iter()
            .filter(|entry| entry.key().0 == tenant_id)
            .map(|entry| entry.value().clone())
            .collect();
        cases.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(cases)
    }

    async fn update_case(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        patch: &UpdateCaseRequest,
        now: DateTime<Utc>,
    ) -> Result<CaseRecord, CyberboxError> {
        let key = (tenant_id.to_string(), case_id);
        let mut entry = self.cases.get_mut(&key).ok_or(CyberboxError::NotFound)?;
        if let Some(t) = &patch.title {
            entry.title = t.clone();
        }
        if let Some(d) = &patch.description {
            entry.description = d.clone();
        }
        if let Some(s) = &patch.status {
            if matches!(s, CaseStatus::Resolved | CaseStatus::Closed) && entry.closed_at.is_none() {
                entry.closed_at = Some(now);
            }
            entry.status = s.clone();
        }
        if let Some(sev) = &patch.severity {
            entry.severity = sev.clone();
            entry.sla_due_at = Some(sla_due_at(sev, entry.created_at));
        }
        if let Some(a) = &patch.assignee {
            entry.assignee = Some(a.clone());
        }
        if let Some(tags) = &patch.tags {
            entry.tags = tags.clone();
        }
        entry.updated_at = now;
        Ok(entry.clone())
    }

    async fn delete_case(&self, tenant_id: &str, case_id: Uuid) -> Result<(), CyberboxError> {
        self.cases
            .remove(&(tenant_id.to_string(), case_id))
            .map(|_| ())
            .ok_or(CyberboxError::NotFound)
    }
}
