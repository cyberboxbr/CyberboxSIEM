use std::collections::BTreeSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use cyberbox_core::CyberboxError;
use cyberbox_models::{
    AlertRecord, AlertStatus, AssignAlertRequest, CaseRecord, CaseStatus, CloseAlertRequest,
    DetectionRule, EventEnvelope, SearchQueryRequest, SearchQueryResponse, UpdateCaseRequest,
};

pub(crate) fn unique_alert_ids(alert_ids: &[Uuid]) -> Vec<Uuid> {
    let mut seen = BTreeSet::new();
    alert_ids
        .iter()
        .copied()
        .filter(|alert_id| seen.insert(*alert_id))
        .collect()
}

pub(crate) fn alert_not_found_error(alert_id: Uuid) -> CyberboxError {
    CyberboxError::BadRequest(format!("alert {alert_id} not found"))
}

pub(crate) fn alert_case_conflict_error(alert_id: Uuid, case_id: Uuid) -> CyberboxError {
    CyberboxError::BadRequest(format!(
        "alert {alert_id} is already linked to case {case_id}"
    ))
}

pub(crate) fn closed_alert_assignment_error(alert_id: Uuid) -> CyberboxError {
    CyberboxError::BadRequest(format!(
        "alert {alert_id} is closed and cannot be reassigned"
    ))
}

pub(crate) fn missing_alert_assignment_error() -> CyberboxError {
    CyberboxError::BadRequest(
        "assign endpoint requires assignee; use null to clear the current assignee".to_string(),
    )
}

pub(crate) fn normalize_optional_string(value: Option<&String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn apply_case_patch(
    case: &mut CaseRecord,
    patch: &UpdateCaseRequest,
    now: DateTime<Utc>,
) {
    if let Some(title) = &patch.title {
        case.title = title.clone();
    }
    if let Some(description) = &patch.description {
        case.description = description.clone();
    }
    if let Some(status) = &patch.status {
        case.status = status.clone();
    }
    if let Some(severity) = &patch.severity {
        case.severity = severity.clone();
        case.sla_due_at = Some(crate::in_memory::sla_due_at(severity, case.created_at));
    }
    if let Some(assignee) = &patch.assignee {
        case.assignee = normalize_optional_string(assignee.as_ref());
    }
    if let Some(tags) = &patch.tags {
        case.tags = tags.clone();
    }

    match case.status {
        CaseStatus::Open | CaseStatus::InProgress => {
            case.closed_at = None;
            case.resolution = None;
            case.close_note = None;
        }
        CaseStatus::Resolved | CaseStatus::Closed => {
            if case.closed_at.is_none() {
                case.closed_at = Some(now);
            }
            if let Some(resolution) = &patch.resolution {
                case.resolution = Some(resolution.clone());
            }
            if let Some(close_note) = &patch.close_note {
                let note = close_note.trim();
                case.close_note = (!note.is_empty()).then(|| note.to_string());
            }
        }
    }

    case.updated_at = now;
}

#[async_trait]
pub trait EventStore: Send + Sync {
    async fn insert_events(&self, events: &[EventEnvelope]) -> Result<(), CyberboxError>;
    async fn search(
        &self,
        query: &SearchQueryRequest,
    ) -> Result<SearchQueryResponse, CyberboxError>;
}

#[async_trait]
pub trait RuleStore: Send + Sync {
    async fn upsert_rule(&self, rule: DetectionRule) -> Result<DetectionRule, CyberboxError>;
    async fn list_rules(&self, tenant_id: &str) -> Result<Vec<DetectionRule>, CyberboxError>;
    async fn get_rule(
        &self,
        tenant_id: &str,
        rule_id: Uuid,
    ) -> Result<DetectionRule, CyberboxError>;
    async fn delete_rule(&self, tenant_id: &str, rule_id: Uuid) -> Result<(), CyberboxError>;
}

#[async_trait]
pub trait AlertStore: Send + Sync {
    async fn upsert_alert(&self, alert: AlertRecord) -> Result<AlertRecord, CyberboxError>;
    async fn list_alerts(&self, tenant_id: &str) -> Result<Vec<AlertRecord>, CyberboxError>;
    async fn acknowledge(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        actor: &str,
    ) -> Result<AlertRecord, CyberboxError>;
    async fn assign(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        assignment: &AssignAlertRequest,
    ) -> Result<AlertRecord, CyberboxError>;

    async fn close(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        request: &CloseAlertRequest,
    ) -> Result<AlertRecord, CyberboxError>;

    /// Merges into an existing open/in-progress alert with the same dedupe key,
    /// or creates a new alert if none exists.
    async fn suppress_or_create_alert(
        &self,
        alert: AlertRecord,
    ) -> Result<AlertRecord, CyberboxError> {
        let existing = self
            .list_alerts(&alert.tenant_id)
            .await?
            .into_iter()
            .find(|a| {
                a.routing_state.dedupe_key == alert.routing_state.dedupe_key
                    && matches!(a.status, AlertStatus::Open | AlertStatus::InProgress)
            });

        if let Some(mut existing) = existing {
            existing.last_seen = alert.last_seen;
            existing.hit_count += 1;
            for ev in &alert.evidence_refs {
                if !existing.evidence_refs.contains(ev) {
                    existing.evidence_refs.push(ev.clone());
                }
            }
            self.upsert_alert(existing).await
        } else {
            self.upsert_alert(alert).await
        }
    }
}

/// Case management — create, read, update, delete incident cases.
#[async_trait]
pub trait CaseStore: Send + Sync {
    async fn upsert_case(&self, case: CaseRecord) -> Result<CaseRecord, CyberboxError>;
    async fn get_case(&self, tenant_id: &str, case_id: Uuid) -> Result<CaseRecord, CyberboxError>;
    async fn list_cases(&self, tenant_id: &str) -> Result<Vec<CaseRecord>, CyberboxError>;
    async fn update_case(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        patch: &UpdateCaseRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CaseRecord, CyberboxError>;
    async fn delete_case(&self, tenant_id: &str, case_id: Uuid) -> Result<(), CyberboxError>;

    /// Return all open cases whose `sla_due_at` is in the past.
    async fn list_sla_breaches(&self, tenant_id: &str) -> Result<Vec<CaseRecord>, CyberboxError> {
        let now = chrono::Utc::now();
        let cases = self.list_cases(tenant_id).await?;
        Ok(cases
            .into_iter()
            .filter(|c| {
                matches!(c.status, CaseStatus::Open | CaseStatus::InProgress)
                    && c.sla_due_at.map(|d| d < now).unwrap_or(false)
            })
            .collect())
    }
}
