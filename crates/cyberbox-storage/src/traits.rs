use async_trait::async_trait;
use uuid::Uuid;

use cyberbox_core::CyberboxError;
use cyberbox_models::{
    AlertRecord, AlertStatus, AssignAlertRequest, CaseRecord, CaseStatus, CloseAlertRequest,
    DetectionRule, EventEnvelope, SearchQueryRequest, SearchQueryResponse, UpdateCaseRequest,
};

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
