use std::path::Path;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use cyberbox_core::{AppConfig, CyberboxError};
use cyberbox_models::{
    AgentEnrollRequest, AgentEnrollResponse, AgentEnrollmentTokenResponse, AgentRecord,
    AlertRecord, AssignAlertRequest, AuditLogRecord, CaseRecord, CloseAlertRequest,
    CreateAgentEnrollmentTokenRequest, RotateAgentCredentialResponse, UpdateCaseRequest,
};

use crate::postgres_workflow_store::PostgresWorkflowStore;
use crate::traits::{AlertStore, CaseStore};
use crate::workflow_store::FileWorkflowStore;

#[derive(Clone)]
pub enum WorkflowStore {
    File(FileWorkflowStore),
    Postgres(PostgresWorkflowStore),
}

impl WorkflowStore {
    pub fn open_file_blocking(root: impl AsRef<Path>) -> Result<Self, CyberboxError> {
        Ok(Self::File(FileWorkflowStore::open_blocking(root)?))
    }

    pub fn open_postgres_blocking(url: &str, schema: &str) -> Result<Self, CyberboxError> {
        Ok(Self::Postgres(PostgresWorkflowStore::open_blocking(
            url, schema,
        )?))
    }

    pub fn from_config(config: &AppConfig) -> Result<Self, CyberboxError> {
        match config
            .workflow_store_backend
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "file" => Self::open_file_blocking(&config.state_dir),
            "postgres" => Self::open_postgres_blocking(
                &config.workflow_store_postgres_url,
                &config.workflow_store_postgres_schema,
            ),
            other => Err(CyberboxError::Internal(format!(
                "unsupported workflow_store_backend '{}'; expected 'file' or 'postgres'",
                other
            ))),
        }
    }

    pub async fn list_agents_all(&self) -> Result<Vec<AgentRecord>, CyberboxError> {
        match self {
            Self::File(store) => store.list_agents_all().await,
            Self::Postgres(store) => store.list_agents_all().await,
        }
    }

    pub async fn list_alerts_all(&self) -> Result<Vec<AlertRecord>, CyberboxError> {
        match self {
            Self::File(store) => store.list_alerts_all().await,
            Self::Postgres(store) => store.list_alerts_all().await,
        }
    }

    pub async fn list_cases_all(&self) -> Result<Vec<CaseRecord>, CyberboxError> {
        match self {
            Self::File(store) => store.list_cases_all().await,
            Self::Postgres(store) => store.list_cases_all().await,
        }
    }

    pub async fn create_case_with_alerts(
        &self,
        case: CaseRecord,
    ) -> Result<CaseRecord, CyberboxError> {
        match self {
            Self::File(store) => store.create_case_with_alerts(case).await,
            Self::Postgres(store) => store.create_case_with_alerts(case).await,
        }
    }

    pub async fn attach_alerts_to_case(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        alert_ids: &[Uuid],
        now: DateTime<Utc>,
    ) -> Result<CaseRecord, CyberboxError> {
        match self {
            Self::File(store) => {
                store
                    .attach_alerts_to_case(tenant_id, case_id, alert_ids, now)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .attach_alerts_to_case(tenant_id, case_id, alert_ids, now)
                    .await
            }
        }
    }

    pub async fn detach_alerts_from_case(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        alert_ids: &[Uuid],
        now: DateTime<Utc>,
    ) -> Result<CaseRecord, CyberboxError> {
        match self {
            Self::File(store) => {
                store
                    .detach_alerts_from_case(tenant_id, case_id, alert_ids, now)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .detach_alerts_from_case(tenant_id, case_id, alert_ids, now)
                    .await
            }
        }
    }

    pub async fn delete_case_with_alerts(
        &self,
        tenant_id: &str,
        case_id: Uuid,
    ) -> Result<CaseRecord, CyberboxError> {
        match self {
            Self::File(store) => store.delete_case_with_alerts(tenant_id, case_id).await,
            Self::Postgres(store) => store.delete_case_with_alerts(tenant_id, case_id).await,
        }
    }

    pub async fn list_agents(&self, tenant_id: &str) -> Result<Vec<AgentRecord>, CyberboxError> {
        match self {
            Self::File(store) => store.list_agents(tenant_id).await,
            Self::Postgres(store) => store.list_agents(tenant_id).await,
        }
    }

    pub async fn get_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<AgentRecord, CyberboxError> {
        match self {
            Self::File(store) => store.get_agent(tenant_id, agent_id).await,
            Self::Postgres(store) => store.get_agent(tenant_id, agent_id).await,
        }
    }

    pub async fn upsert_agent(&self, agent: AgentRecord) -> Result<AgentRecord, CyberboxError> {
        match self {
            Self::File(store) => store.upsert_agent(agent).await,
            Self::Postgres(store) => store.upsert_agent(agent).await,
        }
    }

    pub async fn delete_agent(&self, tenant_id: &str, agent_id: &str) -> Result<(), CyberboxError> {
        match self {
            Self::File(store) => store.delete_agent(tenant_id, agent_id).await,
            Self::Postgres(store) => store.delete_agent(tenant_id, agent_id).await,
        }
    }

    pub async fn issue_enrollment_token(
        &self,
        tenant_id: &str,
        issued_by: &str,
        request: &CreateAgentEnrollmentTokenRequest,
    ) -> Result<AgentEnrollmentTokenResponse, CyberboxError> {
        match self {
            Self::File(store) => {
                store
                    .issue_enrollment_token(tenant_id, issued_by, request)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .issue_enrollment_token(tenant_id, issued_by, request)
                    .await
            }
        }
    }

    pub async fn enroll_agent(
        &self,
        request: &AgentEnrollRequest,
    ) -> Result<AgentEnrollResponse, CyberboxError> {
        match self {
            Self::File(store) => store.enroll_agent(request).await,
            Self::Postgres(store) => store.enroll_agent(request).await,
        }
    }

    pub async fn authenticate_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        agent_secret: &str,
    ) -> Result<AgentRecord, CyberboxError> {
        match self {
            Self::File(store) => {
                store
                    .authenticate_agent(tenant_id, agent_id, agent_secret)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .authenticate_agent(tenant_id, agent_id, agent_secret)
                    .await
            }
        }
    }

    pub async fn rotate_agent_secret(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<RotateAgentCredentialResponse, CyberboxError> {
        match self {
            Self::File(store) => store.rotate_agent_secret(tenant_id, agent_id).await,
            Self::Postgres(store) => store.rotate_agent_secret(tenant_id, agent_id).await,
        }
    }

    pub async fn revoke_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        reason: Option<String>,
    ) -> Result<AgentRecord, CyberboxError> {
        match self {
            Self::File(store) => store.revoke_agent(tenant_id, agent_id, reason).await,
            Self::Postgres(store) => store.revoke_agent(tenant_id, agent_id, reason).await,
        }
    }

    pub async fn append_audit_log(&self, audit: AuditLogRecord) -> Result<(), CyberboxError> {
        match self {
            Self::File(store) => store.append_audit_log(audit).await,
            Self::Postgres(store) => store.append_audit_log(audit).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
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
        match self {
            Self::File(store) => {
                store
                    .list_audit_logs(
                        tenant_id,
                        action,
                        entity_type,
                        actor,
                        from,
                        to,
                        cursor,
                        limit,
                    )
                    .await
            }
            Self::Postgres(store) => {
                store
                    .list_audit_logs(
                        tenant_id,
                        action,
                        entity_type,
                        actor,
                        from,
                        to,
                        cursor,
                        limit,
                    )
                    .await
            }
        }
    }
}

#[async_trait]
impl AlertStore for WorkflowStore {
    async fn upsert_alert(&self, alert: AlertRecord) -> Result<AlertRecord, CyberboxError> {
        match self {
            Self::File(store) => store.upsert_alert(alert).await,
            Self::Postgres(store) => store.upsert_alert(alert).await,
        }
    }

    async fn list_alerts(&self, tenant_id: &str) -> Result<Vec<AlertRecord>, CyberboxError> {
        match self {
            Self::File(store) => store.list_alerts(tenant_id).await,
            Self::Postgres(store) => store.list_alerts(tenant_id).await,
        }
    }

    async fn acknowledge(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        actor: &str,
    ) -> Result<AlertRecord, CyberboxError> {
        match self {
            Self::File(store) => store.acknowledge(tenant_id, alert_id, actor).await,
            Self::Postgres(store) => store.acknowledge(tenant_id, alert_id, actor).await,
        }
    }

    async fn assign(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        assignment: &AssignAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        match self {
            Self::File(store) => store.assign(tenant_id, alert_id, assignment).await,
            Self::Postgres(store) => store.assign(tenant_id, alert_id, assignment).await,
        }
    }

    async fn close(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        request: &CloseAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        match self {
            Self::File(store) => store.close(tenant_id, alert_id, request).await,
            Self::Postgres(store) => store.close(tenant_id, alert_id, request).await,
        }
    }

    async fn suppress_or_create_alert(
        &self,
        alert: AlertRecord,
    ) -> Result<AlertRecord, CyberboxError> {
        match self {
            Self::File(store) => store.suppress_or_create_alert(alert).await,
            Self::Postgres(store) => store.suppress_or_create_alert(alert).await,
        }
    }
}

#[async_trait]
impl CaseStore for WorkflowStore {
    async fn upsert_case(&self, case: CaseRecord) -> Result<CaseRecord, CyberboxError> {
        match self {
            Self::File(store) => store.upsert_case(case).await,
            Self::Postgres(store) => store.upsert_case(case).await,
        }
    }

    async fn get_case(&self, tenant_id: &str, case_id: Uuid) -> Result<CaseRecord, CyberboxError> {
        match self {
            Self::File(store) => store.get_case(tenant_id, case_id).await,
            Self::Postgres(store) => store.get_case(tenant_id, case_id).await,
        }
    }

    async fn list_cases(&self, tenant_id: &str) -> Result<Vec<CaseRecord>, CyberboxError> {
        match self {
            Self::File(store) => store.list_cases(tenant_id).await,
            Self::Postgres(store) => store.list_cases(tenant_id).await,
        }
    }

    async fn update_case(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        patch: &UpdateCaseRequest,
        now: DateTime<Utc>,
    ) -> Result<CaseRecord, CyberboxError> {
        match self {
            Self::File(store) => store.update_case(tenant_id, case_id, patch, now).await,
            Self::Postgres(store) => store.update_case(tenant_id, case_id, patch, now).await,
        }
    }

    async fn delete_case(&self, tenant_id: &str, case_id: Uuid) -> Result<(), CyberboxError> {
        match self {
            Self::File(store) => store.delete_case(tenant_id, case_id).await,
            Self::Postgres(store) => store.delete_case(tenant_id, case_id).await,
        }
    }
}
