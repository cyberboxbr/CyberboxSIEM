use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::sync::Mutex;
use uuid::Uuid;

use cyberbox_core::CyberboxError;
use cyberbox_models::{
    AgentEnrollRequest, AgentEnrollResponse, AgentEnrollmentTokenRecord,
    AgentEnrollmentTokenResponse, AgentRecord, AlertRecord, AlertStatus, AssignAlertRequest,
    AuditLogRecord, CaseRecord, CaseStatus, CloseAlertRequest, CreateAgentEnrollmentTokenRequest,
    RotateAgentCredentialResponse, UpdateCaseRequest,
};

use crate::in_memory::sla_due_at;
use crate::traits::{AlertStore, CaseStore};

const SNAPSHOT_DIR: &str = "workflow";
const SNAPSHOT_FILE: &str = "workflow_store.json";
const ENROLLMENT_TOKEN_PREFIX: &str = "cbe_";
const AGENT_SECRET_PREFIX: &str = "cbs_";
const DEFAULT_ENROLLMENT_TTL_SECS: u64 = 3600;
const MAX_ENROLLMENT_TTL_SECS: u64 = 86400;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct WorkflowSnapshot {
    tenants: BTreeMap<String, TenantWorkflowState>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TenantWorkflowState {
    alerts: BTreeMap<String, AlertRecord>,
    cases: BTreeMap<String, CaseRecord>,
    audits: Vec<AuditLogRecord>,
    agents: BTreeMap<String, AgentRecord>,
    enrollment_tokens: BTreeMap<String, AgentEnrollmentTokenRecord>,
}

#[derive(Clone)]
pub struct FileWorkflowStore {
    path: Arc<PathBuf>,
    inner: Arc<Mutex<WorkflowSnapshot>>,
}

impl FileWorkflowStore {
    pub fn open_blocking(root: impl AsRef<Path>) -> Result<Self, CyberboxError> {
        let path = workflow_store_path(root.as_ref());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| CyberboxError::Internal(format!("create workflow dir: {err}")))?;
        }

        let snapshot = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<WorkflowSnapshot>(&bytes).map_err(|err| {
                CyberboxError::Internal(format!(
                    "parse workflow snapshot {}: {err}",
                    path.display()
                ))
            })?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => WorkflowSnapshot::default(),
            Err(err) => {
                return Err(CyberboxError::Internal(format!(
                    "read workflow snapshot {}: {err}",
                    path.display()
                )));
            }
        };

        Ok(Self {
            path: Arc::new(path),
            inner: Arc::new(Mutex::new(snapshot)),
        })
    }

    pub async fn open(root: impl AsRef<Path>) -> Result<Self, CyberboxError> {
        Self::open_blocking(root)
    }

    pub async fn list_agents_all(&self) -> Result<Vec<AgentRecord>, CyberboxError> {
        Ok(self
            .read(|snapshot| {
                snapshot
                    .tenants
                    .values()
                    .flat_map(|tenant| tenant.agents.values().cloned())
                    .collect::<Vec<_>>()
            })
            .await)
    }

    pub async fn list_alerts_all(&self) -> Result<Vec<AlertRecord>, CyberboxError> {
        Ok(self
            .read(|snapshot| {
                snapshot
                    .tenants
                    .values()
                    .flat_map(|tenant| tenant.alerts.values().cloned())
                    .collect::<Vec<_>>()
            })
            .await)
    }

    pub async fn list_cases_all(&self) -> Result<Vec<CaseRecord>, CyberboxError> {
        Ok(self
            .read(|snapshot| {
                snapshot
                    .tenants
                    .values()
                    .flat_map(|tenant| tenant.cases.values().cloned())
                    .collect::<Vec<_>>()
            })
            .await)
    }

    pub async fn list_agents(&self, tenant_id: &str) -> Result<Vec<AgentRecord>, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        Ok(self
            .read(move |snapshot| {
                let mut agents = tenant_state(snapshot, &tenant_id)
                    .map(|tenant| tenant.agents.values().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                agents.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                agents
            })
            .await)
    }

    pub async fn get_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<AgentRecord, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        self.read(move |snapshot| {
            tenant_state(snapshot, &tenant_id)
                .and_then(|tenant| tenant.agents.get(&agent_id))
                .cloned()
                .ok_or(CyberboxError::NotFound)
        })
        .await
    }

    pub async fn upsert_agent(&self, agent: AgentRecord) -> Result<AgentRecord, CyberboxError> {
        self.mutate(move |snapshot| {
            tenant_state_mut(snapshot, &agent.tenant_id)
                .agents
                .insert(agent.agent_id.clone(), agent.clone());
            Ok(agent)
        })
        .await
    }

    pub async fn delete_agent(&self, tenant_id: &str, agent_id: &str) -> Result<(), CyberboxError> {
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        self.mutate(move |snapshot| {
            let tenant = tenant_state_mut(snapshot, &tenant_id);
            tenant
                .agents
                .remove(&agent_id)
                .map(|_| ())
                .ok_or(CyberboxError::NotFound)
        })
        .await
    }

    pub async fn issue_enrollment_token(
        &self,
        tenant_id: &str,
        issued_by: &str,
        request: &CreateAgentEnrollmentTokenRequest,
    ) -> Result<AgentEnrollmentTokenResponse, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        let issued_by = issued_by.to_string();
        let request = request.clone();
        self.mutate(move |snapshot| {
            let now = Utc::now();
            let ttl = request
                .ttl_seconds
                .unwrap_or(DEFAULT_ENROLLMENT_TTL_SECS)
                .clamp(60, MAX_ENROLLMENT_TTL_SECS);
            let expires_at = now + chrono::Duration::seconds(ttl as i64);
            let token_id = Uuid::new_v4();
            let raw_token = generate_secret(ENROLLMENT_TOKEN_PREFIX);
            let record = AgentEnrollmentTokenRecord {
                token_id,
                tenant_id: tenant_id.clone(),
                issued_by,
                issued_at: now,
                expires_at,
                allowed_agent_id: request.allowed_agent_id.clone(),
                used_at: None,
                revoked_at: None,
                token_hash: hash_secret(&raw_token),
            };
            tenant_state_mut(snapshot, &tenant_id)
                .enrollment_tokens
                .insert(token_id.to_string(), record.clone());
            Ok(AgentEnrollmentTokenResponse {
                token_id,
                tenant_id: tenant_id.clone(),
                enrollment_token: raw_token,
                expires_at,
                allowed_agent_id: record.allowed_agent_id,
            })
        })
        .await
    }

    pub async fn enroll_agent(
        &self,
        request: &AgentEnrollRequest,
    ) -> Result<AgentEnrollResponse, CyberboxError> {
        let request = request.clone();
        self.mutate(move |snapshot| {
            let now = Utc::now();
            let tenant = tenant_state_mut(snapshot, &request.tenant_id);
            let token_hash = hash_secret(&request.enrollment_token);
            let token_id = tenant
                .enrollment_tokens
                .iter()
                .find_map(|(token_id, record)| {
                    (record.token_hash == token_hash).then(|| token_id.clone())
                })
                .ok_or(CyberboxError::Unauthorized)?;
            let allowed_agent_id = {
                let token = tenant
                    .enrollment_tokens
                    .get(&token_id)
                    .ok_or(CyberboxError::Unauthorized)?;
                if token.revoked_at.is_some() || token.used_at.is_some() || token.expires_at < now {
                    return Err(CyberboxError::Unauthorized);
                }
                token.allowed_agent_id.clone()
            };
            if allowed_agent_id
                .as_deref()
                .is_some_and(|expected| expected != request.agent_id)
            {
                return Err(CyberboxError::Forbidden);
            }

            let agent_secret = generate_secret(AGENT_SECRET_PREFIX);
            let agent = tenant
                .agents
                .entry(request.agent_id.clone())
                .or_insert_with(|| AgentRecord {
                    agent_id: request.agent_id.clone(),
                    tenant_id: request.tenant_id.clone(),
                    hostname: request.hostname.clone(),
                    os: request.os.clone(),
                    version: request.version.clone(),
                    ip: None,
                    registered_at: now,
                    last_seen: now,
                    group: None,
                    tags: Vec::new(),
                    pending_config: None,
                    enrolled_at: None,
                    credential_version: 0,
                    credential_hash: None,
                    credential_rotated_at: None,
                    device_certificate_serial: None,
                    device_certificate_expires_at: None,
                    revoked_at: None,
                    revoked_reason: None,
                });

            agent.hostname = request.hostname.clone();
            agent.os = request.os.clone();
            agent.version = request.version.clone();
            agent.registered_at = now;
            agent.last_seen = now;
            agent.enrolled_at = Some(now);
            agent.credential_version = agent.credential_version.saturating_add(1).max(1);
            agent.credential_hash = Some(hash_secret(&agent_secret));
            agent.credential_rotated_at = Some(now);
            agent.revoked_at = None;
            agent.revoked_reason = None;
            if let Some(token) = tenant.enrollment_tokens.get_mut(&token_id) {
                token.used_at = Some(now);
            }

            Ok(AgentEnrollResponse {
                agent_id: agent.agent_id.clone(),
                tenant_id: agent.tenant_id.clone(),
                status: "enrolled".to_string(),
                agent_secret,
                device_certificate: None,
                device_certificate_serial: None,
                device_certificate_expires_at: None,
                credential_version: agent.credential_version,
                enrolled_at: now,
            })
        })
        .await
    }

    pub async fn authenticate_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        agent_secret: &str,
    ) -> Result<AgentRecord, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        let provided_hash = hash_secret(agent_secret);
        self.read(move |snapshot| {
            let agent = tenant_state(snapshot, &tenant_id)
                .and_then(|tenant| tenant.agents.get(&agent_id))
                .cloned()
                .ok_or(CyberboxError::Unauthorized)?;
            if agent.revoked_at.is_some() {
                return Err(CyberboxError::Forbidden);
            }
            if agent.tenant_id != tenant_id {
                return Err(CyberboxError::Forbidden);
            }
            match agent.credential_hash.as_deref() {
                Some(expected_hash) if expected_hash == provided_hash => Ok(agent),
                _ => Err(CyberboxError::Unauthorized),
            }
        })
        .await
    }

    pub async fn rotate_agent_secret(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<RotateAgentCredentialResponse, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        self.mutate(move |snapshot| {
            let now = Utc::now();
            let agent_secret = generate_secret(AGENT_SECRET_PREFIX);
            let agent = tenant_state_mut(snapshot, &tenant_id)
                .agents
                .get_mut(&agent_id)
                .ok_or(CyberboxError::NotFound)?;
            if agent.revoked_at.is_some() {
                return Err(CyberboxError::Forbidden);
            }
            agent.credential_version = agent.credential_version.saturating_add(1).max(1);
            agent.credential_hash = Some(hash_secret(&agent_secret));
            agent.credential_rotated_at = Some(now);
            Ok(RotateAgentCredentialResponse {
                agent_id: agent.agent_id.clone(),
                tenant_id: agent.tenant_id.clone(),
                agent_secret,
                device_certificate: None,
                device_certificate_serial: None,
                device_certificate_expires_at: None,
                credential_version: agent.credential_version,
                rotated_at: now,
            })
        })
        .await
    }

    pub async fn revoke_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        reason: Option<String>,
    ) -> Result<AgentRecord, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        self.mutate(move |snapshot| {
            let agent = tenant_state_mut(snapshot, &tenant_id)
                .agents
                .get_mut(&agent_id)
                .ok_or(CyberboxError::NotFound)?;
            agent.revoked_at = Some(Utc::now());
            agent.revoked_reason = reason.clone();
            Ok(agent.clone())
        })
        .await
    }

    pub async fn append_audit_log(&self, audit: AuditLogRecord) -> Result<(), CyberboxError> {
        self.mutate(move |snapshot| {
            tenant_state_mut(snapshot, &audit.tenant_id)
                .audits
                .push(audit);
            Ok(())
        })
        .await
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
        let tenant_id = tenant_id.to_string();
        let action = action.map(str::to_string);
        let entity_type = entity_type.map(str::to_string);
        let actor = actor.map(str::to_string);
        Ok(self
            .read(move |snapshot| {
                let mut audits = tenant_state(snapshot, &tenant_id)
                    .map(|tenant| tenant.audits.clone())
                    .unwrap_or_default();
                audits.retain(|entry| {
                    if action.as_deref().is_some_and(|value| entry.action != value) {
                        return false;
                    }
                    if entity_type
                        .as_deref()
                        .is_some_and(|value| entry.entity_type != value)
                    {
                        return false;
                    }
                    if actor.as_deref().is_some_and(|value| entry.actor != value) {
                        return false;
                    }
                    if from.is_some_and(|value| entry.timestamp < value) {
                        return false;
                    }
                    if to.is_some_and(|value| entry.timestamp > value) {
                        return false;
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
                audits
            })
            .await)
    }

    async fn read<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&WorkflowSnapshot) -> T,
    {
        let snapshot = self.inner.lock().await;
        f(&snapshot)
    }

    async fn mutate<T, F>(&self, f: F) -> Result<T, CyberboxError>
    where
        F: FnOnce(&mut WorkflowSnapshot) -> Result<T, CyberboxError>,
    {
        let mut snapshot = self.inner.lock().await;
        let result = f(&mut snapshot)?;
        let persisted = snapshot.clone();
        drop(snapshot);
        persist_snapshot(self.path.as_ref(), &persisted).await?;
        Ok(result)
    }
}

#[async_trait]
impl AlertStore for FileWorkflowStore {
    async fn upsert_alert(&self, alert: AlertRecord) -> Result<AlertRecord, CyberboxError> {
        self.mutate(move |snapshot| {
            tenant_state_mut(snapshot, &alert.tenant_id)
                .alerts
                .insert(alert.alert_id.to_string(), alert.clone());
            Ok(alert)
        })
        .await
    }

    async fn list_alerts(&self, tenant_id: &str) -> Result<Vec<AlertRecord>, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        Ok(self
            .read(move |snapshot| {
                let mut alerts = tenant_state(snapshot, &tenant_id)
                    .map(|tenant| tenant.alerts.values().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                alerts.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                alerts
            })
            .await)
    }

    async fn acknowledge(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        _actor: &str,
    ) -> Result<AlertRecord, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        self.mutate(move |snapshot| {
            let alert = tenant_state_mut(snapshot, &tenant_id)
                .alerts
                .get_mut(&alert_id.to_string())
                .ok_or(CyberboxError::NotFound)?;
            alert.status = AlertStatus::Acknowledged;
            alert.last_seen = Utc::now();
            Ok(alert.clone())
        })
        .await
    }

    async fn assign(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        assignment: &AssignAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        let assignment = assignment.clone();
        self.mutate(move |snapshot| {
            let alert = tenant_state_mut(snapshot, &tenant_id)
                .alerts
                .get_mut(&alert_id.to_string())
                .ok_or(CyberboxError::NotFound)?;
            alert.assignee = Some(assignment.assignee);
            alert.status = AlertStatus::InProgress;
            alert.last_seen = Utc::now();
            Ok(alert.clone())
        })
        .await
    }

    async fn close(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        request: &CloseAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        let request = request.clone();
        self.mutate(move |snapshot| {
            let alert = tenant_state_mut(snapshot, &tenant_id)
                .alerts
                .get_mut(&alert_id.to_string())
                .ok_or(CyberboxError::NotFound)?;
            alert.status = AlertStatus::Closed;
            alert.resolution = Some(request.resolution);
            alert.close_note = request.note;
            alert.last_seen = Utc::now();
            Ok(alert.clone())
        })
        .await
    }

    async fn suppress_or_create_alert(
        &self,
        alert: AlertRecord,
    ) -> Result<AlertRecord, CyberboxError> {
        self.mutate(move |snapshot| {
            let tenant = tenant_state_mut(snapshot, &alert.tenant_id);
            if let Some(existing) = tenant.alerts.values_mut().find(|existing| {
                existing.routing_state.dedupe_key == alert.routing_state.dedupe_key
                    && matches!(existing.status, AlertStatus::Open | AlertStatus::InProgress)
            }) {
                existing.last_seen = alert.last_seen;
                existing.hit_count += 1;
                for evidence in &alert.evidence_refs {
                    if !existing.evidence_refs.contains(evidence) {
                        existing.evidence_refs.push(evidence.clone());
                    }
                }
                return Ok(existing.clone());
            }
            tenant
                .alerts
                .insert(alert.alert_id.to_string(), alert.clone());
            Ok(alert)
        })
        .await
    }
}

#[async_trait]
impl CaseStore for FileWorkflowStore {
    async fn upsert_case(&self, case: CaseRecord) -> Result<CaseRecord, CyberboxError> {
        self.mutate(move |snapshot| {
            tenant_state_mut(snapshot, &case.tenant_id)
                .cases
                .insert(case.case_id.to_string(), case.clone());
            Ok(case)
        })
        .await
    }

    async fn get_case(&self, tenant_id: &str, case_id: Uuid) -> Result<CaseRecord, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        self.read(move |snapshot| {
            tenant_state(snapshot, &tenant_id)
                .and_then(|tenant| tenant.cases.get(&case_id.to_string()))
                .cloned()
                .ok_or(CyberboxError::NotFound)
        })
        .await
    }

    async fn list_cases(&self, tenant_id: &str) -> Result<Vec<CaseRecord>, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        Ok(self
            .read(move |snapshot| {
                let mut cases = tenant_state(snapshot, &tenant_id)
                    .map(|tenant| tenant.cases.values().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                cases.sort_by(|a, b| b.created_at.cmp(&a.created_at));
                cases
            })
            .await)
    }

    async fn update_case(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        patch: &UpdateCaseRequest,
        now: DateTime<Utc>,
    ) -> Result<CaseRecord, CyberboxError> {
        let tenant_id = tenant_id.to_string();
        let patch = patch.clone();
        self.mutate(move |snapshot| {
            let case = tenant_state_mut(snapshot, &tenant_id)
                .cases
                .get_mut(&case_id.to_string())
                .ok_or(CyberboxError::NotFound)?;
            if let Some(title) = patch.title {
                case.title = title;
            }
            if let Some(description) = patch.description {
                case.description = description;
            }
            if let Some(status) = patch.status {
                if matches!(status, CaseStatus::Resolved | CaseStatus::Closed)
                    && case.closed_at.is_none()
                {
                    case.closed_at = Some(now);
                }
                case.status = status;
            }
            if let Some(severity) = patch.severity {
                case.severity = severity.clone();
                case.sla_due_at = Some(sla_due_at(&severity, case.created_at));
            }
            if let Some(assignee) = patch.assignee {
                case.assignee = Some(assignee);
            }
            if let Some(tags) = patch.tags {
                case.tags = tags;
            }
            case.updated_at = now;
            Ok(case.clone())
        })
        .await
    }

    async fn delete_case(&self, tenant_id: &str, case_id: Uuid) -> Result<(), CyberboxError> {
        let tenant_id = tenant_id.to_string();
        self.mutate(move |snapshot| {
            tenant_state_mut(snapshot, &tenant_id)
                .cases
                .remove(&case_id.to_string())
                .map(|_| ())
                .ok_or(CyberboxError::NotFound)
        })
        .await
    }
}

fn workflow_store_path(root: &Path) -> PathBuf {
    root.join(SNAPSHOT_DIR).join(SNAPSHOT_FILE)
}

fn tenant_state<'a>(
    snapshot: &'a WorkflowSnapshot,
    tenant_id: &str,
) -> Option<&'a TenantWorkflowState> {
    snapshot.tenants.get(tenant_id)
}

fn tenant_state_mut<'a>(
    snapshot: &'a mut WorkflowSnapshot,
    tenant_id: &str,
) -> &'a mut TenantWorkflowState {
    snapshot.tenants.entry(tenant_id.to_string()).or_default()
}

async fn persist_snapshot(path: &Path, snapshot: &WorkflowSnapshot) -> Result<(), CyberboxError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|err| CyberboxError::Internal(format!("create workflow dir: {err}")))?;
    }
    let bytes = serde_json::to_vec_pretty(snapshot)
        .map_err(|err| CyberboxError::Internal(format!("serialize workflow snapshot: {err}")))?;
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, bytes)
        .await
        .map_err(|err| CyberboxError::Internal(format!("write workflow snapshot: {err}")))?;
    fs::rename(&temp_path, path)
        .await
        .map_err(|err| CyberboxError::Internal(format!("replace workflow snapshot: {err}")))?;
    Ok(())
}

fn generate_secret(prefix: &str) -> String {
    format!(
        "{prefix}{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberbox_models::{AlertResolution, RoutingState, Severity};

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("cyberbox-workflow-store-{}", Uuid::new_v4()))
    }

    fn make_alert() -> AlertRecord {
        AlertRecord {
            alert_id: Uuid::new_v4(),
            tenant_id: "tenant-a".to_string(),
            rule_id: Uuid::new_v4(),
            severity: Severity::High,
            rule_title: "Test Rule".to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            status: AlertStatus::Open,
            evidence_refs: vec!["event:1".to_string()],
            routing_state: RoutingState {
                destinations: vec!["soc".to_string()],
                last_routed_at: None,
                dedupe_key: "dedupe-key".to_string(),
                suppression_until: None,
            },
            assignee: None,
            hit_count: 1,
            mitre_attack: Vec::new(),
            resolution: None,
            close_note: None,
            agent_meta: None,
        }
    }

    #[tokio::test]
    async fn workflow_store_persists_alerts_to_disk() {
        let root = temp_root();
        let store = FileWorkflowStore::open(&root).await.unwrap();
        let alert = make_alert();
        store.upsert_alert(alert.clone()).await.unwrap();

        let reopened = FileWorkflowStore::open(&root).await.unwrap();
        let alerts = reopened.list_alerts("tenant-a").await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_id, alert.alert_id);
    }

    #[tokio::test]
    async fn enrollment_issues_rotatable_machine_secret() {
        let root = temp_root();
        let store = FileWorkflowStore::open(&root).await.unwrap();
        let token = store
            .issue_enrollment_token(
                "tenant-a",
                "admin",
                &CreateAgentEnrollmentTokenRequest {
                    ttl_seconds: Some(600),
                    allowed_agent_id: Some("agent-1".to_string()),
                },
            )
            .await
            .unwrap();
        let enrolled = store
            .enroll_agent(&AgentEnrollRequest {
                enrollment_token: token.enrollment_token,
                agent_id: "agent-1".to_string(),
                tenant_id: "tenant-a".to_string(),
                hostname: "host-1".to_string(),
                os: "linux".to_string(),
                version: "1.0.0".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(enrolled.credential_version, 1);

        let auth = store
            .authenticate_agent("tenant-a", "agent-1", &enrolled.agent_secret)
            .await
            .unwrap();
        assert_eq!(auth.agent_id, "agent-1");

        let rotated = store
            .rotate_agent_secret("tenant-a", "agent-1")
            .await
            .unwrap();
        assert_eq!(rotated.credential_version, 2);
        assert!(store
            .authenticate_agent("tenant-a", "agent-1", &enrolled.agent_secret)
            .await
            .is_err());
        assert!(store
            .authenticate_agent("tenant-a", "agent-1", &rotated.agent_secret)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn duplicate_open_alerts_merge_on_dedupe_key() {
        let root = temp_root();
        let store = FileWorkflowStore::open(&root).await.unwrap();
        let first = make_alert();
        let merged = store.suppress_or_create_alert(first.clone()).await.unwrap();
        assert_eq!(merged.hit_count, 1);

        let mut second = make_alert();
        second.alert_id = Uuid::new_v4();
        second.evidence_refs.push("event:2".to_string());
        let merged = store.suppress_or_create_alert(second).await.unwrap();
        assert_eq!(merged.alert_id, first.alert_id);
        assert_eq!(merged.hit_count, 2);
        assert_eq!(merged.evidence_refs.len(), 2);
    }

    #[tokio::test]
    async fn closed_alerts_stop_deduping() {
        let root = temp_root();
        let store = FileWorkflowStore::open(&root).await.unwrap();
        let alert = store.suppress_or_create_alert(make_alert()).await.unwrap();
        store
            .close(
                "tenant-a",
                alert.alert_id,
                &CloseAlertRequest {
                    actor: "analyst".to_string(),
                    resolution: AlertResolution::FalsePositive,
                    note: None,
                },
            )
            .await
            .unwrap();

        let created = store.suppress_or_create_alert(make_alert()).await.unwrap();
        assert_ne!(created.alert_id, alert.alert_id);
    }
}
