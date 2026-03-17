use std::sync::Arc;

use chrono::{DateTime, Utc};
use postgres::{types::Json as PgJson, types::ToSql, Client, GenericClient, NoTls, Row};
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::task;
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

const ENROLLMENT_TOKEN_PREFIX: &str = "cbe_";
const AGENT_SECRET_PREFIX: &str = "cbs_";
const DEFAULT_ENROLLMENT_TTL_SECS: u64 = 3600;
const MAX_ENROLLMENT_TTL_SECS: u64 = 86400;

#[derive(Clone)]
pub struct PostgresWorkflowStore {
    pool: Pool<PostgresConnectionManager<NoTls>>,
    schema: Arc<String>,
    #[allow(dead_code)]
    url: Arc<String>,
}

impl PostgresWorkflowStore {
    pub fn open_blocking(url: &str, schema: &str) -> Result<Self, CyberboxError> {
        if url.trim().is_empty() {
            return Err(CyberboxError::Internal(
                "workflow_store_postgres_url is empty".to_string(),
            ));
        }
        let schema = sanitize_identifier(schema)?;
        let manager = PostgresConnectionManager::new(
            url.parse().map_err(|err| {
                CyberboxError::Internal(format!("parse workflow postgres url: {err}"))
            })?,
            NoTls,
        );
        let pool = Pool::builder()
            .min_idle(Some(1))
            .max_size(4)
            .build(manager)
            .map_err(|err| {
                CyberboxError::Internal(format!("build workflow postgres pool: {err}"))
            })?;
        let mut conn = pool
            .get()
            .map_err(|err| CyberboxError::Internal(format!("get workflow postgres conn: {err}")))?;
        ensure_schema(&mut conn, &schema)?;
        Ok(Self {
            pool,
            schema: Arc::new(schema),
            url: Arc::new(url.to_string()),
        })
    }

    pub fn list_agents_all_blocking(&self) -> Result<Vec<AgentRecord>, CyberboxError> {
        self.with_client(|client, schema| {
            let rows = client
                .query(
                    &format!("SELECT record FROM {schema}.workflow_agents ORDER BY last_seen DESC"),
                    &[],
                )
                .map_err(pg_err("list workflow agents"))?;
            rows.into_iter().map(row_to_model::<AgentRecord>).collect()
        })
    }

    pub fn list_alerts_all_blocking(&self) -> Result<Vec<AlertRecord>, CyberboxError> {
        self.with_client(|client, schema| {
            let rows = client
                .query(
                    &format!("SELECT record FROM {schema}.workflow_alerts ORDER BY last_seen DESC"),
                    &[],
                )
                .map_err(pg_err("list workflow alerts"))?;
            rows.into_iter().map(row_to_model::<AlertRecord>).collect()
        })
    }

    pub fn list_cases_all_blocking(&self) -> Result<Vec<CaseRecord>, CyberboxError> {
        self.with_client(|client, schema| {
            let rows = client
                .query(
                    &format!("SELECT record FROM {schema}.workflow_cases ORDER BY created_at DESC"),
                    &[],
                )
                .map_err(pg_err("list workflow cases"))?;
            rows.into_iter().map(row_to_model::<CaseRecord>).collect()
        })
    }

    pub async fn list_agents_all(&self) -> Result<Vec<AgentRecord>, CyberboxError> {
        let store = self.clone();
        run_blocking(move || store.list_agents_all_blocking()).await
    }

    pub async fn list_alerts_all(&self) -> Result<Vec<AlertRecord>, CyberboxError> {
        let store = self.clone();
        run_blocking(move || store.list_alerts_all_blocking()).await
    }

    pub async fn list_cases_all(&self) -> Result<Vec<CaseRecord>, CyberboxError> {
        let store = self.clone();
        run_blocking(move || store.list_cases_all_blocking()).await
    }

    pub async fn list_agents(&self, tenant_id: &str) -> Result<Vec<AgentRecord>, CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let rows = client
                    .query(
                        &format!(
                            "SELECT record FROM {schema}.workflow_agents \
                             WHERE tenant_id = $1 ORDER BY last_seen DESC"
                        ),
                        &[&tenant_id],
                    )
                    .map_err(pg_err("list tenant agents"))?;
                rows.into_iter().map(row_to_model::<AgentRecord>).collect()
            })
        })
        .await
    }

    pub async fn get_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<AgentRecord, CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let row = client
                    .query_opt(
                        &format!(
                            "SELECT record FROM {schema}.workflow_agents \
                             WHERE tenant_id = $1 AND agent_id = $2"
                        ),
                        &[&tenant_id, &agent_id],
                    )
                    .map_err(pg_err("get workflow agent"))?
                    .ok_or(CyberboxError::NotFound)?;
                row_to_model(row)
            })
        })
        .await
    }

    pub async fn upsert_agent(&self, agent: AgentRecord) -> Result<AgentRecord, CyberboxError> {
        let store = self.clone();
        run_blocking(move || {
            store.with_client(|client, schema| {
                upsert_agent_row(client, schema, &agent)?;
                Ok(agent)
            })
        })
        .await
    }

    pub async fn delete_agent(&self, tenant_id: &str, agent_id: &str) -> Result<(), CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let deleted = client
                    .execute(
                        &format!(
                            "DELETE FROM {schema}.workflow_agents \
                             WHERE tenant_id = $1 AND agent_id = $2"
                        ),
                        &[&tenant_id, &agent_id],
                    )
                    .map_err(pg_err("delete workflow agent"))?;
                if deleted == 0 {
                    return Err(CyberboxError::NotFound);
                }
                Ok(())
            })
        })
        .await
    }

    pub async fn issue_enrollment_token(
        &self,
        tenant_id: &str,
        issued_by: &str,
        request: &CreateAgentEnrollmentTokenRequest,
    ) -> Result<AgentEnrollmentTokenResponse, CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        let issued_by = issued_by.to_string();
        let request = request.clone();
        run_blocking(move || {
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
            store.with_client(|client, schema| {
                upsert_enrollment_token_row(client, schema, &record)?;
                Ok(AgentEnrollmentTokenResponse {
                    token_id,
                    tenant_id: tenant_id.clone(),
                    enrollment_token: raw_token,
                    expires_at,
                    allowed_agent_id: record.allowed_agent_id.clone(),
                })
            })
        })
        .await
    }

    pub async fn enroll_agent(
        &self,
        request: &AgentEnrollRequest,
    ) -> Result<AgentEnrollResponse, CyberboxError> {
        let store = self.clone();
        let request = request.clone();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let mut tx = client
                    .transaction()
                    .map_err(pg_err("begin workflow enroll transaction"))?;
                let now = Utc::now();
                let token_hash = hash_secret(&request.enrollment_token);
                let token_row = tx
                    .query_opt(
                        &format!(
                            "SELECT record FROM {schema}.workflow_enrollment_tokens \
                             WHERE tenant_id = $1 AND token_hash = $2 FOR UPDATE"
                        ),
                        &[&request.tenant_id, &token_hash],
                    )
                    .map_err(pg_err("select enrollment token"))?
                    .ok_or(CyberboxError::Unauthorized)?;
                let mut token: AgentEnrollmentTokenRecord = row_to_model(token_row)?;
                if token.revoked_at.is_some() || token.used_at.is_some() || token.expires_at < now {
                    return Err(CyberboxError::Unauthorized);
                }
                if token
                    .allowed_agent_id
                    .as_deref()
                    .is_some_and(|expected| expected != request.agent_id)
                {
                    return Err(CyberboxError::Forbidden);
                }

                let existing_agent = tx
                    .query_opt(
                        &format!(
                            "SELECT record FROM {schema}.workflow_agents \
                             WHERE tenant_id = $1 AND agent_id = $2 FOR UPDATE"
                        ),
                        &[&request.tenant_id, &request.agent_id],
                    )
                    .map_err(pg_err("select workflow agent for enrollment"))?
                    .map(row_to_model::<AgentRecord>)
                    .transpose()?;

                let agent_secret = generate_secret(AGENT_SECRET_PREFIX);
                let mut agent = existing_agent.unwrap_or(AgentRecord {
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

                token.used_at = Some(now);

                upsert_agent_row_tx(&mut tx, schema, &agent)?;
                upsert_enrollment_token_row_tx(&mut tx, schema, &token)?;
                tx.commit()
                    .map_err(pg_err("commit workflow enroll transaction"))?;

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
        })
        .await
    }

    pub async fn authenticate_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        agent_secret: &str,
    ) -> Result<AgentRecord, CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        let provided_hash = hash_secret(agent_secret);
        run_blocking(move || {
            store.with_client(|client, schema| {
                let row = client
                    .query_opt(
                        &format!(
                            "SELECT record FROM {schema}.workflow_agents \
                             WHERE tenant_id = $1 AND agent_id = $2"
                        ),
                        &[&tenant_id, &agent_id],
                    )
                    .map_err(pg_err("authenticate workflow agent"))?
                    .ok_or(CyberboxError::Unauthorized)?;
                let agent: AgentRecord = row_to_model(row)?;
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
        })
        .await
    }

    pub async fn rotate_agent_secret(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<RotateAgentCredentialResponse, CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let mut tx = client
                    .transaction()
                    .map_err(pg_err("begin rotate workflow secret transaction"))?;
                let row = tx
                    .query_opt(
                        &format!(
                            "SELECT record FROM {schema}.workflow_agents \
                             WHERE tenant_id = $1 AND agent_id = $2 FOR UPDATE"
                        ),
                        &[&tenant_id, &agent_id],
                    )
                    .map_err(pg_err("select workflow agent for secret rotation"))?
                    .ok_or(CyberboxError::NotFound)?;
                let mut agent: AgentRecord = row_to_model(row)?;
                if agent.revoked_at.is_some() {
                    return Err(CyberboxError::Forbidden);
                }
                let now = Utc::now();
                let agent_secret = generate_secret(AGENT_SECRET_PREFIX);
                agent.credential_version = agent.credential_version.saturating_add(1).max(1);
                agent.credential_hash = Some(hash_secret(&agent_secret));
                agent.credential_rotated_at = Some(now);
                upsert_agent_row_tx(&mut tx, schema, &agent)?;
                tx.commit()
                    .map_err(pg_err("commit rotate workflow secret transaction"))?;
                Ok(RotateAgentCredentialResponse {
                    agent_id: agent.agent_id,
                    tenant_id: agent.tenant_id,
                    agent_secret,
                    device_certificate: None,
                    device_certificate_serial: None,
                    device_certificate_expires_at: None,
                    credential_version: agent.credential_version,
                    rotated_at: now,
                })
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
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        let agent_id = agent_id.to_string();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let mut tx = client
                    .transaction()
                    .map_err(pg_err("begin revoke workflow agent transaction"))?;
                let row = tx
                    .query_opt(
                        &format!(
                            "SELECT record FROM {schema}.workflow_agents \
                             WHERE tenant_id = $1 AND agent_id = $2 FOR UPDATE"
                        ),
                        &[&tenant_id, &agent_id],
                    )
                    .map_err(pg_err("select workflow agent for revoke"))?
                    .ok_or(CyberboxError::NotFound)?;
                let mut agent: AgentRecord = row_to_model(row)?;
                agent.revoked_at = Some(Utc::now());
                agent.revoked_reason = reason;
                upsert_agent_row_tx(&mut tx, schema, &agent)?;
                tx.commit()
                    .map_err(pg_err("commit revoke workflow agent transaction"))?;
                Ok(agent)
            })
        })
        .await
    }

    pub async fn append_audit_log(&self, audit: AuditLogRecord) -> Result<(), CyberboxError> {
        let store = self.clone();
        run_blocking(move || {
            store.with_client(|client, schema| upsert_audit_row(client, schema, &audit))
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
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        let action = action.map(str::to_string);
        let entity_type = entity_type.map(str::to_string);
        let actor = actor.map(str::to_string);
        let pg_limit = limit.max(1) as i64;
        run_blocking(move || {
            store.with_client(|client, schema| {
                // Build WHERE clause dynamically; $1 is always tenant_id.
                let mut conditions = vec![format!("tenant_id = $1")];
                let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();
                params.push(Box::new(tenant_id));
                let mut idx: usize = 2; // next placeholder index

                if let Some(ref action) = action {
                    conditions.push(format!("action = ${idx}"));
                    params.push(Box::new(action.clone()));
                    idx += 1;
                }
                if let Some(ref entity_type) = entity_type {
                    conditions.push(format!("entity_type = ${idx}"));
                    params.push(Box::new(entity_type.clone()));
                    idx += 1;
                }
                if let Some(ref actor) = actor {
                    conditions.push(format!("actor = ${idx}"));
                    params.push(Box::new(actor.clone()));
                    idx += 1;
                }
                if let Some(from_ts) = from {
                    conditions.push(format!("ts >= ${idx}"));
                    params.push(Box::new(from_ts));
                    idx += 1;
                }
                if let Some(to_ts) = to {
                    conditions.push(format!("ts <= ${idx}"));
                    params.push(Box::new(to_ts));
                    idx += 1;
                }
                if let Some((cursor_ts, cursor_id)) = cursor {
                    // Keyset pagination: rows strictly before the cursor in (ts DESC, audit_id DESC) order.
                    let ts_idx = idx;
                    let id_idx = idx + 1;
                    conditions.push(format!(
                        "(ts < ${ts_idx} OR (ts = ${ts_idx} AND audit_id < ${id_idx}))"
                    ));
                    params.push(Box::new(cursor_ts));
                    params.push(Box::new(cursor_id));
                    idx += 2;
                }

                let where_clause = conditions.join(" AND ");
                let sql = format!(
                    "SELECT record FROM {schema}.workflow_audits \
                     WHERE {where_clause} \
                     ORDER BY ts DESC, audit_id DESC \
                     LIMIT ${idx}"
                );
                params.push(Box::new(pg_limit));

                let param_refs: Vec<&(dyn ToSql + Sync)> =
                    params.iter().map(|p| p.as_ref()).collect();
                let rows = client
                    .query(&sql, &param_refs)
                    .map_err(pg_err("list workflow audits"))?;
                rows.into_iter()
                    .map(row_to_model::<AuditLogRecord>)
                    .collect()
            })
        })
        .await
    }

    fn with_client<T, F>(&self, f: F) -> Result<T, CyberboxError>
    where
        F: FnOnce(&mut Client, &str) -> Result<T, CyberboxError>,
    {
        let mut conn = self
            .pool
            .get()
            .map_err(|err| CyberboxError::Internal(format!("workflow postgres pool get: {err}")))?;
        f(&mut conn, self.schema.as_str())
    }
}

#[async_trait::async_trait]
impl AlertStore for PostgresWorkflowStore {
    async fn upsert_alert(&self, alert: AlertRecord) -> Result<AlertRecord, CyberboxError> {
        let store = self.clone();
        run_blocking(move || {
            store.with_client(|client, schema| {
                upsert_alert_row(client, schema, &alert)?;
                Ok(alert)
            })
        })
        .await
    }

    async fn list_alerts(&self, tenant_id: &str) -> Result<Vec<AlertRecord>, CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let rows = client
                    .query(
                        &format!(
                            "SELECT record FROM {schema}.workflow_alerts \
                             WHERE tenant_id = $1 ORDER BY last_seen DESC"
                        ),
                        &[&tenant_id],
                    )
                    .map_err(pg_err("list workflow alerts by tenant"))?;
                rows.into_iter().map(row_to_model::<AlertRecord>).collect()
            })
        })
        .await
    }

    async fn acknowledge(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        _actor: &str,
    ) -> Result<AlertRecord, CyberboxError> {
        update_alert_status(self.clone(), tenant_id, alert_id, |alert| {
            alert.status = AlertStatus::Acknowledged;
            alert.last_seen = Utc::now();
        })
        .await
    }

    async fn assign(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        assignment: &AssignAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        let assignment = assignment.clone();
        update_alert_status(self.clone(), tenant_id, alert_id, move |alert| {
            alert.assignee = Some(assignment.assignee.clone());
            alert.status = AlertStatus::InProgress;
            alert.last_seen = Utc::now();
        })
        .await
    }

    async fn close(
        &self,
        tenant_id: &str,
        alert_id: Uuid,
        request: &CloseAlertRequest,
    ) -> Result<AlertRecord, CyberboxError> {
        let request = request.clone();
        update_alert_status(self.clone(), tenant_id, alert_id, move |alert| {
            alert.status = AlertStatus::Closed;
            alert.resolution = Some(request.resolution.clone());
            alert.close_note = request.note.clone();
            alert.last_seen = Utc::now();
        })
        .await
    }

    async fn suppress_or_create_alert(
        &self,
        alert: AlertRecord,
    ) -> Result<AlertRecord, CyberboxError> {
        let store = self.clone();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let mut tx = client
                    .transaction()
                    .map_err(pg_err("begin suppress workflow alert transaction"))?;
                let existing = tx
                    .query_opt(
                        &format!(
                            "SELECT record FROM {schema}.workflow_alerts \
                             WHERE tenant_id = $1 AND dedupe_key = $2 \
                               AND status IN ('open', 'inprogress') \
                             ORDER BY last_seen DESC LIMIT 1 FOR UPDATE"
                        ),
                        &[&alert.tenant_id, &alert.routing_state.dedupe_key],
                    )
                    .map_err(pg_err("select workflow alert dedupe match"))?
                    .map(row_to_model::<AlertRecord>)
                    .transpose()?;

                let saved = if let Some(mut existing) = existing {
                    existing.last_seen = alert.last_seen;
                    existing.hit_count += 1;
                    for evidence in &alert.evidence_refs {
                        if !existing.evidence_refs.contains(evidence) {
                            existing.evidence_refs.push(evidence.clone());
                        }
                    }
                    upsert_alert_row_tx(&mut tx, schema, &existing)?;
                    existing
                } else {
                    upsert_alert_row_tx(&mut tx, schema, &alert)?;
                    alert
                };
                tx.commit()
                    .map_err(pg_err("commit suppress workflow alert transaction"))?;
                Ok(saved)
            })
        })
        .await
    }
}

#[async_trait::async_trait]
impl CaseStore for PostgresWorkflowStore {
    async fn upsert_case(&self, case: CaseRecord) -> Result<CaseRecord, CyberboxError> {
        let store = self.clone();
        run_blocking(move || {
            store.with_client(|client, schema| {
                upsert_case_row(client, schema, &case)?;
                Ok(case)
            })
        })
        .await
    }

    async fn get_case(&self, tenant_id: &str, case_id: Uuid) -> Result<CaseRecord, CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let row = client
                    .query_opt(
                        &format!(
                            "SELECT record FROM {schema}.workflow_cases \
                             WHERE tenant_id = $1 AND case_id = $2"
                        ),
                        &[&tenant_id, &case_id],
                    )
                    .map_err(pg_err("get workflow case"))?
                    .ok_or(CyberboxError::NotFound)?;
                row_to_model(row)
            })
        })
        .await
    }

    async fn list_cases(&self, tenant_id: &str) -> Result<Vec<CaseRecord>, CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let rows = client
                    .query(
                        &format!(
                            "SELECT record FROM {schema}.workflow_cases \
                             WHERE tenant_id = $1 ORDER BY created_at DESC"
                        ),
                        &[&tenant_id],
                    )
                    .map_err(pg_err("list workflow cases"))?;
                rows.into_iter().map(row_to_model::<CaseRecord>).collect()
            })
        })
        .await
    }

    async fn update_case(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        patch: &UpdateCaseRequest,
        now: DateTime<Utc>,
    ) -> Result<CaseRecord, CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        let patch = patch.clone();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let mut tx = client
                    .transaction()
                    .map_err(pg_err("begin update workflow case transaction"))?;
                let row = tx
                    .query_opt(
                        &format!(
                            "SELECT record FROM {schema}.workflow_cases \
                             WHERE tenant_id = $1 AND case_id = $2 FOR UPDATE"
                        ),
                        &[&tenant_id, &case_id],
                    )
                    .map_err(pg_err("select workflow case for update"))?
                    .ok_or(CyberboxError::NotFound)?;
                let mut case: CaseRecord = row_to_model(row)?;
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
                upsert_case_row_tx(&mut tx, schema, &case)?;
                tx.commit()
                    .map_err(pg_err("commit update workflow case transaction"))?;
                Ok(case)
            })
        })
        .await
    }

    async fn delete_case(&self, tenant_id: &str, case_id: Uuid) -> Result<(), CyberboxError> {
        let store = self.clone();
        let tenant_id = tenant_id.to_string();
        run_blocking(move || {
            store.with_client(|client, schema| {
                let deleted = client
                    .execute(
                        &format!(
                            "DELETE FROM {schema}.workflow_cases \
                             WHERE tenant_id = $1 AND case_id = $2"
                        ),
                        &[&tenant_id, &case_id],
                    )
                    .map_err(pg_err("delete workflow case"))?;
                if deleted == 0 {
                    return Err(CyberboxError::NotFound);
                }
                Ok(())
            })
        })
        .await
    }
}

async fn update_alert_status<F>(
    store: PostgresWorkflowStore,
    tenant_id: &str,
    alert_id: Uuid,
    update: F,
) -> Result<AlertRecord, CyberboxError>
where
    F: FnOnce(&mut AlertRecord) + Send + 'static,
{
    let tenant_id = tenant_id.to_string();
    run_blocking(move || {
        store.with_client(|client, schema| {
            let mut tx = client
                .transaction()
                .map_err(pg_err("begin workflow alert update transaction"))?;
            let row = tx
                .query_opt(
                    &format!(
                        "SELECT record FROM {schema}.workflow_alerts \
                         WHERE tenant_id = $1 AND alert_id = $2 FOR UPDATE"
                    ),
                    &[&tenant_id, &alert_id],
                )
                .map_err(pg_err("select workflow alert for update"))?
                .ok_or(CyberboxError::NotFound)?;
            let mut alert: AlertRecord = row_to_model(row)?;
            update(&mut alert);
            upsert_alert_row_tx(&mut tx, schema, &alert)?;
            tx.commit()
                .map_err(pg_err("commit workflow alert update transaction"))?;
            Ok(alert)
        })
    })
    .await
}

fn ensure_schema(client: &mut Client, schema: &str) -> Result<(), CyberboxError> {
    let agents_last_seen_idx = format!("{schema}_workflow_agents_last_seen_idx");
    let alerts_lookup_idx = format!("{schema}_workflow_alerts_lookup_idx");
    let cases_created_idx = format!("{schema}_workflow_cases_created_idx");
    let audits_lookup_idx = format!("{schema}_workflow_audits_lookup_idx");
    let tokens_hash_idx = format!("{schema}_workflow_tokens_hash_idx");

    client
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA IF NOT EXISTS {schema};

            CREATE TABLE IF NOT EXISTS {schema}.workflow_agents (
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                last_seen TIMESTAMPTZ NOT NULL,
                record JSONB NOT NULL,
                PRIMARY KEY (tenant_id, agent_id)
            );
            CREATE INDEX IF NOT EXISTS {agents_last_seen_idx}
                ON {schema}.workflow_agents (tenant_id, last_seen DESC);

            CREATE TABLE IF NOT EXISTS {schema}.workflow_alerts (
                tenant_id TEXT NOT NULL,
                alert_id UUID NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL,
                last_seen TIMESTAMPTZ NOT NULL,
                record JSONB NOT NULL,
                PRIMARY KEY (tenant_id, alert_id)
            );
            CREATE INDEX IF NOT EXISTS {alerts_lookup_idx}
                ON {schema}.workflow_alerts (tenant_id, dedupe_key, status, last_seen DESC);

            CREATE TABLE IF NOT EXISTS {schema}.workflow_cases (
                tenant_id TEXT NOT NULL,
                case_id UUID NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                record JSONB NOT NULL,
                PRIMARY KEY (tenant_id, case_id)
            );
            CREATE INDEX IF NOT EXISTS {cases_created_idx}
                ON {schema}.workflow_cases (tenant_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS {schema}.workflow_audits (
                tenant_id TEXT NOT NULL,
                audit_id UUID NOT NULL,
                ts TIMESTAMPTZ NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                record JSONB NOT NULL,
                PRIMARY KEY (tenant_id, audit_id)
            );
            CREATE INDEX IF NOT EXISTS {audits_lookup_idx}
                ON {schema}.workflow_audits (tenant_id, ts DESC, audit_id DESC);

            CREATE TABLE IF NOT EXISTS {schema}.workflow_enrollment_tokens (
                tenant_id TEXT NOT NULL,
                token_id UUID NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used_at TIMESTAMPTZ NULL,
                revoked_at TIMESTAMPTZ NULL,
                allowed_agent_id TEXT NULL,
                record JSONB NOT NULL,
                PRIMARY KEY (tenant_id, token_id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS {tokens_hash_idx}
                ON {schema}.workflow_enrollment_tokens (tenant_id, token_hash);
            "#
        ))
        .map_err(pg_err("ensure workflow postgres schema"))?;
    Ok(())
}

fn upsert_agent_row<C>(
    client: &mut C,
    schema: &str,
    agent: &AgentRecord,
) -> Result<(), CyberboxError>
where
    C: GenericClient,
{
    let record = PgJson(to_json_value(agent)?);
    client
        .execute(
            &format!(
                "INSERT INTO {schema}.workflow_agents \
                 (tenant_id, agent_id, last_seen, record) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (tenant_id, agent_id) DO UPDATE SET \
                    last_seen = EXCLUDED.last_seen, \
                    record = EXCLUDED.record"
            ),
            &[&agent.tenant_id, &agent.agent_id, &agent.last_seen, &record],
        )
        .map_err(pg_err("upsert workflow agent"))?;
    Ok(())
}

fn upsert_agent_row_tx(
    client: &mut postgres::Transaction<'_>,
    schema: &str,
    agent: &AgentRecord,
) -> Result<(), CyberboxError> {
    upsert_agent_row(client, schema, agent)
}

fn upsert_alert_row<C>(
    client: &mut C,
    schema: &str,
    alert: &AlertRecord,
) -> Result<(), CyberboxError>
where
    C: GenericClient,
{
    let record = PgJson(to_json_value(alert)?);
    let status = status_label(&alert.status);
    client
        .execute(
            &format!(
                "INSERT INTO {schema}.workflow_alerts \
                 (tenant_id, alert_id, dedupe_key, status, last_seen, record) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (tenant_id, alert_id) DO UPDATE SET \
                    dedupe_key = EXCLUDED.dedupe_key, \
                    status = EXCLUDED.status, \
                    last_seen = EXCLUDED.last_seen, \
                    record = EXCLUDED.record"
            ),
            &[
                &alert.tenant_id,
                &alert.alert_id,
                &alert.routing_state.dedupe_key,
                &status,
                &alert.last_seen,
                &record,
            ],
        )
        .map_err(pg_err("upsert workflow alert"))?;
    Ok(())
}

fn upsert_alert_row_tx(
    client: &mut postgres::Transaction<'_>,
    schema: &str,
    alert: &AlertRecord,
) -> Result<(), CyberboxError> {
    upsert_alert_row(client, schema, alert)
}

fn upsert_case_row<C>(client: &mut C, schema: &str, case: &CaseRecord) -> Result<(), CyberboxError>
where
    C: GenericClient,
{
    let record = PgJson(to_json_value(case)?);
    let status = case_status_label(&case.status);
    client
        .execute(
            &format!(
                "INSERT INTO {schema}.workflow_cases \
                 (tenant_id, case_id, status, created_at, record) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (tenant_id, case_id) DO UPDATE SET \
                    status = EXCLUDED.status, \
                    created_at = EXCLUDED.created_at, \
                    record = EXCLUDED.record"
            ),
            &[
                &case.tenant_id,
                &case.case_id,
                &status,
                &case.created_at,
                &record,
            ],
        )
        .map_err(pg_err("upsert workflow case"))?;
    Ok(())
}

fn upsert_case_row_tx(
    client: &mut postgres::Transaction<'_>,
    schema: &str,
    case: &CaseRecord,
) -> Result<(), CyberboxError> {
    upsert_case_row(client, schema, case)
}

fn upsert_audit_row<C>(
    client: &mut C,
    schema: &str,
    audit: &AuditLogRecord,
) -> Result<(), CyberboxError>
where
    C: GenericClient,
{
    let record = PgJson(to_json_value(audit)?);
    client
        .execute(
            &format!(
                "INSERT INTO {schema}.workflow_audits \
                 (tenant_id, audit_id, ts, action, entity_type, actor, record) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (tenant_id, audit_id) DO UPDATE SET \
                    ts = EXCLUDED.ts, \
                    action = EXCLUDED.action, \
                    entity_type = EXCLUDED.entity_type, \
                    actor = EXCLUDED.actor, \
                    record = EXCLUDED.record"
            ),
            &[
                &audit.tenant_id,
                &audit.audit_id,
                &audit.timestamp,
                &audit.action,
                &audit.entity_type,
                &audit.actor,
                &record,
            ],
        )
        .map_err(pg_err("upsert workflow audit"))?;
    Ok(())
}

fn upsert_enrollment_token_row<C>(
    client: &mut C,
    schema: &str,
    token: &AgentEnrollmentTokenRecord,
) -> Result<(), CyberboxError>
where
    C: GenericClient,
{
    let record = PgJson(to_json_value(token)?);
    client
        .execute(
            &format!(
                "INSERT INTO {schema}.workflow_enrollment_tokens \
                 (tenant_id, token_id, token_hash, expires_at, used_at, revoked_at, allowed_agent_id, record) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (tenant_id, token_id) DO UPDATE SET \
                    token_hash = EXCLUDED.token_hash, \
                    expires_at = EXCLUDED.expires_at, \
                    used_at = EXCLUDED.used_at, \
                    revoked_at = EXCLUDED.revoked_at, \
                    allowed_agent_id = EXCLUDED.allowed_agent_id, \
                    record = EXCLUDED.record"
            ),
            &[
                &token.tenant_id,
                &token.token_id,
                &token.token_hash,
                &token.expires_at,
                &token.used_at,
                &token.revoked_at,
                &token.allowed_agent_id,
                &record,
            ],
        )
        .map_err(pg_err("upsert workflow enrollment token"))?;
    Ok(())
}

fn upsert_enrollment_token_row_tx(
    client: &mut postgres::Transaction<'_>,
    schema: &str,
    token: &AgentEnrollmentTokenRecord,
) -> Result<(), CyberboxError> {
    upsert_enrollment_token_row(client, schema, token)
}

fn row_to_model<T>(row: Row) -> Result<T, CyberboxError>
where
    T: DeserializeOwned,
{
    let record: PgJson<Value> = row
        .try_get("record")
        .map_err(|err| CyberboxError::Internal(format!("decode workflow record column: {err}")))?;
    serde_json::from_value(record.0)
        .map_err(|err| CyberboxError::Internal(format!("decode workflow record payload: {err}")))
}

fn to_json_value<T>(value: &T) -> Result<Value, CyberboxError>
where
    T: Serialize,
{
    serde_json::to_value(value)
        .map_err(|err| CyberboxError::Internal(format!("serialize workflow record: {err}")))
}

fn sanitize_identifier(value: &str) -> Result<String, CyberboxError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CyberboxError::Internal(
            "workflow postgres schema must not be empty".to_string(),
        ));
    }
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return Err(CyberboxError::Internal(
            "workflow postgres schema must not be empty".to_string(),
        ));
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(CyberboxError::Internal(format!(
            "workflow postgres schema '{}' must start with a letter or underscore",
            trimmed
        )));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(CyberboxError::Internal(format!(
            "workflow postgres schema '{}' contains invalid characters",
            trimmed
        )));
    }
    Ok(trimmed.to_string())
}

fn status_label(status: &AlertStatus) -> &'static str {
    match status {
        AlertStatus::Open => "open",
        AlertStatus::Acknowledged => "acknowledged",
        AlertStatus::InProgress => "inprogress",
        AlertStatus::Closed => "closed",
    }
}

fn case_status_label(status: &CaseStatus) -> &'static str {
    match status {
        CaseStatus::Open => "open",
        CaseStatus::InProgress => "inprogress",
        CaseStatus::Resolved => "resolved",
        CaseStatus::Closed => "closed",
    }
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

fn pg_err(context: &'static str) -> impl FnOnce(postgres::Error) -> CyberboxError {
    move |err| CyberboxError::Internal(format!("{context}: {err}"))
}

async fn run_blocking<T, F>(f: F) -> Result<T, CyberboxError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CyberboxError> + Send + 'static,
{
    task::spawn_blocking(f)
        .await
        .map_err(|err| CyberboxError::Internal(format!("workflow blocking task failed: {err}")))?
}
