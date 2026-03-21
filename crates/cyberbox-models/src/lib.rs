use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use uuid::Uuid;

fn deserialize_nullable_patch_field<'de, D, T>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Syslog,
    Otlp,
    AgentForwarded,
    WindowsSysmon,
    LinuxAudit,
    LinuxAuth,
    Firewall,
    CloudAudit,
    EntraId,
    O365,
    Okta,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: Uuid,
    pub tenant_id: String,
    pub source: EventSource,
    pub event_time: DateTime<Utc>,
    pub ingest_time: DateTime<Utc>,
    pub raw_payload: Value,
    pub ocsf_record: Value,
    pub enrichment: EnrichmentMetadata,
    pub integrity_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnrichmentMetadata {
    pub asset_tags: Vec<String>,
    pub geoip: Option<GeoIpContext>,
    pub ioc_matches: Vec<IocMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpContext {
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub indicator_type: String,
    pub indicator_value: String,
    pub feed_name: String,
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMode {
    Stream,
    Scheduled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleScheduleConfig {
    pub interval_seconds: u32,
    pub lookback_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub rule_id: Uuid,
    pub tenant_id: String,
    pub sigma_source: String,
    pub compiled_plan: Value,
    pub schedule_or_stream: DetectionMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<RuleScheduleConfig>,
    pub severity: Severity,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_health: Option<RuleSchedulerHealth>,
    /// Threshold: minimum number of matching events before an alert fires.
    /// `None` or `1` = fire on every match (default behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_count: Option<u32>,
    /// Field used to group events for threshold counting (e.g. `"src_ip"`).
    /// `None` = count all events globally for this rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_group_by: Option<String>,
    /// Cooldown: suppress repeat alerts for this many seconds after the rule fires.
    /// `None` or `0` = no suppression (every match fires an alert).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression_window_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSchedulerHealth {
    pub run_count: u64,
    pub skipped_by_interval_count: u64,
    pub match_count: u64,
    pub error_count: u64,
    pub last_run_duration_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTestRequest {
    pub sample_event: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTestResult {
    pub matched: bool,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    InProgress,
    Closed,
}

/// Why an alert was closed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertResolution {
    TruePositive,
    FalsePositive,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseAlertRequest {
    pub actor: String,
    pub resolution: AlertResolution,
    /// Optional free-text note captured in the audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A parsed MITRE ATT&CK technique reference extracted from a Sigma rule's `tags:` block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MitreAttack {
    /// Canonical technique ID, e.g. `"T1059.001"`.
    pub technique_id: String,
    /// ATT&CK tactic slug, e.g. `"execution"`. `None` for unknown techniques.
    pub tactic: Option<String>,
    /// Human-readable technique name. `None` for unknown techniques.
    pub technique_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub alert_id: Uuid,
    pub tenant_id: String,
    pub rule_id: Uuid,
    /// Severity inherited from the triggering rule at fire time.
    #[serde(default)]
    pub severity: Severity,
    /// Human-readable title from the Sigma rule's `title:` field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule_title: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: AlertStatus,
    pub evidence_refs: Vec<String>,
    pub routing_state: RoutingState,
    pub assignee: Option<String>,
    /// Linked case, if this alert has been attached to an investigation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<Uuid>,
    #[serde(default = "default_one")]
    pub hit_count: u64,
    /// MITRE ATT&CK techniques referenced by the triggering rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_attack: Vec<MitreAttack>,
    /// Resolution set when the alert is closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<AlertResolution>,
    /// Optional analyst note captured at close time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_note: Option<String>,
    /// Metadata injected at alert-fire time when the source event came from a
    /// registered cyberbox-agent (agent_id, hostname, os, version, group, tags).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_meta: Option<serde_json::Value>,
}

fn default_one() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingState {
    pub destinations: Vec<String>,
    pub last_routed_at: Option<DateTime<Utc>>,
    pub dedupe_key: String,
    pub suppression_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQueryRequest {
    pub tenant_id: String,
    pub sql: String,
    pub time_range: TimeRange,
    pub filters: Vec<QueryFilter>,
    pub pagination: Pagination,
    /// Optional extra WHERE clause injected by the NLQ engine.
    /// Appended after the mandatory tenant_id + time_range predicates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_where: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFilter {
    pub field: String,
    pub op: String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub page: u32,
    pub page_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQueryResponse {
    pub rows: Vec<Value>,
    pub total: u64,
    /// `true` when more rows exist beyond the current page.
    #[serde(default)]
    pub has_more: bool,
    /// Cursor for the next page — pass as `pagination.page` + 1 (currently page-number based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventIngestRequest {
    pub events: Vec<IncomingEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingEvent {
    pub tenant_id: String,
    pub source: EventSource,
    pub raw_payload: Value,
    pub event_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventIngestResponse {
    pub accepted: usize,
    pub rejected: usize,
    pub rejected_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckAlertRequest {
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignAlertRequest {
    pub actor: String,
    /// Tri-state patch: omitted = invalid request, null/empty = clear, string = set.
    #[serde(default, deserialize_with = "deserialize_nullable_patch_field")]
    pub assignee: Option<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub audit_id: Uuid,
    pub tenant_id: String,
    pub actor: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub timestamp: DateTime<Utc>,
    pub before: Value,
    pub after: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogsResponse {
    pub entries: Vec<AuditLogRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqMessage {
    pub stage: String,
    pub reason: String,
    pub source_topic: String,
    pub source_partition: i32,
    pub source_offset: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRequest {
    pub target_topic: String,
    pub payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub requested_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReplayRequest {
    pub target_topic: String,
    pub payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayFromDlqRequest {
    pub dlq_message: DlqMessage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_topic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRequestResponse {
    pub status: String,
    pub target_topic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub requested_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

// ─── Detection Engineering Endpoints ─────────────────────────────────────────

/// Request body for `POST /api/v1/rules/dry-run`.
/// Compiles a rule from source and evaluates it against a sample event — no persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunRequest {
    pub sigma_source: String,
    pub severity: Severity,
    pub sample_event: Value,
}

/// Response from `POST /api/v1/rules/dry-run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunResponse {
    /// `"ok"` on successful compile, or `"error: <message>"` if the YAML is invalid.
    pub compile_result: String,
    pub matched: bool,
    pub reasoning: String,
}

/// Request body for `POST /api/v1/rules/:id/backtest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacktestRequest {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// Maximum events to scan (default: 10 000, hard cap: 100 000).
    #[serde(default)]
    pub max_events: Option<u64>,
}

/// Response from `POST /api/v1/rules/:id/backtest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacktestResponse {
    pub rule_id: Uuid,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub total_events_scanned: u64,
    pub matched_count: u64,
    pub match_rate_pct: f64,
    /// Event IDs of the first (up to 10) matched events.
    pub sample_event_ids: Vec<String>,
}

/// A MITRE ATT&CK technique covered by at least one active rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoveredTechnique {
    pub technique_id: String,
    pub tactic: Option<String>,
    pub technique_name: Option<String>,
    pub rule_count: usize,
    pub rule_ids: Vec<Uuid>,
}

/// Response from `GET /api/v1/coverage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub covered_techniques: Vec<CoveredTechnique>,
    pub total_covered: usize,
    pub total_in_framework: usize,
    pub coverage_pct: f64,
}

// ─── Case Management ──────────────────────────────────────────────────────────

/// Lifecycle status of an incident case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Newly created, not yet investigated.
    Open,
    /// Analyst has started investigation.
    InProgress,
    /// Root cause identified; remediation in progress.
    Resolved,
    /// Case fully closed (true positive, false positive, or informational).
    Closed,
}

/// Analyst-recorded outcome when a case is closed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseResolution {
    TpContained,
    TpNotContained,
    BenignTp,
    FalsePositive,
    Duplicate,
}

/// An incident case groups one or more alerts into a single investigation workflow.
///
/// SLA deadlines are automatically computed from `severity` at creation time:
/// - Critical → 15 min, High → 1 h, Medium → 4 h, Low → 24 h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRecord {
    pub case_id: Uuid,
    pub tenant_id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub status: CaseStatus,
    pub severity: Severity,
    /// Alert IDs attached to this case.
    #[serde(default)]
    pub alert_ids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// SLA response deadline computed at creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sla_due_at: Option<DateTime<Utc>>,
    /// Timestamp when the case transitioned to Resolved or Closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,
    /// Analyst-recorded outcome when the case is closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<CaseResolution>,
    /// Optional analyst note captured when the case is closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_note: Option<String>,
    /// Analyst-defined labels for grouping / filtering.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Request body for `POST /api/v1/cases`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaseRequest {
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    #[serde(default)]
    pub alert_ids: Vec<Uuid>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Request body for `PATCH /api/v1/cases/:id`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateCaseRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub status: Option<CaseStatus>,
    pub severity: Option<Severity>,
    /// Tri-state patch: omitted = leave unchanged, null = clear, string = set.
    #[serde(default, deserialize_with = "deserialize_nullable_patch_field")]
    pub assignee: Option<Option<String>>,
    pub resolution: Option<CaseResolution>,
    pub close_note: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Request body for `POST /api/v1/cases/:id/alerts` and
/// `DELETE /api/v1/cases/:id/alerts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseAlertIdsRequest {
    pub alert_ids: Vec<Uuid>,
}

// ─── Cursor-paginated alert listing ───────────────────────────────────────────

/// Query parameters for `GET /api/v1/alerts`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ListAlertsQuery {
    /// Opaque cursor returned by a previous page response (base64-encoded position).
    #[serde(default)]
    pub after: Option<String>,
    /// Maximum alerts to return per page. Capped at 500 server-side; defaults to 100.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Filter by status (open | acknowledged | in_progress | closed).
    #[serde(default)]
    pub status: Option<String>,
    /// Filter by severity (low | medium | high | critical).
    #[serde(default)]
    pub severity: Option<String>,
}

/// Paginated alert list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsPage {
    pub alerts: Vec<AlertRecord>,
    /// Opaque cursor to pass as `after=` in the next request. `null` when this
    /// is the last page.
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub total: usize,
}

// ─── Source tracking ─────────────────────────────────────────────────────────

/// Per-source ingestion statistics exposed via `GET /api/v1/sources`.
/// A "source" is identified by `(tenant_id, source_type)` where `source_type`
/// is the `EventSource` discriminant string (e.g. `"syslog"`, `"firewall"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    /// Tenant that owns this source.
    pub tenant_id: String,
    /// EventSource discriminant (e.g. `"syslog"`, `"windows_sysmon"`).
    pub source_type: String,
    /// ISO 8601 timestamp of the first event seen from this source.
    pub first_seen: DateTime<Utc>,
    /// ISO 8601 timestamp of the most recent event from this source.
    pub last_seen: DateTime<Utc>,
    /// Total events accepted from this source since the API started.
    pub total_events: u64,
    /// Status derived from last_seen: "active" (<60 s), "stale" (<5 min), "silent".
    pub status: String,
}

// ─── Agent registry ───────────────────────────────────────────────────────────

/// Record for a cyberbox-agent that has registered with the API.
/// Status is computed on read: "active" (<90s), "stale" (<5min), "offline".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    /// Stable agent identifier (UUID or hostname-based string sent at registration)
    pub agent_id: String,
    pub tenant_id: String,
    pub hostname: String,
    /// OS name (e.g. "linux", "windows")
    pub os: String,
    /// Agent version string
    pub version: String,
    /// Source IP of the registration request
    pub ip: Option<String>,
    pub registered_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Logical group this agent belongs to (e.g. "prod-web", "dc-emea")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Arbitrary labels for filtering/display (e.g. ["linux", "critical"])
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Pending TOML config to deliver on the next heartbeat. Cleared after delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_config: Option<String>,
    /// When the machine completed the enrollment workflow and was issued a credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<DateTime<Utc>>,
    /// Monotonic credential generation. Incremented on every enrollment/rotation.
    #[serde(default)]
    pub credential_version: u64,
    /// SHA-256 hash of the current machine secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_hash: Option<String>,
    /// When the current credential was last issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_rotated_at: Option<DateTime<Utc>>,
    /// Current signed device certificate serial tracked for revocation/rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_certificate_serial: Option<String>,
    /// Expiry of the currently active signed device certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_certificate_expires_at: Option<DateTime<Utc>>,
    /// Revoked agents are denied registration and heartbeat until re-enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
}

impl AgentRecord {
    /// Computed status based on time since last heartbeat.
    pub fn status(&self) -> &'static str {
        if self.revoked_at.is_some() {
            return "revoked";
        }
        let secs = (Utc::now() - self.last_seen).num_seconds();
        if secs < 90 {
            "active"
        } else if secs < 300 {
            "stale"
        } else {
            "offline"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAgentEnrollmentTokenRequest {
    /// Token lifetime in seconds. Defaults to 1 hour and is capped server-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Optional fixed agent ID this token is allowed to enroll.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_agent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentTokenRecord {
    pub token_id: Uuid,
    pub tenant_id: String,
    pub issued_by: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub token_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentTokenResponse {
    pub token_id: Uuid,
    pub tenant_id: String,
    pub enrollment_token: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_agent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollRequest {
    pub enrollment_token: String,
    pub agent_id: String,
    pub tenant_id: String,
    pub hostname: String,
    pub os: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollResponse {
    pub agent_id: String,
    pub tenant_id: String,
    pub status: String,
    pub agent_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_certificate_serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_certificate_expires_at: Option<DateTime<Utc>>,
    pub credential_version: u64,
    pub enrolled_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateAgentCredentialResponse {
    pub agent_id: String,
    pub tenant_id: String,
    pub agent_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_certificate_serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_certificate_expires_at: Option<DateTime<Utc>>,
    pub credential_version: u64,
    pub rotated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeAgentRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ─── Rule versioning ──────────────────────────────────────────────────────────

/// An immutable snapshot of a detection rule at the time it was created or
/// last modified. Appended on every successful `upsert_rule` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleVersion {
    pub rule_id: Uuid,
    pub tenant_id: String,
    /// Monotonically increasing version number (starts at 1).
    pub version: u32,
    pub sigma_source: String,
    pub compiled_plan: serde_json::Value,
    pub severity: Severity,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn case_record_serializes_empty_collections() {
        let case = CaseRecord {
            case_id: Uuid::nil(),
            tenant_id: "tenant-a".to_string(),
            title: "Test case".to_string(),
            description: String::new(),
            status: CaseStatus::Open,
            severity: Severity::Medium,
            alert_ids: vec![],
            assignee: None,
            created_by: "soc-admin".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            sla_due_at: None,
            closed_at: None,
            resolution: None,
            close_note: None,
            tags: vec![],
        };

        let value = serde_json::to_value(case).expect("case should serialize");

        assert_eq!(value["alert_ids"], json!([]));
        assert_eq!(value["tags"], json!([]));
    }
}
