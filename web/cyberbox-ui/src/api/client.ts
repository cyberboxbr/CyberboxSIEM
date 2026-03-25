// ---------------------------------------------------------------------------
// CyberboxSIEM — Full API Client
// ---------------------------------------------------------------------------

// ── Shared scalars ─────────────────────────────────────────────────────────

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type DetectionMode = 'stream' | 'scheduled';
export type AlertStatus = 'open' | 'acknowledged' | 'in_progress' | 'closed';
export type AlertResolution = 'true_positive' | 'false_positive' | 'informational';
export type CaseStatus = 'open' | 'in_progress' | 'resolved' | 'closed';
export type CaseResolution =
  | 'tp_contained'
  | 'tp_not_contained'
  | 'benign_tp'
  | 'false_positive'
  | 'duplicate';
export type AgentStatus = 'active' | 'stale' | 'offline';
export type FeedType = 'taxii' | 'stix' | 'csv' | 'json';

// ── Token provider ────────────────────────────────────────────────────────

/**
 * Function that returns a Bearer access token. Set by the AuthContext once
 * the user is authenticated via MSAL. When null, requests fall back to
 * dev-mode identity headers (for local development with auth_disabled=true).
 */
let tokenProvider: (() => Promise<string>) | null = null;
let pendingToken: Promise<string> | null = null;

export interface FallbackIdentity {
  tenantId: string;
  userId: string;
  roles: string[];
}

export const DEFAULT_FALLBACK_IDENTITY: FallbackIdentity = {
  tenantId: 'tenant-a',
  userId: 'soc-admin',
  roles: ['admin', 'analyst', 'viewer', 'ingestor'],
};

function normalizeIdentityRoles(
  roles: string | string[] | undefined,
  fallback: string[] = DEFAULT_FALLBACK_IDENTITY.roles,
): string[] {
  const source = Array.isArray(roles)
    ? roles
    : typeof roles === 'string'
      ? roles.split(',')
      : fallback;

  return source
    .map((role) => role.trim())
    .filter(Boolean)
    .filter((role, index, list) => list.indexOf(role) === index);
}

export function getDefaultFallbackIdentity(): FallbackIdentity {
  return {
    tenantId: DEFAULT_FALLBACK_IDENTITY.tenantId,
    userId: DEFAULT_FALLBACK_IDENTITY.userId,
    roles: [...DEFAULT_FALLBACK_IDENTITY.roles],
  };
}

export function normalizeFallbackIdentity(identity: Partial<FallbackIdentity>): FallbackIdentity {
  return {
    tenantId: identity.tenantId?.trim() || DEFAULT_FALLBACK_IDENTITY.tenantId,
    userId: identity.userId?.trim() || DEFAULT_FALLBACK_IDENTITY.userId,
    roles: normalizeIdentityRoles(identity.roles),
  };
}

/**
 * Called by AuthContext after login to wire up token acquisition.
 */
export function setTokenProvider(provider: (() => Promise<string>) | null): void {
  tokenProvider = provider;
  pendingToken = null;
}

// ── Dev-mode identity headers (used when no token provider is set) ────────

const initialFallbackIdentity = getDefaultFallbackIdentity();

const BASE_HEADERS: Record<string, string> = {
  'x-tenant-id': initialFallbackIdentity.tenantId,
  'x-user-id': initialFallbackIdentity.userId,
  'x-roles': initialFallbackIdentity.roles.join(','),
};

/**
 * Override the dev-mode identity headers (only used when auth is disabled).
 */
export function setIdentity(
  tenantId: string,
  userId: string,
  roles: string | string[],
): void {
  const next = normalizeFallbackIdentity({
    tenantId,
    userId,
    roles: normalizeIdentityRoles(roles, []),
  });

  BASE_HEADERS['x-tenant-id'] = next.tenantId;
  BASE_HEADERS['x-user-id'] = next.userId;
  BASE_HEADERS['x-roles'] = next.roles.join(',');
}

export function getFallbackIdentity(): FallbackIdentity {
  return normalizeFallbackIdentity({
    tenantId: BASE_HEADERS['x-tenant-id'],
    userId: BASE_HEADERS['x-user-id'],
    roles: normalizeIdentityRoles(BASE_HEADERS['x-roles'], []),
  });
}

/**
 * Generic fetch wrapper — attaches Bearer token (production) or identity
 * headers (dev mode), throws on non-2xx, and returns parsed JSON.
 */
async function apiRequest<T>(url: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...(init.headers as Record<string, string> ?? {}),
  };

  if (tokenProvider) {
    try {
      if (!pendingToken) {
        pendingToken = tokenProvider().finally(() => {
          pendingToken = null;
        });
      }
      const token = await pendingToken;
      headers['Authorization'] = `Bearer ${token}`;
    } catch (e) {
      console.warn('Token acquisition failed', e);
      throw new Error('Authentication failed. Please sign in again.');
    }
  } else {
    // Dev mode: use plain identity headers (auth_disabled=true on backend)
    Object.assign(headers, BASE_HEADERS);
  }

  const response = await fetch(url, { ...init, headers });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API ${response.status}: ${text}`);
  }

  const ct = response.headers.get('content-type') ?? '';
  if (ct.includes('application/json')) {
    return response.json() as Promise<T>;
  }
  return response.text() as unknown as Promise<T>;
}

/**
 * Build a query-string from an object, omitting undefined/null values.
 */
function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

/**
 * Derive a WebSocket URL from the current page origin.
 * Automatically switches http→ws / https→wss.
 */
export function buildWsUrl(path: string, params?: Record<string, string>): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const base = `${proto}//${window.location.host}${path}`;
  if (!params) return base;
  const sp = new URLSearchParams(params);
  return `${base}?${sp.toString()}`;
}

// ── Interfaces: Health & Metrics ───────────────────────────────────────────

export interface HealthResponse {
  status: string;
  time: string;
}

// ── Interfaces: Events ─────────────────────────────────────────────────────

export interface IngestEvent {
  tenant_id?: string;
  source: string;
  event_time: string;
  raw_payload: Record<string, unknown>;
}

export interface IngestResponse {
  accepted: number;
  rejected: number;
  alerts_generated: number;
}

export interface SourceInfo {
  tenant_id?: string;
  source_type: string;
  first_seen?: string;
  last_seen?: string;
  total_events: number;
  status?: string;
}

// ── Interfaces: Rules ──────────────────────────────────────────────────────

export interface RuleScheduleConfig {
  interval_seconds: number;
  lookback_seconds: number;
}

export interface RuleSchedulerHealth {
  run_count: number;
  skipped_by_interval_count: number;
  match_count: number;
  error_count: number;
  last_run_duration_seconds: number;
}

export interface DetectionRule {
  rule_id: string;
  tenant_id: string;
  sigma_source: string;
  compiled_plan: Record<string, unknown>;
  schedule_or_stream: DetectionMode;
  schedule?: RuleScheduleConfig;
  severity: Severity;
  enabled: boolean;
  scheduler_health?: RuleSchedulerHealth;
}

export interface RuleCreateInput {
  sigma_source: string;
  schedule_or_stream: DetectionMode;
  schedule?: RuleScheduleConfig;
  severity: Severity;
  enabled: boolean;
}

export interface RuleUpdateInput {
  sigma_source?: string;
  schedule_or_stream?: DetectionMode;
  schedule?: RuleScheduleConfig;
  severity?: Severity;
  enabled?: boolean;
}

export interface RuleTestResult {
  matched: boolean;
  matched_conditions: string[];
  error?: string;
}

export interface DryRunInput {
  sigma_source: string;
  severity: Severity;
  sample_event: Record<string, unknown>;
}

export interface DryRunResult {
  compile_result: Record<string, unknown>;
  matched: boolean;
  matched_conditions: string[];
  error?: string;
}

export interface BacktestInput {
  from: string;
  to: string;
}

export interface BacktestResult {
  total_events_scanned: number;
  matched_count: number;
  match_rate_pct: number;
  sample_event_ids: string[];
}

export interface RuleVersion {
  version: number;
  sigma_source: string;
  severity: Severity;
  enabled: boolean;
  created_at: string;
}

export interface ImportPackInput {
  path: string;
  prune?: boolean;
}

export interface ImportResult {
  imported: number;
  updated: number;
  skipped: number;
  errors: string[];
  pruned?: number;
}

export interface GenerateRuleInput {
  description: string;
}

export interface GenerateRuleResult {
  sigma_source: string;
  explanation: string;
}

export interface TuneRuleResult {
  suggested_sigma_source: string;
  explanation: string;
  changes: string[];
}

export interface ExplainAlertResult {
  summary: string;
  why_suspicious: string;
  likely_cause: string;
  recommended_actions: string[];
  false_positive_likelihood: string;
}

// ── Interfaces: Alerts ─────────────────────────────────────────────────────

export interface MitreAttack {
  technique_id: string;
  tactic: string;
  technique_name: string;
}

export interface RoutingState {
  dedupe_key: string;
  destinations: string[];
  suppression_until?: string;
}

export interface AgentMeta {
  hostname: string;
  os: string;
  group: string;
  tags: string[];
}

export interface AlertRecord {
  alert_id: string;
  tenant_id: string;
  rule_id: string;
  severity: Severity;
  rule_title: string;
  first_seen: string;
  last_seen: string;
  status: AlertStatus;
  hit_count: number;
  evidence_refs: string[];
  assignee?: string;
  case_id?: string;
  mitre_attack: MitreAttack[];
  routing_state: RoutingState;
  resolution?: AlertResolution;
  close_note?: string;
  agent_meta?: AgentMeta;
}

export interface AlertsPage {
  alerts: AlertRecord[];
  next_cursor?: string;
  has_more: boolean;
  total: number;
}

export interface AlertsQuery {
  after?: string;
  limit?: number;
  status?: AlertStatus;
  severity?: Severity;
}

export interface WsTokenResponse {
  token: string;
  expires_in_seconds: number;
}

// ── Interfaces: Cases ──────────────────────────────────────────────────────

export interface CaseRecord {
  case_id: string;
  title: string;
  description?: string;
  status: CaseStatus;
  severity: Severity;
  assignee?: string;
  alert_ids: string[];
  sla_due_at?: string;
  closed_at?: string;
  resolution?: CaseResolution;
  close_note?: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

type ApiCaseRecord = Omit<
  CaseRecord,
  'description' | 'status' | 'severity' | 'assignee' | 'alert_ids' | 'sla_due_at' | 'closed_at' | 'resolution' | 'close_note' | 'tags'
> & {
  description?: string | null;
  status?: CaseStatus | null;
  severity?: Severity | null;
  assignee?: string | null;
  alert_ids?: string[] | null;
  sla_due_at?: string | null;
  closed_at?: string | null;
  resolution?: CaseResolution | null;
  close_note?: string | null;
  tags?: string[] | null;
};

export interface CaseCreateInput {
  title: string;
  description?: string;
  severity: Severity;
  assignee?: string;
  tags?: string[];
  alert_ids?: string[];
}

export interface CaseUpdateInput {
  title?: string;
  description?: string;
  status?: CaseStatus;
  severity?: Severity;
  assignee?: string | null;
  resolution?: CaseResolution | null;
  close_note?: string | null;
  tags?: string[];
}

function normalizeCaseRecord(record: ApiCaseRecord): CaseRecord {
  return {
    ...record,
    description: record.description ?? '',
    status: record.status ?? 'open',
    severity: record.severity ?? 'medium',
    assignee: record.assignee ?? undefined,
    alert_ids: Array.isArray(record.alert_ids) ? record.alert_ids : [],
    sla_due_at: record.sla_due_at ?? undefined,
    closed_at: record.closed_at ?? undefined,
    resolution: record.resolution ?? undefined,
    close_note: record.close_note ?? undefined,
    tags: Array.isArray(record.tags) ? record.tags : [],
  };
}

function normalizeCaseRecords(records: ApiCaseRecord[] | null | undefined): CaseRecord[] {
  return (records ?? []).map(normalizeCaseRecord);
}

// ── Interfaces: Search ─────────────────────────────────────────────────────

export interface TimeRange {
  start: string;
  end: string;
}

export interface SearchPagination {
  page: number;
  page_size: number;
  cursor?: string;
}

export interface SearchQueryInput {
  sql: string;
  time_range: TimeRange;
  filters?: unknown[];
  pagination?: SearchPagination;
}

export interface SearchQueryResponse {
  rows: Array<Record<string, unknown>>;
  has_more: boolean;
  next_cursor?: string;
  total?: number;
}

export interface NlqInput {
  query: string;
  time_range?: TimeRange;
}

export interface NlqResponse {
  rows: Array<Record<string, unknown>>;
  generated_where: string;
  interpreted_as: string;
  time_range: TimeRange;
  total?: number;
}

// ── Interfaces: MITRE Coverage ─────────────────────────────────────────────

export interface CoveredTechnique {
  technique_id: string;
  technique_name: string | null;
  tactic: string | null;
  rule_count: number;
  rule_ids: string[];
}

export interface CoverageReport {
  total_in_framework: number;
  total_covered: number;
  coverage_pct: number;
  covered_techniques: CoveredTechnique[];
}

// ── Interfaces: Threat Intelligence ────────────────────────────────────────

export interface ThreatIntelFeed {
  feed_id: string;
  name: string;
  feed_type: FeedType;
  url: string;
  auto_sync_interval_secs: number;
  enabled: boolean;
  ioc_count: number;
  last_synced_at?: string;
}

export interface ThreatIntelFeedCreateInput {
  name: string;
  feed_type: FeedType;
  url: string;
  auto_sync_interval_secs?: number;
  enabled?: boolean;
}

// ── Interfaces: Agents ─────────────────────────────────────────────────────

export interface AgentRecord {
  agent_id: string;
  tenant_id: string;
  hostname: string;
  os: string;
  version: string;
  ip?: string;
  last_seen: string;
  group?: string;
  tags: string[];
  status: AgentStatus;
}

export interface AgentUpdateInput {
  group?: string | null;
  tags?: string[];
  hostname?: string | null;
  os?: string | null;
  ip?: string | null;
}

export interface AgentRegisterInput {
  hostname: string;
  os: string;
  version: string;
  ip?: string;
  group?: string;
  tags?: string[];
}

// ── Interfaces: Audit Logs ─────────────────────────────────────────────────

export interface AuditLogRecord {
  audit_id: string;
  tenant_id: string;
  actor: string;
  action: string;
  entity_type: string;
  entity_id: string;
  timestamp: string;
  before: unknown;
  after: unknown;
}

export interface AuditLogsQuery {
  action?: string;
  actor?: string;
  entity_type?: string;
  from?: string;
  to?: string;
  cursor?: string;
  limit?: number;
}

export interface AuditLogsResponse {
  entries: AuditLogRecord[];
  next_cursor?: string;
  has_more: boolean;
}

// ── Interfaces: RBAC ───────────────────────────────────────────────────────

export interface RbacEntry {
  user_id: string;
  roles: string[];
}

// ── Interfaces: LGPD ───────────────────────────────────────────────────────

export interface LgpdExportInput {
  subject_id: string;
}

export interface LgpdExportResponse {
  controller_name: string;
  dpo_email: string;
  legal_basis: string;
  subject_id: string;
  tenant_id: string;
  generated_at: string;
  events: Array<Record<string, unknown>>;
  total_events: number;
}

export interface LgpdAnonymizeInput {
  subject_id: string;
  before?: string;
}

export interface LgpdAnonymizeResponse {
  subject_id: string;
  tenant_id: string;
  anonymized_events: number;
}

export interface LgpdBreachReportInput {
  description: string;
  data_categories: string[];
  estimated_subjects_affected: number;
  reported_to_anpd?: boolean;
}

export interface LgpdBreachReportResponse {
  incident_id: string;
  tenant_id: string;
  reported_at: string;
  anpd_notification_deadline: string;
  reported_to_anpd: boolean;
}

export interface LgpdConfig {
  dpo_email: string;
  legal_basis: string;
  controller_name: string;
}

// ── Interfaces: Scheduler ──────────────────────────────────────────────────

export interface SchedulerTickResponse {
  rules_scanned: number;
  alerts_emitted: number;
}

// ── Interfaces: Lookup Tables ──────────────────────────────────────────────

export interface LookupTable {
  name: string;
  columns: string[];
  row_count: number;
}

export interface LookupTableCreateInput {
  name: string;
  columns: string[];
  rows: Array<Record<string, string>>;
}

// ═══════════════════════════════════════════════════════════════════════════
//  API Functions
// ═══════════════════════════════════════════════════════════════════════════

// ── Health & Metrics ───────────────────────────────────────────────────────

export async function healthCheck(): Promise<HealthResponse> {
  return apiRequest<HealthResponse>('/healthz');
}

export async function getMetrics(): Promise<string> {
  return apiRequest<string>('/metrics');
}

// ── Dashboard ─────────────────────────────────────────────────────────────

export interface DashboardStats {
  total_events: number;
  events_by_source: { source: string; count: string }[];
  events_by_host: { hostname: string; count: string }[];
  hourly_events: { bucket: string; count: string }[];
  active_agents: number;
  total_agents: number;
  agents: { agent_id: string; hostname: string; os: string; status: string }[];
  active_rules: number;
  open_alerts: number;
  total_alerts: number;
  current_eps: number;
  eps_trend: { bucket: string; eps: string }[];
  alerts_by_severity: { critical: number; high: number; medium: number; low: number };
  top_rules: { rule_id: string; rule_title: string; severity: string; alert_count: number }[];
  alert_trend: { bucket: string; count: string }[];
  mttr_seconds: number | null;
}

export async function getDashboardStats(range = '24h'): Promise<DashboardStats> {
  return apiRequest<DashboardStats>(`/api/v1/dashboard/stats?range=${encodeURIComponent(range)}`);
}

// ── Events ─────────────────────────────────────────────────────────────────

export async function ingestEvents(events: IngestEvent[]): Promise<IngestResponse> {
  return apiRequest<IngestResponse>('/api/v1/events:ingest', {
    method: 'POST',
    body: JSON.stringify({ events }),
  });
}

export async function purgeEvents(): Promise<void> {
  await apiRequest('/api/v1/events', { method: 'DELETE' });
}

export async function getSources(): Promise<SourceInfo[]> {
  const response = await apiRequest<Array<SourceInfo & {
    source?: string;
    event_count?: number;
  }>>('/api/v1/sources');

  return (response ?? []).map((source) => ({
    tenant_id: source.tenant_id,
    source_type: source.source_type ?? source.source ?? 'unknown',
    first_seen: source.first_seen,
    last_seen: source.last_seen,
    total_events: source.total_events ?? source.event_count ?? 0,
    status: source.status,
  }));
}

/**
 * Convenience: ingest a single sample event with sensible defaults.
 */
export async function ingestSampleEvent(message = 'powershell -enc AAAA'): Promise<IngestResponse> {
  return ingestEvents([
    {
      tenant_id: BASE_HEADERS['x-tenant-id'],
      source: 'windows_sysmon',
      event_time: new Date().toISOString(),
      raw_payload: {
        event_code: 1,
        process_name: 'powershell.exe',
        cmdline: message,
        message,
        host: 'endpoint-01',
      },
    },
  ]);
}

// ── Rules ──────────────────────────────────────────────────────────────────

export async function getRules(): Promise<DetectionRule[]> {
  return apiRequest<DetectionRule[]>('/api/v1/rules');
}

export async function createRule(input: RuleCreateInput): Promise<DetectionRule> {
  return apiRequest<DetectionRule>('/api/v1/rules', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function updateRule(ruleId: string, input: RuleUpdateInput): Promise<DetectionRule> {
  return apiRequest<DetectionRule>(`/api/v1/rules/${ruleId}`, {
    method: 'PATCH',
    body: JSON.stringify(input),
  });
}

export async function deleteRule(ruleId: string): Promise<{ deleted: boolean; rule_id: string }> {
  return apiRequest<{ deleted: boolean; rule_id: string }>(`/api/v1/rules/${ruleId}`, {
    method: 'DELETE',
  });
}

export async function testRule(ruleId: string, event: Record<string, unknown>): Promise<RuleTestResult> {
  return apiRequest<RuleTestResult>(`/api/v1/rules/${ruleId}/test`, {
    method: 'POST',
    body: JSON.stringify(event),
  });
}

export async function dryRunRule(input: DryRunInput): Promise<DryRunResult> {
  return apiRequest<DryRunResult>('/api/v1/rules/dry-run', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function backtestRule(ruleId: string, input: BacktestInput): Promise<BacktestResult> {
  return apiRequest<BacktestResult>(`/api/v1/rules/${ruleId}/backtest`, {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function getRuleVersions(ruleId: string): Promise<RuleVersion[]> {
  return apiRequest<RuleVersion[]>(`/api/v1/rules/${ruleId}/versions`);
}

export async function restoreRuleVersion(ruleId: string, version: number): Promise<DetectionRule> {
  return apiRequest<DetectionRule>(`/api/v1/rules/${ruleId}/versions/${version}/restore`, {
    method: 'POST',
  });
}

export async function importRulePack(input: ImportPackInput): Promise<ImportResult> {
  return apiRequest<ImportResult>('/api/v1/rules/import-pack', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function syncRuleDir(input: ImportPackInput): Promise<ImportResult> {
  return apiRequest<ImportResult>('/api/v1/rules/sync-dir', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function generateRule(input: GenerateRuleInput): Promise<GenerateRuleResult> {
  return apiRequest<GenerateRuleResult>('/api/v1/rules/generate', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function tuneRule(ruleId: string): Promise<TuneRuleResult> {
  return apiRequest<TuneRuleResult>(`/api/v1/rules/${ruleId}/tune`, {
    method: 'POST',
  });
}

export async function explainAlert(alertId: string): Promise<ExplainAlertResult> {
  return apiRequest<ExplainAlertResult>(`/api/v1/explain/alert/${alertId}`, {
    method: 'POST',
  });
}

// ── Alerts ─────────────────────────────────────────────────────────────────

export async function getAlerts(query: AlertsQuery = {}): Promise<AlertsPage> {
  return apiRequest<AlertsPage>(`/api/v1/alerts${qs({ ...query })}`);
}

export async function getAlert(alertId: string): Promise<AlertRecord> {
  return apiRequest<AlertRecord>(`/api/v1/alerts/${alertId}`);
}

/**
 * Fetch all alerts by following cursor pagination.
 */
export async function getAllAlerts(filters: Omit<AlertsQuery, 'after'> = {}): Promise<AlertRecord[]> {
  const all: AlertRecord[] = [];
  let cursor: string | undefined;
  for (;;) {
    const page = await getAlerts({ ...filters, after: cursor });
    all.push(...page.alerts);
    if (!page.has_more || !page.next_cursor) break;
    cursor = page.next_cursor;
  }
  return all;
}

export async function acknowledgeAlert(alertId: string, actor = 'soc-admin'): Promise<AlertRecord> {
  return apiRequest<AlertRecord>(`/api/v1/alerts/${alertId}/ack`, {
    method: 'POST',
    body: JSON.stringify({ actor }),
  });
}

export async function assignAlert(
  alertId: string,
  assignee: string | null,
  actor = 'soc-admin',
): Promise<AlertRecord> {
  return apiRequest<AlertRecord>(`/api/v1/alerts/${alertId}/assign`, {
    method: 'POST',
    body: JSON.stringify({ actor, assignee }),
  });
}

export async function closeAlert(
  alertId: string,
  resolution: AlertResolution,
  actor = 'soc-admin',
  note?: string,
): Promise<AlertRecord> {
  return apiRequest<AlertRecord>(`/api/v1/alerts/${alertId}/close`, {
    method: 'POST',
    body: JSON.stringify({ actor, resolution, note }),
  });
}

export async function falsePositiveAlert(
  alertId: string,
  actor = 'soc-admin',
  note?: string,
): Promise<AlertRecord> {
  return closeAlert(alertId, 'false_positive', actor, note);
}

export async function getWsToken(): Promise<WsTokenResponse> {
  return apiRequest<WsTokenResponse>('/api/v1/alerts/ws-token');
}

/**
 * Open a WebSocket to the real-time alert stream.
 * Fetches a single-use token first, then connects.
 */
export async function connectAlertWebSocket(): Promise<WebSocket> {
  const { token } = await getWsToken();
  const url = buildWsUrl('/api/v1/alerts/ws', { token });
  return new WebSocket(url);
}

/**
 * Open an SSE EventSource for the real-time alert stream.
 * Fetches a single-use ws-token first (EventSource cannot send headers).
 */
export async function connectAlertSSE(): Promise<EventSource> {
  const { token } = await getWsToken();
  return new EventSource(`/api/v1/alerts/stream?token=${encodeURIComponent(token)}`);
}

/**
 * Open an SSE EventSource for the real-time event stream (live tail).
 * Fetches a single-use ws-token first (EventSource cannot send headers).
 */
export async function connectEventSSE(): Promise<EventSource> {
  const { token } = await getWsToken();
  return new EventSource(`/api/v1/events/stream?token=${encodeURIComponent(token)}`);
}

// ── Cases ──────────────────────────────────────────────────────────────────

export async function getCases(): Promise<CaseRecord[]> {
  const resp = await apiRequest<{ cases?: ApiCaseRecord[]; total: number }>('/api/v1/cases');
  return normalizeCaseRecords(resp.cases);
}

export async function createCase(input: CaseCreateInput): Promise<CaseRecord> {
  const response = await apiRequest<ApiCaseRecord>('/api/v1/cases', {
    method: 'POST',
    body: JSON.stringify(input),
  });
  return normalizeCaseRecord(response);
}

export async function getCase(caseId: string): Promise<CaseRecord> {
  const response = await apiRequest<ApiCaseRecord>(`/api/v1/cases/${caseId}`);
  return normalizeCaseRecord(response);
}

export async function updateCase(caseId: string, input: CaseUpdateInput): Promise<CaseRecord> {
  const response = await apiRequest<ApiCaseRecord>(`/api/v1/cases/${caseId}`, {
    method: 'PATCH',
    body: JSON.stringify(input),
  });
  return normalizeCaseRecord(response);
}

export async function addAlertsToCase(caseId: string, alertIds: string[]): Promise<CaseRecord> {
  const response = await apiRequest<ApiCaseRecord>(`/api/v1/cases/${caseId}/alerts`, {
    method: 'POST',
    body: JSON.stringify({ alert_ids: alertIds }),
  });
  return normalizeCaseRecord(response);
}

export async function getSlaBreaches(): Promise<CaseRecord[]> {
  const resp = await apiRequest<{ breaches?: ApiCaseRecord[]; total: number }>('/api/v1/cases/sla-breaches');
  return normalizeCaseRecords(resp.breaches);
}

// ── Search ─────────────────────────────────────────────────────────────────

export async function runSearch(input: SearchQueryInput): Promise<SearchQueryResponse> {
  const body = {
    tenant_id: '_', // overridden server-side from auth
    filters: [],
    ...input,
    pagination: input.pagination ?? { page: 1, page_size: 50 },
  };
  return apiRequest<SearchQueryResponse>('/api/v1/search:query', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/**
 * Convenience: search recent events (last N hours) with a SQL string.
 */
export async function searchRecent(sql: string, hoursBack = 1, pageSize = 25): Promise<SearchQueryResponse> {
  const now = new Date();
  const start = new Date(now.getTime() - hoursBack * 60 * 60 * 1000);
  return runSearch({
    sql,
    time_range: { start: start.toISOString(), end: now.toISOString() },
    pagination: { page: 1, page_size: pageSize },
  });
}

export async function naturalLanguageQuery(input: NlqInput): Promise<NlqResponse> {
  return apiRequest<NlqResponse>('/api/v1/events/nlq', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

// ── MITRE Coverage ─────────────────────────────────────────────────────────

export async function getCoverage(): Promise<CoverageReport> {
  return apiRequest<CoverageReport>('/api/v1/coverage');
}

// ── Threat Intelligence ────────────────────────────────────────────────────

export async function getThreatIntelFeeds(): Promise<ThreatIntelFeed[]> {
  const resp = await apiRequest<{ feeds: ThreatIntelFeed[]; total: number }>('/api/v1/threatintel/feeds');
  return resp.feeds ?? [];
}

export async function createThreatIntelFeed(input: ThreatIntelFeedCreateInput): Promise<ThreatIntelFeed> {
  return apiRequest<ThreatIntelFeed>('/api/v1/threatintel/feeds', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function getThreatIntelFeed(feedId: string): Promise<ThreatIntelFeed> {
  return apiRequest<ThreatIntelFeed>(`/api/v1/threatintel/feeds/${feedId}`);
}

export async function deleteThreatIntelFeed(feedId: string): Promise<{ deleted: boolean }> {
  return apiRequest<{ deleted: boolean }>(`/api/v1/threatintel/feeds/${feedId}`, {
    method: 'DELETE',
  });
}

export async function syncThreatIntelFeed(feedId: string): Promise<{ indicators_added: number }> {
  return apiRequest<{ indicators_added: number }>(`/api/v1/threatintel/feeds/${feedId}/sync`, {
    method: 'POST',
  });
}

// ── Agents ─────────────────────────────────────────────────────────────────

export async function getAgents(group?: string): Promise<AgentRecord[]> {
  return apiRequest<AgentRecord[]>(`/api/v1/agents${qs({ group })}`);
}

export async function registerAgent(input: AgentRegisterInput): Promise<AgentRecord> {
  return apiRequest<AgentRecord>('/api/v1/agents/register', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function updateAgent(agentId: string, input: AgentUpdateInput): Promise<AgentRecord> {
  return apiRequest<AgentRecord>(`/api/v1/agents/${agentId}`, {
    method: 'PATCH',
    body: JSON.stringify(input),
  });
}

export async function agentHeartbeat(agentId: string): Promise<{ pending_config?: Record<string, unknown> }> {
  return apiRequest<{ pending_config?: Record<string, unknown> }>(`/api/v1/agents/${agentId}/heartbeat`, {
    method: 'POST',
  });
}

export async function pushAgentConfig(agentId: string, configToml: string): Promise<void> {
  await apiRequest(`/api/v1/agents/${agentId}/config`, {
    method: 'POST',
    body: JSON.stringify({ config_toml: configToml }),
  });
}

export async function deleteAgent(agentId: string): Promise<void> {
  await apiRequest(`/api/v1/agents/${agentId}`, { method: 'DELETE' });
}

// ── Audit Logs ─────────────────────────────────────────────────────────────

export async function getAuditLogs(query: AuditLogsQuery = {}): Promise<AuditLogsResponse> {
  return apiRequest<AuditLogsResponse>(`/api/v1/audit-logs${qs({ ...query, limit: query.limit ?? 100 })}`);
}

/**
 * Fetch all audit log entries by following cursor pagination.
 */
export async function getAllAuditLogs(
  filters: Omit<AuditLogsQuery, 'cursor'> = {},
): Promise<AuditLogRecord[]> {
  const all: AuditLogRecord[] = [];
  let cursor: string | undefined;
  for (;;) {
    const page = await getAuditLogs({ ...filters, cursor });
    all.push(...page.entries);
    if (!page.has_more || !page.next_cursor) break;
    cursor = page.next_cursor;
  }
  return all;
}

// ── RBAC ───────────────────────────────────────────────────────────────────

export async function getRbacUsers(): Promise<RbacEntry[]> {
  const resp = await apiRequest<{ assignments: RbacEntry[]; total: number }>('/api/v1/rbac/users');
  return resp.assignments ?? [];
}

export async function setRbacUserRoles(userId: string, roles: string[]): Promise<RbacEntry> {
  return apiRequest<RbacEntry>(`/api/v1/rbac/users/${userId}`, {
    method: 'PUT',
    body: JSON.stringify({ roles }),
  });
}

export async function deleteRbacUser(userId: string): Promise<{ deleted: boolean }> {
  return apiRequest<{ deleted: boolean }>(`/api/v1/rbac/users/${userId}`, {
    method: 'DELETE',
  });
}

// ── LGPD ───────────────────────────────────────────────────────────────────

export async function lgpdExport(input: LgpdExportInput): Promise<LgpdExportResponse> {
  return apiRequest<LgpdExportResponse>(`/api/v1/lgpd/export${qs({ subject_id: input.subject_id })}`);
}

export async function lgpdAnonymize(input: LgpdAnonymizeInput): Promise<LgpdAnonymizeResponse> {
  return apiRequest<LgpdAnonymizeResponse>('/api/v1/lgpd/anonymize', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function lgpdBreachReport(input: LgpdBreachReportInput): Promise<LgpdBreachReportResponse> {
  return apiRequest<LgpdBreachReportResponse>('/api/v1/lgpd/breach', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function getLgpdConfig(): Promise<LgpdConfig> {
  return apiRequest<LgpdConfig>('/api/v1/lgpd/config');
}

// ── Scheduler ──────────────────────────────────────────────────────────────

export async function schedulerTick(): Promise<SchedulerTickResponse> {
  return apiRequest<SchedulerTickResponse>('/api/v1/scheduler/tick', {
    method: 'POST',
  });
}

// ── Lookup Tables ──────────────────────────────────────────────────────────

export async function getLookupTables(): Promise<LookupTable[]> {
  const resp = await apiRequest<{ tables: LookupTable[] }>('/api/v1/lookups');
  return resp.tables ?? [];
}

export async function createLookupTable(input: LookupTableCreateInput): Promise<LookupTable> {
  return apiRequest<LookupTable>('/api/v1/lookups', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function getLookupEntries(name: string): Promise<Array<Record<string, string>>> {
  const resp = await apiRequest<{ name: string; entries: Array<Record<string, string>> }>(`/api/v1/lookups/${name}`);
  return resp.entries ?? [];
}

export async function updateLookupEntries(
  name: string,
  rows: Array<Record<string, string>>,
): Promise<Array<Record<string, string>>> {
  return apiRequest<Array<Record<string, string>>>(`/api/v1/lookups/${name}`, {
    method: 'PUT',
    body: JSON.stringify(rows),
  });
}

// ── API Keys ──────────────────────────────────────────────────────────────

export interface ApiKeyRecord {
  key_id: string;
  name: string;
  key_prefix: string;
  tenant_id: string;
  roles: string[];
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface ApiKeyCreateInput {
  name: string;
  roles: string[];
  expires_at?: string;
}

export interface ApiKeyCreateResult extends ApiKeyRecord {
  key: string; // plaintext key, only returned once
}

export async function getApiKeys(): Promise<ApiKeyRecord[]> {
  return apiRequest<ApiKeyRecord[]>('/api/v1/admin/api-keys');
}

export async function createApiKey(input: ApiKeyCreateInput): Promise<ApiKeyCreateResult> {
  return apiRequest<ApiKeyCreateResult>('/api/v1/admin/api-keys', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function revokeApiKey(keyId: string): Promise<void> {
  await apiRequest(`/api/v1/admin/api-keys/${keyId}`, { method: 'DELETE' });
}

// ── IOC Enrichment ────────────────────────────────────────────────────────

export interface AbuseIpDbResult {
  abuse_confidence_score: number;
  country_code: string;
  isp: string;
  domain: string;
  total_reports: number;
  last_reported_at: string | null;
  is_whitelisted: boolean;
}

export interface VirusTotalResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation: number;
  tags: string[];
  last_analysis_date: string | null;
}

export interface EnrichmentResult {
  indicator: string;
  indicator_type: string;
  abuseipdb: AbuseIpDbResult | null;
  virustotal: VirusTotalResult | null;
}

export async function enrichIoc(indicator: string): Promise<EnrichmentResult> {
  return apiRequest<EnrichmentResult>('/api/v1/enrich/ioc', {
    method: 'POST',
    body: JSON.stringify({ indicator }),
  });
}
