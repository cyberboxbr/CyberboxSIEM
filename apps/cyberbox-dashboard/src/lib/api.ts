const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
const DEFAULT_TENANT = process.env.NEXT_PUBLIC_TENANT_ID ?? "default";
const DEFAULT_USER = process.env.NEXT_PUBLIC_USER_ID ?? "dashboard-preview";
const DEFAULT_ROLES = process.env.NEXT_PUBLIC_ROLES ?? "admin,analyst,viewer";

export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "in_progress" | "closed";
export type CaseStatus = "open" | "in_progress" | "resolved" | "closed";
export type DetectionMode = "stream" | "scheduled";

export interface AlertRecord {
  alert_id: string;
  rule_id: string;
  rule_title: string;
  severity: Severity;
  status: AlertStatus;
  first_seen: string;
  last_seen: string;
  hit_count: number;
  evidence_refs: string[];
}

interface AlertsPage {
  alerts: AlertRecord[];
  next_cursor?: string;
  has_more: boolean;
  total: number;
}

export interface RuleScheduleConfig {
  interval_seconds: number;
  lookback_seconds: number;
}

export interface DetectionRule {
  rule_id: string;
  sigma_source: string;
  schedule_or_stream: DetectionMode;
  schedule?: RuleScheduleConfig;
  severity: Severity;
  enabled: boolean;
}

export interface RuleCreateInput {
  sigma_source: string;
  schedule_or_stream: DetectionMode;
  schedule?: RuleScheduleConfig;
  severity: Severity;
  enabled: boolean;
}

export interface CoveredTechnique {
  technique_id: string;
  technique_name: string | null;
  tactic: string | null;
  rule_count: number;
  rule_ids: string[];
}

export interface CoverageReport {
  covered_techniques: CoveredTechnique[];
  total_covered: number;
  total_in_framework: number;
  coverage_pct: number;
}

interface CasesResponse {
  cases: CaseRecord[];
  total: number;
}

export interface CaseRecord {
  case_id: string;
  title: string;
  description: string;
  status: CaseStatus;
  severity: Severity;
  assignee?: string;
  alert_ids: string[];
  created_at: string;
  updated_at: string;
  sla_due_at?: string;
  tags: string[];
}

export interface NlqSearchResponse {
  rows: Array<Record<string, unknown>>;
  total?: number;
  generated_where: string;
  interpreted_as: string;
  time_range: {
    start: string;
    end: string;
  };
}

interface WsTokenResponse {
  token: string;
  expires_in_seconds: number;
  tenant_id?: string;
}

function defaultHeaders(tenant = DEFAULT_TENANT, user = DEFAULT_USER): Headers {
  const headers = new Headers();
  headers.set("Content-Type", "application/json");
  headers.set("x-tenant-id", tenant);
  headers.set("x-user-id", user);
  headers.set("x-roles", DEFAULT_ROLES);
  return headers;
}

async function apiRequest<T>(
  path: string,
  init: RequestInit = {},
  tenant = DEFAULT_TENANT,
): Promise<T> {
  const headers = defaultHeaders(tenant);
  if (init.headers) {
    new Headers(init.headers).forEach((value, key) => {
      headers.set(key, value);
    });
  }
  if (init.body instanceof FormData) {
    headers.delete("Content-Type");
  }

  const response = await fetch(`${BASE}${path}`, {
    ...init,
    headers,
    cache: init.cache ?? "no-store",
  });

  const text = await response.text();
  if (!response.ok) {
    throw new Error(`API ${response.status}: ${text}`);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return JSON.parse(text) as T;
  }
  return text as T;
}

export async function listAlerts(tenant = DEFAULT_TENANT): Promise<AlertRecord[]> {
  const page = await apiRequest<AlertsPage>("/api/v1/alerts", {}, tenant);
  return page.alerts ?? [];
}

export async function listRules(tenant = DEFAULT_TENANT): Promise<DetectionRule[]> {
  return apiRequest<DetectionRule[]>("/api/v1/rules", {}, tenant);
}

export async function createRule(
  tenant = DEFAULT_TENANT,
  body: RuleCreateInput,
): Promise<DetectionRule> {
  return apiRequest<DetectionRule>(
    "/api/v1/rules",
    {
      method: "POST",
      body: JSON.stringify(body),
    },
    tenant,
  );
}

export async function deleteRule(
  tenant = DEFAULT_TENANT,
  id: string,
): Promise<{ deleted: boolean; rule_id: string }> {
  return apiRequest<{ deleted: boolean; rule_id: string }>(
    `/api/v1/rules/${id}`,
    { method: "DELETE" },
    tenant,
  );
}

export async function getCoverage(tenant = DEFAULT_TENANT): Promise<CoverageReport> {
  return apiRequest<CoverageReport>("/api/v1/coverage", {}, tenant);
}

export async function nlqSearch(
  tenant = DEFAULT_TENANT,
  query: string,
): Promise<NlqSearchResponse> {
  return apiRequest<NlqSearchResponse>(
    "/api/v1/events/nlq",
    {
      method: "POST",
      body: JSON.stringify({ query }),
    },
    tenant,
  );
}

export async function listCases(tenant = DEFAULT_TENANT): Promise<CaseRecord[]> {
  const response = await apiRequest<CasesResponse>("/api/v1/cases", {}, tenant);
  return response.cases ?? [];
}

export async function issueAlertStreamToken(tenant = DEFAULT_TENANT): Promise<string> {
  const response = await apiRequest<WsTokenResponse>("/api/v1/alerts/ws-token", {}, tenant);
  return response.token;
}

export function buildAlertStreamUrl(token: string): string {
  return `${BASE}/api/v1/alerts/stream?token=${encodeURIComponent(token)}`;
}

export function previewTenant(): string {
  return DEFAULT_TENANT;
}
