export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type DetectionMode = 'stream' | 'scheduled';

const BASE_HEADERS = {
  'x-tenant-id': 'tenant-a',
  'x-user-id': 'soc-admin',
  'x-roles': 'admin,analyst,viewer,ingestor',
};

async function apiRequest<T>(url: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...BASE_HEADERS,
      ...(init.headers ?? {}),
    },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API ${response.status}: ${text}`);
  }

  return response.json() as Promise<T>;
}

export interface RuleScheduleConfig {
  interval_seconds: number;
  lookback_seconds: number;
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

export interface RuleSchedulerHealth {
  run_count: number;
  skipped_by_interval_count: number;
  match_count: number;
  error_count: number;
  last_run_duration_seconds: number;
}

export interface AlertRecord {
  alert_id: string;
  tenant_id: string;
  rule_id: string;
  status: string;
  first_seen: string;
  last_seen: string;
  assignee?: string;
}

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

export interface AuditLogsResponse {
  entries: AuditLogRecord[];
  next_cursor?: string;
  has_more: boolean;
}

export interface SearchResult {
  rows: Array<Record<string, unknown>>;
  total: number;
}

export async function getRules(): Promise<DetectionRule[]> {
  return apiRequest<DetectionRule[]>('/api/v1/rules', { method: 'GET' });
}

export async function createRule(input: {
  sigma_source: string;
  schedule_or_stream: DetectionMode;
  schedule?: RuleScheduleConfig;
  severity: Severity;
  enabled: boolean;
}): Promise<DetectionRule> {
  return apiRequest<DetectionRule>('/api/v1/rules', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function updateRule(
  ruleId: string,
  input: {
    sigma_source?: string;
    schedule_or_stream?: DetectionMode;
    schedule?: RuleScheduleConfig;
    severity?: Severity;
    enabled?: boolean;
  },
): Promise<DetectionRule> {
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

export async function getAlerts(): Promise<AlertRecord[]> {
  return apiRequest<AlertRecord[]>('/api/v1/alerts', { method: 'GET' });
}

export async function getAuditLogs(input: {
  action?: string;
  entity_type?: string;
  actor?: string;
  from?: string;
  to?: string;
  cursor?: string;
  limit?: number;
} = {}): Promise<AuditLogsResponse> {
  const params = new URLSearchParams();
  if (input.action) {
    params.set('action', input.action);
  }
  if (input.entity_type) {
    params.set('entity_type', input.entity_type);
  }
  if (input.actor) {
    params.set('actor', input.actor);
  }
  if (input.from) {
    params.set('from', input.from);
  }
  if (input.to) {
    params.set('to', input.to);
  }
  if (input.cursor) {
    params.set('cursor', input.cursor);
  }
  params.set('limit', String(input.limit ?? 100));
  return apiRequest<AuditLogsResponse>(`/api/v1/audit-logs?${params.toString()}`, { method: 'GET' });
}

export async function acknowledgeAlert(alertId: string, actor = 'soc-admin'): Promise<AlertRecord> {
  return apiRequest<AlertRecord>(`/api/v1/alerts/${alertId}:ack`, {
    method: 'POST',
    body: JSON.stringify({ actor }),
  });
}

export async function assignAlert(
  alertId: string,
  assignee: string,
  actor = 'soc-admin',
): Promise<AlertRecord> {
  return apiRequest<AlertRecord>(`/api/v1/alerts/${alertId}:assign`, {
    method: 'POST',
    body: JSON.stringify({ actor, assignee }),
  });
}

export async function ingestSampleEvent(message = 'powershell -enc AAAA'): Promise<void> {
  await apiRequest('/api/v1/events:ingest', {
    method: 'POST',
    body: JSON.stringify({
      events: [
        {
          tenant_id: 'tenant-a',
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
      ],
    }),
  });
}

export async function runSearch(sql: string): Promise<SearchResult> {
  const now = new Date();
  const start = new Date(now.getTime() - 60 * 60 * 1000);

  return apiRequest<SearchResult>('/api/v1/search:query', {
    method: 'POST',
    body: JSON.stringify({
      tenant_id: 'tenant-a',
      sql,
      time_range: {
        start: start.toISOString(),
        end: now.toISOString(),
      },
      filters: [],
      pagination: { page: 1, page_size: 25 },
    }),
  });
}

export async function healthCheck(): Promise<{ status: string; time: string }> {
  return apiRequest('/healthz', { method: 'GET', headers: BASE_HEADERS });
}
