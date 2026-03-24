import { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, Clock3, Database, RefreshCcw, Server, ShieldCheck } from 'lucide-react';

import {
  getMetrics,
  getSources,
  healthCheck,
  schedulerTick,
  type HealthResponse,
  type SchedulerTickResponse,
  type SourceInfo,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { WorkspaceTableShell } from '@/components/workspace/table-shell';

function parseAllMatchingValues(raw: string, metricName: string): number {
  const regex = new RegExp(`^${metricName}(?:\\{[^}]*\\})?\\s+([\\d.eE+\\-]+)`, 'gm');
  let total = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(raw)) !== null) {
    total += parseFloat(match[1]);
  }

  return total;
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function appendError(current: string, next: string): string {
  return current ? `${current} ${next}` : next;
}

function formatSystemError(error: unknown): string {
  const message = getErrorMessage(error);
  const normalized = message.toLowerCase();
  if (message.includes('API 401') || normalized.includes('authentication failed')) {
    return 'Your session expired or you are not authorized to view system data. Please sign in again and retry.';
  }
  if (message.includes('API 403')) {
    return 'You do not have permission to view system data.';
  }
  return message;
}

function formatTimestamp(value?: string): string {
  if (!value) return 'Unavailable';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatCount(value: number | null | undefined): string {
  return Number.isFinite(value) ? Number(value).toLocaleString() : '0';
}

function sourceVariant(status?: string): 'default' | 'secondary' | 'outline' | 'destructive' | 'success' | 'warning' | 'info' {
  const normalized = (status ?? 'unknown').toLowerCase();
  if (normalized === 'active') return 'success';
  if (normalized === 'stale') return 'warning';
  if (normalized === 'offline') return 'destructive';
  return 'secondary';
}

export function SystemHealth() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState('');
  const [metricsRaw, setMetricsRaw] = useState('');
  const [sources, setSources] = useState<SourceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [tickResult, setTickResult] = useState<SchedulerTickResponse | null>(null);
  const [tickLoading, setTickLoading] = useState(false);
  const [tickError, setTickError] = useState('');

  const refresh = useCallback(async () => {
    setLoading(true);
    setHealthError('');

    try {
      const [healthResult, metricsResult, sourcesResult] = await Promise.allSettled([
        healthCheck(),
        getMetrics(),
        getSources(),
      ]);

      let nextError = '';

      if (healthResult.status === 'fulfilled') {
        setHealth(healthResult.value);
      } else {
        setHealth(null);
        nextError = appendError(nextError, `Health check unavailable: ${formatSystemError(healthResult.reason)}`);
      }

      if (metricsResult.status === 'fulfilled') {
        setMetricsRaw(metricsResult.value);
      } else {
        setMetricsRaw('');
        nextError = appendError(nextError, `Metrics unavailable: ${formatSystemError(metricsResult.reason)}`);
      }

      if (sourcesResult.status === 'fulfilled') {
        setSources(sourcesResult.value);
      } else {
        setSources([]);
        nextError = appendError(nextError, `Sources unavailable: ${formatSystemError(sourcesResult.reason)}`);
      }

      setHealthError(nextError);
    } catch (err) {
      setHealth(null);
      setMetricsRaw('');
      setSources([]);
      setHealthError(formatSystemError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const onTick = async () => {
    setTickLoading(true);
    setTickError('');
    setTickResult(null);

    try {
      setTickResult(await schedulerTick());
    } catch (err) {
      setTickError(formatSystemError(err));
    } finally {
      setTickLoading(false);
    }
  };

  const eventsIngested = parseAllMatchingValues(metricsRaw, 'events_ingested_total');
  const alertsFired = parseAllMatchingValues(metricsRaw, 'alerts_fired_total');
  const epsRejected = parseAllMatchingValues(metricsRaw, 'eps_rejected_total');
  const dedupDropped = parseAllMatchingValues(metricsRaw, 'dedup_dropped_total');

  const isHealthy = health?.status === 'ok' || health?.status === 'healthy';
  const healthLabel = health ? (isHealthy ? 'Healthy' : health.status) : loading ? 'Checking' : 'Unknown';

  const sourceStats = useMemo(() => ({
    total: sources.length,
    active: sources.filter((source) => (source.status ?? '').toLowerCase() === 'active').length,
    stale: sources.filter((source) => (source.status ?? '').toLowerCase() === 'stale').length,
  }), [sources]);

  const sortedSources = useMemo(() => (
    [...sources].sort((left, right) => {
      const lastSeenDiff = new Date(right.last_seen ?? 0).getTime() - new Date(left.last_seen ?? 0).getTime();
      if (lastSeenDiff !== 0) return lastSeenDiff;
      return right.total_events - left.total_events;
    })
  ), [sources]);

  return (
    <div className="space-y-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.45fr)_380px]">
        <Card className="overflow-hidden border-primary/15 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.15),transparent_40%),linear-gradient(145deg,hsl(var(--card)),hsl(var(--card)/0.85))]">
          <CardContent className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(260px,0.85fr)]">
            <div>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant={isHealthy ? 'success' : health ? 'destructive' : 'secondary'}>{healthLabel}</Badge>
                <Badge variant="outline" className="border-primary/25 bg-primary/10 text-primary">System health workspace</Badge>
              </div>
              <div className="max-w-2xl font-display text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-foreground sm:text-[3rem]">
                Keep ingestion, scheduling, and source visibility inside one operations board.
              </div>
              <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
                This workspace combines service health, Prometheus counters, event source inventory, and a manual scheduler trigger so operators can diagnose the platform quickly.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button type="button" variant="outline" onClick={() => void refresh()} disabled={loading}>
                  <RefreshCcw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
                  Refresh health
                </Button>
              </div>
            </div>
            <div className="grid gap-3 rounded-xl border border-border/70 bg-background/35 p-4">
              <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">System status</div>
                <div className="mt-3 font-display text-4xl font-semibold tracking-[-0.04em] text-foreground">{healthLabel}</div>
                <div className="mt-2 text-sm text-muted-foreground">Server time: {formatTimestamp(health?.time)}</div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
                <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Sources</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{sourceStats.total}</div>
                </div>
                <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Active</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{sourceStats.active}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Runtime actions</CardTitle>
            <CardDescription>Refresh platform state or force one scheduler pass without leaving the system view.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Button type="button" className="w-full justify-center" onClick={() => void onTick()} disabled={tickLoading}>
              <Activity className={tickLoading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
              {tickLoading ? 'Running scheduler tick...' : 'Manual scheduler tick'}
            </Button>
            {tickResult && (
              <WorkspaceStatusBanner>
                Rules scanned: <strong>{tickResult.rules_scanned}</strong>. Alerts emitted: <strong>{tickResult.alerts_emitted}</strong>.
              </WorkspaceStatusBanner>
            )}
            {tickError && <WorkspaceStatusBanner tone="warning">{tickError}</WorkspaceStatusBanner>}
            <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
              <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Last refresh</div>
              <div className="mt-2 flex items-center gap-2 text-sm font-medium text-foreground">
                <Clock3 className="h-4 w-4 text-muted-foreground" />
                {formatTimestamp(health?.time)}
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {healthError && <WorkspaceStatusBanner tone="warning">{healthError}</WorkspaceStatusBanner>}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Events" value={formatCount(eventsIngested)} hint="Total ingested events across the current Prometheus snapshot." icon={Database} />
        <WorkspaceMetricCard label="Alerts" value={formatCount(alertsFired)} hint="Alerts emitted according to the metrics endpoint." icon={AlertTriangle} />
        <WorkspaceMetricCard label="Rejected" value={formatCount(epsRejected)} hint="Events rejected by EPS or rate protections." icon={Server} />
        <WorkspaceMetricCard label="Deduped" value={formatCount(dedupDropped)} hint="Events dropped because they matched dedupe suppression." icon={ShieldCheck} />
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
        <Card>
          <CardHeader className="pb-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <CardTitle>Event sources</CardTitle>
                <CardDescription>Current source inventory with status, tenant ownership, and recent activity.</CardDescription>
              </div>
              <Badge variant="outline">{sourceStats.total} total</Badge>
            </div>
          </CardHeader>
          <CardContent>
            {!sortedSources.length ? (
              <WorkspaceEmptyState title="No event sources reported yet" body="Once ingestion starts reporting source metadata, this table will populate automatically." />
            ) : (
              <WorkspaceTableShell>
                <table className="min-w-full border-collapse text-sm">
                  <thead>
                    <tr className="border-b border-border/70 bg-card/70">
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Source</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Status</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Tenant</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Events</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">First seen</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedSources.map((source) => (
                      <tr key={`${source.tenant_id ?? 'tenant'}-${source.source_type}-${source.last_seen ?? 'never'}`} className="border-b border-border/70 last:border-b-0">
                        <td className="px-4 py-3 align-top">
                          <div className="font-medium text-foreground">{source.source_type}</div>
                        </td>
                        <td className="px-4 py-3 align-top">
                          <Badge variant={sourceVariant(source.status)}>{source.status ?? 'unknown'}</Badge>
                        </td>
                        <td className="px-4 py-3 align-top text-foreground">{source.tenant_id ?? 'shared'}</td>
                        <td className="px-4 py-3 align-top font-medium text-foreground">{formatCount(source.total_events)}</td>
                        <td className="px-4 py-3 align-top text-muted-foreground">{formatTimestamp(source.first_seen)}</td>
                        <td className="px-4 py-3 align-top text-muted-foreground">{formatTimestamp(source.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </WorkspaceTableShell>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Raw metrics</CardTitle>
            <CardDescription>Prometheus output is available here for quick spot checks and deeper debugging.</CardDescription>
          </CardHeader>
          <CardContent>
            {!metricsRaw ? (
              <WorkspaceEmptyState title="Metrics are not available" body="Refresh the page or verify the metrics endpoint if you expected Prometheus output here." />
            ) : (
              <pre className="max-h-[560px] overflow-auto rounded-lg border border-border/70 bg-background/35 p-4 font-mono text-xs leading-6 text-muted-foreground whitespace-pre-wrap break-all">
                {metricsRaw}
              </pre>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
