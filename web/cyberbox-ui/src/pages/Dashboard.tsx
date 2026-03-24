import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BellRing,
  RefreshCcw,
  Search,
  ServerCog,
  Shield,
} from 'lucide-react';

import { getAlerts, getDashboardStats, type AlertRecord, type DashboardStats, type Severity } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import DashboardEventVolumeChart from '@/components/dashboard/event-volume-chart';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';

interface DashboardProps {
  onRefresh: () => Promise<void>;
}

const RANGE_OPTIONS = [
  { value: '1h', label: '1H' },
  { value: '24h', label: '24H' },
  { value: '7d', label: '7D' },
  { value: '30d', label: '30D' },
];

const SOURCE_LABELS: Record<string, string> = {
  agent: 'Agent',
  api: 'API',
  cef: 'CEF',
  gelf: 'GELF',
  json: 'JSON',
  leef: 'LEEF',
  o365: 'Office 365',
  otlp: 'OTLP',
  syslog: 'Syslog',
  wineventlog: 'Windows Event Log',
};

function formatCompact(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1).replace(/\.0$/, '')}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1).replace(/\.0$/, '')}K`;
  return String(value);
}

function formatDuration(seconds: number | null): string {
  if (seconds == null || Number.isNaN(seconds)) return 'Unmeasured';
  if (seconds < 60) return `${Math.round(seconds)} sec`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86_400) return `${(seconds / 3600).toFixed(1).replace(/\.0$/, '')} hr`;
  return `${(seconds / 86_400).toFixed(1).replace(/\.0$/, '')} d`;
}

function formatRelative(timestamp: string): string {
  const minutes = Math.round((Date.now() - new Date(timestamp).getTime()) / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.round(minutes / 60)}h ago`;
  return `${Math.round(minutes / 1440)}d ago`;
}

function severityRank(severity: Severity): number {
  if (severity === 'critical') return 0;
  if (severity === 'high') return 1;
  if (severity === 'medium') return 2;
  return 3;
}

function severityVariant(severity: Severity): 'destructive' | 'warning' | 'info' | 'secondary' {
  if (severity === 'critical') return 'destructive';
  if (severity === 'high') return 'warning';
  if (severity === 'medium') return 'info';
  return 'secondary';
}

function prettySource(source: string): string {
  if (!source) return 'Other';
  return SOURCE_LABELS[source.toLowerCase()] ?? source;
}

export function Dashboard({ onRefresh }: DashboardProps) {
  const [timeRange, setTimeRange] = useState('24h');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const loadDashboardData = useCallback(
    async (showLoader: boolean) => {
      if (showLoader || !stats) setIsLoading(true);

      const [statsResult, alertsResult] = await Promise.allSettled([
        getDashboardStats(timeRange),
        getAlerts({ status: 'open', limit: 8 }),
      ]);

      let updated = false;

      if (statsResult.status === 'fulfilled') {
        setStats(statsResult.value);
        updated = true;
      }

      if (alertsResult.status === 'fulfilled') {
        setAlerts(
          [...alertsResult.value.alerts].sort(
            (left, right) =>
              severityRank(left.severity) - severityRank(right.severity) ||
              new Date(right.first_seen).getTime() - new Date(left.first_seen).getTime(),
          ),
        );
        updated = true;
      }

      setError(updated && statsResult.status === 'fulfilled' && alertsResult.status === 'fulfilled'
        ? null
        : 'Some dashboard tiles may be stale while data refreshes.');

      if (updated) setLastUpdated(new Date());
      setIsLoading(false);
    },
    [stats, timeRange],
  );

  useEffect(() => {
    void loadDashboardData(true);
    const intervalId = window.setInterval(() => {
      void loadDashboardData(false);
    }, 15_000);
    return () => window.clearInterval(intervalId);
  }, [loadDashboardData]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await onRefresh();
      await loadDashboardData(true);
    } finally {
      setIsRefreshing(false);
    }
  };

  const rangeLabel = useMemo(
    () => RANGE_OPTIONS.find((option) => option.value === timeRange)?.label ?? timeRange,
    [timeRange],
  );

  const eventVolume = useMemo(
    () =>
      (stats?.hourly_events ?? []).map((point) => ({
        time: new Date(point.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        count: Number.parseInt(point.count, 10) || 0,
      })),
    [stats],
  );

  const topSources = useMemo(
    () =>
      (stats?.events_by_source ?? [])
        .filter((item) => item.source)
        .slice(0, 5)
        .map((item) => ({ label: prettySource(item.source), count: Number.parseInt(item.count, 10) || 0 })),
    [stats],
  );

  const topRules = useMemo(() => (stats?.top_rules ?? []).slice(0, 5), [stats]);
  const topAgents = useMemo(() => (stats?.agents ?? []).slice(0, 5), [stats]);
  const activeCoverage = stats?.total_agents ? Math.round((stats.active_agents / stats.total_agents) * 100) : 0;

  return (
    <div className="flex flex-col gap-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(320px,0.95fr)]">
        <Card className="overflow-hidden border-primary/15 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.16),transparent_38%),linear-gradient(145deg,hsl(var(--card)),hsl(var(--card)/0.82))]">
          <CardContent className="grid gap-8 p-6 lg:grid-cols-[minmax(0,1.2fr)_minmax(240px,0.8fr)]">
            <div>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant="outline" className="border-primary/25 bg-primary/10 text-primary">Live SOC workspace</Badge>
                <Badge variant="secondary" className="bg-background/55">Auto refresh every 15s</Badge>
              </div>
              <div className="max-w-2xl font-display text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-foreground sm:text-[3.1rem]">
                A sharper shell for the Cyberbox command center.
              </div>
              <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
                The new dashboard leans into a shadcn-style block layout so the highest-signal telemetry is easier to scan, refresh, and act on.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button asChild>
                  <Link to="/alerts">Open alert queue <ArrowRight className="h-4 w-4" /></Link>
                </Button>
                <Button asChild variant="outline">
                  <Link to="/search">Hunt in search <Search className="h-4 w-4" /></Link>
                </Button>
              </div>
            </div>
            <div className="grid gap-3 rounded-[28px] border border-border/70 bg-background/35 p-4">
              <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Sync state</div>
                <div className="mt-3 text-sm text-foreground">Last update: <span className="font-medium">{lastUpdated ? lastUpdated.toLocaleTimeString() : 'waiting'}</span></div>
              </div>
              <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-1">
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Current EPS</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats ? stats.current_eps.toFixed(1) : '0.0'}</div>
                </div>
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">MTTR</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{formatDuration(stats?.mttr_seconds ?? null)}</div>
                </div>
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Fleet coverage</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{activeCoverage}%</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Range and refresh</CardTitle>
            <CardDescription>Keep the board focused on the window you want to investigate.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid grid-cols-2 gap-3">
              {RANGE_OPTIONS.map((option) => (
                <Button
                  key={option.value}
                  type="button"
                  variant={option.value === timeRange ? 'default' : 'outline'}
                  className={cn('rounded-[22px]', option.value === timeRange && 'shadow-[0_14px_40px_-22px_hsl(var(--primary)/0.95)]')}
                  onClick={() => setTimeRange(option.value)}
                >
                  {option.label}
                </Button>
              ))}
            </div>
            {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}
            <Button type="button" className="w-full rounded-[22px]" onClick={handleRefresh} disabled={isRefreshing}>
              <RefreshCcw className={cn('h-4 w-4', isRefreshing && 'animate-spin')} />
              {isRefreshing ? 'Refreshing workspace' : `Refresh ${rangeLabel}`}
            </Button>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Events" value={formatCompact(stats?.total_events ?? 0)} hint={`Across ${stats?.events_by_source.length ?? 0} active sources.`} icon={Activity} valueClassName="text-4xl" />
        <WorkspaceMetricCard label="Open Alerts" value={String(stats?.open_alerts ?? 0)} hint={`${stats?.alerts_by_severity.critical ?? 0} critical and ${stats?.alerts_by_severity.high ?? 0} high.`} icon={AlertTriangle} valueClassName="text-4xl" />
        <WorkspaceMetricCard label="Active Agents" value={`${stats?.active_agents ?? 0}/${stats?.total_agents ?? 0}`} hint={`${topAgents.filter((agent) => agent.status !== 'active').length} agents need attention.`} icon={ServerCog} valueClassName="text-4xl" />
        <WorkspaceMetricCard label="Detections" value={String(stats?.active_rules ?? 0)} hint={`${topRules.length} rules contributed alerts in this window.`} icon={Shield} valueClassName="text-4xl" />
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(360px,0.8fr)]">
        <div className="grid gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Event volume</CardTitle>
              <CardDescription>Telemetry throughput across the current {rangeLabel.toLowerCase()} window.</CardDescription>
            </CardHeader>
            <CardContent className="h-[320px]">
              {isLoading && !stats ? (
                <WorkspaceEmptyState title="Loading telemetry" body="Pulling the latest event profile for this tenant." className="min-h-[220px]" />
              ) : eventVolume.length === 0 ? (
                <WorkspaceEmptyState title="No event traffic yet" body="Once collectors begin sending data, this panel will fill in." className="min-h-[220px]" />
              ) : (
                <DashboardEventVolumeChart data={eventVolume} />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Analyst queue</CardTitle>
              <CardDescription>Open alerts sorted so the riskiest work stays visible first.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {alerts.length === 0 ? (
                <WorkspaceEmptyState title="Queue is clear" body="New open alerts will land here as detections trigger." className="min-h-[220px]" />
              ) : (
                alerts.map((alert) => (
                  <Link
                    key={alert.alert_id}
                    to={`/alerts/${alert.alert_id}`}
                    className="group flex flex-col gap-3 rounded-[24px] border border-border/70 bg-background/35 p-4 transition-colors hover:bg-muted/55"
                  >
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant={severityVariant(alert.severity)}>{alert.severity}</Badge>
                          <span className="text-xs uppercase tracking-[0.22em] text-muted-foreground">{formatRelative(alert.first_seen)}</span>
                        </div>
                        <div className="mt-3 truncate font-display text-xl font-semibold tracking-[-0.03em] text-foreground">
                          {alert.rule_title || `Rule ${alert.rule_id.slice(0, 8)}`}
                        </div>
                        <div className="mt-2 flex flex-wrap gap-3 text-sm text-muted-foreground">
                          <span>{alert.agent_meta?.hostname ?? 'Unassigned asset'}</span>
                          <span>{alert.hit_count} hits</span>
                          <span>{alert.assignee ? `Owner: ${alert.assignee}` : 'Unassigned'}</span>
                        </div>
                      </div>
                      <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-1" />
                    </div>
                  </Link>
                ))
              )}
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Top ingest sources</CardTitle>
              <CardDescription>Where the telemetry load is coming from.</CardDescription>
            </CardHeader>
            <CardContent>
              {topSources.length === 0 ? (
                <WorkspaceEmptyState title="No sources yet" body="Source activity will appear here once telemetry starts flowing." className="min-h-[220px]" />
              ) : (
                <div className="space-y-3">
                  {topSources.map((source, index) => {
                    const max = topSources[0]?.count ?? 1;
                    const width = max > 0 ? (source.count / max) * 100 : 0;
                    return (
                      <div key={source.label} className="space-y-2">
                        <div className="flex items-center justify-between gap-3 text-sm">
                          <span className="font-medium text-foreground">{source.label}</span>
                          <span className="text-muted-foreground">{formatCompact(source.count)}</span>
                        </div>
                        <div className="h-2 overflow-hidden rounded-full bg-muted/60">
                          <div className="h-full rounded-full bg-gradient-to-r from-primary via-chart-2 to-cyan-300" style={{ width: `${Math.max(width, index === 0 ? 18 : 8)}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Top triggered rules</CardTitle>
              <CardDescription>The detections creating the most pressure right now.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {topRules.length === 0 ? (
                <WorkspaceEmptyState title="No rule activity yet" body="Triggered rules will show up here when alerts are flowing." className="min-h-[220px]" />
              ) : (
                topRules.map((rule) => (
                  <div key={rule.rule_id} className="rounded-[22px] border border-border/70 bg-background/35 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate font-medium text-foreground">{rule.rule_title}</div>
                        <div className="mt-2 flex flex-wrap items-center gap-2">
                          <Badge variant={severityVariant((['critical', 'high', 'medium', 'low'].includes(rule.severity) ? rule.severity : 'medium') as Severity)}>
                            {rule.severity}
                          </Badge>
                          <span className="text-sm text-muted-foreground">{rule.alert_count} alerts</span>
                        </div>
                      </div>
                      <BellRing className="mt-1 h-4 w-4 shrink-0 text-primary" />
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Fleet health</CardTitle>
              <CardDescription>Collector readiness and the endpoints to watch first.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {topAgents.length === 0 ? (
                <WorkspaceEmptyState title="No agents registered" body="Agent health will appear here once the fleet is enrolled." className="min-h-[220px]" />
              ) : (
                topAgents.map((agent) => (
                  <div key={agent.agent_id} className="flex items-center justify-between gap-3 rounded-[22px] border border-border/70 bg-background/35 px-4 py-3">
                    <div className="min-w-0">
                      <div className="truncate font-medium text-foreground">{agent.hostname}</div>
                      <div className="truncate text-sm text-muted-foreground">{agent.agent_id}</div>
                    </div>
                    <Badge variant={agent.status === 'active' ? 'success' : agent.status === 'stale' ? 'warning' : 'destructive'}>
                      {agent.status}
                    </Badge>
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}
