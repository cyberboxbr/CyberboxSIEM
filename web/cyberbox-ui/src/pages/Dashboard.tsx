import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowRight,
  BellRing,
  CheckCircle2,
  Circle,
  RefreshCcw,
} from 'lucide-react';

import { getAlerts, getDashboardStats, getDiskUsage, type AlertRecord, type DashboardStats, type DiskUsageSample, type Severity } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import DashboardEventVolumeChart from '@/components/dashboard/event-volume-chart';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { exportPdf } from '@/lib/export';
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
  if (seconds == null || Number.isNaN(seconds)) return '--';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86_400) return `${(seconds / 3600).toFixed(1).replace(/\.0$/, '')}h`;
  return `${(seconds / 86_400).toFixed(1).replace(/\.0$/, '')}d`;
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

interface OnboardingStep {
  label: string;
  done: boolean;
  to: string;
}

export function Dashboard({ onRefresh }: DashboardProps) {
  const [timeRange, setTimeRange] = useState('24h');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [diskSamples, setDiskSamples] = useState<DiskUsageSample[]>([]);
  const [diskCurrent, setDiskCurrent] = useState<{ used_bytes: number; total_bytes: number; used_pct: number } | null>(null);

  const loadDashboardData = useCallback(
    async (showLoader: boolean) => {
      if (showLoader || !stats) setIsLoading(true);

      const [statsResult, alertsResult, diskResult] = await Promise.allSettled([
        getDashboardStats(timeRange),
        getAlerts({ status: 'open', limit: 8 }),
        getDiskUsage(),
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

      if (diskResult.status === 'fulfilled') {
        setDiskSamples(diskResult.value.samples);
        setDiskCurrent(diskResult.value.current);
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

  const alertVolume = useMemo(
    () =>
      (stats?.alert_trend ?? []).map((point) => ({
        time: new Date(point.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        count: Number.parseInt(point.count, 10) || 0,
      })),
    [stats],
  );

  const topRules = useMemo(
    () =>
      [...(stats?.top_rules ?? [])]
        .sort((a, b) => b.alert_count - a.alert_count || a.rule_id.localeCompare(b.rule_id))
        .slice(0, 5),
    [stats],
  );

  const diskVolume = useMemo(
    () =>
      diskSamples.map((s) => ({
        time: new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        count: Math.round(s.used_pct),
      })),
    [diskSamples],
  );
  const activeCoverage = stats?.total_agents ? Math.round((stats.active_agents / stats.total_agents) * 100) : 0;

  const hasData = (stats?.total_events ?? 0) > 0 || alerts.length > 0 || topSources.length > 0 || (stats?.total_agents ?? 0) > 0;

  const onboardingSteps: OnboardingStep[] = useMemo(() => [
    { label: 'Enroll at least one collector or agent', done: (stats?.total_agents ?? 0) > 0, to: '/agents' },
    { label: 'Ingest the first events', done: (stats?.total_events ?? 0) > 0, to: '/search' },
    { label: 'Enable detection rules', done: (stats?.active_rules ?? 0) > 0, to: '/rules' },
    { label: 'Configure threat intel feeds', done: false, to: '/threat-intel' },
    { label: 'Set up RBAC roles for your team', done: false, to: '/admin/rbac' },
  ], [stats]);

  // ── Severity breakdown bar ──────────────────────────────────────────────
  const sevCounts = stats?.alerts_by_severity ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const sevTotal = sevCounts.critical + sevCounts.high + sevCounts.medium + sevCounts.low;

  return (
    <div className="flex flex-col gap-3">
      {/* ── Toolbar: error (if any) + range selector + refresh ────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {error && <WorkspaceStatusBanner tone="warning" className="flex-1">{error}</WorkspaceStatusBanner>}
        <div className="ml-auto flex items-center gap-2">
          <div className="flex items-center gap-1 rounded-lg border border-border/70 bg-card/60 p-0.5">
            {RANGE_OPTIONS.map((option) => (
              <button
                key={option.value}
                type="button"
                onClick={() => setTimeRange(option.value)}
                className={cn(
                  'rounded-md px-3 py-1 text-xs font-medium transition-colors',
                  option.value === timeRange
                    ? 'bg-primary text-primary-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {option.label}
              </button>
            ))}
          </div>
          <Button type="button" size="sm" variant="outline" onClick={handleRefresh} disabled={isRefreshing}>
            <RefreshCcw className={cn('h-3.5 w-3.5', isRefreshing && 'animate-spin')} />
            Refresh
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={() => {
            exportPdf({
              title: 'Executive Summary',
              subtitle: `${rangeLabel} window — Generated ${new Date().toLocaleString()}`,
              filename: `cyberbox-executive-summary-${Date.now()}`,
              kpis: [
                { label: 'Events', value: formatCompact(stats?.total_events ?? 0) },
                { label: 'Open Alerts', value: String(stats?.open_alerts ?? 0) },
                { label: 'Agents', value: `${stats?.active_agents ?? 0}/${stats?.total_agents ?? 0}` },
                { label: 'Rules', value: String(stats?.active_rules ?? 0) },
                { label: 'EPS', value: stats ? stats.current_eps.toFixed(1) : '0' },
                { label: 'MITRE', value: `${activeCoverage}%` },
              ],
              columns: ['Rule', 'Severity', 'Alert Count'],
              rows: topRules.map((r) => ({ Rule: r.rule_title, Severity: r.severity, 'Alert Count': r.alert_count })),
            });
          }}>
            PDF
          </Button>
        </div>
      </div>

      {/* ── KPI row ──────────────────────────────────────────────────── */}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <WorkspaceMetricCard label="Events" value={formatCompact(stats?.total_events ?? 0)} hint={`${stats?.events_by_source.length ?? 0} sources`} />
        <WorkspaceMetricCard label="Open alerts" value={String(stats?.open_alerts ?? 0)} hint={`${sevCounts.critical} crit · ${sevCounts.high} high`} />
        <WorkspaceMetricCard label="Agents" value={`${stats?.active_agents ?? 0}/${stats?.total_agents ?? 0}`} hint={`${activeCoverage}% coverage`} />
        <WorkspaceMetricCard label="Rules" value={String(stats?.active_rules ?? 0)} hint={`${topRules.length} triggered`} />
        <WorkspaceMetricCard label="EPS" value={stats ? stats.current_eps.toFixed(1) : '0.0'} hint="Events/sec" />
        <WorkspaceMetricCard label="MTTR" value={formatDuration(stats?.mttr_seconds ?? null)} hint="Mean time to resolve" />
      </section>

      {/* ── Severity breakdown bar (only when alerts exist) ──────────── */}
      {sevTotal > 0 && (
        <div className="flex h-2 overflow-hidden rounded-full bg-muted/40">
          {sevCounts.critical > 0 && <div className="bg-destructive" style={{ width: `${(sevCounts.critical / sevTotal) * 100}%` }} />}
          {sevCounts.high > 0 && <div style={{ width: `${(sevCounts.high / sevTotal) * 100}%`, background: 'var(--bar-high)' }} />}
          {sevCounts.medium > 0 && <div className="bg-accent" style={{ width: `${(sevCounts.medium / sevTotal) * 100}%` }} />}
          {sevCounts.low > 0 && <div className="bg-chart-2" style={{ width: `${(sevCounts.low / sevTotal) * 100}%` }} />}
        </div>
      )}

      {/* ── Charts row ──────────────────────────────────────────────── */}
      <section className="grid gap-3 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Event volume</CardTitle>
            <CardDescription>Throughput across the current {rangeLabel.toLowerCase()} window.</CardDescription>
          </CardHeader>
          <CardContent className="h-[200px]">
            {isLoading && !stats ? (
              <WorkspaceEmptyState title="Loading telemetry" body="Pulling the latest event profile." />
            ) : eventVolume.length === 0 ? (
              <WorkspaceEmptyState title="No event traffic" body="Volume will appear once collectors send data." />
            ) : (
              <DashboardEventVolumeChart data={eventVolume} />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Alert volume</CardTitle>
            <CardDescription>Detection pressure across the current {rangeLabel.toLowerCase()} window.</CardDescription>
          </CardHeader>
          <CardContent className="h-[200px]">
            {isLoading && !stats ? (
              <WorkspaceEmptyState title="Loading alerts" body="Pulling alert trend data." />
            ) : alertVolume.length === 0 ? (
              <WorkspaceEmptyState title="No alert activity" body="Alert volume will appear once detections trigger." />
            ) : (
              <DashboardEventVolumeChart data={alertVolume} />
            )}
          </CardContent>
        </Card>
      </section>

      {/* ── Detail grid (3 columns) ─────────────────────────────────── */}
      <section className="grid gap-3 xl:grid-cols-3">
        {/* ── Analyst queue ── */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Analyst queue</CardTitle>
                <CardDescription>Open alerts, riskiest first.</CardDescription>
              </div>
              {alerts.length > 0 && (
                <Button asChild size="sm" variant="ghost">
                  <Link to="/alerts">View all <ArrowRight className="h-3 w-3" /></Link>
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-1.5">
            {alerts.length === 0 ? (
              <WorkspaceEmptyState title="Queue is clear" body="Alerts will land here as detections trigger." />
            ) : (
              alerts.map((alert) => (
                <Link
                  key={alert.alert_id}
                  to={`/alerts/${alert.alert_id}`}
                  className="group flex items-center justify-between gap-3 rounded-lg border border-border/70 bg-background/35 px-3 py-2 transition-colors hover:bg-muted/55"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <Badge variant={severityVariant(alert.severity)} className="shrink-0">{alert.severity}</Badge>
                    <span className="truncate text-sm font-medium text-foreground">
                      {alert.rule_title || `Rule ${alert.rule_id.slice(0, 8)}`}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-xs text-muted-foreground">{alert.hit_count} hits</span>
                    <span className="text-[10px] text-muted-foreground">{formatRelative(alert.first_seen)}</span>
                    <ArrowRight className="h-3 w-3 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                  </div>
                </Link>
              ))
            )}
          </CardContent>
        </Card>

        {/* ── Disk usage chart ── */}
        <Card>
          <CardHeader>
            <CardTitle>Disk usage</CardTitle>
            <CardDescription>
              Log storage utilization{diskCurrent ? ` — ${diskCurrent.used_pct}% used` : ''}.
            </CardDescription>
          </CardHeader>
          <CardContent className="h-[200px]">
            {diskVolume.length === 0 ? (
              <WorkspaceEmptyState title="Sampling" body="Disk usage samples every 30 min." />
            ) : (
              <DashboardEventVolumeChart data={diskVolume} />
            )}
          </CardContent>
        </Card>

        {/* ── Top sources ── */}
        <Card>
          <CardHeader>
            <CardTitle>Top sources</CardTitle>
            <CardDescription>Ingest load by source type.</CardDescription>
          </CardHeader>
          <CardContent>
            {topSources.length === 0 ? (
              <WorkspaceEmptyState title="No sources" body="Appears once telemetry starts flowing." />
            ) : (
              <div className="space-y-2.5">
                {topSources.map((source, index) => {
                  const max = topSources[0]?.count ?? 1;
                  const width = max > 0 ? (source.count / max) * 100 : 0;
                  return (
                    <div key={source.label} className="space-y-1">
                      <div className="flex items-center justify-between gap-3 text-xs">
                        <span className="font-medium text-foreground">{source.label}</span>
                        <span className="text-muted-foreground">{formatCompact(source.count)}</span>
                      </div>
                      <div className="h-1.5 overflow-hidden rounded-full bg-muted/60">
                        <div className="h-full rounded-full bg-primary" style={{ width: `${Math.max(width, index === 0 ? 18 : 8)}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      {/* ── Onboarding checklist (shown when data is sparse) ────────── */}
      {!hasData && (
        <Card>
          <CardHeader>
            <CardTitle>Getting started</CardTitle>
            <CardDescription>Complete these steps to bring the dashboard to life.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1">
            {onboardingSteps.map((step) => (
              <Link
                key={step.label}
                to={step.to}
                className={cn(
                  'flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors hover:bg-muted/55',
                  step.done ? 'text-muted-foreground line-through' : 'text-foreground',
                )}
              >
                {step.done
                  ? <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-primary" />
                  : <Circle className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />}
                {step.label}
              </Link>
            ))}
          </CardContent>
        </Card>
      )}

      {/* ── Top triggered rules (full width) ─────────────────────────── */}
      {topRules.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs font-medium text-foreground">Top triggered rules</div>
          {topRules.map((rule) => (
            <div key={rule.rule_id} className="flex items-center gap-3 rounded-lg border border-border/70 bg-background/35 px-3 py-2">
              <Badge variant={severityVariant((['critical', 'high', 'medium', 'low'].includes(rule.severity) ? rule.severity : 'medium') as Severity)} className="shrink-0">
                {rule.severity}
              </Badge>
              <span className="text-sm font-medium text-foreground">{rule.rule_title}</span>
              <span className="ml-auto text-xs text-muted-foreground">{rule.alert_count} alerts</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
