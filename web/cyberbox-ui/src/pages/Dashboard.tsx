import { useEffect, useMemo, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  AlertRecord,
  AuditLogRecord,
  DetectionRule,
  Severity,
  getAuditLogs,
  healthCheck,
  runSearch,
} from '../api/client';

interface DashboardProps {
  rules: DetectionRule[];
  alerts: AlertRecord[];
  health: string;
  onRefresh: () => Promise<void>;
}

interface EventVolumePoint {
  hour: string;
  total: number;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function timeAgo(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`severity-badge severity-badge--${severity.toLowerCase()}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function KpiCard({
  label,
  value,
  variant,
}: {
  label: string;
  value: string | number;
  variant?: 'good' | 'bad' | 'neutral';
}) {
  return (
    <div className="kpi-card">
      <span className="kpi-label">{label}</span>
      <span className={`kpi-value${variant ? ` ${variant}` : ''}`}>{value}</span>
    </div>
  );
}

export function Dashboard({ rules, alerts, health, onRefresh }: DashboardProps) {
  const [eventVolume, setEventVolume] = useState<EventVolumePoint[]>([]);
  const [recentAudit, setRecentAudit] = useState<AuditLogRecord[]>([]);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [refreshing, setRefreshing] = useState(false);

  const openAlerts = useMemo(
    () => alerts.filter((a) => a.status === 'open' || a.status === 'in_progress'),
    [alerts],
  );

  const criticalAlerts = useMemo(
    () =>
      openAlerts.filter((a) => {
        const rule = rules.find((r) => r.rule_id === a.rule_id);
        return rule?.severity === 'critical';
      }),
    [openAlerts, rules],
  );

  const sortedAlerts = useMemo(() => {
    return [...openAlerts].sort((a, b) => {
      const ruleA = rules.find((r) => r.rule_id === a.rule_id);
      const ruleB = rules.find((r) => r.rule_id === b.rule_id);
      const sevA = SEVERITY_ORDER[ruleA?.severity ?? 'low'] ?? 3;
      const sevB = SEVERITY_ORDER[ruleB?.severity ?? 'low'] ?? 3;
      return sevA - sevB;
    });
  }, [openAlerts, rules]);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const rule of rules) {
      if (rule.severity in counts) {
        counts[rule.severity as keyof typeof counts]++;
      }
    }
    return counts;
  }, [rules]);

  const streamCount = useMemo(
    () => rules.filter((r) => r.schedule_or_stream === 'stream').length,
    [rules],
  );
  const scheduledCount = useMemo(
    () => rules.filter((r) => r.schedule_or_stream === 'scheduled').length,
    [rules],
  );
  const enabledCount = useMemo(() => rules.filter((r) => r.enabled).length, [rules]);

  const maxSeverityCount = useMemo(
    () => Math.max(1, ...Object.values(severityCounts)),
    [severityCounts],
  );

  const totalEvents24h = useMemo(
    () => eventVolume.reduce((sum, p) => sum + p.total, 0),
    [eventVolume],
  );

  const loadDashboardData = async () => {
    try {
      const [volumeResult, auditResult] = await Promise.all([
        runSearch(
          'SELECT bucket_hour, sum(event_count) as total FROM events_hot_hourly_rollup WHERE bucket_hour >= now() - INTERVAL 24 HOUR GROUP BY bucket_hour ORDER BY bucket_hour',
        ),
        getAuditLogs({ limit: 5 }),
      ]);

      const points: EventVolumePoint[] = volumeResult.rows.map((row) => ({
        hour: new Date(String(row['bucket_hour'])).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
        }),
        total: Number(row['total']) || 0,
      }));
      setEventVolume(points);
      setRecentAudit(auditResult.entries);
    } catch {
      // silently ignore — dashboard degrades gracefully
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await onRefresh();
      await loadDashboardData();
      setLastRefresh(new Date());
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  const healthVariant: 'good' | 'bad' =
    health === 'ok' ? 'good' : 'bad';

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">SOC Dashboard</h1>
        <div className="page-header-meta">
          <span className="page-last-refresh">
            Last refresh: {lastRefresh.toLocaleTimeString()}
          </span>
          <button
            type="button"
            className="btn-refresh"
            onClick={handleRefresh}
            disabled={refreshing}
          >
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* KPI Row */}
      <div className="kpi-grid">
        <KpiCard label="Events (24h)" value={totalEvents24h.toLocaleString()} />
        <KpiCard
          label="Open Alerts"
          value={openAlerts.length}
          variant={openAlerts.length > 0 ? 'bad' : 'good'}
        />
        <KpiCard
          label="Critical Alerts"
          value={criticalAlerts.length}
          variant={criticalAlerts.length > 0 ? 'bad' : 'neutral'}
        />
        <KpiCard label="Total Rules" value={rules.length} />
        <KpiCard label="Enabled Rules" value={enabledCount} variant="good" />
        <KpiCard label="System Health" value={health} variant={healthVariant} />
      </div>

      {/* Chart + Rule Summary row */}
      <div className="dashboard-grid">
        <div className="panel">
          <h2 className="panel-title">Event Volume (24h)</h2>
          {eventVolume.length === 0 ? (
            <div className="chart-empty">No event data available</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={eventVolume} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(88,143,186,0.2)" />
                <XAxis
                  dataKey="hour"
                  tick={{ fill: '#9fd3ff', fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: 'rgba(88,143,186,0.35)' }}
                />
                <YAxis
                  tick={{ fill: '#9fd3ff', fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(9,21,35,0.95)',
                    border: '1px solid rgba(88,143,186,0.5)',
                    borderRadius: 8,
                    color: '#dbe4f3',
                  }}
                  cursor={{ fill: 'rgba(88,143,186,0.1)' }}
                />
                <Bar dataKey="total" fill="#4a9eda" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="panel">
          <h2 className="panel-title">Rules by Severity</h2>
          <div className="rule-severity-chart">
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => {
              const count = severityCounts[sev];
              const pct = Math.round((count / maxSeverityCount) * 100);
              return (
                <div key={sev} className="mini-bar-row">
                  <span className={`mini-bar-label severity-text--${sev}`}>
                    {sev.charAt(0).toUpperCase() + sev.slice(1)}
                  </span>
                  <div className="mini-bar-track">
                    <div
                      className={`mini-bar mini-bar--${sev}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="mini-bar-count">{count}</span>
                </div>
              );
            })}
          </div>
          <div className="rule-mode-summary">
            <div className="rule-mode-item">
              <span className="rule-mode-dot rule-mode-dot--stream" />
              Stream
              <strong>{streamCount}</strong>
            </div>
            <div className="rule-mode-item">
              <span className="rule-mode-dot rule-mode-dot--scheduled" />
              Scheduled
              <strong>{scheduledCount}</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Alert Feed */}
      <div className="panel">
        <h2 className="panel-title">
          Active Alerts
          {openAlerts.length > 0 && (
            <span className="panel-title-badge">{openAlerts.length}</span>
          )}
        </h2>
        {sortedAlerts.length === 0 ? (
          <p className="empty-state">No active alerts. System is clear.</p>
        ) : (
          <ul className="alert-feed">
            {sortedAlerts.map((alert) => {
              const rule = rules.find((r) => r.rule_id === alert.rule_id);
              const severity = rule?.severity ?? 'low';
              return (
                <li key={alert.alert_id} className="alert-feed__item">
                  <SeverityBadge severity={severity} />
                  <span className="alert-feed__rule">
                    rule <code>{alert.rule_id.slice(0, 8)}</code>
                  </span>
                  <span className={`alert-feed__status status--${alert.status}`}>
                    {alert.status}
                  </span>
                  <span className="alert-feed__assignee">
                    {alert.assignee ? `@${alert.assignee}` : 'unassigned'}
                  </span>
                  <span className="alert-feed__time">{timeAgo(alert.last_seen)}</span>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Recent Audit Activity */}
      <div className="panel">
        <h2 className="panel-title">Recent Activity</h2>
        {recentAudit.length === 0 ? (
          <p className="empty-state">No recent audit activity.</p>
        ) : (
          <ul className="recent-audit">
            {recentAudit.map((entry) => (
              <li key={entry.audit_id} className="recent-audit__item">
                <span className="recent-audit__action">{entry.action}</span>
                <span className="recent-audit__entity">
                  {entry.entity_type}:{entry.entity_id.slice(0, 8)}
                </span>
                <span className="recent-audit__actor">by {entry.actor}</span>
                <span className="recent-audit__time">
                  {new Date(entry.timestamp).toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
