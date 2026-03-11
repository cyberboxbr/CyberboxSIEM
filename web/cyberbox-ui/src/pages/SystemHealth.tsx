import { useCallback, useEffect, useState } from 'react';
import {
  healthCheck,
  HealthResponse,
  getMetrics,
  getSources,
  schedulerTick,
  SchedulerTickResponse,
  SourceInfo,
} from '../api/client';

// ---------------------------------------------------------------------------
// Dark theme tokens
// ---------------------------------------------------------------------------

const s = {
  panelBg: 'rgba(9,21,35,0.82)',
  border: 'rgba(88,143,186,0.35)',
  inputBg: 'rgba(4,12,21,0.75)',
  text: '#dbe4f3',
  dim: 'rgba(219,228,243,0.5)',
  accent: '#4a9eda',
  good: '#58d68d',
  bad: '#f45d5d',
  warn: '#f5a623',
} as const;

// ---------------------------------------------------------------------------
// Prometheus text parser (extract specific counters/gauges)
// ---------------------------------------------------------------------------

function parseMetricValue(raw: string, metricName: string): number | null {
  // Matches lines like: metric_name{...} 123 or metric_name 123
  const regex = new RegExp(`^${metricName}(?:\\{[^}]*\\})?\\s+([\\d.eE+\\-]+)`, 'm');
  const match = raw.match(regex);
  if (!match) return null;
  return parseFloat(match[1]);
}

function parseAllMatchingValues(raw: string, metricName: string): number {
  // Sum all matching lines (handles label variants)
  const regex = new RegExp(`^${metricName}(?:\\{[^}]*\\})?\\s+([\\d.eE+\\-]+)`, 'gm');
  let total = 0;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(raw)) !== null) {
    total += parseFloat(m[1]);
  }
  return total;
}

// ---------------------------------------------------------------------------
// KPI card
// ---------------------------------------------------------------------------

function KpiCard({
  label,
  value,
  color,
}: {
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <div className="kpi-card">
      <span className="kpi-label">{label}</span>
      <span className="kpi-value" style={{ color: color || s.text }}>{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SystemHealth() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState('');
  const [metricsRaw, setMetricsRaw] = useState('');
  const [sources, setSources] = useState<SourceInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [tickResult, setTickResult] = useState<SchedulerTickResponse | null>(null);
  const [tickLoading, setTickLoading] = useState(false);
  const [tickError, setTickError] = useState('');

  const refresh = useCallback(async () => {
    setLoading(true);
    setHealthError('');
    try {
      const [h, m, src] = await Promise.all([
        healthCheck(),
        getMetrics(),
        getSources(),
      ]);
      setHealth(h);
      setMetricsRaw(m);
      setSources(src);
    } catch (err) {
      setHealthError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const onTick = async () => {
    setTickLoading(true);
    setTickError('');
    setTickResult(null);
    try {
      setTickResult(await schedulerTick());
    } catch (err) {
      setTickError(String(err));
    } finally {
      setTickLoading(false);
    }
  };

  // Parse key metrics
  const eventsIngested = parseAllMatchingValues(metricsRaw, 'events_ingested_total');
  const alertsFired = parseAllMatchingValues(metricsRaw, 'alerts_fired_total');
  const epsRejected = parseAllMatchingValues(metricsRaw, 'eps_rejected_total');
  const dedupDropped = parseAllMatchingValues(metricsRaw, 'dedup_dropped_total');

  // ─── table styles ────────────────────────────────────────────────────────

  const th: React.CSSProperties = {
    textAlign: 'left',
    padding: '8px 10px',
    borderBottom: `1px solid ${s.border}`,
    color: s.accent,
    fontWeight: 600,
    fontSize: 12,
  };

  const td: React.CSSProperties = {
    padding: '8px 10px',
    fontSize: 13,
    borderBottom: `1px solid ${s.border}`,
  };

  const isHealthy = health?.status === 'ok' || health?.status === 'healthy';

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">System Health</h1>
        <button className="btn-refresh" onClick={refresh} disabled={loading}>
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {healthError && <p style={{ color: s.bad, fontSize: 13, margin: 0 }}>{healthError}</p>}

      {/* Health Status */}
      <div className="panel" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <span
          style={{
            width: 14,
            height: 14,
            borderRadius: '50%',
            display: 'inline-block',
            background: health ? (isHealthy ? s.good : s.bad) : s.dim,
            boxShadow: health ? `0 0 8px ${isHealthy ? s.good : s.bad}` : 'none',
          }}
        />
        <div>
          <strong style={{ fontSize: 15 }}>
            {health ? (isHealthy ? 'Healthy' : health.status) : 'Unknown'}
          </strong>
          {health?.time && (
            <span style={{ fontSize: 12, color: s.dim, marginLeft: 12 }}>
              Server time: {new Date(health.time).toLocaleString()}
            </span>
          )}
        </div>
      </div>

      {/* Key Metrics */}
      <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <KpiCard
          label="Events Ingested"
          value={eventsIngested.toLocaleString()}
          color={s.accent}
        />
        <KpiCard
          label="Alerts Fired"
          value={alertsFired.toLocaleString()}
          color={alertsFired > 0 ? s.warn : s.good}
        />
        <KpiCard
          label="EPS Rejected"
          value={epsRejected.toLocaleString()}
          color={epsRejected > 0 ? s.bad : s.good}
        />
        <KpiCard
          label="Dedup Dropped"
          value={dedupDropped.toLocaleString()}
          color={dedupDropped > 0 ? s.warn : s.dim}
        />
      </div>

      {/* Scheduler Tick */}
      <div className="panel" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <button
          type="button"
          onClick={onTick}
          disabled={tickLoading}
          style={{
            padding: '8px 20px',
            background: 'rgba(74,158,218,0.2)',
            borderColor: s.accent,
            fontWeight: 700,
          }}
        >
          {tickLoading ? 'Running...' : 'Manual Scheduler Tick'}
        </button>
        {tickResult && (
          <span style={{ fontSize: 13 }}>
            Rules scanned: <strong style={{ color: s.accent }}>{tickResult.rules_scanned}</strong>
            {' | '}
            Alerts emitted: <strong style={{ color: tickResult.alerts_emitted > 0 ? s.warn : s.good }}>
              {tickResult.alerts_emitted}
            </strong>
          </span>
        )}
        {tickError && <span style={{ fontSize: 12, color: s.bad }}>{tickError}</span>}
      </div>

      {/* Event Sources */}
      <div className="panel wide">
        <div className="panel-title">
          Event Sources
          <span style={{ fontWeight: 400, fontSize: 12, color: s.dim, marginLeft: 8 }}>
            {sources.length} source{sources.length !== 1 ? 's' : ''}
          </span>
        </div>
        {sources.length === 0 ? (
          <p className="empty-state">No event sources reported yet.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={th}>Source</th>
                <th style={th}>Event Count</th>
                <th style={th}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {sources.map((src) => (
                <tr key={src.source}>
                  <td style={td}><code style={{ fontSize: 12 }}>{src.source}</code></td>
                  <td style={{ ...td, fontWeight: 700, color: s.accent }}>
                    {src.event_count.toLocaleString()}
                  </td>
                  <td style={td}>{new Date(src.last_seen).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Raw Metrics (collapsible) */}
      {metricsRaw && (
        <details className="panel wide">
          <summary style={{ cursor: 'pointer', fontWeight: 600, fontSize: 13, color: s.accent }}>
            Raw Prometheus Metrics
          </summary>
          <pre
            style={{
              marginTop: 8,
              fontFamily: '"IBM Plex Mono", monospace',
              fontSize: 11,
              background: s.inputBg,
              padding: 12,
              borderRadius: 6,
              maxHeight: 400,
              overflow: 'auto',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}
          >
            {metricsRaw}
          </pre>
        </details>
      )}
    </div>
  );
}
