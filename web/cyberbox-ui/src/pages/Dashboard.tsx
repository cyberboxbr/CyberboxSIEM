import { useEffect, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  searchRecent,
} from '../api/client';

/* ── Dashboard placeholder data (until real API endpoints exist) ────────── */

interface RiskScorePoint { day: string; score: number; incidents: number }
interface MttPoint { hour: string; value: number }
interface AlertSparkPoint { day: string; value: number }
type AssetOs = 'windows' | 'windows-server' | 'linux' | 'linux-server' | 'docker';
interface TopAlertRow {
  severity: 'critical' | 'high' | 'medium' | 'low';
  alert_name: string;
  target_asset: string;
  asset_os: AssetOs;
  vendor: string;
  assigned_to: string | null;
}

const RISK_TREND: RiskScorePoint[] = Array.from({ length: 8 }, (_, i) => ({
  day: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun', 'Today'][i],
  score: [62, 58, 65, 61, 70, 68, 72, 74][i],
  incidents: [12, 8, 15, 10, 18, 14, 16, 11][i],
}));
const RISK_SCORE = RISK_TREND[RISK_TREND.length - 1].score;
const RISK_DELTA = RISK_SCORE - RISK_TREND[0].score;

const MTTD_TREND: MttPoint[] = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2, '0')}:00`,
  value: +(4.5 + Math.sin(i / 3) * 2 + Math.random() * 1.5).toFixed(2),
}));
const MTTD_CURRENT = +(MTTD_TREND.slice(-3).reduce((s, p) => s + p.value, 0) / 3).toFixed(2);

const MTTR_TREND: MttPoint[] = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2, '0')}:00`,
  value: +(12 + Math.cos(i / 4) * 5 + Math.random() * 3).toFixed(2),
}));
const MTTR_CURRENT = +(MTTR_TREND.slice(-3).reduce((s, p) => s + p.value, 0) / 3).toFixed(2);

const OPEN_ALERTS_COUNT = 149;
const CRITICAL_HIGH_COUNT = 7;

const OPEN_ALERTS_TREND: AlertSparkPoint[] = [
  { day: 'Mon', value: 182 }, { day: 'Tue', value: 170 }, { day: 'Wed', value: 165 },
  { day: 'Thu', value: 158 }, { day: 'Fri', value: 162 }, { day: 'Sat', value: 155 },
  { day: 'Sun', value: 150 }, { day: 'Now', value: 149 },
];
const CRITICAL_HIGH_TREND: AlertSparkPoint[] = [
  { day: 'Mon', value: 4 }, { day: 'Tue', value: 5 }, { day: 'Wed', value: 6 },
  { day: 'Thu', value: 5 }, { day: 'Fri', value: 8 }, { day: 'Sat', value: 6 },
  { day: 'Sun', value: 7 }, { day: 'Now', value: 7 },
];

const TOP_ALERTS: TopAlertRow[] = [
  { severity: 'critical', alert_name: 'Multi-Stage Supply Chain Attack', target_asset: 'WS-FINANCE-01', asset_os: 'windows', vendor: 'CyberboxSIEM', assigned_to: 'Nina T' },
  { severity: 'critical', alert_name: 'A Malicious Scheduled Task Was Created', target_asset: 'SRV-DC-02.corp.local', asset_os: 'windows-server', vendor: 'CyberboxSIEM', assigned_to: null },
  { severity: 'critical', alert_name: 'Ransomware Encryption Detected', target_asset: 'SRV-APP-10', asset_os: 'linux-server', vendor: 'CyberboxSIEM', assigned_to: null },
  { severity: 'critical', alert_name: 'Lateral Movement: Ransomware Patterns', target_asset: 'WS-HR-08', asset_os: 'windows', vendor: 'CyberboxSIEM', assigned_to: 'Nina T' },
  { severity: 'high', alert_name: 'API Abuse For Data Theft', target_asset: 'VPN-GW-01', asset_os: 'docker', vendor: 'CyberboxSIEM', assigned_to: null },
];

/* ── Props ───────────────────────────────────────── */

interface DashboardProps {
  onRefresh: () => Promise<void>;
}

/* ── Helpers ─────────────────────────────────────── */

const TIME_RANGE_QUICK = [
  { value: '15m', label: 'Last 15 min' },
  { value: '1h',  label: 'Last 1 hour' },
  { value: '4h',  label: 'Last 4 hours' },
  { value: '12h', label: 'Last 12 hours' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '3d',  label: 'Last 3 days' },
  { value: '7d',  label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
];

const TIME_RANGE_PRECISE = [
  { value: '1m',  label: 'Last 1 minute' },
  { value: '5m',  label: 'Last 5 minutes' },
];

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'];
const ASSET_OPTIONS = ['WS-FINANCE-01', 'SRV-DC-02.corp.local', 'SRV-APP-10', 'WS-HR-08', 'VPN-GW-01', 'SRV-DB-03', 'SRV-WEB-11', 'K8S-NODE-04', 'WS-DEV-09'];

interface EventVolumePoint { hour: string; total: number }

/* ── Shared chart config ─────────────────────────── */

const AXIS_STYLE = { fill: 'var(--chart-axis)', fontSize: 10 };
const GRID_STROKE = 'var(--chart-grid)';
const TOOLTIP_STYLE: React.CSSProperties = {
  background: 'var(--card-bg)',
  border: '1px solid var(--card-border)',
  borderRadius: 8,
  color: 'var(--text-primary)',
  fontSize: 12,
  padding: '8px 12px',
};

/* ── OS icons for target asset ───────────────────── */

const osIcons: Record<string, JSX.Element> = {
  windows: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style={{ color: '#0078D4' }}>
      <path d="M0 3.5l9.9-1.4v9.5H0V3.5zm11.1-1.6L24 0v11.6H11.1V1.9zM0 12.6h9.9v9.5L0 20.6v-8zm11.1 0H24V24l-12.9-1.8V12.6z"/>
    </svg>
  ),
  'windows-server': (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0078D4" strokeWidth="1.5">
      <rect x="2" y="2" width="20" height="20" rx="2"/>
      <path d="M5 7l4.5-.6v4.3H5V7zm5.5-.8L18 5v5.7h-7.5V6.2zM5 12.3h4.5v4.3L5 17v-4.7zm5.5 0H18V18l-7.5-1v-4.7z" fill="#0078D4"/>
    </svg>
  ),
  linux: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style={{ color: '#FCC624' }}>
      <path d="M12 2C9.2 2 7 5.1 7 9c0 2.4.8 4.5 2 5.9-.8.5-2.3 1.6-2.8 2.5-.6 1-.2 2.1.8 2.6 1.4.7 3 .5 4-.5.3.3.6.5 1 .5s.7-.2 1-.5c1 1 2.6 1.2 4 .5 1-.5 1.4-1.6.8-2.6-.5-.9-2-2-2.8-2.5 1.2-1.4 2-3.5 2-5.9 0-3.9-2.2-7-5-7zm-2 7c0-2.8 1-5 2-5s2 2.2 2 5-.9 5-2 5-2-2.2-2-5z"/>
    </svg>
  ),
  'linux-server': (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#FCC624" strokeWidth="1.5">
      <rect x="4" y="1" width="16" height="22" rx="2"/>
      <circle cx="12" cy="5" r="1.5" fill="#FCC624"/>
      <line x1="8" y1="10" x2="16" y2="10"/>
      <line x1="8" y1="14" x2="16" y2="14"/>
      <line x1="8" y1="18" x2="16" y2="18"/>
    </svg>
  ),
  docker: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style={{ color: '#2496ED' }}>
      <path d="M13.98 11.08h2.12a.19.19 0 00.19-.19V9.01a.19.19 0 00-.19-.19h-2.12a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm-2.95 0h2.12a.19.19 0 00.19-.19V9.01a.19.19 0 00-.19-.19H11.03a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm-2.93 0h2.12a.19.19 0 00.19-.19V9.01a.19.19 0 00-.19-.19H8.1a.19.19 0 00-.19.19v1.88c0 .1.08.19.19.19zm-2.96 0h2.12a.19.19 0 00.19-.19V9.01a.19.19 0 00-.19-.19H5.14a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm5.89-2.8h2.12a.19.19 0 00.19-.19V6.21a.19.19 0 00-.19-.19H11.03a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm-2.93 0h2.12a.19.19 0 00.19-.19V6.21a.19.19 0 00-.19-.19H8.1a.19.19 0 00-.19.19v1.88c0 .1.08.19.19.19zm5.88 0h2.12a.19.19 0 00.19-.19V6.21a.19.19 0 00-.19-.19h-2.12a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm0-2.8h2.12a.19.19 0 00.19-.19V3.41a.19.19 0 00-.19-.19h-2.12a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zM24 12.04c-.55-.49-1.81-.69-2.78-.47-.13-.95-.65-1.78-1.27-2.46l-.26-.3-.31.25c-.65.52-1.03 1.24-1.16 2.04-.06.38-.04.78.06 1.16-.44.25-.96.39-1.41.48-.67.14-1.38.12-2.07.12H.57l-.05.38c-.12 1.14.07 2.28.51 3.32l.2.42v.02c1.37 2.34 3.76 3.34 6.4 3.34 5.32 0 9.67-2.45 11.67-7.72 1.3.07 2.6-.32 3.21-1.53l.16-.32-.67-.43z"/>
    </svg>
  ),
};

/* ── Sparkline sub-components ────────────────────── */

function RiskScoreCard({ score, delta, trend }: { score: number; delta: number; trend: RiskScorePoint[] }) {
  const isUp = delta >= 0;
  return (
    <div className="panel dash-kpi-card">
      <span className="kpi-label">CSOC RISK SCORE</span>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
        <span className="dash-big-number">{score}</span>
        <span className={`dash-delta ${isUp ? 'dash-delta--bad' : 'dash-delta--good'}`}>
          {isUp ? '↑' : '↓'} {Math.abs(delta)}
        </span>
      </div>
      <div style={{ marginTop: 8, height: 48 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={trend} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--accent-green)" stopOpacity={0.35} />
                <stop offset="100%" stopColor="var(--accent-green)" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <Area type="monotone" dataKey="score" stroke="var(--accent-green)" fill="url(#riskFill)" strokeWidth={2} dot={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function MttCard({ label, value, unit, trend, gradientId }: { label: string; value: number; unit: string; trend: MttPoint[]; gradientId: string }) {
  return (
    <div className="panel dash-kpi-card">
      <span className="kpi-label">{label}</span>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 2 }}>
        <span className="dash-big-number">{value}</span>
        <span className="dash-unit">{unit}</span>
      </div>
      <div style={{ marginTop: 8, height: 48 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={trend} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity={0.3} />
                <stop offset="100%" stopColor="var(--accent-cyan)" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <Area type="monotone" dataKey="value" stroke="var(--accent-cyan)" fill={`url(#${gradientId})`} strokeWidth={2} dot={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/* ── Main Dashboard ──────────────────────────────── */

export function Dashboard({ onRefresh }: DashboardProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'trends' | 'health'>('overview');
  const [timeRange, setTimeRange] = useState('24h');
  const [customLabel, setCustomLabel] = useState<string | null>(null);
  const [timeDropdownOpen, setTimeDropdownOpen] = useState(false);
  const [showCustomPicker, setShowCustomPicker] = useState(false);
  const [customFrom, setCustomFrom] = useState('');
  const [customTo, setCustomTo] = useState('');
  const [filterDropdownOpen, setFilterDropdownOpen] = useState(false);
  const [filterMenu, setFilterMenu] = useState<'main' | 'severity' | 'asset'>('main');
  const [severityFilters, setSeverityFilters] = useState<Set<string>>(new Set());
  const [assetFilters, setAssetFilters] = useState<Set<string>>(new Set());
  const [eventVolume, setEventVolume] = useState<EventVolumePoint[]>([]);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [refreshing, setRefreshing] = useState(false);

  const totalEvents24h = useMemo(
    () => eventVolume.reduce((sum, p) => sum + p.total, 0),
    [eventVolume],
  );

  const filteredTopAlerts = useMemo(() => {
    return TOP_ALERTS.filter(row => {
      if (severityFilters.size > 0 && !severityFilters.has(row.severity)) return false;
      if (assetFilters.size > 0 && !assetFilters.has(row.target_asset)) return false;
      return true;
    });
  }, [severityFilters, assetFilters]);

  const loadDashboardData = async () => {
    try {
      const volumeResult = await searchRecent(
        'SELECT bucket_hour, sum(event_count) as total FROM events_hot_hourly_rollup WHERE bucket_hour >= now() - INTERVAL 24 HOUR GROUP BY bucket_hour ORDER BY bucket_hour',
        24,
      );
      const points: EventVolumePoint[] = volumeResult.rows.map((row) => ({
        hour: new Date(String(row['bucket_hour'])).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        total: Number(row['total']) || 0,
      }));
      setEventVolume(points);
    } catch { /* degrades gracefully */ }
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

  useEffect(() => { loadDashboardData(); }, []);

  return (
    <div className="page">
      {/* ── Header ─────────────────────────────────── */}
      <div className="dash-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <h1 className="dash-page-title">DASHBOARD</h1>
          <div className="dash-tabs">
            <button
              type="button"
              className={`dash-tab${activeTab === 'overview' ? ' dash-tab--active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              Overview
            </button>
            <button
              type="button"
              className={`dash-tab${activeTab === 'trends' ? ' dash-tab--active' : ''}`}
              onClick={() => setActiveTab('trends')}
            >
              Trends
            </button>
            <button
              type="button"
              className={`dash-tab${activeTab === 'health' ? ' dash-tab--active' : ''}`}
              onClick={() => setActiveTab('health')}
            >
              Health
            </button>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {/* Time range picker */}
          <div className="dash-time-picker">
            <button
              type="button"
              className="dash-time-picker-btn"
              onClick={() => setTimeDropdownOpen(!timeDropdownOpen)}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
              </svg>
              {customLabel ?? [...TIME_RANGE_QUICK, ...TIME_RANGE_PRECISE].find(o => o.value === timeRange)?.label ?? timeRange}
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginLeft: 'auto' }}>
                <polyline points="6 9 12 15 18 9"/>
              </svg>
            </button>
            {timeDropdownOpen && !showCustomPicker && (
              <>
                <div className="dash-time-picker-backdrop" onClick={() => setTimeDropdownOpen(false)} />
                <div className="dash-time-picker-dropdown dash-time-picker-dropdown--split">
                  <div className="dash-time-picker-col">
                    <div className="dash-time-picker-col-title">Quick ranges</div>
                    {TIME_RANGE_QUICK.map(opt => (
                      <button
                        key={opt.value}
                        type="button"
                        className={`dash-time-picker-option${opt.value === timeRange && !customLabel ? ' dash-time-picker-option--active' : ''}`}
                        onClick={() => { setTimeRange(opt.value); setCustomLabel(null); setTimeDropdownOpen(false); handleRefresh(); }}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                  <div className="dash-time-picker-divider" />
                  <div className="dash-time-picker-col">
                    <div className="dash-time-picker-col-title">Precise</div>
                    {TIME_RANGE_PRECISE.map(opt => (
                      <button
                        key={opt.value}
                        type="button"
                        className={`dash-time-picker-option${opt.value === timeRange && !customLabel ? ' dash-time-picker-option--active' : ''}`}
                        onClick={() => { setTimeRange(opt.value); setCustomLabel(null); setTimeDropdownOpen(false); handleRefresh(); }}
                      >
                        {opt.label}
                      </button>
                    ))}
                    <div style={{ height: 8 }} />
                    <div className="dash-time-picker-col-title">Custom</div>
                    <button
                      type="button"
                      className={`dash-time-picker-option${customLabel ? ' dash-time-picker-option--active' : ''}`}
                      onClick={() => setShowCustomPicker(true)}
                    >
                      Custom range...
                    </button>
                  </div>
                </div>
              </>
            )}
            {timeDropdownOpen && showCustomPicker && (
              <>
                <div className="dash-time-picker-backdrop" onClick={() => { setTimeDropdownOpen(false); setShowCustomPicker(false); }} />
                <div className="dash-time-picker-dropdown dash-time-picker-custom">
                  <div className="dash-time-picker-col-title">Custom Range</div>
                  <label className="dash-custom-label">
                    From
                    <input
                      type="datetime-local"
                      className="dash-custom-input"
                      value={customFrom}
                      onChange={e => setCustomFrom(e.target.value)}
                    />
                  </label>
                  <label className="dash-custom-label">
                    To
                    <input
                      type="datetime-local"
                      className="dash-custom-input"
                      value={customTo}
                      onChange={e => setCustomTo(e.target.value)}
                    />
                  </label>
                  <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                    <button
                      type="button"
                      className="dash-time-picker-option"
                      onClick={() => { setShowCustomPicker(false); }}
                    >
                      Back
                    </button>
                    <button
                      type="button"
                      className="dash-custom-apply"
                      disabled={!customFrom || !customTo}
                      onClick={() => {
                        const from = new Date(customFrom);
                        const to = new Date(customTo);
                        const fmt = (d: Date) => d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                        setTimeRange('custom');
                        setCustomLabel(`${fmt(from)} – ${fmt(to)}`);
                        setShowCustomPicker(false);
                        setTimeDropdownOpen(false);
                        handleRefresh();
                      }}
                    >
                      Apply
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
          {/* Active filter pills */}
          {severityFilters.size > 0 && (
            <span className="dash-filter-pill">
              Severity: {[...severityFilters].join(', ')}
              <button type="button" className="dash-filter-pill-x" onClick={() => setSeverityFilters(new Set())}>×</button>
            </span>
          )}
          {assetFilters.size > 0 && (
            <span className="dash-filter-pill">
              Asset: {[...assetFilters].join(', ')}
              <button type="button" className="dash-filter-pill-x" onClick={() => setAssetFilters(new Set())}>×</button>
            </span>
          )}
          {/* Add Filter dropdown */}
          <div className="dash-time-picker">
            <button
              type="button"
              className="dash-filter-btn"
              onClick={() => { setFilterDropdownOpen(!filterDropdownOpen); setFilterMenu('main'); }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>
              </svg>
              Add Filter
            </button>
            {filterDropdownOpen && (
              <>
                <div className="dash-time-picker-backdrop" onClick={() => { setFilterDropdownOpen(false); setFilterMenu('main'); }} />
                <div className="dash-time-picker-dropdown" style={{ minWidth: 220 }}>
                  {filterMenu === 'main' && (
                    <>
                      <div className="dash-time-picker-col-title">Filter by</div>
                      <button type="button" className="dash-time-picker-option dash-filter-menu-item" onClick={() => setFilterMenu('severity')}>
                        <span>Severity</span>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 6 15 12 9 18"/></svg>
                      </button>
                      <button type="button" className="dash-time-picker-option dash-filter-menu-item" onClick={() => setFilterMenu('asset')}>
                        <span>Asset</span>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 6 15 12 9 18"/></svg>
                      </button>
                    </>
                  )}
                  {filterMenu === 'severity' && (
                    <>
                      <button type="button" className="dash-time-picker-option dash-filter-back" onClick={() => setFilterMenu('main')}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
                        Severity
                      </button>
                      <div className="dash-time-picker-divider" style={{ width: '100%', height: 1, margin: '4px 0' }} />
                      {SEVERITY_OPTIONS.map(sev => {
                        const active = severityFilters.has(sev);
                        return (
                          <button
                            key={sev}
                            type="button"
                            className={`dash-time-picker-option dash-filter-check${active ? ' dash-time-picker-option--active' : ''}`}
                            onClick={() => {
                              const next = new Set(severityFilters);
                              if (active) next.delete(sev); else next.add(sev);
                              setSeverityFilters(next);
                            }}
                          >
                            <span className="dash-filter-checkbox">{active ? '✓' : ''}</span>
                            <span className={`dash-sev-badge dash-sev-badge--${sev}`}>{sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
                          </button>
                        );
                      })}
                    </>
                  )}
                  {filterMenu === 'asset' && (
                    <>
                      <button type="button" className="dash-time-picker-option dash-filter-back" onClick={() => setFilterMenu('main')}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
                        Asset
                      </button>
                      <div className="dash-time-picker-divider" style={{ width: '100%', height: 1, margin: '4px 0' }} />
                      {ASSET_OPTIONS.map(asset => {
                        const active = assetFilters.has(asset);
                        return (
                          <button
                            key={asset}
                            type="button"
                            className={`dash-time-picker-option dash-filter-check${active ? ' dash-time-picker-option--active' : ''}`}
                            onClick={() => {
                              const next = new Set(assetFilters);
                              if (active) next.delete(asset); else next.add(asset);
                              setAssetFilters(next);
                            }}
                          >
                            <span className="dash-filter-checkbox">{active ? '✓' : ''}</span>
                            {asset}
                          </button>
                        );
                      })}
                    </>
                  )}
                </div>
              </>
            )}
          </div>
          <button
            type="button"
            className="dash-refresh-icon-btn"
            onClick={handleRefresh}
            disabled={refreshing}
            title="Refresh"
          >
            <svg
              width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
              className={refreshing ? 'dash-spin' : ''}
            >
              <polyline points="23 4 23 10 17 10"/>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
            </svg>
          </button>
        </div>
      </div>

      {/* ── Overview tab ────────────────────────────── */}
      {activeTab === 'overview' && (
        <>
          <div className="dash-kpis">
            <RiskScoreCard score={RISK_SCORE} delta={RISK_DELTA} trend={RISK_TREND} />
            <div className="panel dash-kpi-card">
              <span className="kpi-label">OPEN ALERTS</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">{OPEN_ALERTS_COUNT}</span>
                <span className="dash-delta dash-delta--good">↓ 30%</span>
              </div>
              <div style={{ marginTop: 8, height: 48 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={OPEN_ALERTS_TREND} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="openAlertsFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--accent-violet)" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="var(--accent-violet)" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="value" stroke="var(--accent-violet)" fill="url(#openAlertsFill)" strokeWidth={2} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">CRITICAL / HIGH ALERTS</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">{CRITICAL_HIGH_COUNT}</span>
                <span className="dash-delta dash-delta--bad">↑ 10%</span>
              </div>
              <div style={{ marginTop: 8, height: 48 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={CRITICAL_HIGH_TREND} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="critHighFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--sev-critical)" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="var(--sev-critical)" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="value" stroke="var(--sev-critical)" fill="url(#critHighFill)" strokeWidth={2} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* ── Top unmitigated alerts ──────────────── */}
          <div className="panel dash-table-panel">
            <h2 className="panel-title">Top 5 unmitigated alerts by severity</h2>
            <table className="dash-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Alert name</th>
                  <th>Target Asset</th>
                  <th>Assigned to</th>
                </tr>
              </thead>
              <tbody>
                {filteredTopAlerts.map((row, i) => (
                  <tr key={i}>
                    <td>
                      <span className={`dash-sev-badge dash-sev-badge--${row.severity}`}>
                        {row.severity.charAt(0).toUpperCase() + row.severity.slice(1)}
                      </span>
                    </td>
                    <td className="dash-alert-name">{row.alert_name}</td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        {osIcons[row.asset_os] ?? null}
                        {row.target_asset}
                      </span>
                    </td>
                    <td>{row.assigned_to ?? '–'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ── Trends tab ───────────────────────────────── */}
      {activeTab === 'trends' && (
        <>
          <div className="dash-kpis">
            <MttCard label="MTTD" value={MTTD_CURRENT} unit="min" trend={MTTD_TREND} gradientId="mttdFill" />
            <MttCard label="MTTR" value={MTTR_CURRENT} unit="min" trend={MTTR_TREND} gradientId="mttrFill" />
          </div>

          <div className="dash-charts-row">
            <div className="panel dash-chart-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                  <h2 className="panel-title">CSOC RISK SCORE TREND</h2>
                  <p className="dash-chart-desc">Composite security posture and incident volume.</p>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span className="dash-big-number" style={{ fontSize: 28 }}>{RISK_SCORE}</span>
                  <div style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>Last 8 days</div>
                </div>
              </div>
              <div style={{ height: 220 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={RISK_TREND} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                    <defs>
                      <linearGradient id="riskTrendFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity={0.25} />
                        <stop offset="100%" stopColor="var(--accent-cyan)" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} />
                    <XAxis dataKey="day" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: GRID_STROKE }} />
                    <YAxis yAxisId="left" tick={AXIS_STYLE} tickLine={false} axisLine={false} domain={[0, 100]} />
                    <YAxis yAxisId="right" orientation="right" tick={AXIS_STYLE} tickLine={false} axisLine={false} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(0,244,163,0.06)' }} />
                    <Bar yAxisId="right" dataKey="incidents" fill="var(--accent-cyan)" opacity={0.6} radius={[3, 3, 0, 0]} />
                    <Line yAxisId="left" type="monotone" dataKey="score" stroke="var(--accent-green)" strokeWidth={2.5} dot={{ r: 3, fill: 'var(--accent-green)' }} />
                    <Area yAxisId="left" type="monotone" dataKey="score" fill="url(#riskTrendFill)" stroke="none" />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="panel dash-chart-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                  <h2 className="panel-title">MTTD TREND</h2>
                  <p className="dash-chart-desc">Mean time from breach to detection.</p>
                </div>
              </div>
              <div style={{ height: 220 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={MTTD_TREND} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                    <defs>
                      <linearGradient id="mttdTrendFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--accent-green)" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="var(--accent-green)" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} />
                    <XAxis dataKey="hour" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: GRID_STROKE }} interval={3} />
                    <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} domain={[0, 'auto']} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(0,244,163,0.06)' }} />
                    <Area type="monotone" dataKey="value" stroke="var(--accent-green)" fill="url(#mttdTrendFill)" strokeWidth={2} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <div className="dash-charts-row">
            <div className="panel dash-chart-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                  <h2 className="panel-title">EVENT VOLUME (24H)</h2>
                  <p className="dash-chart-desc">Hourly ingested event count.</p>
                </div>
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                  {totalEvents24h.toLocaleString()} total
                </span>
              </div>
              <div style={{ height: 200 }}>
                {eventVolume.length === 0 ? (
                  <div className="chart-empty">Loading...</div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={eventVolume} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} />
                      <XAxis dataKey="hour" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: GRID_STROKE }} interval={3} />
                      <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} allowDecimals={false} />
                      <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(107,45,189,0.08)' }} />
                      <Bar dataKey="total" fill="var(--accent-violet)" radius={[3, 3, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            <div className="panel dash-chart-panel">
              <h2 className="panel-title">MTTR TREND</h2>
              <p className="dash-chart-desc">Mean time from detection to containment over time.</p>
              <div style={{ height: 200 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={MTTR_TREND} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                    <defs>
                      <linearGradient id="mttrTrendFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="var(--accent-cyan)" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} />
                    <XAxis dataKey="hour" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: GRID_STROKE }} interval={3} />
                    <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(50,245,225,0.06)' }} />
                    <Area type="monotone" dataKey="value" stroke="var(--accent-cyan)" fill="url(#mttrTrendFill)" strokeWidth={2} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Health tab ──────────────────────────────── */}
      {activeTab === 'health' && (
        <>
          {/* ── KPI row 1: core metrics ──────────────── */}
          <div className="dash-kpis">
            <div className="panel dash-kpi-card">
              <span className="kpi-label">AGENTS ONLINE</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">47</span>
                <span className="dash-unit">/ 52</span>
              </div>
              <div className="dash-health-bar" style={{ marginTop: 10 }}>
                <div className="dash-health-bar-fill" style={{ width: '90%' }} />
              </div>
            </div>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">EPS (EVENTS/SEC)</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">12,480</span>
                <span className="dash-delta dash-delta--good">↑ 8%</span>
              </div>
            </div>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">STORAGE USED</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">68%</span>
                <span className="dash-unit">1.2 TB / 1.8 TB</span>
              </div>
              <div className="dash-health-bar" style={{ marginTop: 10 }}>
                <div className="dash-health-bar-fill dash-health-bar-fill--warn" style={{ width: '68%' }} />
              </div>
            </div>
          </div>

          {/* ── KPI row 2: pipeline metrics ──────────── */}
          <div className="dash-kpis">
            <div className="panel dash-kpi-card">
              <span className="kpi-label">INGESTION LAG</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">1.2</span>
                <span className="dash-unit">sec</span>
              </div>
            </div>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">DROPPED EVENTS (24H)</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">34</span>
                <span className="dash-delta dash-delta--good">↓ 60%</span>
              </div>
            </div>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">DETECTION LATENCY</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">4.8</span>
                <span className="dash-unit">ms</span>
              </div>
            </div>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">QUEUE DEPTH</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">128</span>
                <span className="dash-unit">events</span>
              </div>
              <div className="dash-health-bar" style={{ marginTop: 10 }}>
                <div className="dash-health-bar-fill" style={{ width: '3%' }} />
              </div>
            </div>
          </div>

          {/* ── Offline agents (stopped sending logs) ── */}
          <div className="dash-charts-row">
            <div className="panel dash-table-panel" style={{ flex: 1 }}>
              <h2 className="panel-title">Agents Offline</h2>
              <p className="dash-chart-desc">Agents that stopped sending logs — no heartbeat received.</p>
              <table className="dash-table">
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>OS</th>
                    <th>Last Seen</th>
                    <th>Downtime</th>
                    <th>Group</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td style={{ fontWeight: 600 }}>SRV-DB-03</td>
                    <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{osIcons['linux-server']} Linux Server</span></td>
                    <td>2h ago</td>
                    <td><span className="dash-sev-badge dash-sev-badge--critical">2h 14m</span></td>
                    <td>databases</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>SRV-WEB-11</td>
                    <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{osIcons['linux-server']} Linux Server</span></td>
                    <td>5h ago</td>
                    <td><span className="dash-sev-badge dash-sev-badge--critical">5h 02m</span></td>
                    <td>web-servers</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>WS-SALES-14</td>
                    <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{osIcons['windows']} Windows</span></td>
                    <td>45m ago</td>
                    <td><span className="dash-sev-badge dash-sev-badge--high">45m</span></td>
                    <td>sales</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="panel dash-table-panel" style={{ flex: 1 }}>
              <h2 className="panel-title">Degraded / Warnings</h2>
              <p className="dash-chart-desc">Agents sending logs but reporting issues.</p>
              <table className="dash-table">
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>OS</th>
                    <th>Status</th>
                    <th>Issue</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td style={{ fontWeight: 600 }}>WS-FINANCE-07</td>
                    <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{osIcons['windows']} Windows</span></td>
                    <td><span className="dash-sev-badge dash-sev-badge--high">Degraded</span></td>
                    <td>High CPU (92%)</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>K8S-NODE-04</td>
                    <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{osIcons['docker']} Docker</span></td>
                    <td><span className="dash-sev-badge dash-sev-badge--high">Degraded</span></td>
                    <td>Disk queue backlog (4,200 events)</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>WS-DEV-09</td>
                    <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{osIcons['linux']} Linux</span></td>
                    <td><span className="dash-sev-badge dash-sev-badge--medium">Warning</span></td>
                    <td>Outdated agent (v1.2.0 → v1.4.2)</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>SRV-APP-06</td>
                    <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{osIcons['linux-server']} Linux Server</span></td>
                    <td><span className="dash-sev-badge dash-sev-badge--medium">Warning</span></td>
                    <td>Memory usage 87%</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>WS-EXEC-12</td>
                    <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{osIcons['windows']} Windows</span></td>
                    <td><span className="dash-sev-badge dash-sev-badge--medium">Warning</span></td>
                    <td>TLS cert expires in 5 days</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* ── Data source coverage ─────────────────── */}
          <div className="panel dash-table-panel">
            <h2 className="panel-title">Data Source Coverage</h2>
            <p className="dash-chart-desc">Log sources and their ingestion status over the last 24h.</p>
            <table className="dash-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Protocol</th>
                  <th>Events (24h)</th>
                  <th>Status</th>
                  <th>Last Event</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style={{ fontWeight: 600 }}>Windows Event Logs</td>
                  <td>Agent</td>
                  <td>1,284,320</td>
                  <td><span className="dash-sev-badge" style={{ color: 'var(--accent-green)' }}>Active</span></td>
                  <td>just now</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Sysmon</td>
                  <td>Agent</td>
                  <td>892,140</td>
                  <td><span className="dash-sev-badge" style={{ color: 'var(--accent-green)' }}>Active</span></td>
                  <td>just now</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Linux Syslog</td>
                  <td>UDP/TCP</td>
                  <td>534,800</td>
                  <td><span className="dash-sev-badge" style={{ color: 'var(--accent-green)' }}>Active</span></td>
                  <td>2s ago</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Firewall (PAN-OS)</td>
                  <td>Syslog TLS</td>
                  <td>2,104,500</td>
                  <td><span className="dash-sev-badge" style={{ color: 'var(--accent-green)' }}>Active</span></td>
                  <td>1s ago</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>NetFlow v9</td>
                  <td>UDP</td>
                  <td>4,230,100</td>
                  <td><span className="dash-sev-badge" style={{ color: 'var(--accent-green)' }}>Active</span></td>
                  <td>just now</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Okta SSO</td>
                  <td>Cloud Poll</td>
                  <td>12,480</td>
                  <td><span className="dash-sev-badge" style={{ color: 'var(--accent-green)' }}>Active</span></td>
                  <td>58s ago</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Office 365</td>
                  <td>Cloud Poll</td>
                  <td>0</td>
                  <td><span className="dash-sev-badge dash-sev-badge--critical">Silent</span></td>
                  <td>6h ago</td>
                </tr>
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
