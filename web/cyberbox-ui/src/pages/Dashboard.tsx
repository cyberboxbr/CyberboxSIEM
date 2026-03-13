import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  getAllAlerts,
  getDashboardStats,
  type AlertRecord,
  type DashboardStats,
} from '../api/client';

interface AlertSparkPoint { day: string; value: number }
type AssetOs = 'windows' | 'windows-server' | 'linux' | 'linux-server' | 'docker' | 'syslog' | 'firewall';
interface TopAlertRow {
  severity: 'critical' | 'high' | 'medium' | 'low';
  alert_name: string;
  target_asset: string;
  asset_os: AssetOs;
  vendor: string;
  assigned_to: string | null;
}


/* -- Helpers -- */

function formatCompact(n: number): string {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1).replace(/\.0$/, '') + 'B';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\.0$/, '') + 'K';
  return String(n);
}

function buildAlertSparkline(alerts: AlertRecord[]): AlertSparkPoint[] {
  const now = new Date();
  return Array.from({ length: 8 }, (_, i) => {
    const bucketStart = new Date(now);
    bucketStart.setDate(bucketStart.getDate() - (7 - i));
    bucketStart.setHours(0, 0, 0, 0);
    const bucketEnd = i < 7
      ? new Date(bucketStart.getTime() + 24 * 60 * 60 * 1000)
      : now;
    const label = i < 7
      ? bucketStart.toLocaleDateString([], { weekday: 'short' })
      : 'Now';
    const value = alerts.filter(a => {
      const t = new Date(a.first_seen);
      return t >= bucketStart && t < bucketEnd;
    }).length;
    return { day: label, value };
  });
}

const FIREWALL_KEYWORDS = ['opnsense', 'pfsense', 'fortinet', 'fortigate', 'sophos', 'paloalto', 'firewall', 'fw.', 'asa'];

function osFromString(os?: string, hostname?: string): AssetOs {
  if (!os) return 'linux';
  const lower = os.toLowerCase();
  const host = (hostname || '').toLowerCase();
  if (lower === 'firewall') return 'firewall';
  if (FIREWALL_KEYWORDS.some(k => host.includes(k))) return 'firewall';
  if (lower === 'syslog' && FIREWALL_KEYWORDS.some(k => host.includes(k))) return 'firewall';
  if (lower.includes('windows server')) return 'windows-server';
  if (lower.includes('windows')) return 'windows';
  if (lower.includes('docker') || lower.includes('container')) return 'docker';
  if (lower === 'syslog') return 'linux';
  if (lower.includes('server')) return 'linux-server';
  return 'linux';
}

const SOURCE_LABELS: Record<string, string> = {
  syslog: 'Syslog',
  otlp: 'OTLP',
  api: 'API',
  agent: 'Agent',
  cef: 'CEF',
  leef: 'LEEF',
  json: 'JSON',
  gelf: 'GELF',
  netflow: 'NetFlow',
  wineventlog: 'Windows Event Log',
  file: 'File',
  s3: 'S3',
  okta: 'Okta',
  o365: 'Office 365',
};

function prettySource(raw: string): string {
  if (!raw || raw === '') return 'Other';
  return SOURCE_LABELS[raw.toLowerCase()] ?? raw.charAt(0).toUpperCase() + raw.slice(1);
}

/* -- Props */

interface DashboardProps {
  onRefresh: () => Promise<void>;
}

/* -- Helpers */

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

/* -- OS icons for target asset */

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
    <img src="/tux.png" width="16" height="16" alt="Linux" style={{ verticalAlign: 'middle' }} />
  ),
  'linux-server': (
    <img src="/tux.png" width="16" height="16" alt="Linux Server" style={{ verticalAlign: 'middle' }} />
  ),
  docker: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style={{ color: '#2496ED' }}>
      <path d="M13.98 11.08h2.12a.19.19 0 00.19-.19V9.01a.19.19 0 00-.19-.19h-2.12a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm-2.95 0h2.12a.19.19 0 00.19-.19V9.01a.19.19 0 00-.19-.19H11.03a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm-2.93 0h2.12a.19.19 0 00.19-.19V9.01a.19.19 0 00-.19-.19H8.1a.19.19 0 00-.19.19v1.88c0 .1.08.19.19.19zm-2.96 0h2.12a.19.19 0 00.19-.19V9.01a.19.19 0 00-.19-.19H5.14a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm5.89-2.8h2.12a.19.19 0 00.19-.19V6.21a.19.19 0 00-.19-.19H11.03a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm-2.93 0h2.12a.19.19 0 00.19-.19V6.21a.19.19 0 00-.19-.19H8.1a.19.19 0 00-.19.19v1.88c0 .1.08.19.19.19zm5.88 0h2.12a.19.19 0 00.19-.19V6.21a.19.19 0 00-.19-.19h-2.12a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zm0-2.8h2.12a.19.19 0 00.19-.19V3.41a.19.19 0 00-.19-.19h-2.12a.19.19 0 00-.19.19v1.88c0 .1.09.19.19.19zM24 12.04c-.55-.49-1.81-.69-2.78-.47-.13-.95-.65-1.78-1.27-2.46l-.26-.3-.31.25c-.65.52-1.03 1.24-1.16 2.04-.06.38-.04.78.06 1.16-.44.25-.96.39-1.41.48-.67.14-1.38.12-2.07.12H.57l-.05.38c-.12 1.14.07 2.28.51 3.32l.2.42v.02c1.37 2.34 3.76 3.34 6.4 3.34 5.32 0 9.67-2.45 11.67-7.72 1.3.07 2.6-.32 3.21-1.53l.16-.32-.67-.43z"/>
    </svg>
  ),
  syslog: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="18" rx="2"/>
      <path d="M7 8h10M7 12h6"/>
    </svg>
  ),
  firewall: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
      <rect x="2" y="4" width="20" height="6" rx="1.5" stroke="#f45d5d" strokeWidth="1.5" fill="rgba(244,93,93,0.1)" />
      <rect x="2" y="14" width="20" height="6" rx="1.5" stroke="#f45d5d" strokeWidth="1.5" fill="rgba(244,93,93,0.1)" />
      <circle cx="5.5" cy="7" r="1" fill="#58d68d" />
      <circle cx="5.5" cy="17" r="1" fill="#58d68d" />
      <line x1="8" y1="7" x2="14" y2="7" stroke="#f45d5d" strokeWidth="1" strokeLinecap="round" />
      <line x1="8" y1="17" x2="14" y2="17" stroke="#f45d5d" strokeWidth="1" strokeLinecap="round" />
      <path d="M12 10V14" stroke="rgba(219,228,243,0.3)" strokeWidth="1.5" strokeDasharray="2 1" />
    </svg>
  ),
};

/* -- Tooltip formatter */
const compactTooltipFormatter = (value: number | undefined) => [formatCompact(value ?? 0), 'Events'];
const epsTooltipFormatter = (value: number | undefined) => [(value ?? 0).toFixed(1), 'EPS'];

/* -- Main Dashboard */

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
  const [openAlertsCount, setOpenAlertsCount] = useState<number>(0);
  const [critHighCount, setCritHighCount] = useState<number>(0);
  const [openAlertsTrend, setOpenAlertsTrend] = useState<AlertSparkPoint[]>([]);
  const [critHighTrend, setCritHighTrend] = useState<AlertSparkPoint[]>([]);
  const [topAlerts, setTopAlerts] = useState<TopAlertRow[]>([]);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [refreshing, setRefreshing] = useState(false);
  const [stats, setStats] = useState<DashboardStats | null>(null);

  const timeRangeLabel = useMemo(() => {
    if (customLabel) return customLabel;
    return [...TIME_RANGE_QUICK, ...TIME_RANGE_PRECISE].find(o => o.value === timeRange)?.label ?? timeRange;
  }, [timeRange, customLabel]);

  const filteredTopAlerts = useMemo(() => {
    return topAlerts.filter(row => {
      if (severityFilters.size > 0 && !severityFilters.has(row.severity)) return false;
      if (assetFilters.size > 0 && !assetFilters.has(row.target_asset)) return false;
      return true;
    });
  }, [topAlerts, severityFilters, assetFilters]);

  const hourlyChartData = useMemo(() => {
    if (!stats?.hourly_events?.length) return [];
    return stats.hourly_events.map(h => ({
      time: new Date(h.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      count: parseInt(h.count, 10) || 0,
    }));
  }, [stats]);

  const sourceChartData = useMemo(() => {
    if (!stats?.events_by_source?.length) return [];
    return stats.events_by_source
      .filter(s => s.source && s.source !== '')
      .slice(0, 6)
      .map(s => ({
        source: prettySource(s.source),
        count: parseInt(s.count, 10) || 0,
      }));
  }, [stats]);

  const hostChartData = useMemo(() => {
    if (!stats?.events_by_host?.length) return [];
    return stats.events_by_host
      .filter(h => h.hostname && h.hostname !== 'unknown')
      .slice(0, 6)
      .map(h => ({
        hostname: h.hostname,
        count: parseInt(h.count, 10) || 0,
      }));
  }, [stats]);

  const epsTrendData = useMemo(() => {
    if (!stats?.eps_trend?.length) return [];
    return stats.eps_trend.map(p => ({
      time: new Date(p.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      eps: parseFloat(p.eps) || 0,
    }));
  }, [stats]);

  const assetOptions = useMemo(() => {
    if (!stats?.agents?.length) return [];
    return stats.agents.map(a => a.hostname);
  }, [stats]);

  const loadDashboardData = useCallback(async () => {
    const rangeParam = timeRange === 'custom' ? '24h' : timeRange;
    const [openAlerts, dashStats] = await Promise.all([
      getAllAlerts({ status: 'open' }).catch(() => [] as AlertRecord[]),
      getDashboardStats(rangeParam).catch(() => null),
    ]);

    if (dashStats) setStats(dashStats);

    const critHigh = openAlerts.filter(a => a.severity === 'critical' || a.severity === 'high');

    setOpenAlertsCount(dashStats?.open_alerts ?? openAlerts.length);
    setCritHighCount(critHigh.length);
    setOpenAlertsTrend(buildAlertSparkline(openAlerts));
    setCritHighTrend(buildAlertSparkline(critHigh));

    const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const top5 = [...openAlerts]
      .sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4))
      .slice(0, 5)
      .map(a => ({
        severity: a.severity as TopAlertRow['severity'],
        alert_name: a.rule_title || `Rule ${a.rule_id.slice(0, 8)}`,
        target_asset: a.agent_meta?.hostname ?? '-',
        asset_os: osFromString(a.agent_meta?.os, a.agent_meta?.hostname),
        vendor: 'CyberboxSIEM',
        assigned_to: a.assignee ?? null,
      }));
    setTopAlerts(top5);
  }, [timeRange]);

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
    const id = setInterval(loadDashboardData, 15_000);
    return () => clearInterval(id);
  }, [loadDashboardData]);

  return (
    <div className="page">
      {/* -- Header */}
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
              {timeRangeLabel}
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
                        onClick={() => { setTimeRange(opt.value); setCustomLabel(null); setTimeDropdownOpen(false); }}
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
                        onClick={() => { setTimeRange(opt.value); setCustomLabel(null); setTimeDropdownOpen(false); }}
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
                        setCustomLabel(`${fmt(from)} - ${fmt(to)}`);
                        setShowCustomPicker(false);
                        setTimeDropdownOpen(false);
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
              <button type="button" className="dash-filter-pill-x" onClick={() => setSeverityFilters(new Set())}>x</button>
            </span>
          )}
          {assetFilters.size > 0 && (
            <span className="dash-filter-pill">
              Asset: {[...assetFilters].join(', ')}
              <button type="button" className="dash-filter-pill-x" onClick={() => setAssetFilters(new Set())}>x</button>
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
                            <span className="dash-filter-checkbox">{active ? 'v' : ''}</span>
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
                      {assetOptions.map(asset => {
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
                            <span className="dash-filter-checkbox">{active ? 'v' : ''}</span>
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

      {/* -- Overview tab */}
      {activeTab === 'overview' && (
        <>
          {/* KPI cards row */}
          <div className="dash-kpis" style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 16 }}>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">TOTAL EVENTS</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">{stats?.total_events != null ? formatCompact(stats.total_events) : '-'}</span>
              </div>
              <div style={{ marginTop: 8, height: 48 }}>
                {hourlyChartData.length > 0 && (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={hourlyChartData} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="eventsFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#10b981" stopOpacity={0.35} />
                          <stop offset="100%" stopColor="#10b981" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <Area type="monotone" dataKey="count" stroke="#10b981" fill="url(#eventsFill)" strokeWidth={2} dot={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">EPS USAGE</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 2 }}>
                <span className="dash-big-number" style={{ color: '#f59e0b' }}>{stats?.current_eps?.toFixed(1) ?? '0'}</span>
                <span style={{ fontSize: 13, color: 'var(--text-dim)' }}>events/s</span>
              </div>
              <div style={{ marginTop: 8, height: 48 }}>
                {epsTrendData.length > 0 && (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={epsTrendData} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="epsFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.35} />
                          <stop offset="100%" stopColor="#f59e0b" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <Area type="monotone" dataKey="eps" stroke="#f59e0b" fill="url(#epsFill)" strokeWidth={2} dot={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">OPEN ALERTS</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">{openAlertsCount}</span>
              </div>
              <div style={{ marginTop: 8, height: 48 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={openAlertsTrend} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
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
              <span className="kpi-label">ACTIVE AGENTS</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">{stats?.active_agents ?? 0}</span>
                <span style={{ fontSize: 13, color: 'var(--text-dim)' }}>/ {stats?.total_agents ?? 0}</span>
              </div>
              <div style={{ marginTop: 12 }}>
                {stats?.agents?.map(a => (
                  <div key={a.agent_id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, fontSize: 13 }}>
                    {osIcons[osFromString(a.os, a.hostname)] ?? null}
                    <span style={{ color: 'var(--text-main)' }}>{a.hostname}</span>
                    <span style={{
                      marginLeft: 'auto',
                      fontSize: 11,
                      padding: '1px 8px',
                      borderRadius: 10,
                      background: a.status === 'active' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
                      color: a.status === 'active' ? '#10b981' : '#ef4444',
                    }}>{a.status}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="panel dash-kpi-card">
              <span className="kpi-label">ACTIVE RULES</span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 2 }}>
                <span className="dash-big-number">{stats?.active_rules ?? 0}</span>
              </div>
              <div style={{ marginTop: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--text-dim)' }}>
                  <span>Crit/High alerts</span>
                  <span style={{ marginLeft: 'auto', fontWeight: 600, color: critHighCount > 0 ? '#ef4444' : 'var(--text-dim)' }}>{critHighCount}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Charts row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 16 }}>
            {/* Event volume */}
            <div className="panel" style={{ padding: '16px 20px' }}>
              <h2 className="panel-title" style={{ marginBottom: 12 }}>Event volume ({timeRangeLabel.toLowerCase()})</h2>
              {hourlyChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={hourlyChartData}>
                    <XAxis dataKey="time" tick={{ fill: '#888', fontSize: 11 }} tickLine={false} axisLine={false} interval={Math.max(0, Math.floor(hourlyChartData.length / 8) - 1)} />
                    <YAxis tick={{ fill: '#888', fontSize: 11 }} tickLine={false} axisLine={false} width={48} tickFormatter={formatCompact} />
                    <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: 8 }} labelStyle={{ color: '#aaa' }} formatter={compactTooltipFormatter} />
                    <Bar dataKey="count" fill="#6366f1" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="chart-empty" style={{ padding: '40px 0' }}>Waiting for events...</div>
              )}
            </div>

            {/* Events by source type */}
            <div className="panel" style={{ padding: '16px 20px' }}>
              <h2 className="panel-title" style={{ marginBottom: 12 }}>Events by source</h2>
              {sourceChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={sourceChartData} layout="vertical">
                    <XAxis type="number" tick={{ fill: '#888', fontSize: 11 }} tickLine={false} axisLine={false} tickFormatter={formatCompact} />
                    <YAxis type="category" dataKey="source" tick={{ fill: '#ccc', fontSize: 12 }} tickLine={false} axisLine={false} width={120} />
                    <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: 8 }} labelStyle={{ color: '#aaa' }} formatter={compactTooltipFormatter} />
                    <Bar dataKey="count" fill="#10b981" radius={[0, 3, 3, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="chart-empty" style={{ padding: '40px 0' }}>No event sources yet</div>
              )}
            </div>
          </div>

          {/* Events by host row */}
          {hostChartData.length > 0 && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 16, marginTop: 16 }}>
              <div className="panel" style={{ padding: '16px 20px' }}>
                <h2 className="panel-title" style={{ marginBottom: 12 }}>Events by host ({timeRangeLabel.toLowerCase()})</h2>
                <ResponsiveContainer width="100%" height={Math.max(120, hostChartData.length * 36)}>
                  <BarChart data={hostChartData} layout="vertical">
                    <XAxis type="number" tick={{ fill: '#888', fontSize: 11 }} tickLine={false} axisLine={false} tickFormatter={formatCompact} />
                    <YAxis type="category" dataKey="hostname" tick={{ fill: '#ccc', fontSize: 12 }} tickLine={false} axisLine={false} width={180} />
                    <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: 8 }} labelStyle={{ color: '#aaa' }} formatter={compactTooltipFormatter} />
                    <Bar dataKey="count" fill="#8b5cf6" radius={[0, 3, 3, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Top unmitigated alerts */}
          <div className="panel dash-table-panel" style={{ marginTop: 16 }}>
            <h2 className="panel-title">Top 5 unmitigated alerts by severity</h2>
            {filteredTopAlerts.length === 0 ? (
              <div className="chart-empty" style={{ padding: '32px 0' }}>
                {topAlerts.length === 0 ? 'No open alerts - environment is clean.' : 'No alerts match the active filters.'}
              </div>
            ) : (
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
                      <td>{row.assigned_to ?? '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {/* -- Trends tab */}
      {activeTab === 'trends' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="panel" style={{ padding: '16px 20px' }}>
            <h2 className="panel-title" style={{ marginBottom: 12 }}>Event volume ({timeRangeLabel.toLowerCase()})</h2>
            {hourlyChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={hourlyChartData}>
                  <XAxis dataKey="time" tick={{ fill: '#888', fontSize: 11 }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fill: '#888', fontSize: 11 }} tickLine={false} axisLine={false} width={50} tickFormatter={formatCompact} />
                  <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: 8 }} labelStyle={{ color: '#aaa' }} formatter={compactTooltipFormatter} />
                  <defs>
                    <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#6366f1" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#6366f1" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <Area type="monotone" dataKey="count" stroke="#6366f1" fill="url(#trendFill)" strokeWidth={2} dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="chart-empty" style={{ padding: '60px 0' }}>
                Waiting for event data to populate trends...
              </div>
            )}
          </div>

          <div className="panel" style={{ padding: '16px 20px' }}>
            <h2 className="panel-title" style={{ marginBottom: 12 }}>EPS usage ({timeRangeLabel.toLowerCase()})</h2>
            {epsTrendData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={epsTrendData}>
                  <XAxis dataKey="time" tick={{ fill: '#888', fontSize: 11 }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fill: '#888', fontSize: 11 }} tickLine={false} axisLine={false} width={50} />
                  <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: 8 }} labelStyle={{ color: '#aaa' }} formatter={epsTooltipFormatter} />
                  <Line type="monotone" dataKey="eps" stroke="#f59e0b" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="chart-empty" style={{ padding: '60px 0' }}>
                Waiting for EPS data...
              </div>
            )}
          </div>
        </div>
      )}

      {/* -- Health tab */}
      {activeTab === 'health' && (
        <div className="panel" style={{ padding: '16px 20px' }}>
          <h2 className="panel-title" style={{ marginBottom: 16 }}>Agent Health</h2>
          {stats?.agents && stats.agents.length > 0 ? (
            <table className="dash-table">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Hostname</th>
                  <th>OS</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {stats.agents.map(a => (
                  <tr key={a.agent_id}>
                    <td style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      {osIcons[osFromString(a.os, a.hostname)] ?? null}
                      {a.agent_id}
                    </td>
                    <td>{a.hostname}</td>
                    <td>{osFromString(a.os, a.hostname)}</td>
                    <td>
                      <span style={{
                        fontSize: 12,
                        padding: '2px 10px',
                        borderRadius: 10,
                        background: a.status === 'active' ? 'rgba(16,185,129,0.15)' : a.status === 'stale' ? 'rgba(245,158,11,0.15)' : 'rgba(239,68,68,0.15)',
                        color: a.status === 'active' ? '#10b981' : a.status === 'stale' ? '#f59e0b' : '#ef4444',
                      }}>{a.status.toUpperCase()}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="chart-empty" style={{ padding: '48px 0' }}>
              No agents registered yet
            </div>
          )}
        </div>
      )}
    </div>
  );
}
