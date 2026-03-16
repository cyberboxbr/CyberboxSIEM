import { useCallback, useMemo, useState } from 'react';
import {
  falsePositiveAlert,
  explainAlert,
} from '../api/client';
import type { AlertRecord } from '../api/client';
import { useAlertStream } from '../hooks/useAlertStream';

/* ── helpers ─────────────────────────────────────── */

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function ruleTitle(alert: AlertRecord): string {
  const plan = (alert as any).compiled_plan;
  if (plan && typeof plan === 'object' && typeof plan.title === 'string' && plan.title.length > 0) {
    return plan.title;
  }
  return alert.rule_id.slice(0, 8);
}

type StatusFilter = 'open' | 'acknowledged' | 'all';
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f45d5d',
  high: '#f5a623',
  medium: '#d4bc00',
  low: '#4a9eda',
};

const STATUS_LABELS: Record<string, { bg: string; color: string }> = {
  open: { bg: 'rgba(244,93,93,0.15)', color: '#f45d5d' },
  acknowledged: { bg: 'rgba(74,158,218,0.15)', color: '#4a9eda' },
  closed: { bg: 'rgba(88,214,141,0.15)', color: '#58d68d' },
  false_positive: { bg: 'rgba(212,188,0,0.12)', color: '#d4bc00' },
};

interface ExplainResult {
  summary: string;
  why_suspicious: string;
  likely_cause: string;
  recommended_actions: string[];
  false_positive_likelihood: string;
}

/* ── OS icons ─────────────────────────────────────── */

function getOsIcon(os: string): JSX.Element | null {
  const l = os?.toLowerCase() ?? '';
  if (l.includes('windows server'))
    return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#0078D4" strokeWidth="1.5"><rect x="2" y="2" width="20" height="20" rx="2"/><path d="M5 7l4.5-.6v4.3H5V7zm5.5-.8L18 5v5.7h-7.5V6.2zM5 12.3h4.5v4.3L5 17v-4.7zm5.5 0H18V18l-7.5-1v-4.7z" fill="#0078D4"/></svg>;
  if (l.includes('windows'))
    return <svg width="14" height="14" viewBox="0 0 24 24" fill="#0078D4"><path d="M0 3.5l9.9-1.4v9.5H0V3.5zm11.1-1.6L24 0v11.6H11.1V1.9zM0 12.6h9.9v9.5L0 20.6v-8zm11.1 0H24V24l-12.9-1.8V12.6z"/></svg>;
  if (l.includes('ubuntu') || l.includes('linux'))
    return <svg width="14" height="14" viewBox="0 0 24 24" fill="#FCC624"><path d="M12 2C9.2 2 7 5.1 7 9c0 2.4.8 4.5 2 5.9-.8.5-2.3 1.6-2.8 2.5-.6 1-.2 2.1.8 2.6 1.4.7 3 .5 4-.5.3.3.6.5 1 .5s.7-.2 1-.5c1 1 2.6 1.2 4 .5 1-.5 1.4-1.6.8-2.6-.5-.9-2-2-2.8-2.5 1.2-1.4 2-3.5 2-5.9 0-3.9-2.2-7-5-7zm-2 7c0-2.8 1-5 2-5s2 2.2 2 5-.9 5-2 5-2-2.2-2-5z"/></svg>;
  return null;
}

/* ── SVG icons ────────────────────────────────────── */

const chevronIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="6 9 12 15 18 9" />
  </svg>
);

const linkIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
  </svg>
);

const refreshIcon = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="23 4 23 10 17 10" />
    <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
  </svg>
);

/* ── component ───────────────────────────────────── */

export function AlertQueue() {
  const { alerts, connected, error, refresh } = useAlertStream();

  const [statusFilter, setStatusFilter] = useState<StatusFilter>('open');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // explain panel
  const [explainAlertId, setExplainAlertId] = useState<string | null>(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainResult, setExplainResult] = useState<ExplainResult | null>(null);
  const [explainError, setExplainError] = useState<string | null>(null);

  // status text
  const [statusText, setStatusText] = useState('');

  /* ── filtering ─────────────────────────────────── */

  const filtered = useMemo(() => {
    let list = alerts;
    if (statusFilter !== 'all') {
      list = list.filter((a) => a.status === statusFilter);
    }
    if (severityFilter !== 'all') {
      list = list.filter((a) => {
        const sev = (a as any).severity ?? 'low';
        return sev === severityFilter;
      });
    }
    return list;
  }, [alerts, statusFilter, severityFilter]);

  /* ── summary stats ────────────────────────────── */

  const stats = useMemo(() => {
    const open = alerts.filter(a => a.status === 'open').length;
    const critical = alerts.filter(a => (a as any).severity === 'critical' && a.status !== 'closed' && a.status !== 'false_positive').length;
    const high = alerts.filter(a => (a as any).severity === 'high' && a.status !== 'closed' && a.status !== 'false_positive').length;
    const medium = alerts.filter(a => (a as any).severity === 'medium' && a.status !== 'closed' && a.status !== 'false_positive').length;
    const low = alerts.filter(a => (a as any).severity === 'low' && a.status !== 'closed' && a.status !== 'false_positive').length;
    const unassigned = alerts.filter(a => !a.assignee && a.status === 'open').length;
    return { open, critical, high, medium, low, unassigned };
  }, [alerts]);

  /* ── selection ─────────────────────────────────── */

  const allSelected = filtered.length > 0 && filtered.every((a) => selected.has(a.alert_id));

  const toggleSelectAll = () => {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map((a) => a.alert_id)));
    }
  };

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  /* ── bulk actions ──────────────────────────────── */

  const selectedIds = Array.from(selected);

  const handleBulkFalsePositive = useCallback(async () => {
    setStatusText(`Marking ${selectedIds.length} alerts as false positive...`);
    try {
      await Promise.all(selectedIds.map((id) => falsePositiveAlert(id, 'soc-admin')));
      setSelected(new Set());
      await refresh();
      setStatusText(`Marked ${selectedIds.length} alerts as false positive.`);
    } catch (err) {
      setStatusText(`False positive failed: ${String(err)}`);
    }
  }, [selectedIds, refresh]);

  const handleSingleFP = async (id: string) => {
    setStatusText('Marking as false positive...');
    try {
      await falsePositiveAlert(id, 'soc-admin');
      await refresh();
      setStatusText('Marked as false positive.');
    } catch (err) {
      setStatusText(`Failed: ${String(err)}`);
    }
  };

  /* ── explain ───────────────────────────────────── */

  const handleExplain = async (alertId: string) => {
    setExplainAlertId(alertId);
    setExplainLoading(true);
    setExplainResult(null);
    setExplainError(null);
    try {
      const result = await explainAlert(alertId);
      setExplainResult(result);
    } catch (err) {
      setExplainError(String(err));
    } finally {
      setExplainLoading(false);
    }
  };

  /* ── render ────────────────────────────────────── */

  const statusTabs: { key: StatusFilter; label: string; count?: number }[] = [
    { key: 'open', label: 'Open', count: stats.open },
    { key: 'acknowledged', label: 'Acknowledged' },
    { key: 'all', label: 'All', count: alerts.length },
  ];

  const severityPills: { key: SeverityFilter; label: string; count?: number }[] = [
    { key: 'all', label: 'All Severities' },
    { key: 'critical', label: 'Critical', count: stats.critical },
    { key: 'high', label: 'High', count: stats.high },
    { key: 'medium', label: 'Medium', count: stats.medium },
    { key: 'low', label: 'Low', count: stats.low },
  ];

  return (
    <div className="page" style={{ position: 'relative' }}>
      {/* ── Header ─────────────────────────────────── */}
      <div className="aq-header">
        <div className="aq-header-left">
          <h1 className="dash-page-title" style={{ margin: 0 }}>ALERTS</h1>
          <span className="aq-live-badge" data-connected={connected}>
            <span className="aq-live-dot" />
            {connected ? 'Live' : 'Offline'}
          </span>
          <span className="aq-count">{filtered.length} results</span>
        </div>
        <div className="aq-header-right">
          {error && <span className="aq-error">{error}</span>}
          <button className="dash-refresh-icon-btn" onClick={refresh} title="Refresh">
            {refreshIcon}
          </button>
        </div>
      </div>

      {/* ── Summary KPI Strip ────────────────────── */}
      <div className="aq-kpi-strip">
        <div className="aq-kpi" data-severity="critical">
          <span className="aq-kpi-value">{stats.critical}</span>
          <span className="aq-kpi-label">Critical</span>
        </div>
        <div className="aq-kpi" data-severity="high">
          <span className="aq-kpi-value">{stats.high}</span>
          <span className="aq-kpi-label">High</span>
        </div>
        <div className="aq-kpi" data-severity="medium">
          <span className="aq-kpi-value">{stats.medium}</span>
          <span className="aq-kpi-label">Medium</span>
        </div>
        <div className="aq-kpi" data-severity="low">
          <span className="aq-kpi-value">{stats.low}</span>
          <span className="aq-kpi-label">Low</span>
        </div>
        <div className="aq-kpi-divider" />
        <div className="aq-kpi">
          <span className="aq-kpi-value">{stats.unassigned}</span>
          <span className="aq-kpi-label">Unassigned</span>
        </div>
      </div>

      {/* ── Filter bar ───────────────────────────── */}
      <div className="aq-filter-bar">
        <div className="aq-tabs">
          {statusTabs.map((tab) => (
            <button
              key={tab.key}
              className={`dash-tab${statusFilter === tab.key ? ' dash-tab--active' : ''}`}
              onClick={() => setStatusFilter(tab.key)}
            >
              {tab.label}
              {tab.count != null && <span className="aq-tab-count">{tab.count}</span>}
            </button>
          ))}
        </div>
        <div className="aq-severity-pills">
          {severityPills.map((pill) => {
            const active = severityFilter === pill.key;
            const color = pill.key === 'all' ? 'var(--text-primary)' : (SEVERITY_COLORS[pill.key] ?? 'var(--text-primary)');
            return (
              <button
                key={pill.key}
                className={`aq-sev-pill${active ? ' aq-sev-pill--active' : ''}`}
                onClick={() => setSeverityFilter(pill.key)}
                style={{
                  '--pill-color': color,
                } as React.CSSProperties}
              >
                {pill.key !== 'all' && <span className="aq-sev-dot" style={{ background: color }} />}
                {pill.label}
                {pill.count != null && <span className="aq-pill-count">{pill.count}</span>}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Status text ────────────────────────────── */}
      {statusText && (
        <div className="aq-status-toast">{statusText}</div>
      )}

      {/* ── Alert table ─────────────────────────────── */}
      <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        {/* Header row */}
        <div className="aq-table-header">
          <label className="aq-col-check">
            <input
              type="checkbox"
              checked={allSelected}
              onChange={toggleSelectAll}
            />
          </label>
          <span className="aq-col-sev">Severity</span>
          <span className="aq-col-rule">Alert Name</span>
          <span className="aq-col-host">Source</span>
          <span className="aq-col-dest">Destination</span>
          <span className="aq-col-mitre">MITRE ATT&CK</span>
          <span className="aq-col-status">Status</span>
          <span className="aq-col-assign">Assignee</span>
          <span className="aq-col-hits">Hits</span>
          <span className="aq-col-time">Time</span>
          <span className="aq-col-actions">Actions</span>
        </div>

        {filtered.length === 0 ? (
          <p className="empty-state">No alerts match the current filters.</p>
        ) : (
          <div className="aq-table-body">
            {filtered.map((alert) => {
              const sev = (alert as any).severity ?? 'low';
              const sevColor = SEVERITY_COLORS[sev] ?? '#4a9eda';
              const isHighSev = sev === 'critical' || sev === 'high';
              const mitre: any[] = (alert as any).mitre_attack ?? [];
              const agentMeta = (alert as any).agent_meta;
              const isSelected = selected.has(alert.alert_id);
              const isExpanded = expandedId === alert.alert_id;
              const srcIp = (alert as any).src_ip;
              const dstIp = (alert as any).dst_ip;
              const dstPort = (alert as any).dst_port;
              const processName = (alert as any).process_name;
              const caseId = (alert as any).case_id;
              const statusStyle = STATUS_LABELS[alert.status] ?? STATUS_LABELS.open;

              return (
                <div key={alert.alert_id}>
                  {/* Main row */}
                  <div
                    className={`aq-row${isSelected ? ' aq-row--selected' : ''}${isHighSev ? ' aq-row--high' : ''}`}
                    style={{ borderLeftColor: isHighSev ? sevColor : 'transparent' }}
                    onClick={() => setExpandedId(isExpanded ? null : alert.alert_id)}
                  >
                    {/* Checkbox */}
                    <label className="aq-col-check" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleSelect(alert.alert_id)}
                      />
                    </label>

                    {/* Severity */}
                    <span className="aq-col-sev">
                      <span className={`dash-sev-badge dash-sev-badge--${sev}`}>
                        {sev.toUpperCase()}
                      </span>
                    </span>

                    {/* Alert name + process */}
                    <span className="aq-col-rule">
                      <span className="aq-alert-name">{ruleTitle(alert)}</span>
                      {processName && (
                        <span className="aq-process-name">{processName}</span>
                      )}
                    </span>

                    {/* Source: hostname + IP */}
                    <span className="aq-col-host">
                      <span className="aq-host-row">
                        {agentMeta?.os && getOsIcon(agentMeta.os)}
                        <span className="aq-hostname">{agentMeta?.hostname ?? '--'}</span>
                      </span>
                      {srcIp && <span className="aq-ip">{srcIp}</span>}
                    </span>

                    {/* Destination */}
                    <span className="aq-col-dest">
                      {dstIp ? (
                        <>
                          <span className="aq-hostname">{dstIp}</span>
                          {dstPort && <span className="aq-ip">:{dstPort}</span>}
                        </>
                      ) : (
                        <span className="aq-dim">--</span>
                      )}
                    </span>

                    {/* MITRE */}
                    <span className="aq-col-mitre">
                      {mitre.length === 0 ? (
                        <span className="aq-dim">--</span>
                      ) : (
                        <div className="aq-mitre-tags">
                          {mitre.slice(0, 2).map((m: any, i: number) => (
                            <span
                              key={i}
                              className="aq-mitre-tag"
                              title={`${m.tactic}: ${m.technique_name}`}
                            >
                              {m.technique_id}
                            </span>
                          ))}
                          {mitre.length > 2 && (
                            <span className="aq-mitre-more">+{mitre.length - 2}</span>
                          )}
                        </div>
                      )}
                    </span>

                    {/* Status */}
                    <span className="aq-col-status">
                      <span
                        className="aq-status-badge"
                        style={{ background: statusStyle.bg, color: statusStyle.color }}
                      >
                        {alert.status === 'false_positive' ? 'FP' : alert.status}
                      </span>
                    </span>

                    {/* Assignee */}
                    <span className="aq-col-assign">
                      {alert.assignee ? (
                        <span className="aq-assignee">{alert.assignee}</span>
                      ) : (
                        <span className="aq-dim">--</span>
                      )}
                    </span>

                    {/* Hits */}
                    <span className="aq-col-hits">
                      {(alert as any).hit_count > 1 ? (
                        <span className="aq-hit-badge">
                          x{(alert as any).hit_count}
                        </span>
                      ) : (
                        <span className="aq-dim">x1</span>
                      )}
                    </span>

                    {/* Time */}
                    <span className="aq-col-time" title={new Date(alert.last_seen).toLocaleString()}>
                      {timeAgo(alert.last_seen)}
                    </span>

                    {/* Actions */}
                    <span className="aq-col-actions" onClick={(e) => e.stopPropagation()}>
                      <button className="aq-action-btn aq-action-btn--fp" onClick={() => handleSingleFP(alert.alert_id)} title="False Positive">FP</button>
                      <button className="aq-action-btn aq-action-btn--ai" onClick={() => handleExplain(alert.alert_id)} title="AI Explain">AI</button>
                      {caseId && (
                        <button className="aq-action-btn aq-action-btn--detail" onClick={() => { window.location.hash = `#/cases/${caseId}`; }} title="Go to Case">Case</button>
                      )}
                    </span>
                  </div>

                  {/* Expanded detail panel */}
                  {isExpanded && (
                    <div className="aq-expanded">
                      <div className="aq-expanded-grid">
                        {/* Left: Alert details */}
                        <div className="aq-detail-section">
                          <h4 className="aq-detail-title">Alert Details</h4>
                          <div className="aq-detail-rows">
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">Alert ID</span>
                              <span className="aq-detail-value" style={{ fontFamily: 'monospace', fontSize: 11 }}>{alert.alert_id}</span>
                            </div>
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">Rule ID</span>
                              <span className="aq-detail-value" style={{ fontFamily: 'monospace', fontSize: 11 }}>{alert.rule_id}</span>
                            </div>
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">First Seen</span>
                              <span className="aq-detail-value">{new Date(alert.first_seen).toLocaleString()} ({timeAgo(alert.first_seen)})</span>
                            </div>
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">Last Seen</span>
                              <span className="aq-detail-value">{new Date(alert.last_seen).toLocaleString()} ({timeAgo(alert.last_seen)})</span>
                            </div>
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">Hit Count</span>
                              <span className="aq-detail-value" style={{ fontWeight: 700, color: (alert as any).hit_count > 5 ? '#f45d5d' : 'var(--text-primary)' }}>
                                {(alert as any).hit_count ?? 1}
                              </span>
                            </div>
                            {processName && (
                              <div className="aq-detail-row">
                                <span className="aq-detail-label">Process</span>
                                <span className="aq-detail-value" style={{ fontFamily: 'monospace' }}>{processName}</span>
                              </div>
                            )}
                            {caseId && (
                              <div className="aq-detail-row">
                                <span className="aq-detail-label">Linked Case</span>
                                <span className="aq-detail-value">
                                  <span
                                    className="aq-case-link"
                                    onClick={() => { window.location.hash = `#/cases/${caseId}`; }}
                                  >
                                    {linkIcon} {caseId}
                                  </span>
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Middle: Source & Destination */}
                        <div className="aq-detail-section">
                          <h4 className="aq-detail-title">Network Context</h4>
                          <div className="aq-detail-rows">
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">Source Host</span>
                              <span className="aq-detail-value">{agentMeta?.hostname ?? '--'}</span>
                            </div>
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">Source IP</span>
                              <span className="aq-detail-value" style={{ fontFamily: 'monospace' }}>{srcIp ?? '--'}</span>
                            </div>
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">Destination IP</span>
                              <span className="aq-detail-value" style={{ fontFamily: 'monospace' }}>{dstIp ?? '--'}</span>
                            </div>
                            {dstPort && (
                              <div className="aq-detail-row">
                                <span className="aq-detail-label">Destination Port</span>
                                <span className="aq-detail-value">{dstPort}</span>
                              </div>
                            )}
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">OS</span>
                              <span className="aq-detail-value">{agentMeta?.os ?? '--'}</span>
                            </div>
                            <div className="aq-detail-row">
                              <span className="aq-detail-label">Group</span>
                              <span className="aq-detail-value">{agentMeta?.group ?? '--'}</span>
                            </div>
                            {agentMeta?.tags?.length > 0 && (
                              <div className="aq-detail-row">
                                <span className="aq-detail-label">Tags</span>
                                <span className="aq-detail-value">
                                  <span className="aq-tag-list">
                                    {agentMeta.tags.map((t: string, i: number) => (
                                      <span key={i} className="aq-tag">{t}</span>
                                    ))}
                                  </span>
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Right: MITRE & Evidence */}
                        <div className="aq-detail-section">
                          <h4 className="aq-detail-title">MITRE ATT&CK</h4>
                          {mitre.length === 0 ? (
                            <span className="aq-dim" style={{ fontSize: 12 }}>No mappings</span>
                          ) : (
                            <div className="aq-mitre-detail-list">
                              {mitre.map((m: any, i: number) => (
                                <div key={i} className="aq-mitre-detail-row">
                                  <span className="aq-mitre-id">{m.technique_id}</span>
                                  <span className="aq-mitre-tactic">{m.tactic?.replace(/-/g, ' ')}</span>
                                  <span className="aq-mitre-name">{m.technique_name}</span>
                                </div>
                              ))}
                            </div>
                          )}

                          <h4 className="aq-detail-title" style={{ marginTop: 16 }}>Evidence</h4>
                          <div className="aq-evidence-list">
                            {(alert as any).evidence_refs?.map((ref: string, i: number) => (
                              <span key={i} className="aq-evidence-ref" title={ref}>{ref}</span>
                            )) ?? <span className="aq-dim" style={{ fontSize: 12 }}>None</span>}
                          </div>
                        </div>
                      </div>

                      {/* Action bar in expanded view */}
                      <div className="aq-expanded-actions">
                        <button className="aq-action-btn aq-action-btn--fp" onClick={() => handleSingleFP(alert.alert_id)}>False Positive</button>
                        <button className="aq-action-btn aq-action-btn--ai" onClick={() => handleExplain(alert.alert_id)}>AI Explain</button>
                        {caseId && (
                          <button className="aq-action-btn aq-action-btn--detail" onClick={() => { window.location.hash = `#/cases/${caseId}`; }}>
                            Go to Case
                          </button>
                        )}
                        <button
                          className="aq-action-btn aq-action-btn--detail"
                          onClick={() => { window.location.hash = `#/alerts/${alert.alert_id}`; }}
                        >
                          Full Detail
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Floating bulk action bar ─────────────── */}
      {selected.size > 0 && (
        <div className="aq-bulk-bar">
          <span className="aq-bulk-count">{selected.size} selected</span>
          <div className="aq-bulk-divider" />
          <button className="aq-action-btn aq-action-btn--fp" onClick={handleBulkFalsePositive}>Mark False Positive</button>
        </div>
      )}

      {/* ── AI Explain slide-out panel ────────────── */}
      {explainAlertId && (
        <div className="aq-explain-panel">
          <div className="aq-explain-header">
            <h3 className="aq-explain-title">AI Explanation</h3>
            <button className="aq-explain-close" onClick={() => setExplainAlertId(null)}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
          <div className="aq-explain-body">
            <div className="aq-explain-alert-id">Alert: {explainAlertId.slice(0, 12)}</div>

            {explainLoading && (
              <div className="stack" style={{ gap: 12 }}>
                {[1, 2, 3].map((i) => (
                  <div key={i} className="aq-skeleton" style={{ height: i === 1 ? 60 : 20 }} />
                ))}
              </div>
            )}

            {explainError && (
              <div style={{ color: '#f45d5d', fontSize: 13 }}>{explainError}</div>
            )}

            {explainResult && (
              <div className="stack" style={{ gap: 20 }}>
                <div>
                  <h4 className="aq-explain-section-title">Summary</h4>
                  <p className="aq-explain-text">{explainResult.summary}</p>
                </div>
                <div>
                  <h4 className="aq-explain-section-title">Why Suspicious</h4>
                  <p className="aq-explain-text">{explainResult.why_suspicious}</p>
                </div>
                <div>
                  <h4 className="aq-explain-section-title">Likely Cause</h4>
                  <p className="aq-explain-text">{explainResult.likely_cause}</p>
                </div>
                <div>
                  <h4 className="aq-explain-section-title">False Positive Likelihood</h4>
                  <p className="aq-explain-text" style={{ fontWeight: 600 }}>{explainResult.false_positive_likelihood.toUpperCase()}</p>
                </div>
                <div>
                  <h4 className="aq-explain-section-title">Recommended Actions</h4>
                  <ul className="aq-explain-actions">
                    {explainResult.recommended_actions.map((action, i) => (
                      <li key={i}>{action}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
