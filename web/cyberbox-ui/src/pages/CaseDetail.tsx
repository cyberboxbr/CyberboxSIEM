import { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  AuditLogRecord,
  AlertRecord,
  CaseRecord,
  CaseStatus,
  Severity,
  addAlertsToCase,
  getAlerts,
  getAuditLogs,
  getCase,
  updateCase,
} from '../api/client';

/* ── Helpers ──────────────────────────────────────── */

function timeAgo(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function slaCountdown(sla_due_at?: string): { label: string; color: string; pct: number; breached: boolean } {
  if (!sla_due_at) return { label: 'No SLA', color: 'rgba(255,255,255,0.25)', pct: 100, breached: false };
  const due = new Date(sla_due_at).getTime();
  const now = Date.now();
  const remaining = due - now;
  if (remaining <= 0) return { label: 'BREACHED', color: '#f45d5d', pct: 0, breached: true };
  const hours = Math.floor(remaining / 3_600_000);
  const mins = Math.floor((remaining % 3_600_000) / 60_000);
  const secs = Math.floor((remaining % 60_000) / 1_000);
  const label = hours > 0 ? `${hours}h ${mins}m ${secs}s` : `${mins}m ${secs}s`;
  const totalWindow = 24 * 3_600_000;
  const pct = Math.min(100, (remaining / totalWindow) * 100);
  let color = '#00F4A3';
  if (pct < 10) color = '#f45d5d';
  else if (pct < 50) color = '#d4bc00';
  return { label, color, pct, breached: false };
}

const RESOLUTION_LABELS: Record<string, { label: string; color: string }> = {
  tp_contained: { label: 'True Positive — Contained', color: '#00F4A3' },
  tp_not_contained: { label: 'True Positive — Not Contained', color: '#f45d5d' },
  benign_tp: { label: 'Benign True Positive', color: '#d4bc00' },
  false_positive: { label: 'False Positive', color: '#a78bfa' },
  duplicate: { label: 'Duplicate', color: 'rgba(255,255,255,0.5)' },
};

const RESOLUTION_OPTIONS = Object.entries(RESOLUTION_LABELS);

const STATUS_TRANSITIONS: Record<CaseStatus, CaseStatus[]> = {
  open: ['in_progress'],
  in_progress: ['closed'],
  closed: [],
};

/* ── SVG Icons ────────────────────────────────────── */

const backIcon = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 12H5"/><polyline points="12 19 5 12 12 5"/>
  </svg>
);

const clockIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
  </svg>
);

const userIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
  </svg>
);

const tagIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/>
  </svg>
);

const alertIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>
  </svg>
);

const shieldIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);

const editIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
  </svg>
);

const plusIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
  </svg>
);

const historyIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
  </svg>
);

/* ── Component ────────────────────────────────────── */

export function CaseDetail() {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();
  const [caseData, setCaseData] = useState<CaseRecord | null>(null);
  const [timeline, setTimeline] = useState<AuditLogRecord[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Edit state
  const [editAssignee, setEditAssignee] = useState('');
  const [showReassign, setShowReassign] = useState(false);
  const [editTags, setEditTags] = useState('');
  const [showEditTags, setShowEditTags] = useState(false);
  const [attachAlertId, setAttachAlertId] = useState('');
  const [showAttach, setShowAttach] = useState(false);

  // Close modal
  const [showCloseModal, setShowCloseModal] = useState(false);
  const [resolution, setResolution] = useState('tp_contained');
  const [closeNote, setCloseNote] = useState('');

  // SLA live countdown
  const [sla, setSla] = useState(slaCountdown(undefined));

  const loadCase = useCallback(async () => {
    if (!caseId) return;
    try {
      setLoading(true);
      const [c, auditResp, alertsPage] = await Promise.all([
        getCase(caseId),
        getAuditLogs({ limit: 50 }),
        getAlerts({ limit: 100 }),
      ]);
      setCaseData(c);
      setEditAssignee(c.assignee ?? '');
      setEditTags(c.tags.join(', '));
      const caseTimeline = auditResp.entries.filter(
        (e) => e.entity_id === caseId || e.entity_type === 'case',
      );
      setTimeline(caseTimeline);
      // Match alert IDs to full alert data
      const allAlerts = alertsPage.alerts;
      const matched = c.alert_ids
        .map((id) => allAlerts.find((a) => a.alert_id === id))
        .filter(Boolean) as AlertRecord[];
      setAlerts(matched);
      setSla(slaCountdown(c.sla_due_at));
      setError('');
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => { loadCase(); }, [loadCase]);

  useEffect(() => {
    if (!caseData?.sla_due_at) return;
    const interval = setInterval(() => setSla(slaCountdown(caseData.sla_due_at)), 1_000);
    return () => clearInterval(interval);
  }, [caseData?.sla_due_at]);

  /* ── Handlers ─────────────────────────────────── */

  const handleStatusChange = async (newStatus: CaseStatus) => {
    if (!caseId) return;
    if (newStatus === 'closed') { setShowCloseModal(true); return; }
    try {
      await updateCase(caseId, { status: newStatus });
      await loadCase();
    } catch (err) { setError(String(err)); }
  };

  const handleClose = async () => {
    if (!caseId) return;
    try {
      await updateCase(caseId, { status: 'closed' });
      setShowCloseModal(false);
      await loadCase();
    } catch (err) { setError(String(err)); }
  };

  const handleReassign = async () => {
    if (!caseId || !editAssignee.trim()) return;
    try {
      await updateCase(caseId, { assignee: editAssignee.trim() });
      setShowReassign(false);
      await loadCase();
    } catch (err) { setError(String(err)); }
  };

  const handleEditTags = async () => {
    if (!caseId) return;
    try {
      const tags = editTags.split(',').map((t) => t.trim()).filter(Boolean);
      await updateCase(caseId, { tags });
      setShowEditTags(false);
      await loadCase();
    } catch (err) { setError(String(err)); }
  };

  const handleAttachAlert = async () => {
    if (!caseId || !attachAlertId.trim()) return;
    try {
      await addAlertsToCase(caseId, [attachAlertId.trim()]);
      setAttachAlertId('');
      setShowAttach(false);
      await loadCase();
    } catch (err) { setError(String(err)); }
  };

  /* ── Derived ──────────────────────────────────── */

  const mitreTechniques = useMemo(() => {
    const seen = new Set<string>();
    const result: { id: string; name: string; tactic: string }[] = [];
    alerts.forEach((a) => {
      (a.mitre_attack ?? []).forEach((m) => {
        if (!seen.has(m.technique_id)) {
          seen.add(m.technique_id);
          result.push({ id: m.technique_id, name: m.technique_name, tactic: m.tactic });
        }
      });
    });
    return result;
  }, [alerts]);

  const affectedHosts = useMemo(() => {
    const hosts = new Map<string, { os: string; ip: string }>();
    alerts.forEach((a) => {
      const meta = a.agent_meta;
      if (meta) hosts.set(meta.hostname, { os: meta.os, ip: (meta as any).ip ?? '' });
    });
    return Array.from(hosts.entries());
  }, [alerts]);

  /* ── Loading / Error ──────────────────────────── */

  if (loading) return <div className="page"><p className="empty-state">Loading case...</p></div>;
  if (!caseData) return <div className="page"><p className="empty-state">Case not found. {error}</p></div>;

  const nextStatuses = STATUS_TRANSITIONS[caseData.status] ?? [];
  const c = caseData;
  const res = (c as any).resolution as string | undefined;
  const cNote = (c as any).close_note as string | undefined;

  return (
    <div className="page cd-page">
      {/* ── Breadcrumb + Header ──────────────────── */}
      <div className="cd-breadcrumb">
        <button type="button" className="cd-back-btn" onClick={() => navigate('/cases')}>
          {backIcon} Cases
        </button>
        <span className="cd-breadcrumb-sep">/</span>
        <span className="cd-breadcrumb-current">{c.case_id.toUpperCase()}</span>
      </div>

      <div className="cd-header">
        <div className="cd-header-left">
          <h1 className="cd-title">{c.title}</h1>
          {c.description && <p className="cd-description">{c.description}</p>}
          <div className="cd-header-badges">
            <span className={`cd-sev-badge cd-sev-badge--${c.severity}`}>
              {c.severity.toUpperCase()}
            </span>
            <span className={`cs-status-badge cs-status-badge--${c.status}`}>
              {c.status.replace('_', ' ')}
            </span>
            {c.priority && (
              <span className="cd-priority-badge">P{c.priority}</span>
            )}
          </div>
        </div>
        <div className="cd-header-actions">
          {nextStatuses.map((s) => (
            <button
              key={s}
              type="button"
              className={`cd-action-btn ${s === 'closed' ? 'cd-action-btn--close' : 'cd-action-btn--primary'}`}
              onClick={() => handleStatusChange(s)}
            >
              {s === 'in_progress' ? 'Start Investigation' : 'Close Case'}
            </button>
          ))}
          <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setShowReassign(!showReassign)}>
            {userIcon} Reassign
          </button>
          <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setShowEditTags(!showEditTags)}>
            {editIcon} Edit Tags
          </button>
        </div>
      </div>

      {error && <div className="cd-error">{error}</div>}

      {/* ── Inline edit panels ───────────────────── */}
      {showReassign && (
        <div className="cd-inline-edit">
          <label className="cd-inline-label">Assign to</label>
          <input className="cd-inline-input" value={editAssignee} onChange={(e) => setEditAssignee(e.target.value)} placeholder="analyst-1" />
          <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleReassign}>Save</button>
          <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setShowReassign(false)}>Cancel</button>
        </div>
      )}
      {showEditTags && (
        <div className="cd-inline-edit">
          <label className="cd-inline-label">Tags</label>
          <input className="cd-inline-input" value={editTags} onChange={(e) => setEditTags(e.target.value)} placeholder="comma-separated tags" />
          <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleEditTags}>Save</button>
          <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setShowEditTags(false)}>Cancel</button>
        </div>
      )}

      {/* ── Top cards row ────────────────────────── */}
      <div className="cd-cards-row">
        {/* SLA Card */}
        <div className={`cd-card cd-sla-card ${sla.breached ? 'cd-sla-card--breached' : ''}`}>
          <div className="cd-card-header">
            {clockIcon}
            <span className="cd-card-label">SLA COUNTDOWN</span>
          </div>
          <div className="cd-sla-time" style={{ color: sla.color }}>{sla.label}</div>
          {c.sla_due_at && (
            <>
              <div className="cd-sla-bar-track">
                <div className="cd-sla-bar-fill" style={{ width: `${Math.max(0, sla.pct)}%`, background: sla.color }} />
              </div>
              <div className="cd-sla-due">Due: {new Date(c.sla_due_at).toLocaleString()}</div>
            </>
          )}
        </div>

        {/* Assignee Card */}
        <div className="cd-card">
          <div className="cd-card-header">
            {userIcon}
            <span className="cd-card-label">ASSIGNEE</span>
          </div>
          <div className="cd-assignee-row">
            <div className="cd-avatar">{(c.assignee ?? '?')[0].toUpperCase()}</div>
            <div className="cd-assignee-info">
              <span className="cd-assignee-name">{c.assignee ?? 'Unassigned'}</span>
              <span className="cd-assignee-role">SOC Analyst</span>
            </div>
          </div>
        </div>

        {/* Timestamps Card */}
        <div className="cd-card">
          <div className="cd-card-header">
            {clockIcon}
            <span className="cd-card-label">TIMELINE</span>
          </div>
          <div className="cd-meta-grid">
            <div className="cd-meta-item">
              <span className="cd-meta-label">Created</span>
              <span className="cd-meta-value">{timeAgo(c.created_at)}</span>
            </div>
            <div className="cd-meta-item">
              <span className="cd-meta-label">Updated</span>
              <span className="cd-meta-value">{timeAgo(c.updated_at)}</span>
            </div>
            <div className="cd-meta-item">
              <span className="cd-meta-label">Alerts</span>
              <span className="cd-meta-value">{c.alert_ids.length}</span>
            </div>
            <div className="cd-meta-item">
              <span className="cd-meta-label">Priority</span>
              <span className="cd-meta-value">P{c.priority ?? '-'}</span>
            </div>
          </div>
        </div>

        {/* Resolution Card (for closed cases) */}
        {res && (
          <div className="cd-card">
            <div className="cd-card-header">
              {shieldIcon}
              <span className="cd-card-label">RESOLUTION</span>
            </div>
            <div className="cd-resolution-value" style={{ color: RESOLUTION_LABELS[res]?.color ?? '#fff' }}>
              {RESOLUTION_LABELS[res]?.label ?? res}
            </div>
            {cNote && <div className="cd-resolution-note">{cNote}</div>}
          </div>
        )}
      </div>

      {/* ── Tags ─────────────────────────────────── */}
      {c.tags.length > 0 && (
        <div className="cd-tags-row">
          {tagIcon}
          {c.tags.map((tag) => (
            <span key={tag} className="cd-tag">{tag}</span>
          ))}
        </div>
      )}

      {/* ── Two-column: Linked Alerts + MITRE ────── */}
      <div className="cd-two-col">
        {/* Linked Alerts */}
        <div className="cd-panel">
          <div className="cd-panel-header">
            <div className="cd-panel-title">
              {alertIcon}
              <span>LINKED ALERTS</span>
              {c.alert_ids.length > 0 && <span className="cd-count-badge">{c.alert_ids.length}</span>}
            </div>
            <button type="button" className="cd-action-btn cd-action-btn--small" onClick={() => setShowAttach(!showAttach)}>
              {plusIcon} Attach
            </button>
          </div>

          {showAttach && (
            <div className="cd-inline-edit" style={{ marginBottom: 12 }}>
              <input className="cd-inline-input" value={attachAlertId} onChange={(e) => setAttachAlertId(e.target.value)} placeholder="Alert ID" />
              <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleAttachAlert}>Attach</button>
              <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setShowAttach(false)}>Cancel</button>
            </div>
          )}

          {alerts.length === 0 && c.alert_ids.length === 0 ? (
            <p className="empty-state">No linked alerts.</p>
          ) : (
            <div className="cd-alert-list">
              {alerts.map((a) => {
                const sev = (a as any).severity as string ?? 'medium';
                const title = (a as any).compiled_plan?.title ?? a.rule_id;
                const host = a.agent_meta?.hostname ?? 'Unknown';
                const mitre = a.mitre_attack?.[0];
                return (
                  <div key={a.alert_id} className="cd-alert-card">
                    <div className="cd-alert-sev-strip" data-severity={sev} />
                    <div className="cd-alert-body">
                      <div className="cd-alert-top">
                        <span className="cd-alert-title">{title}</span>
                        <span className={`cd-sev-pill cd-sev-pill--${sev}`}>{sev.toUpperCase()}</span>
                      </div>
                      <div className="cd-alert-details">
                        <span className="cd-alert-detail">
                          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                          {host}
                        </span>
                        {(a as any).src_ip && (
                          <span className="cd-alert-detail">
                            {(a as any).src_ip}
                            {(a as any).dst_ip ? ` → ${(a as any).dst_ip}:${(a as any).dst_port}` : ''}
                          </span>
                        )}
                        {mitre && <span className="cd-mitre-pill">{mitre.technique_id}</span>}
                      </div>
                      <div className="cd-alert-footer">
                        <span className="cd-alert-hits">{a.hit_count} hits</span>
                        <span className="cd-alert-time">{timeAgo(a.last_seen)}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
              {/* Show IDs for alerts we couldn't resolve */}
              {c.alert_ids.filter((id) => !alerts.find((a) => a.alert_id === id)).map((id) => (
                <div key={id} className="cd-alert-card cd-alert-card--unresolved">
                  <div className="cd-alert-sev-strip" />
                  <div className="cd-alert-body">
                    <span className="cd-alert-title" style={{ opacity: 0.6 }}>{id}</span>
                    <span className="cd-alert-detail">Alert data unavailable</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right column: MITRE + Affected Assets */}
        <div className="cd-right-col">
          {/* MITRE ATT&CK */}
          <div className="cd-panel">
            <div className="cd-panel-header">
              <div className="cd-panel-title">
                {shieldIcon}
                <span>MITRE ATT&CK</span>
                {mitreTechniques.length > 0 && <span className="cd-count-badge">{mitreTechniques.length}</span>}
              </div>
            </div>
            {mitreTechniques.length === 0 ? (
              <p className="empty-state">No MITRE techniques mapped.</p>
            ) : (
              <div className="cd-mitre-list">
                {mitreTechniques.map((t) => (
                  <div key={t.id} className="cd-mitre-row">
                    <span className="cd-mitre-id">{t.id}</span>
                    <span className="cd-mitre-name">{t.name}</span>
                    <span className="cd-mitre-tactic">{t.tactic.replace(/-/g, ' ')}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Affected Assets */}
          <div className="cd-panel">
            <div className="cd-panel-header">
              <div className="cd-panel-title">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
                </svg>
                <span>AFFECTED ASSETS</span>
                {affectedHosts.length > 0 && <span className="cd-count-badge">{affectedHosts.length}</span>}
              </div>
            </div>
            {affectedHosts.length === 0 ? (
              <p className="empty-state">No assets identified.</p>
            ) : (
              <div className="cd-asset-list">
                {affectedHosts.map(([hostname, info]) => (
                  <div key={hostname} className="cd-asset-row">
                    <div className="cd-asset-icon">
                      {info.os.toLowerCase().includes('windows') ? 'W' : 'L'}
                    </div>
                    <div className="cd-asset-info">
                      <span className="cd-asset-hostname">{hostname}</span>
                      <span className="cd-asset-os">{info.os}{info.ip ? ` — ${info.ip}` : ''}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Activity Timeline ────────────────────── */}
      <div className="cd-panel">
        <div className="cd-panel-header">
          <div className="cd-panel-title">
            {historyIcon}
            <span>ACTIVITY TIMELINE</span>
            {timeline.length > 0 && <span className="cd-count-badge">{timeline.length}</span>}
          </div>
        </div>
        {timeline.length === 0 ? (
          <p className="empty-state">No audit activity for this case.</p>
        ) : (
          <div className="cd-timeline">
            {timeline.map((entry, i) => (
              <div key={entry.audit_id} className="cd-timeline-item">
                <div className="cd-timeline-rail">
                  <div className="cd-timeline-dot" />
                  {i < timeline.length - 1 && <div className="cd-timeline-line" />}
                </div>
                <div className="cd-timeline-content">
                  <div className="cd-timeline-top">
                    <span className="cd-timeline-action">{entry.action}</span>
                    <span className="cd-timeline-actor">by {entry.actor}</span>
                  </div>
                  <div className="cd-timeline-meta">
                    {entry.entity_type}:{entry.entity_id.slice(0, 8)} — {new Date(entry.timestamp).toLocaleString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Close Modal ──────────────────────────── */}
      {showCloseModal && (
        <div className="cd-modal-overlay" onClick={() => setShowCloseModal(false)}>
          <div className="cd-modal" onClick={(e) => e.stopPropagation()}>
            <h3 className="cd-modal-title">Close Case</h3>
            <p className="cd-modal-subtitle">Select a resolution and add a closing note.</p>

            <div className="cd-modal-field">
              <label className="cd-modal-label">Resolution</label>
              <div className="cd-resolution-options">
                {RESOLUTION_OPTIONS.map(([key, meta]) => (
                  <button
                    key={key}
                    type="button"
                    className={`cd-resolution-option ${resolution === key ? 'cd-resolution-option--active' : ''}`}
                    style={resolution === key ? { borderColor: meta.color, background: `color-mix(in srgb, ${meta.color} 10%, transparent)` } : {}}
                    onClick={() => setResolution(key)}
                  >
                    <span className="cd-resolution-dot" style={{ background: meta.color }} />
                    {meta.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="cd-modal-field">
              <label className="cd-modal-label">Closing Note</label>
              <textarea
                className="cd-modal-textarea"
                rows={3}
                value={closeNote}
                onChange={(e) => setCloseNote(e.target.value)}
                placeholder="Describe the findings and actions taken..."
              />
            </div>

            <div className="cd-modal-actions">
              <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setShowCloseModal(false)}>
                Cancel
              </button>
              <button type="button" className="cd-action-btn cd-action-btn--close" onClick={handleClose}>
                Close Case
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
