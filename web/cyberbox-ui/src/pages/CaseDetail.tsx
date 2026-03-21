import { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  AuditLogRecord,
  AlertRecord,
  CaseRecord,
  CaseResolution,
  CaseStatus,
  getAlert,
  addAlertsToCase,
  getAlerts,
  getAuditLogs,
  getCase,
  runSearch,
  updateCase,
} from '../api/client';
import { aggregateEventContexts, extractEventContext, formatNetworkFlow, limitValues } from '../lib/logContext';

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

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function formatLoadError(error: unknown): string {
  const message = getErrorMessage(error);
  const normalized = message.toLowerCase();
  if (message.includes('API 401') || normalized.includes('authentication failed')) {
    return 'Your session expired or you are not authorized to load this case. Please sign in again and retry.';
  }
  if (message.includes('API 404')) {
    return 'Case not found.';
  }
  return message;
}

function appendError(current: string, next: string): string {
  return current ? `${current} ${next}` : next;
}

function mergeUnique(...groups: Array<Array<string | undefined> | undefined>): string[] {
  const seen = new Set<string>();
  const values: string[] = [];
  groups.forEach((group) => {
    group?.forEach((value) => {
      if (!value) return;
      if (seen.has(value)) return;
      seen.add(value);
      values.push(value);
    });
  });
  return values;
}

function stripEvidenceRef(ref: string): string {
  return ref.replace(/^event:/, '');
}

function buildEvidenceWindow(alerts: AlertRecord[]): { start: string; end: string } {
  const timestamps = alerts
    .flatMap((alert) => [Date.parse(alert.first_seen), Date.parse(alert.last_seen)])
    .filter((value) => Number.isFinite(value));
  if (timestamps.length === 0) {
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    return { start: weekAgo.toISOString(), end: now.toISOString() };
  }

  const start = new Date(Math.min(...timestamps) - 12 * 60 * 60 * 1000);
  const end = new Date(Math.max(...timestamps) + 12 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

const RESOLUTION_LABELS: Record<CaseResolution, { label: string; color: string }> = {
  tp_contained: { label: 'True Positive — Contained', color: '#00F4A3' },
  tp_not_contained: { label: 'True Positive — Not Contained', color: '#f45d5d' },
  benign_tp: { label: 'Benign True Positive', color: '#d4bc00' },
  false_positive: { label: 'False Positive', color: '#a78bfa' },
  duplicate: { label: 'Duplicate', color: 'rgba(255,255,255,0.5)' },
};

const RESOLUTION_OPTIONS = Object.entries(RESOLUTION_LABELS) as Array<
  [CaseResolution, { label: string; color: string }]
>;

const STATUS_TRANSITIONS: Record<CaseStatus, CaseStatus[]> = {
  open: ['in_progress'],
  in_progress: ['resolved'],
  resolved: ['closed'],
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
  const [evidenceEvents, setEvidenceEvents] = useState<Record<string, unknown>[]>([]);
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
  const [resolution, setResolution] = useState<CaseResolution>('tp_contained');
  const [closeNote, setCloseNote] = useState('');

  // SLA live countdown
  const [sla, setSla] = useState(slaCountdown(undefined));

  const loadCase = useCallback(async () => {
    if (!caseId) {
      setCaseData(null);
      setTimeline([]);
      setAlerts([]);
      setEvidenceEvents([]);
      setError('Case not found.');
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      setError('');
      setTimeline([]);
      setAlerts([]);
      setEvidenceEvents([]);

      const c = await getCase(caseId);
      const caseTags = c.tags ?? [];
      const caseAlertIds = c.alert_ids ?? [];
      setCaseData(c);
      setEditAssignee(c.assignee ?? '');
      setEditTags(caseTags.join(', '));
      setSla(slaCountdown(c.sla_due_at));

      const [auditResult, alertsResult] = await Promise.allSettled([
        getAuditLogs({ limit: 50 }),
        caseAlertIds.length > 0
          ? getAlerts({ limit: Math.min(500, Math.max(100, caseAlertIds.length * 2)) })
          : Promise.resolve(null),
      ]);

      let nextError = '';
      let resolvedAlerts: AlertRecord[] = [];

      if (auditResult.status === 'fulfilled') {
        const caseTimeline = auditResult.value.entries.filter(
          (entry) => entry.entity_id === caseId || entry.entity_type === 'case',
        );
        setTimeline(caseTimeline);
      } else {
        nextError = appendError(
          nextError,
          `Activity timeline unavailable: ${formatLoadError(auditResult.reason)}`,
        );
      }

      if (alertsResult.status === 'fulfilled') {
        const alertsPage = alertsResult.value;
        if (alertsPage) {
          const allAlerts = alertsPage.alerts;
          const matchedMap = new Map(allAlerts.map((alert) => [alert.alert_id, alert]));
          resolvedAlerts = caseAlertIds
            .map((id) => matchedMap.get(id))
            .filter(Boolean) as AlertRecord[];

          const missingAlertIds = caseAlertIds.filter((id) => !matchedMap.has(id));
          if (missingAlertIds.length > 0) {
            const missingResults = await Promise.allSettled(missingAlertIds.map((id) => getAlert(id)));
            missingResults.forEach((result) => {
              if (result.status === 'fulfilled') {
                resolvedAlerts.push(result.value);
              } else {
                nextError = appendError(
                  nextError,
                  `Linked alert details unavailable for one or more alerts: ${formatLoadError(result.reason)}`,
                );
              }
            });
          }

          setAlerts(resolvedAlerts);

          const evidenceIds = mergeUnique(
            resolvedAlerts.flatMap((alert) => (alert.evidence_refs ?? []).map((ref) => stripEvidenceRef(ref))),
          ).slice(0, 75);
          if (evidenceIds.length > 0) {
            try {
              const evidenceRows = await runSearch({
                sql: `event_id IN (${evidenceIds.map((id) => `'${id.replace(/'/g, "''")}'`).join(',')})`,
                time_range: buildEvidenceWindow(resolvedAlerts),
                pagination: { page: 1, page_size: Math.min(100, Math.max(25, evidenceIds.length * 2)) },
              });
              setEvidenceEvents(evidenceRows.rows ?? []);
            } catch (evidenceError) {
              nextError = appendError(
                nextError,
                `Linked evidence unavailable: ${formatLoadError(evidenceError)}`,
              );
            }
          }
        }
      } else {
        nextError = appendError(
          nextError,
          `Linked alert details unavailable: ${formatLoadError(alertsResult.reason)}`,
        );
      }

      setError(nextError);
    } catch (err) {
      setCaseData(null);
      setTimeline([]);
      setAlerts([]);
      setEvidenceEvents([]);
      setError(formatLoadError(err));
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
      await updateCase(caseId, {
        status: 'closed',
        resolution,
        close_note: closeNote.trim() || null,
      });
      setShowCloseModal(false);
      setResolution('tp_contained');
      setCloseNote('');
      await loadCase();
    } catch (err) { setError(String(err)); }
  };

  const handleReassign = async () => {
    if (!caseId) return;
    const nextAssignee = editAssignee.trim();
    if (!nextAssignee && !caseData?.assignee) return;
    try {
      await updateCase(caseId, { assignee: nextAssignee || null });
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
          result.push({
            id: m.technique_id,
            name: m.technique_name ?? 'Unknown technique',
            tactic: m.tactic ?? 'unknown',
          });
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

  const evidenceContexts = useMemo(
    () => evidenceEvents.map((row) => extractEventContext(row)),
    [evidenceEvents],
  );

  const evidenceContextById = useMemo(() => {
    const next = new Map<string, ReturnType<typeof extractEventContext>>();
    evidenceContexts.forEach((context) => {
      if (context.eventId) {
        next.set(context.eventId, context);
      }
    });
    return next;
  }, [evidenceContexts]);

  const caseEvidenceAggregate = useMemo(
    () => aggregateEventContexts(evidenceContexts),
    [evidenceContexts],
  );

  const alertInsights = useMemo(() => {
    const insights = new Map<string, ReturnType<typeof aggregateEventContexts>>();
    alerts.forEach((alert) => {
      const contexts = (alert.evidence_refs ?? [])
        .map((ref) => evidenceContextById.get(stripEvidenceRef(ref)))
        .filter(Boolean);
      insights.set(alert.alert_id, aggregateEventContexts(contexts as ReturnType<typeof extractEventContext>[]));
    });
    return insights;
  }, [alerts, evidenceContextById]);

  const caseSources = useMemo(
    () => limitValues(caseEvidenceAggregate.sources, 6),
    [caseEvidenceAggregate.sources],
  );
  const caseObservedHosts = useMemo(
    () => limitValues(mergeUnique(affectedHosts.map(([hostname]) => hostname), caseEvidenceAggregate.hosts), 6),
    [affectedHosts, caseEvidenceAggregate.hosts],
  );
  const caseObservedUsers = useMemo(
    () => limitValues(caseEvidenceAggregate.users, 6),
    [caseEvidenceAggregate.users],
  );
  const caseObservedProcesses = useMemo(
    () => limitValues(caseEvidenceAggregate.processes, 6),
    [caseEvidenceAggregate.processes],
  );
  const caseObservedNetworks = useMemo(
    () => limitValues(caseEvidenceAggregate.networkFlows, 6),
    [caseEvidenceAggregate.networkFlows],
  );
  const caseObservedArtifacts = useMemo(
    () => limitValues(
      mergeUnique(
        caseEvidenceAggregate.domains,
        caseEvidenceAggregate.files,
        caseEvidenceAggregate.registryPaths,
        caseEvidenceAggregate.services,
      ),
      8,
    ),
    [caseEvidenceAggregate.domains, caseEvidenceAggregate.files, caseEvidenceAggregate.registryPaths, caseEvidenceAggregate.services],
  );
  const caseMessageHighlights = useMemo(
    () => limitValues(caseEvidenceAggregate.messages, 4),
    [caseEvidenceAggregate.messages],
  );

  if (loading) return <div className="page"><p className="empty-state">Loading case...</p></div>;
  if (!caseData) return <div className="page"><p className="empty-state">{error || 'Case not found.'}</p></div>;

  const nextStatuses = STATUS_TRANSITIONS[caseData.status ?? 'open'] ?? [];
  const c = caseData;
  const caseSeverity = c.severity ?? 'medium';
  const caseStatus = c.status ?? 'open';
  const caseAlertIds = c.alert_ids ?? [];
  const caseTags = c.tags ?? [];
  const res = c.resolution;
  const cNote = c.close_note;
  const canSubmitReassign = editAssignee.trim().length > 0 || Boolean(c.assignee);

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
            <span className={`cd-sev-badge cd-sev-badge--${caseSeverity}`}>
              {caseSeverity.toUpperCase()}
            </span>
            <span className={`cs-status-badge cs-status-badge--${caseStatus}`}>
              {caseStatus.replace('_', ' ')}
            </span>
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
              {s === 'in_progress'
                ? 'Start Investigation'
                : s === 'resolved'
                  ? 'Resolve Case'
                  : 'Close Case'}
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
          <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleReassign} disabled={!canSubmitReassign}>
            {editAssignee.trim() ? 'Save' : 'Clear'}
          </button>
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
              <span className="cd-meta-value">{caseAlertIds.length}</span>
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
      {caseTags.length > 0 && (
        <div className="cd-tags-row">
          {tagIcon}
          {caseTags.map((tag) => (
            <span key={tag} className="cd-tag">{tag}</span>
          ))}
        </div>
      )}

      {/* ── Two-column: Linked Alerts + MITRE ────── */}
      {(caseSources.length > 0
        || caseObservedHosts.length > 0
        || caseObservedUsers.length > 0
        || caseObservedProcesses.length > 0
        || caseObservedNetworks.length > 0
        || caseObservedArtifacts.length > 0
        || caseMessageHighlights.length > 0) && (
        <div className="cd-panel">
          <div className="cd-panel-header">
            <div className="cd-panel-title">
              {historyIcon}
              <span>INVESTIGATION SNAPSHOT</span>
              {evidenceEvents.length > 0 && <span className="cd-count-badge">{evidenceEvents.length}</span>}
            </div>
          </div>
          <div className="cd-insight-grid">
            {caseSources.length > 0 && (
              <div className="cd-insight-card">
                <span className="cd-insight-label">Log Sources</span>
                <div className="cd-insight-values">
                  {caseSources.map((value) => <span key={value} className="cd-tag">{value}</span>)}
                </div>
              </div>
            )}
            {caseObservedHosts.length > 0 && (
              <div className="cd-insight-card">
                <span className="cd-insight-label">Observed Hosts</span>
                <div className="cd-insight-values">
                  {caseObservedHosts.map((value) => <span key={value} className="cd-tag">{value}</span>)}
                </div>
              </div>
            )}
            {caseObservedUsers.length > 0 && (
              <div className="cd-insight-card">
                <span className="cd-insight-label">Users</span>
                <div className="cd-insight-values">
                  {caseObservedUsers.map((value) => <span key={value} className="cd-tag">{value}</span>)}
                </div>
              </div>
            )}
            {caseObservedProcesses.length > 0 && (
              <div className="cd-insight-card">
                <span className="cd-insight-label">Processes</span>
                <div className="cd-insight-values">
                  {caseObservedProcesses.map((value) => <span key={value} className="cd-tag">{value}</span>)}
                </div>
              </div>
            )}
            {caseObservedNetworks.length > 0 && (
              <div className="cd-insight-card cd-insight-card--wide">
                <span className="cd-insight-label">Network Paths</span>
                <div className="cd-insight-values">
                  {caseObservedNetworks.map((value) => <span key={value} className="cd-insight-pill">{value}</span>)}
                </div>
              </div>
            )}
            {caseObservedArtifacts.length > 0 && (
              <div className="cd-insight-card cd-insight-card--wide">
                <span className="cd-insight-label">Artifacts</span>
                <div className="cd-insight-values">
                  {caseObservedArtifacts.map((value) => <span key={value} className="cd-insight-pill">{value}</span>)}
                </div>
              </div>
            )}
            {caseMessageHighlights.length > 0 && (
              <div className="cd-insight-card cd-insight-card--wide">
                <span className="cd-insight-label">Message Highlights</span>
                <div className="cd-insight-notes">
                  {caseMessageHighlights.map((value) => <div key={value} className="cd-insight-note">{value}</div>)}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="cd-two-col">
        {/* Linked Alerts */}
        <div className="cd-panel">
          <div className="cd-panel-header">
            <div className="cd-panel-title">
              {alertIcon}
              <span>LINKED ALERTS</span>
              {caseAlertIds.length > 0 && <span className="cd-count-badge">{caseAlertIds.length}</span>}
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

          {alerts.length === 0 && caseAlertIds.length === 0 ? (
            <p className="empty-state">No linked alerts.</p>
          ) : (
            <div className="cd-alert-list">
              {alerts.map((a) => {
                const sev = (a as any).severity as string ?? 'medium';
                const title = a.rule_title || (a as any).compiled_plan?.title || a.rule_id;
                const insight = alertInsights.get(a.alert_id);
                const host = insight?.hosts[0] ?? a.agent_meta?.hostname ?? 'Unknown';
                const process = insight?.processes[0] ?? ((a as any).process_name as string | undefined);
                const user = insight?.users[0];
                const source = insight?.sources[0];
                const eventKind = insight?.eventKinds[0];
                const message = insight?.messages[0];
                const network = insight?.networkFlows[0] ?? formatNetworkFlow({
                  sourceIp: (a as any).src_ip as string | undefined,
                  destinationIp: (a as any).dst_ip as string | undefined,
                  destinationHost: undefined,
                  destinationPort: (a as any).dst_port ? String((a as any).dst_port) : undefined,
                });
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
                        {process && <span className="cd-alert-detail">{process}</span>}
                        {user && <span className="cd-alert-detail">{user}</span>}
                        {network && <span className="cd-alert-detail">{network}</span>}
                        {source && <span className="cd-alert-detail">{source}</span>}
                        {eventKind && <span className="cd-alert-detail">{eventKind}</span>}
                        {(a as any).src_ip && (
                          <span className="cd-alert-detail">
                            {(a as any).src_ip}
                            {(a as any).dst_ip ? ` → ${(a as any).dst_ip}:${(a as any).dst_port}` : ''}
                          </span>
                        )}
                        {mitre && <span className="cd-mitre-pill">{mitre.technique_id}</span>}
                      </div>
                      {message && <div className="cd-alert-note">{message}</div>}
                      <div className="cd-alert-footer">
                        <span className="cd-alert-hits">{a.hit_count} hits</span>
                        <span className="cd-alert-time">{timeAgo(a.last_seen)}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
              {/* Show IDs for alerts we couldn't resolve */}
              {caseAlertIds.filter((id) => !alerts.find((a) => a.alert_id === id)).map((id) => (
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
                    <span className="cd-mitre-name">{t.name ?? 'Unknown technique'}</span>
                    <span className="cd-mitre-tactic">{(t.tactic ?? 'unknown').replace(/-/g, ' ')}</span>
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
