import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  CaseCreateInput,
  CaseRecord,
  CaseStatus,
  Severity,
  createCase,
  getCases,
  getSlaBreaches,
  updateCase,
} from '../api/client';

/* ── helpers ─────────────────────────────────────── */

function timeAgo(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function slaInfo(sla_due_at?: string): { label: string; color: string; pct: number } {
  if (!sla_due_at) return { label: 'No SLA', color: 'var(--text-secondary)', pct: 100 };
  const due = new Date(sla_due_at).getTime();
  const now = Date.now();
  const remaining = due - now;
  if (remaining <= 0) return { label: 'BREACHED', color: '#f45d5d', pct: 0 };
  const hours = Math.floor(remaining / 3_600_000);
  const mins = Math.floor((remaining % 3_600_000) / 60_000);
  const label = hours > 0 ? `${hours}h ${mins}m left` : `${mins}m left`;
  const totalWindow = 24 * 3_600_000;
  const pct = Math.min(100, (remaining / totalWindow) * 100);
  let color = '#58d68d';
  if (pct < 10) color = '#f45d5d';
  else if (pct < 50) color = '#d4bc00';
  return { label, color, pct };
}

type FilterTab = 'all' | 'open' | 'in_progress' | 'closed';

const RESOLUTION_LABELS: Record<string, { label: string; color: string }> = {
  tp_contained: { label: 'True Positive — Contained', color: '#58d68d' },
  tp_not_contained: { label: 'True Positive — Not Contained', color: '#f45d5d' },
  benign_tp: { label: 'Benign True Positive', color: '#4a9eda' },
  false_positive: { label: 'False Positive', color: '#d4bc00' },
  duplicate: { label: 'Duplicate', color: 'var(--text-secondary)' },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f45d5d',
  high: '#f5a623',
  medium: '#d4bc00',
  low: '#4a9eda',
};

/* ── SVG icons ────────────────────────────────────── */

const refreshIcon = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="23 4 23 10 17 10" />
    <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
  </svg>
);

const plusIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);

/* ── component ───────────────────────────────────── */

export function Cases() {
  const navigate = useNavigate();
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [slaBreaches, setSlaBreaches] = useState<CaseRecord[]>([]);
  const [filter, setFilter] = useState<FilterTab>('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [statusText, setStatusText] = useState('');

  // New case modal
  const [showModal, setShowModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState<Severity>('medium');
  const [newAssignee, setNewAssignee] = useState('');
  const [newTags, setNewTags] = useState('');
  const [newAlertIds, setNewAlertIds] = useState('');
  const [creating, setCreating] = useState(false);

  // Close case modal
  const [closeCaseId, setCloseCaseId] = useState<string | null>(null);
  const [closeResolution, setCloseResolution] = useState('tp_contained');
  const [closeNote, setCloseNote] = useState('');

  // Assign modal
  const [assignCaseId, setAssignCaseId] = useState<string | null>(null);
  const [assignName, setAssignName] = useState('');

  const loadCases = async () => {
    try {
      setLoading(true);
      const [casesResp, breachResp] = await Promise.all([
        getCases().catch(() => []),
        getSlaBreaches().catch(() => []),
      ]);
      setCases(casesResp ?? []);
      setSlaBreaches(breachResp ?? []);
      setError('');
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const filteredCases = useMemo(() => {
    if (filter === 'all') return cases;
    return cases.filter((c) => c.status === filter);
  }, [cases, filter]);

  /* ── stats ─────────────────────────────────────── */

  const stats = useMemo(() => {
    const open = cases.filter(c => c.status === 'open').length;
    const inProgress = cases.filter(c => c.status === 'in_progress').length;
    const closed = cases.filter(c => c.status === 'closed').length;
    const unassigned = cases.filter(c => !c.assignee && c.status !== 'closed').length;
    const breached = slaBreaches.length;
    return { open, inProgress, closed, unassigned, breached };
  }, [cases, slaBreaches]);

  /* ── actions ───────────────────────────────────── */

  const handleCreate = async () => {
    if (!newTitle.trim()) return;
    setCreating(true);
    try {
      const body: CaseCreateInput = {
        title: newTitle.trim(),
        severity: newSeverity,
      };
      if (newDescription.trim()) body.description = newDescription.trim();
      if (newAssignee.trim()) body.assignee = newAssignee.trim();
      if (newTags.trim()) body.tags = newTags.split(',').map((t) => t.trim()).filter(Boolean);
      if (newAlertIds.trim()) body.alert_ids = newAlertIds.split(',').map((t) => t.trim()).filter(Boolean);
      await createCase(body);
      setShowModal(false);
      setNewTitle(''); setNewDescription(''); setNewSeverity('medium');
      setNewAssignee(''); setNewTags(''); setNewAlertIds('');
      await loadCases();
      setStatusText('Case created.');
    } catch (err) {
      setError(String(err));
    } finally {
      setCreating(false);
    }
  };

  const handleStatusChange = async (caseId: string, newStatus: CaseStatus) => {
    try {
      await updateCase(caseId, { status: newStatus });
      await loadCases();
      setStatusText(`Case moved to ${newStatus.replace('_', ' ')}.`);
    } catch (err) {
      setError(String(err));
    }
  };

  const handleCloseCase = async () => {
    if (!closeCaseId) return;
    try {
      await updateCase(closeCaseId, { status: 'closed' });
      setCloseCaseId(null);
      setCloseNote('');
      await loadCases();
      setStatusText('Case closed.');
    } catch (err) {
      setError(String(err));
    }
  };

  const handleAssign = async () => {
    if (!assignCaseId || !assignName.trim()) return;
    try {
      await updateCase(assignCaseId, { assignee: assignName.trim() });
      setAssignCaseId(null);
      setAssignName('');
      await loadCases();
      setStatusText(`Case assigned to ${assignName}.`);
    } catch (err) {
      setError(String(err));
    }
  };

  /* ── render ────────────────────────────────────── */

  const tabs: { key: FilterTab; label: string; count: number }[] = [
    { key: 'all', label: 'All Cases', count: cases.length },
    { key: 'open', label: 'Open', count: stats.open },
    { key: 'in_progress', label: 'In Progress', count: stats.inProgress },
    { key: 'closed', label: 'Closed', count: stats.closed },
  ];

  return (
    <div className="page">
      {/* ── Header ─────────────────────────────────── */}
      <div className="aq-header">
        <div className="aq-header-left">
          <h1 className="dash-page-title" style={{ margin: 0 }}>CASES</h1>
          <span className="aq-count">{filteredCases.length} results</span>
        </div>
        <div className="aq-header-right">
          <button className="dash-refresh-icon-btn" onClick={loadCases} title="Refresh">
            {refreshIcon}
          </button>
          <button className="cs-new-btn" onClick={() => setShowModal(true)}>
            {plusIcon} New Case
          </button>
        </div>
      </div>

      {/* ── SLA Breach Banner ──────────────────────── */}
      {slaBreaches.length > 0 && (
        <div className="cs-sla-banner">
          <div className="cs-sla-content">
            <span className="cs-sla-headline">
              {slaBreaches.length} SLA {slaBreaches.length !== 1 ? 'BREACHES' : 'BREACH'} DETECTED
            </span>
            <span className="cs-sla-cases">
              {slaBreaches.map((c, i) => (
                <span key={c.case_id}>
                  <span className="cs-sla-case-link" onClick={() => navigate(`/cases/${c.case_id}`)}>
                    {c.title}
                  </span>
                  {i < slaBreaches.length - 1 && <span className="cs-sla-sep"> / </span>}
                </span>
              ))}
            </span>
          </div>
          <span className="cs-sla-badge">{slaBreaches.length}</span>
        </div>
      )}

      {/* ── Filter Tabs ────────────────────────────── */}
      <div className="aq-filter-bar">
        <div className="aq-tabs">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              className={`dash-tab${filter === tab.key ? ' dash-tab--active' : ''}`}
              onClick={() => setFilter(tab.key)}
            >
              {tab.label}
              <span className="aq-tab-count">{tab.count}</span>
            </button>
          ))}
        </div>
      </div>

      {error && <div style={{ color: '#f45d5d', fontSize: 13 }}>{error}</div>}
      {statusText && <div className="aq-status-toast">{statusText}</div>}

      {/* ── Case Table ─────────────────────────────── */}
      <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="cs-table-header">
          <span className="cs-col-sev">Severity</span>
          <span className="cs-col-title">Case</span>
          <span className="cs-col-status">Status</span>
          <span className="cs-col-assignee">Assignee</span>
          <span className="cs-col-alerts">Alerts</span>
          <span className="cs-col-sla">SLA</span>
          <span className="cs-col-time">Updated</span>
          <span className="cs-col-actions">Actions</span>
        </div>

        {loading ? (
          <p className="empty-state">Loading cases...</p>
        ) : filteredCases.length === 0 ? (
          <p className="empty-state">No cases match the current filter.</p>
        ) : (
          <div className="cs-table-body">
            {filteredCases.map((c) => {
              const sla = slaInfo(c.sla_due_at);
              const sevColor = SEVERITY_COLORS[c.severity] ?? '#4a9eda';
              const resolution = (c as any).resolution;
              const closeNoteText = (c as any).close_note;
              const resLabel = resolution ? RESOLUTION_LABELS[resolution] : null;
              const isOpen = c.status === 'open';
              const isInProgress = c.status === 'in_progress';

              return (
                <div
                  key={c.case_id}
                  className="cs-row"
                  style={{ borderLeftColor: c.severity === 'critical' || c.severity === 'high' ? sevColor : 'transparent' }}
                  onClick={() => navigate(`/cases/${c.case_id}`)}
                >
                  {/* Severity */}
                  <span className="cs-col-sev">
                    <span className={`dash-sev-badge dash-sev-badge--${c.severity}`}>
                      {c.severity.toUpperCase()}
                    </span>
                  </span>

                  {/* Title + description + tags */}
                  <span className="cs-col-title">
                    <span className="cs-case-title">{c.title}</span>
                    {c.description && (
                      <span className="cs-case-desc">{c.description}</span>
                    )}
                    {c.tags.length > 0 && (
                      <span className="cs-tag-row">
                        {c.tags.slice(0, 3).map(t => (
                          <span key={t} className="aq-tag">{t}</span>
                        ))}
                        {c.tags.length > 3 && <span className="aq-dim">+{c.tags.length - 3}</span>}
                      </span>
                    )}
                    {resLabel && (
                      <span className="cs-resolution" style={{ color: resLabel.color }}>
                        {resLabel.label}
                        {closeNoteText && <span className="cs-close-note"> — {closeNoteText}</span>}
                      </span>
                    )}
                  </span>

                  {/* Status */}
                  <span className="cs-col-status">
                    <span className={`cs-status-badge cs-status-badge--${c.status}`}>
                      {(c.status ?? 'open').replace('_', ' ')}
                    </span>
                  </span>

                  {/* Assignee */}
                  <span className="cs-col-assignee">
                    {c.assignee ? (
                      <span className="cs-assignee">{c.assignee}</span>
                    ) : (
                      <span className="cs-unassigned">Unassigned</span>
                    )}
                  </span>

                  {/* Alert count */}
                  <span className="cs-col-alerts">
                    <span className="cs-alert-count">{c.alert_ids.length}</span>
                  </span>

                  {/* SLA */}
                  <span className="cs-col-sla">
                    <span className="cs-sla-label" style={{ color: sla.color }}>{sla.label}</span>
                    {c.sla_due_at && (
                      <span className="cs-sla-bar">
                        <span className="cs-sla-fill" style={{ width: `${Math.max(0, sla.pct)}%`, background: sla.color }} />
                      </span>
                    )}
                  </span>

                  {/* Time */}
                  <span className="cs-col-time">{timeAgo(c.updated_at)}</span>

                  {/* Actions */}
                  <span className="cs-col-actions" onClick={e => e.stopPropagation()}>
                    {isOpen && (
                      <>
                        <button className="aq-action-btn aq-action-btn--ack" onClick={() => handleStatusChange(c.case_id, 'in_progress')}>Investigate</button>
                        <button className="aq-action-btn aq-action-btn--assign" onClick={() => { setAssignCaseId(c.case_id); setAssignName(c.assignee ?? ''); }}>Assign</button>
                      </>
                    )}
                    {isInProgress && (
                      <>
                        <button className="aq-action-btn aq-action-btn--close" onClick={() => { setCloseCaseId(c.case_id); setCloseResolution('tp_contained'); setCloseNote(''); }}>Close</button>
                        <button className="aq-action-btn aq-action-btn--assign" onClick={() => { setAssignCaseId(c.case_id); setAssignName(c.assignee ?? ''); }}>Reassign</button>
                      </>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Close Case Modal (with resolution) ──── */}
      {closeCaseId && (
        <div className="aq-modal-backdrop" onClick={() => setCloseCaseId(null)}>
          <div className="panel aq-modal" style={{ maxWidth: 520 }} onClick={e => e.stopPropagation()}>
            <h3 className="aq-modal-title">Close Case</h3>
            <div className="stack">
              <label>
                Resolution
                <select value={closeResolution} onChange={e => setCloseResolution(e.target.value)}>
                  <option value="tp_contained">True Positive — Contained</option>
                  <option value="tp_not_contained">True Positive — Not Contained</option>
                  <option value="benign_tp">Benign True Positive</option>
                  <option value="false_positive">False Positive</option>
                  <option value="duplicate">Duplicate</option>
                </select>
              </label>
              <label>
                Closing Note
                <textarea value={closeNote} onChange={e => setCloseNote(e.target.value)} rows={3} placeholder="Summary of investigation findings and actions taken..." />
              </label>
              <div className="aq-modal-actions">
                <button className="aq-action-btn" onClick={() => setCloseCaseId(null)}>Cancel</button>
                <button className="aq-action-btn aq-action-btn--close" style={{ fontWeight: 700 }} onClick={handleCloseCase}>
                  Close Case
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Assign Modal ───────────────────────────── */}
      {assignCaseId && (
        <div className="aq-modal-backdrop" onClick={() => setAssignCaseId(null)}>
          <div className="panel aq-modal" onClick={e => e.stopPropagation()}>
            <h3 className="aq-modal-title">Assign Case</h3>
            <div className="stack">
              <label>
                Assignee
                <input value={assignName} onChange={e => setAssignName(e.target.value)} placeholder="e.g. analyst-1" autoFocus />
              </label>
              <div className="aq-modal-actions">
                <button className="aq-action-btn" onClick={() => setAssignCaseId(null)}>Cancel</button>
                <button
                  className="aq-action-btn aq-action-btn--assign"
                  style={{ fontWeight: 700, opacity: assignName.trim() ? 1 : 0.4 }}
                  disabled={!assignName.trim()}
                  onClick={handleAssign}
                >
                  Assign
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── New Case Modal ─────────────────────────── */}
      {showModal && (
        <div className="aq-modal-backdrop" onClick={() => setShowModal(false)}>
          <div className="panel aq-modal" style={{ maxWidth: 540 }} onClick={e => e.stopPropagation()}>
            <h3 className="aq-modal-title">New Case</h3>
            <div className="stack">
              <label>
                Title *
                <input value={newTitle} onChange={e => setNewTitle(e.target.value)} placeholder="Case title" autoFocus />
              </label>
              <label>
                Description
                <textarea rows={3} value={newDescription} onChange={e => setNewDescription(e.target.value)} placeholder="Case description" />
              </label>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <label>
                  Severity
                  <select value={newSeverity} onChange={e => setNewSeverity(e.target.value as Severity)}>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </label>
                <label>
                  Assignee
                  <input value={newAssignee} onChange={e => setNewAssignee(e.target.value)} placeholder="e.g. analyst-1" />
                </label>
              </div>
              <label>
                Tags (comma-separated)
                <input value={newTags} onChange={e => setNewTags(e.target.value)} placeholder="e.g. malware, phishing" />
              </label>
              <label>
                Alert IDs (comma-separated)
                <input value={newAlertIds} onChange={e => setNewAlertIds(e.target.value)} placeholder="e.g. a001, a002" />
              </label>
              <div className="aq-modal-actions">
                <button className="aq-action-btn" onClick={() => setShowModal(false)}>Cancel</button>
                <button
                  className="cs-new-btn"
                  onClick={handleCreate}
                  disabled={creating || !newTitle.trim()}
                  style={{ opacity: newTitle.trim() ? 1 : 0.4 }}
                >
                  {creating ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
