import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  acknowledgeAlert,
  assignAlert,
  closeAlert,
  falsePositiveAlert,
  explainAlert,
  getAlert,
  createCase,
  getRules,
  runSearch,
} from '../api/client';
import type {
  AlertRecord,
  AlertResolution,
  DetectionRule,
  ExplainAlertResult,
} from '../api/client';
import { useAuth } from '../contexts/AuthContext';
import { aggregateEventContexts, extractEventContext, formatNetworkFlow, limitValues } from '../lib/logContext';

/* ── Helpers ──────────────────────────────────────── */

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

function duration(a: AlertRecord): string {
  const ms = new Date(a.last_seen).getTime() - new Date(a.first_seen).getTime();
  if (ms < 1000) return 'Instantaneous';
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ${secs % 60}s`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ${mins % 60}m`;
}

function fpLabel(likelihood: string): { text: string; cls: string } {
  switch (likelihood) {
    case 'high': return { text: 'HIGH', cls: 'ad-fp--high' };
    case 'medium': return { text: 'MEDIUM', cls: 'ad-fp--medium' };
    default: return { text: 'LOW', cls: 'ad-fp--low' };
  }
}

function formatLoadError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const normalized = message.toLowerCase();
  if (message.includes('API 404')) {
    return 'Alert not found.';
  }
  if (message.includes('API 401') || normalized.includes('authentication failed')) {
    return 'Your session expired or you are not authorized to load this alert. Please sign in again and retry.';
  }
  return message;
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

function formatEvidenceTime(value?: string): string | null {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

/* ── SVG Icons ────────────────────────────────────── */

const backIcon = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 12H5"/><polyline points="12 19 5 12 12 5"/>
  </svg>
);
const shieldIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);
const monitorIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
  </svg>
);
const fileIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
  </svg>
);
const clockIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
  </svg>
);
const routeIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/>
  </svg>
);
const sparkleIcon = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 2l3 7h7l-5.5 4.5 2 7L12 16l-6.5 4.5 2-7L2 9h7z"/>
  </svg>
);
const codeIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
  </svg>
);
const terminalIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
  </svg>
);

/* ── Props ────────────────────────────────────────── */

interface AlertDetailProps {
  alertId: string;
  onBack?: () => void;
}

/* ── Component ────────────────────────────────────── */

export function AlertDetail({ alertId, onBack }: AlertDetailProps) {
  const navigate = useNavigate();
  const { userId } = useAuth();
  const actor = userId || 'soc-admin';

  const [alert, setAlert] = useState<AlertRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusText, setStatusText] = useState('');

  const [closeModalOpen, setCloseModalOpen] = useState(false);
  const [closeResolution, setCloseResolution] = useState<AlertResolution>('true_positive');
  const [closeNote, setCloseNote] = useState('');

  const [assignModalOpen, setAssignModalOpen] = useState(false);
  const [assignName, setAssignName] = useState('');

  const [explainLoading, setExplainLoading] = useState(false);
  const [explainResult, setExplainResult] = useState<ExplainAlertResult | null>(null);
  const [explainError, setExplainError] = useState<string | null>(null);

  const [caseModalOpen, setCaseModalOpen] = useState(false);
  const [caseName, setCaseName] = useState('');

  const [rule, setRule] = useState<DetectionRule | null>(null);
  const [ruleYamlOpen, setRuleYamlOpen] = useState(false);

  const [evidenceEvents, setEvidenceEvents] = useState<Record<string, unknown>[]>([]);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [evidenceLoading, setEvidenceLoading] = useState(false);

  /* ── Data fetch ──────────────────────────────── */

  const fetchAlert = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const found = await getAlert(alertId);
      setAlert(found);
    } catch (err) {
      setAlert(null);
      setError(formatLoadError(err));
    }
    finally { setLoading(false); }
  }, [alertId]);

  useEffect(() => { fetchAlert(); }, [fetchAlert]);

  useEffect(() => {
    setCloseModalOpen(false);
    setCloseResolution('true_positive');
    setCloseNote('');
    setAssignModalOpen(false);
    setAssignName('');
    setCaseModalOpen(false);
    setCaseName('');
  }, [alertId]);

  // Fetch rule details
  useEffect(() => {
    if (!alert) return;
    getRules()
      .then((rules) => {
        const match = rules.find((r) => r.rule_id === alert.rule_id);
        if (match) setRule(match);
      })
      .catch(() => {});
  }, [alert]);

  // AI explanation
  useEffect(() => {
    if (!alert) return;
    setExplainLoading(true);
    explainAlert(alertId)
      .then((r) => setExplainResult(r))
      .catch((e) => setExplainError(String(e)))
      .finally(() => setExplainLoading(false));
  }, [alert, alertId]);

  // Fetch evidence events (first 5 evidence refs)
  const fetchEvidence = useCallback(async () => {
    if (!alert || alert.evidence_refs.length === 0) return;
    setEvidenceLoading(true);
    try {
      const refs = alert.evidence_refs.slice(0, 5);
      const ids = refs.map((r) => `'${r.replace(/^event:/, '').replace(/'/g, "''")}'`).join(',');
      const filterClause = `event_id IN (${ids})`;
      const now = new Date();
      const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const result = await runSearch({
        sql: filterClause,
        time_range: { start: weekAgo.toISOString(), end: now.toISOString() },
        pagination: { page: 1, page_size: 10 },
      });
      setEvidenceEvents(result.rows ?? []);
    } catch { /* ignore */ }
    finally { setEvidenceLoading(false); }
  }, [alert]);

  useEffect(() => {
    setEvidenceEvents([]);
    setEvidenceOpen(false);
  }, [alertId]);

  useEffect(() => {
    if (!alert || alert.evidence_refs.length === 0) return;
    void fetchEvidence();
  }, [alert, fetchEvidence]);

  /* ── Actions ─────────────────────────────────── */

  const handleAck = async () => {
    if (!alert) return;
    setStatusText('Acknowledging...');
    try { const u = await acknowledgeAlert(alert.alert_id, actor); setAlert(u); setStatusText('Acknowledged.'); }
    catch (e) { setStatusText(`Failed: ${e}`); }
  };

  const handleClose = async () => {
    if (!alert) return;
    try { const u = await closeAlert(alert.alert_id, closeResolution, actor, closeNote || undefined); setAlert(u); setCloseModalOpen(false); setCloseResolution('true_positive'); setCloseNote(''); setStatusText('Closed.'); }
    catch (e) { setStatusText(`Failed: ${e}`); }
  };

  const handleAssign = async () => {
    if (!alert) return;
    if (alert.status === 'closed') {
      setStatusText('Closed alerts cannot be reassigned.');
      setAssignModalOpen(false);
      return;
    }
    const nextAssignee = assignName.trim();
    if (!nextAssignee && !alert.assignee) return;
    try {
      const u = await assignAlert(alert.alert_id, nextAssignee || null, actor);
      setAlert(u);
      setAssignModalOpen(false);
      setAssignName('');
      setStatusText(nextAssignee ? `Assigned to ${nextAssignee}.` : 'Assignment cleared.');
    }
    catch (e) { setStatusText(`Failed: ${e}`); }
  };

  const handleFP = async () => {
    if (!alert) return;
    try { const u = await falsePositiveAlert(alert.alert_id, actor); setAlert(u); setStatusText('Marked false positive.'); }
    catch (e) { setStatusText(`Failed: ${e}`); }
  };

  const openCloseModal = () => {
    setCloseResolution('true_positive');
    setCloseNote('');
    setCloseModalOpen(true);
  };

  const openAssignModal = () => {
    if (!alert || alert.status === 'closed') return;
    setAssignName(alert.assignee ?? '');
    setAssignModalOpen(true);
  };

  const handleCreateCase = async () => {
    if (!alert) return;
    try {
      const c = await createCase({
        title: caseName || alert.rule_title || `Alert ${alert.alert_id.slice(0, 8)}`,
        severity: alert.severity ?? 'medium',
        alert_ids: [alert.alert_id],
      });
      setCaseModalOpen(false);
      setCaseName('');
      setStatusText(`Case ${c.case_id} created.`);
      navigate(`/cases/${c.case_id}`);
    } catch {
      setStatusText(`Case creation requested.`);
      setCaseModalOpen(false);
      setCaseName('');
    }
  };

  /* ── Loading/Error ───────────────────────────── */

  const evidenceContexts = useMemo(
    () => evidenceEvents.map((row) => extractEventContext(row)),
    [evidenceEvents],
  );
  const evidenceAggregate = useMemo(
    () => aggregateEventContexts(evidenceContexts),
    [evidenceContexts],
  );
  const evidenceById = useMemo(() => {
    const next = new Map<string, ReturnType<typeof extractEventContext>>();
    evidenceContexts.forEach((context) => {
      if (context.eventId) {
        next.set(context.eventId, context);
      }
    });
    return next;
  }, [evidenceContexts]);
  const observedHosts = useMemo(
    () => limitValues(mergeUnique([alert?.agent_meta?.hostname as string | undefined], evidenceAggregate.hosts), 4),
    [alert?.agent_meta, evidenceAggregate.hosts],
  );
  const observedUsers = useMemo(
    () => limitValues(evidenceAggregate.users, 4),
    [evidenceAggregate.users],
  );
  const observedProcesses = useMemo(
    () => limitValues(
      mergeUnique(
        evidenceAggregate.processes,
        [alert ? ((alert as any).process_name as string | undefined) : undefined],
      ),
      4,
    ),
    [alert, evidenceAggregate.processes],
  );
  const observedNetworks = useMemo(
    () => limitValues(
      mergeUnique(
        evidenceAggregate.networkFlows,
        [alert ? formatNetworkFlow({
          sourceIp: (alert as any).src_ip as string | undefined,
          destinationIp: (alert as any).dst_ip as string | undefined,
          destinationHost: undefined,
          destinationPort: (alert as any).dst_port ? String((alert as any).dst_port) : undefined,
        }) : undefined],
      ),
      4,
    ),
    [alert, evidenceAggregate.networkFlows],
  );
  const observedArtifacts = useMemo(
    () => limitValues(
      mergeUnique(
        evidenceAggregate.domains,
        evidenceAggregate.files,
        evidenceAggregate.registryPaths,
        evidenceAggregate.services,
      ),
      6,
    ),
    [evidenceAggregate.domains, evidenceAggregate.files, evidenceAggregate.registryPaths, evidenceAggregate.services],
  );
  const messageHighlights = useMemo(
    () => limitValues(evidenceAggregate.messages, 3),
    [evidenceAggregate.messages],
  );

  if (loading) return <div className="page"><p className="empty-state">Loading alert...</p></div>;
  if (error || !alert) return (
    <div className="page">
      <div className="cd-error">{error ?? 'Alert not found.'}</div>
      {onBack && <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={onBack}>Back</button>}
    </div>
  );

  /* ── Derived ─────────────────────────────────── */

  const sev = alert.severity ?? 'low';
  const ruleCompiledTitle = (rule?.compiled_plan as any)?.title;
  const title = alert.rule_title || ruleCompiledTitle || `Rule ${alert.rule_id.slice(0, 8)}`;
  const mitre: any[] = alert.mitre_attack ?? [];
  const agentMeta = alert.agent_meta;
  const evidenceRefs = alert.evidence_refs ?? [];
  const routingState = alert.routing_state;
  const hitCount = alert.hit_count ?? 1;
  const linkedCase = alert.case_id;
  const compiledPlan = (alert as any).compiled_plan as Record<string, unknown> | undefined;

  return (
    <div className="page ad-page">
      {/* ── Breadcrumb ──────────────────────────── */}
      <div className="cd-breadcrumb">
        <button type="button" className="cd-back-btn" onClick={onBack ?? (() => navigate('/alerts'))}>
          {backIcon} Alerts
        </button>
        <span className="cd-breadcrumb-sep">/</span>
        <span className="cd-breadcrumb-current">{alert.alert_id.slice(0, 8).toUpperCase()}</span>
      </div>

      {/* ── Header ──────────────────────────────── */}
      <div className="ad-header">
        <div className="ad-header-left">
          <h1 className="cd-title">{title}</h1>
          <div className="cd-header-badges">
            <span className={`cd-sev-badge cd-sev-badge--${sev}`}>{String(sev).toUpperCase()}</span>
            <span className={`ad-status-badge ad-status-badge--${alert.status}`}>
              {alert.status.replace('_', ' ').toUpperCase()}
            </span>
            {alert.assignee && <span className="ad-assignee-badge">{alert.assignee}</span>}
            {linkedCase && (
              <span className="ad-case-link" onClick={() => navigate(`/cases/${linkedCase}`)}>
                Case {linkedCase.slice(0, 8)}
              </span>
            )}
          </div>
        </div>
        <div className="cd-header-actions">
          {alert.status === 'open' && (
            <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={handleAck}>Acknowledge</button>
          )}
          {alert.status !== 'closed' && (
            <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={openCloseModal}>Close</button>
          )}
          {alert.status !== 'closed' && (
            <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={openAssignModal}>Assign</button>
          )}
          {alert.status !== 'closed' && (
            <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={handleFP}>False Positive</button>
          )}
          {linkedCase ? (
            <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={() => navigate(`/cases/${linkedCase}`)}>
              View Case
            </button>
          ) : (
            <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={() => setCaseModalOpen(true)}>Create Case</button>
          )}
        </div>
      </div>

      {statusText && <div className="ad-status-msg">{statusText}</div>}

      {/* ── Main Grid ───────────────────────────── */}
      <div className="ad-grid">
        {/* Left Column */}
        <div className="ad-left">
          {/* Summary */}
          <div className="cd-panel">
            <div className="cd-panel-header">
              <div className="cd-panel-title">{shieldIcon} <span>ALERT SUMMARY</span></div>
            </div>
            <div className="ad-field-grid">
              <div className="ad-field"><span className="ad-field-label">Alert ID</span><span className="ad-field-value ad-field-value--mono">{alert.alert_id}</span></div>
              <div className="ad-field"><span className="ad-field-label">Rule ID</span><span className="ad-field-value ad-field-value--mono">{alert.rule_id}</span></div>
              <div className="ad-field"><span className="ad-field-label">First Seen</span><span className="ad-field-value">{new Date(alert.first_seen).toLocaleString()} ({timeAgo(alert.first_seen)})</span></div>
              <div className="ad-field"><span className="ad-field-label">Last Seen</span><span className="ad-field-value">{new Date(alert.last_seen).toLocaleString()} ({timeAgo(alert.last_seen)})</span></div>
              <div className="ad-field">
                <span className="ad-field-label">Hit Count</span>
                <span className={`ad-field-value ad-hit-count ${hitCount > 5 ? 'ad-hit-count--danger' : hitCount > 1 ? 'ad-hit-count--warn' : ''}`}>
                  {hitCount}
                  {hitCount > 1 && <span className="ad-hit-note">(repeated)</span>}
                </span>
              </div>
              <div className="ad-field"><span className="ad-field-label">Duration</span><span className="ad-field-value">{duration(alert)}</span></div>
              {alert.assignee && <div className="ad-field"><span className="ad-field-label">Assignee</span><span className="ad-field-value">{alert.assignee}</span></div>}
              {alert.resolution && <div className="ad-field"><span className="ad-field-label">Resolution</span><span className="ad-field-value">{alert.resolution}</span></div>}
              {alert.close_note && <div className="ad-field ad-field--full"><span className="ad-field-label">Close Note</span><span className="ad-field-value">{alert.close_note}</span></div>}
            </div>
          </div>

          {/* MITRE ATT&CK */}
          {mitre.length > 0 && (
            <div className="cd-panel">
              <div className="cd-panel-header">
                <div className="cd-panel-title">{shieldIcon} <span>MITRE ATT&CK</span> <span className="cd-count-badge">{mitre.length}</span></div>
              </div>
              <div className="cd-mitre-list">
                {mitre.map((m: any, i: number) => (
                  <div key={i} className="cd-mitre-row">
                    <span className="cd-mitre-id">{m.technique_id}</span>
                    <span className="cd-mitre-name">{m.technique_name}</span>
                    <span className="cd-mitre-tactic">{m.tactic?.replace(/-/g, ' ')}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Agent / Network Context */}
          <div className="cd-panel">
            <div className="cd-panel-header">
              <div className="cd-panel-title">{monitorIcon} <span>CONTEXT</span></div>
            </div>
            <div className="ad-field-grid">
              {agentMeta?.hostname && <div className="ad-field"><span className="ad-field-label">Hostname</span><span className="ad-field-value">{agentMeta.hostname}</span></div>}
              {agentMeta?.os && <div className="ad-field"><span className="ad-field-label">OS</span><span className="ad-field-value">{agentMeta.os}</span></div>}
              {(agentMeta as any)?.ip && <div className="ad-field"><span className="ad-field-label">Agent IP</span><span className="ad-field-value ad-field-value--mono">{(agentMeta as any).ip}</span></div>}
              {(alert as any).src_ip && <div className="ad-field"><span className="ad-field-label">Source IP</span><span className="ad-field-value ad-field-value--mono">{(alert as any).src_ip}</span></div>}
              {(alert as any).dst_ip && <div className="ad-field"><span className="ad-field-label">Destination</span><span className="ad-field-value ad-field-value--mono">{(alert as any).dst_ip}{(alert as any).dst_port ? `:${(alert as any).dst_port}` : ''}</span></div>}
              {(alert as any).process_name && <div className="ad-field"><span className="ad-field-label">Process</span><span className="ad-field-value ad-field-value--mono">{(alert as any).process_name}</span></div>}
              {agentMeta?.group && <div className="ad-field"><span className="ad-field-label">Group</span><span className="ad-field-value">{agentMeta.group}</span></div>}
              {agentMeta?.tags && agentMeta.tags.length > 0 && (
                <div className="ad-field ad-field--full">
                  <span className="ad-field-label">Tags</span>
                  <div className="ad-tags">
                    {agentMeta.tags.map((t: string) => <span key={t} className="cd-tag">{t}</span>)}
                  </div>
                </div>
              )}
              {/* Show compiled_plan matched fields if available */}
              {compiledPlan?.description && (
                <div className="ad-field ad-field--full"><span className="ad-field-label">Rule Description</span><span className="ad-field-value">{String(compiledPlan.description)}</span></div>
              )}
            </div>
          </div>

          {(evidenceAggregate.eventKinds.length > 0
            || evidenceAggregate.sources.length > 0
            || observedHosts.length > 0
            || observedUsers.length > 0
            || observedProcesses.length > 0
            || observedNetworks.length > 0
            || observedArtifacts.length > 0
            || messageHighlights.length > 0) && (
            <div className="cd-panel">
              <div className="cd-panel-header">
                <div className="cd-panel-title">{terminalIcon} <span>INVESTIGATION SNAPSHOT</span></div>
              </div>
              <div className="ad-field-grid">
                {evidenceAggregate.eventKinds.length > 0 && (
                  <div className="ad-field ad-field--full">
                    <span className="ad-field-label">Event Types</span>
                    <div className="ad-tags">
                      {evidenceAggregate.eventKinds.map((value) => <span key={value} className="cd-tag">{value}</span>)}
                    </div>
                  </div>
                )}
                {evidenceAggregate.sources.length > 0 && (
                  <div className="ad-field">
                    <span className="ad-field-label">Log Sources</span>
                    <div className="ad-tags">
                      {evidenceAggregate.sources.map((value) => <span key={value} className="cd-tag">{value}</span>)}
                    </div>
                  </div>
                )}
                {observedHosts.length > 0 && (
                  <div className="ad-field">
                    <span className="ad-field-label">Observed Hosts</span>
                    <div className="ad-tags">
                      {observedHosts.map((value) => <span key={value} className="cd-tag">{value}</span>)}
                    </div>
                  </div>
                )}
                {observedUsers.length > 0 && (
                  <div className="ad-field">
                    <span className="ad-field-label">Users</span>
                    <div className="ad-tags">
                      {observedUsers.map((value) => <span key={value} className="cd-tag">{value}</span>)}
                    </div>
                  </div>
                )}
                {observedProcesses.length > 0 && (
                  <div className="ad-field">
                    <span className="ad-field-label">Processes</span>
                    <div className="ad-tags">
                      {observedProcesses.map((value) => <span key={value} className="cd-tag">{value}</span>)}
                    </div>
                  </div>
                )}
                {observedNetworks.length > 0 && (
                  <div className="ad-field ad-field--full">
                    <span className="ad-field-label">Network Paths</span>
                    <div className="ad-observation-list">
                      {observedNetworks.map((value) => <span key={value} className="ad-observation-pill">{value}</span>)}
                    </div>
                  </div>
                )}
                {observedArtifacts.length > 0 && (
                  <div className="ad-field ad-field--full">
                    <span className="ad-field-label">Artifacts</span>
                    <div className="ad-observation-list">
                      {observedArtifacts.map((value) => <span key={value} className="ad-observation-pill">{value}</span>)}
                    </div>
                  </div>
                )}
                {messageHighlights.length > 0 && (
                  <div className="ad-field ad-field--full">
                    <span className="ad-field-label">Message Highlights</span>
                    <div className="ad-observation-list ad-observation-list--stacked">
                      {messageHighlights.map((value) => <div key={value} className="ad-observation-note">{value}</div>)}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Evidence References */}
          <div className="cd-panel">
            <div className="cd-panel-header">
              <div className="cd-panel-title">{fileIcon} <span>EVIDENCE</span> {evidenceRefs.length > 0 && <span className="cd-count-badge">{evidenceRefs.length}</span>}</div>
              {evidenceRefs.length > 0 && !evidenceOpen && (
                <button type="button" className="cd-action-btn cd-action-btn--small" onClick={() => { setEvidenceOpen(true); fetchEvidence(); }}>
                  Show Evidence
                </button>
              )}
            </div>
            {evidenceRefs.length === 0 ? <p className="empty-state">No evidence references.</p> : (
              <>
                <div className="ad-evidence-list">
                  {evidenceRefs.slice(0, 5).map((ref: string, i: number) => {
                    const eventId = ref.replace(/^event:/, '');
                    const context = evidenceById.get(eventId);
                    const eventTime = formatEvidenceTime(context?.time);
                    return (
                    <div key={i} className="ad-evidence-item">
                      <div className="ad-evidence-item-main">
                        <code className="ad-evidence-ref">{ref}</code>
                        {context && <div className="ad-evidence-summary">{context.summary}</div>}
                        {eventTime && <div className="ad-evidence-meta">{eventTime}</div>}
                      </div>
                      <button type="button" className="cd-action-btn cd-action-btn--small" onClick={() => {
                        const now = new Date();
                        const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                        const params = new URLSearchParams({
                          q: `event_id = '${eventId.replace(/'/g, "''")}'`,
                          from: weekAgo.toISOString(),
                          to: now.toISOString(),
                        });
                        navigate(`/search?${params.toString()}`);
                      }}>
                        Search
                      </button>
                    </div>
                  );})}
                  {evidenceRefs.length > 5 && (
                    <div style={{ fontSize: 12, color: 'var(--text-tertiary)', padding: '4px 0' }}>
                      +{evidenceRefs.length - 5} more evidence references
                    </div>
                  )}
                </div>
                {/* Expanded parsed events */}
                {evidenceOpen && (
                  <div className="ad-raw-events">
                    <div className="ad-raw-events-header" onClick={() => setEvidenceOpen(false)}>
                      {terminalIcon} <span>Evidence Events</span>
                    </div>
                    {evidenceLoading && <p className="empty-state">Loading events...</p>}
                    {!evidenceLoading && evidenceContexts.length === 0 && <p className="empty-state">No matching events found in the last 7 days.</p>}
                    {evidenceContexts.map((context, i) => {
                      const flow = formatNetworkFlow(context);
                      const eventTime = formatEvidenceTime(context.time);
                      const rawEvent = evidenceEvents[i];
                      return (
                        <div key={context.eventId ?? i} className="ad-evidence-card">
                          <div className="ad-evidence-card-top">
                            <div className="ad-evidence-card-headline">
                              <div className="ad-evidence-card-title">{context.summary}</div>
                              <div className="ad-evidence-card-chips">
                                {context.eventName && <span className="ad-evidence-chip">{context.eventName}</span>}
                                {context.source && <span className="ad-evidence-chip ad-evidence-chip--muted">{context.source}</span>}
                                {context.host && <span className="ad-evidence-chip ad-evidence-chip--muted">{context.host}</span>}
                              </div>
                            </div>
                            {eventTime && <span className="ad-evidence-card-time">{eventTime}</span>}
                          </div>
                          {context.message && <div className="ad-evidence-card-message">{context.message}</div>}
                          <div className="ad-evidence-grid">
                            {context.user && <div className="ad-evidence-detail"><span>User</span><strong>{context.user}</strong></div>}
                            {context.process && <div className="ad-evidence-detail"><span>Process</span><strong>{context.process}</strong></div>}
                            {context.parentProcess && <div className="ad-evidence-detail"><span>Parent</span><strong>{context.parentProcess}</strong></div>}
                            {flow && <div className="ad-evidence-detail"><span>Network</span><strong>{flow}</strong></div>}
                            {context.dnsQuery && <div className="ad-evidence-detail"><span>Query</span><strong>{context.dnsQuery}</strong></div>}
                            {context.url && <div className="ad-evidence-detail"><span>URL</span><strong>{context.url}</strong></div>}
                            {context.filePath && <div className="ad-evidence-detail"><span>File</span><strong>{context.filePath}</strong></div>}
                            {context.registryPath && <div className="ad-evidence-detail"><span>Registry</span><strong>{context.registryPath}</strong></div>}
                            {context.service && <div className="ad-evidence-detail"><span>Service</span><strong>{context.service}</strong></div>}
                            {context.hashes && <div className="ad-evidence-detail"><span>Hashes</span><strong>{context.hashes}</strong></div>}
                            {context.commandLine && <div className="ad-evidence-detail ad-evidence-detail--wide"><span>Command Line</span><strong>{context.commandLine}</strong></div>}
                          </div>
                          <details className="ad-evidence-raw-toggle">
                            <summary>Raw JSON</summary>
                            <pre className="ad-raw-event-block">{JSON.stringify(rawEvent, null, 2)}</pre>
                          </details>
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}
          </div>

          {/* Detection Rule */}
          {rule && (
            <div className="cd-panel">
              <div className="cd-panel-header">
                <div className="cd-panel-title">{codeIcon} <span>DETECTION RULE</span></div>
                <button type="button" className="cd-action-btn cd-action-btn--small" onClick={() => setRuleYamlOpen(!ruleYamlOpen)}>
                  {ruleYamlOpen ? 'Hide' : 'Show YAML'}
                </button>
              </div>
              <div className="ad-field-grid">
                <div className="ad-field"><span className="ad-field-label">Mode</span><span className="ad-field-value">{rule.schedule_or_stream}</span></div>
                <div className="ad-field"><span className="ad-field-label">Enabled</span><span className="ad-field-value">{rule.enabled ? 'Yes' : 'No'}</span></div>
              </div>
              {ruleYamlOpen && (
                <pre className="ad-rule-yaml">{rule.sigma_source}</pre>
              )}
            </div>
          )}

          {/* Routing State */}
          {routingState && routingState.dedupe_key && (
            <div className="cd-panel">
              <div className="cd-panel-header">
                <div className="cd-panel-title">{routeIcon} <span>ROUTING</span></div>
              </div>
              <div className="ad-field-grid">
                <div className="ad-field"><span className="ad-field-label">Dedupe Key</span><span className="ad-field-value ad-field-value--mono">{routingState.dedupe_key}</span></div>
                {routingState.destinations?.length > 0 && (
                  <div className="ad-field ad-field--full">
                    <span className="ad-field-label">Destinations</span>
                    <div className="ad-tags">
                      {routingState.destinations.map((d: string) => <span key={d} className="cd-tag">{d}</span>)}
                    </div>
                  </div>
                )}
                {routingState.suppression_until && (
                  <div className="ad-field"><span className="ad-field-label">Suppressed Until</span><span className="ad-field-value">{new Date(routingState.suppression_until).toLocaleString()}</span></div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* ── Right Column: AI Explain ──────────── */}
        <div className="ad-right">
          <div className="cd-panel ad-explain-panel">
            <div className="cd-panel-header">
              <div className="cd-panel-title">{sparkleIcon} <span>AI ANALYSIS</span></div>
            </div>

            {explainLoading && (
              <div className="ad-skeleton">
                <div className="ad-skeleton-bar ad-skeleton-bar--lg" />
                <div className="ad-skeleton-bar" />
                <div className="ad-skeleton-bar ad-skeleton-bar--sm" />
              </div>
            )}

            {explainError && <div className="cd-error" style={{ fontSize: 13 }}>{explainError}</div>}

            {explainResult && (
              <div className="ad-explain-content">
                <div className="ad-explain-section">
                  <h4 className="ad-explain-heading">Summary</h4>
                  <p className="ad-explain-text">{explainResult.summary}</p>
                </div>
                <div className="ad-explain-section">
                  <h4 className="ad-explain-heading">Why Suspicious</h4>
                  <p className="ad-explain-text">{explainResult.why_suspicious}</p>
                </div>
                <div className="ad-explain-section">
                  <h4 className="ad-explain-heading">Likely Cause</h4>
                  <p className="ad-explain-text">{explainResult.likely_cause}</p>
                </div>
                <div className="ad-explain-section">
                  <h4 className="ad-explain-heading">False Positive Likelihood</h4>
                  <span className={`ad-fp-badge ${fpLabel(explainResult.false_positive_likelihood).cls}`}>
                    {fpLabel(explainResult.false_positive_likelihood).text}
                  </span>
                </div>
                <div className="ad-explain-section">
                  <h4 className="ad-explain-heading">Recommended Actions</h4>
                  <ul className="ad-explain-actions">
                    {explainResult.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
                  </ul>
                </div>
              </div>
            )}
          </div>

          {/* Timeline (compact, right side) */}
          <div className="cd-panel">
            <div className="cd-panel-header">
              <div className="cd-panel-title">{clockIcon} <span>TIMELINE</span></div>
            </div>
            <div className="ad-timeline">
              <div className="ad-timeline-event">
                <div className="ad-timeline-dot ad-timeline-dot--green" />
                <div className="ad-timeline-content">
                  <span className="ad-timeline-time">{new Date(alert.first_seen).toLocaleString()}</span>
                  <span className="ad-timeline-label">First detection</span>
                </div>
              </div>
              {hitCount > 1 && (
                <div className="ad-timeline-event">
                  <div className="ad-timeline-dot ad-timeline-dot--amber" />
                  <div className="ad-timeline-content">
                    <span className="ad-timeline-time">{hitCount - 1} additional hits</span>
                    <span className="ad-timeline-label">Repeated pattern over {duration(alert)}</span>
                  </div>
                </div>
              )}
              <div className="ad-timeline-event">
                <div className={`ad-timeline-dot ${alert.status === 'closed' ? 'ad-timeline-dot--gray' : 'ad-timeline-dot--red'}`} />
                <div className="ad-timeline-content">
                  <span className="ad-timeline-time">{new Date(alert.last_seen).toLocaleString()}</span>
                  <span className="ad-timeline-label">Last seen ({timeAgo(alert.last_seen)})</span>
                </div>
              </div>
              {alert.status === 'closed' && (
                <div className="ad-timeline-event">
                  <div className="ad-timeline-dot ad-timeline-dot--gray" />
                  <div className="ad-timeline-content">
                    <span className="ad-timeline-time">Closed</span>
                    <span className="ad-timeline-label">{alert.resolution ?? 'No resolution'}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Close Modal ─────────────────────────── */}
      {closeModalOpen && (
        <div className="cd-modal-overlay" onClick={() => setCloseModalOpen(false)}>
          <div className="cd-modal" onClick={(e) => e.stopPropagation()}>
            <h3 className="cd-modal-title">Close Alert</h3>
            <div className="cd-modal-field">
              <label className="cd-modal-label">Resolution</label>
              <select className="re-meta-select" value={closeResolution} onChange={(e) => setCloseResolution(e.target.value as AlertResolution)}>
                <option value="true_positive">True Positive</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>
            <div className="cd-modal-field">
              <label className="cd-modal-label">Note (optional)</label>
              <textarea className="cd-modal-textarea" value={closeNote} onChange={(e) => setCloseNote(e.target.value)} rows={3} placeholder="Add context..." />
            </div>
            <div className="cd-modal-actions">
              <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setCloseModalOpen(false)}>Cancel</button>
              <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleClose}>Close Alert</button>
            </div>
          </div>
        </div>
      )}

      {/* ── Assign Modal ────────────────────────── */}
      {assignModalOpen && (
        <div className="cd-modal-overlay" onClick={() => setAssignModalOpen(false)}>
          <div className="cd-modal" onClick={(e) => e.stopPropagation()}>
            <h3 className="cd-modal-title">Assign Alert</h3>
            <div className="cd-modal-field">
              <label className="cd-modal-label">Assignee</label>
              <input className="cd-inline-input" value={assignName} onChange={(e) => setAssignName(e.target.value)} placeholder="e.g. analyst-1" autoFocus />
            </div>
            <div className="cd-modal-actions">
              <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setAssignModalOpen(false)}>Cancel</button>
              <button
                type="button"
                className="cd-action-btn cd-action-btn--primary"
                onClick={handleAssign}
                disabled={!assignName.trim() && !alert?.assignee}
              >
                {assignName.trim() ? 'Assign' : 'Clear Assignment'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Create Case Modal ───────────────────── */}
      {caseModalOpen && (
        <div className="cd-modal-overlay" onClick={() => setCaseModalOpen(false)}>
          <div className="cd-modal" onClick={(e) => e.stopPropagation()}>
            <h3 className="cd-modal-title">Create Case</h3>
            <div className="cd-modal-field">
              <label className="cd-modal-label">Case Name</label>
              <input className="cd-inline-input" value={caseName} onChange={(e) => setCaseName(e.target.value)} placeholder={`Case for ${title}`} autoFocus />
            </div>
            <p className="ad-modal-hint">This will create a new case and attach alert {alert.alert_id.slice(0, 8)} to it.</p>
            <div className="cd-modal-actions">
              <button type="button" className="cd-action-btn cd-action-btn--secondary" onClick={() => setCaseModalOpen(false)}>Cancel</button>
              <button type="button" className="cd-action-btn cd-action-btn--primary" onClick={handleCreateCase}>Create Case</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
