import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  Clock3,
  History,
  Loader2,
  Monitor,
  Plus,
  RefreshCcw,
  Shield,
  Tag,
  User,
  Workflow,
} from 'lucide-react';

import {
  addAlertsToCase,
  getAlert,
  getAlerts,
  getAuditLogs,
  getCase,
  runSearch,
  updateCase,
  type AlertRecord,
  type AuditLogRecord,
  type CaseRecord,
  type CaseResolution,
  type CaseStatus,
  type Severity,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceModal } from '@/components/workspace/modal-shell';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { aggregateEventContexts, extractEventContext, formatNetworkFlow, limitValues } from '@/lib/logContext';
import { cn } from '@/lib/utils';

type EvidenceRow = Record<string, unknown>;
type Tone = 'default' | 'secondary' | 'outline' | 'destructive' | 'success' | 'warning' | 'info';

const STATUS_TRANSITIONS: Record<CaseStatus, CaseStatus[]> = {
  open: ['in_progress'],
  in_progress: ['resolved'],
  resolved: ['closed'],
  closed: [],
};

const RESOLUTION_LABELS: Record<CaseResolution, string> = {
  tp_contained: 'True positive - contained',
  tp_not_contained: 'True positive - not contained',
  benign_tp: 'Benign true positive',
  false_positive: 'False positive',
  duplicate: 'Duplicate',
};

function rel(iso?: string): string {
  if (!iso) return 'Unknown';
  const diff = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(diff)) return iso;
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function abs(iso?: string): string {
  if (!iso) return 'Unknown';
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toLocaleString();
}

function loadError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const normalized = message.toLowerCase();
  if (message.includes('API 404')) return 'Case not found.';
  if (message.includes('API 401') || normalized.includes('authentication failed')) {
    return 'Your session expired or you are not authorized to load this case. Please sign in again and retry.';
  }
  return message;
}

function mergeUnique(...groups: Array<Array<string | undefined> | undefined>): string[] {
  const seen = new Set<string>();
  const next: string[] = [];
  groups.forEach((group) => group?.forEach((value) => {
    if (!value || seen.has(value)) return;
    seen.add(value);
    next.push(value);
  }));
  return next;
}

function severityVariant(severity: Severity): Tone {
  if (severity === 'critical') return 'destructive';
  if (severity === 'high') return 'warning';
  if (severity === 'medium') return 'info';
  return 'secondary';
}

function statusVariant(status: CaseStatus): Tone {
  if (status === 'closed') return 'secondary';
  if (status === 'resolved') return 'success';
  if (status === 'in_progress') return 'warning';
  return 'default';
}

function stripEvidenceRef(ref: string): string {
  return ref.replace(/^event:/, '');
}

function buildEvidenceWindow(alerts: AlertRecord[]): { start: string; end: string } {
  const timestamps = alerts
    .flatMap((alert) => [Date.parse(alert.first_seen), Date.parse(alert.last_seen)])
    .filter((value) => Number.isFinite(value));
  if (!timestamps.length) {
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    return { start: weekAgo.toISOString(), end: now.toISOString() };
  }
  return {
    start: new Date(Math.min(...timestamps) - 12 * 60 * 60 * 1000).toISOString(),
    end: new Date(Math.max(...timestamps) + 12 * 60 * 60 * 1000).toISOString(),
  };
}

function slaCountdown(slaDueAt?: string): { label: string; pct: number; breached: boolean } {
  if (!slaDueAt) return { label: 'No SLA', pct: 100, breached: false };
  const remaining = new Date(slaDueAt).getTime() - Date.now();
  if (remaining <= 0) return { label: 'Breached', pct: 0, breached: true };
  const hours = Math.floor(remaining / 3_600_000);
  const minutes = Math.floor((remaining % 3_600_000) / 60_000);
  const seconds = Math.floor((remaining % 60_000) / 1_000);
  const total = 24 * 3_600_000;
  return {
    label: hours > 0 ? `${hours}h ${minutes}m ${seconds}s` : `${minutes}m ${seconds}s`,
    pct: Math.min(100, (remaining / total) * 100),
    breached: false,
  };
}

function ChipRow({ label, values }: { label: string; values: string[] }) {
  if (!values.length) return null;
  return (
    <div className="rounded-[24px] border border-border/70 bg-background/35 p-4">
      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">{label}</div>
      <div className="mt-3 flex flex-wrap gap-2">
        {values.map((value) => (
          <span key={value} className="rounded-full border border-border/70 bg-card/70 px-3 py-1.5 text-sm text-foreground">
            {value}
          </span>
        ))}
      </div>
    </div>
  );
}

export function CaseDetail() {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();
  const [caseData, setCaseData] = useState<CaseRecord | null>(null);
  const [timeline, setTimeline] = useState<AuditLogRecord[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [evidenceRows, setEvidenceRows] = useState<EvidenceRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [editAssignee, setEditAssignee] = useState('');
  const [editTags, setEditTags] = useState('');
  const [attachAlertId, setAttachAlertId] = useState('');
  const [showReassign, setShowReassign] = useState(false);
  const [showEditTags, setShowEditTags] = useState(false);
  const [showAttach, setShowAttach] = useState(false);
  const [showClose, setShowClose] = useState(false);
  const [resolution, setResolution] = useState<CaseResolution>('tp_contained');
  const [closeNote, setCloseNote] = useState('');
  const [sla, setSla] = useState(slaCountdown(undefined));

  const loadCase = useCallback(async (showLoader: boolean) => {
    if (!caseId) {
      setCaseData(null);
      setLoading(false);
      setError('Case not found.');
      return;
    }
    if (showLoader) setLoading(true);
    setError('');
    try {
      const currentCase = await getCase(caseId);
      setCaseData(currentCase);
      setEditAssignee(currentCase.assignee ?? '');
      setEditTags((currentCase.tags ?? []).join(', '));
      setSla(slaCountdown(currentCase.sla_due_at));

      const [auditResult, alertsResult] = await Promise.allSettled([
        getAuditLogs({ limit: 100 }),
        currentCase.alert_ids.length ? getAlerts({ limit: Math.min(500, Math.max(100, currentCase.alert_ids.length * 2)) }) : Promise.resolve(null),
      ]);

      let nextError = '';
      let resolvedAlerts: AlertRecord[] = [];

      if (alertsResult.status === 'fulfilled' && alertsResult.value) {
        const known = new Map(alertsResult.value.alerts.map((alert) => [alert.alert_id, alert]));
        resolvedAlerts = currentCase.alert_ids.map((id) => known.get(id)).filter(Boolean) as AlertRecord[];
        const missing = currentCase.alert_ids.filter((id) => !known.has(id));
        if (missing.length) {
          const missingResults = await Promise.allSettled(missing.map((id) => getAlert(id)));
          missingResults.forEach((result) => {
            if (result.status === 'fulfilled') resolvedAlerts.push(result.value);
            else nextError = nextError ? `${nextError} Some linked alerts could not be loaded.` : 'Some linked alerts could not be loaded.';
          });
        }
      } else if (alertsResult.status === 'rejected') {
        nextError = loadError(alertsResult.reason);
      }

      setAlerts(resolvedAlerts);

      if (auditResult.status === 'fulfilled') {
        const alertIds = new Set(currentCase.alert_ids);
        setTimeline(auditResult.value.entries.filter((entry) => entry.entity_id === caseId || alertIds.has(entry.entity_id)));
      } else {
        nextError = nextError ? `${nextError} Activity timeline is partially unavailable.` : 'Activity timeline is partially unavailable.';
      }

      const evidenceIds = mergeUnique(resolvedAlerts.flatMap((alert) => alert.evidence_refs.map((ref) => stripEvidenceRef(ref)))).slice(0, 75);
      if (evidenceIds.length) {
        try {
          const rows = await runSearch({
            sql: `event_id IN (${evidenceIds.map((id) => `'${id.replace(/'/g, "''")}'`).join(', ')})`,
            time_range: buildEvidenceWindow(resolvedAlerts),
            pagination: { page: 1, page_size: Math.min(100, Math.max(25, evidenceIds.length * 2)) },
          });
          setEvidenceRows(rows.rows ?? []);
        } catch {
          setEvidenceRows([]);
          nextError = nextError ? `${nextError} Linked evidence is unavailable.` : 'Linked evidence is unavailable.';
        }
      } else {
        setEvidenceRows([]);
      }

      setError(nextError);
    } catch (err) {
      setCaseData(null);
      setTimeline([]);
      setAlerts([]);
      setEvidenceRows([]);
      setError(loadError(err));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [caseId]);

  useEffect(() => { void loadCase(true); }, [loadCase]);
  useEffect(() => {
    if (!caseData?.sla_due_at) return;
    const timer = window.setInterval(() => setSla(slaCountdown(caseData.sla_due_at)), 1000);
    return () => window.clearInterval(timer);
  }, [caseData?.sla_due_at]);

  const handleStatus = async (status: CaseStatus) => {
    if (!caseId) return;
    if (status === 'closed') { setShowClose(true); return; }
    setMessage('Updating case status...');
    try { await updateCase(caseId, { status }); await loadCase(false); setMessage(`Case moved to ${status.replace(/_/g, ' ')}.`); } catch (err) { setMessage(loadError(err)); }
  };
  const handleClose = async () => {
    if (!caseId) return;
    setMessage('Closing case...');
    try { await updateCase(caseId, { status: 'closed', resolution, close_note: closeNote.trim() || null }); setShowClose(false); setCloseNote(''); await loadCase(false); setMessage('Case closed.'); } catch (err) { setMessage(loadError(err)); }
  };
  const handleReassign = async () => {
    if (!caseId) return;
    setMessage('Saving assignee...');
    try { await updateCase(caseId, { assignee: editAssignee.trim() || null }); setShowReassign(false); await loadCase(false); setMessage(editAssignee.trim() ? `Assigned to ${editAssignee.trim()}.` : 'Assignment cleared.'); } catch (err) { setMessage(loadError(err)); }
  };
  const handleTags = async () => {
    if (!caseId) return;
    setMessage('Saving tags...');
    try { await updateCase(caseId, { tags: editTags.split(',').map((tag) => tag.trim()).filter(Boolean) }); setShowEditTags(false); await loadCase(false); setMessage('Tags updated.'); } catch (err) { setMessage(loadError(err)); }
  };
  const handleAttach = async () => {
    if (!caseId || !attachAlertId.trim()) return;
    setMessage('Attaching alert...');
    try { await addAlertsToCase(caseId, [attachAlertId.trim()]); setAttachAlertId(''); setShowAttach(false); await loadCase(false); setMessage('Alert attached to case.'); } catch (err) { setMessage(loadError(err)); }
  };

  const evidenceContexts = useMemo(() => evidenceRows.map((row) => extractEventContext(row)), [evidenceRows]);
  const evidenceById = useMemo(() => {
    const next = new Map<string, ReturnType<typeof extractEventContext>>();
    evidenceContexts.forEach((context) => { if (context.eventId) next.set(context.eventId, context); });
    return next;
  }, [evidenceContexts]);
  const aggregate = useMemo(() => aggregateEventContexts(evidenceContexts), [evidenceContexts]);
  const alertInsights = useMemo(() => {
    const next = new Map<string, ReturnType<typeof aggregateEventContexts>>();
    alerts.forEach((alert) => {
      const contexts = alert.evidence_refs.map((ref) => evidenceById.get(stripEvidenceRef(ref))).filter(Boolean) as ReturnType<typeof extractEventContext>[];
      next.set(alert.alert_id, aggregateEventContexts(contexts));
    });
    return next;
  }, [alerts, evidenceById]);

  const mitre = useMemo(() => {
    const seen = new Set<string>();
    return alerts.flatMap((alert) => alert.mitre_attack).filter((item) => {
      if (seen.has(item.technique_id)) return false;
      seen.add(item.technique_id);
      return true;
    });
  }, [alerts]);
  const assets = useMemo(() => {
    const next = new Map<string, { os: string; ip: string }>();
    alerts.forEach((alert) => {
      if (alert.agent_meta) next.set(alert.agent_meta.hostname, { os: alert.agent_meta.os, ip: '' });
    });
    return Array.from(next.entries());
  }, [alerts]);

  const sources = useMemo(() => limitValues(aggregate.sources, 6), [aggregate.sources]);
  const hosts = useMemo(() => limitValues(mergeUnique(assets.map(([name]) => name), aggregate.hosts), 6), [assets, aggregate.hosts]);
  const users = useMemo(() => limitValues(aggregate.users, 6), [aggregate.users]);
  const processes = useMemo(() => limitValues(aggregate.processes, 6), [aggregate.processes]);
  const networks = useMemo(() => limitValues(aggregate.networkFlows, 6), [aggregate.networkFlows]);
  const artifacts = useMemo(() => limitValues(mergeUnique(aggregate.domains, aggregate.files, aggregate.registryPaths, aggregate.services), 8), [aggregate.domains, aggregate.files, aggregate.registryPaths, aggregate.services]);
  const notes = useMemo(() => limitValues(aggregate.messages, 4), [aggregate.messages]);

  if (loading) return <Card><CardContent className="h-[320px] animate-pulse p-6" /></Card>;
  if (!caseData) return <Card><CardContent className="flex min-h-[320px] flex-col items-center justify-center p-8 text-center"><AlertTriangle className="h-8 w-8 text-destructive" /><div className="mt-4 font-display text-2xl font-semibold text-foreground">{error || 'Case not found.'}</div><Button type="button" className="mt-6" onClick={() => navigate('/cases')}><ArrowLeft className="h-4 w-4" />Back to cases</Button></CardContent></Card>;

  const nextStatuses = STATUS_TRANSITIONS[caseData.status] ?? [];

  return (
    <div className="space-y-6">
      <section className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <Button type="button" variant="ghost" className="mb-4 rounded-full px-0 hover:bg-transparent" onClick={() => navigate('/cases')}><ArrowLeft className="h-4 w-4" />Back to cases</Button>
          <div className="flex flex-wrap gap-2">
            <Badge variant={severityVariant(caseData.severity)}>{caseData.severity}</Badge>
            <Badge variant={statusVariant(caseData.status)}>{caseData.status.replace(/_/g, ' ')}</Badge>
            {caseData.assignee && <Badge variant="secondary">Owner {caseData.assignee}</Badge>}
            {caseData.resolution && <Badge variant="outline">{RESOLUTION_LABELS[caseData.resolution]}</Badge>}
          </div>
          <h1 className="mt-4 max-w-4xl font-display text-4xl font-semibold tracking-[-0.05em] text-foreground">{caseData.title}</h1>
          {caseData.description && <p className="mt-3 max-w-3xl text-base leading-7 text-muted-foreground">{caseData.description}</p>}
        </div>
        <div className="flex flex-wrap gap-3 lg:max-w-xl lg:justify-end">
          <Button type="button" variant="outline" onClick={() => { setRefreshing(true); void loadCase(false); }} disabled={refreshing}><RefreshCcw className={cn('h-4 w-4', refreshing && 'animate-spin')} />Refresh</Button>
          {nextStatuses.map((status) => <Button key={status} type="button" variant="outline" onClick={() => void handleStatus(status)}>{status.replace(/_/g, ' ')}</Button>)}
          {caseData.status !== 'closed' && <Button type="button" variant="outline" onClick={() => setShowReassign((value) => !value)}><User className="h-4 w-4" />Assignee</Button>}
          <Button type="button" variant="outline" onClick={() => setShowEditTags((value) => !value)}><Tag className="h-4 w-4" />Tags</Button>
          <Button type="button" variant="outline" onClick={() => setShowAttach((value) => !value)}><Plus className="h-4 w-4" />Attach alert</Button>
        </div>
      </section>

      {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}
      {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

      {(showReassign || showEditTags || showAttach) && (
        <Card>
          <CardContent className="grid gap-4 p-5 lg:grid-cols-3">
            {showReassign && <div><div className="mb-2 text-sm font-medium text-foreground">Assignee</div><Input value={editAssignee} onChange={(event) => setEditAssignee(event.target.value)} placeholder="analyst-1" /><div className="mt-3 flex gap-3"><Button type="button" size="sm" onClick={() => void handleReassign()}>Save</Button><Button type="button" size="sm" variant="outline" onClick={() => setShowReassign(false)}>Cancel</Button></div></div>}
            {showEditTags && <div><div className="mb-2 text-sm font-medium text-foreground">Tags</div><Input value={editTags} onChange={(event) => setEditTags(event.target.value)} placeholder="phishing, workstation, urgent" /><div className="mt-3 flex gap-3"><Button type="button" size="sm" onClick={() => void handleTags()}>Save</Button><Button type="button" size="sm" variant="outline" onClick={() => setShowEditTags(false)}>Cancel</Button></div></div>}
            {showAttach && <div><div className="mb-2 text-sm font-medium text-foreground">Attach alert by ID</div><Input value={attachAlertId} onChange={(event) => setAttachAlertId(event.target.value)} placeholder="alert-id" /><div className="mt-3 flex gap-3"><Button type="button" size="sm" onClick={() => void handleAttach()}>Attach</Button><Button type="button" size="sm" variant="outline" onClick={() => setShowAttach(false)}>Cancel</Button></div></div>}
          </CardContent>
        </Card>
      )}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="SLA" value={sla.label} hint={caseData.sla_due_at ? `Due ${abs(caseData.sla_due_at)}` : 'No SLA assigned'} icon={Clock3} />
        <WorkspaceMetricCard label="Created" value={rel(caseData.created_at)} hint={abs(caseData.created_at)} icon={History} />
        <WorkspaceMetricCard label="Updated" value={rel(caseData.updated_at)} hint={abs(caseData.updated_at)} icon={RefreshCcw} />
        <WorkspaceMetricCard label="Linked Alerts" value={String(caseData.alert_ids.length)} hint={caseData.assignee ? `Owned by ${caseData.assignee}` : 'Unassigned'} icon={Shield} />
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_380px]">
        <div className="space-y-6">
          <Card>
            <CardHeader className="pb-4"><CardTitle>Investigation snapshot</CardTitle><CardDescription>Entities and artifacts aggregated from all evidence linked to alerts in this case.</CardDescription></CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              {sources.length || hosts.length || users.length || processes.length || networks.length || artifacts.length || notes.length ? (
                <>
                  <ChipRow label="Log sources" values={sources} />
                  <ChipRow label="Observed hosts" values={hosts} />
                  <ChipRow label="Observed users" values={users} />
                  <ChipRow label="Processes" values={processes} />
                  <ChipRow label="Network paths" values={networks} />
                  <ChipRow label="Artifacts" values={artifacts} />
                  <ChipRow label="Message highlights" values={notes} />
                </>
              ) : <WorkspaceEmptyState title="Evidence summary is still empty" body="As linked alerts collect evidence, the shared investigation snapshot will fill in here." className="min-h-[220px]" />}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-4"><CardTitle>Linked alerts</CardTitle><CardDescription>All alerts attached to this case, with the strongest context available from evidence.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              {!caseData.alert_ids.length ? <WorkspaceEmptyState title="No linked alerts" body="Attach alerts to start building the investigative record for this case." className="min-h-[220px]" /> : (
                <>
                  {alerts.map((alert) => {
                    const insight = alertInsights.get(alert.alert_id);
                    const title = alert.rule_title || alert.rule_id;
                    const host = insight?.hosts[0] ?? alert.agent_meta?.hostname ?? 'Unknown host';
                    const user = insight?.users[0];
                    const process = insight?.processes[0];
                    const network = insight?.networkFlows[0] ?? formatNetworkFlow({
                      sourceIp: (alert as AlertRecord & { src_ip?: string }).src_ip,
                      destinationIp: (alert as AlertRecord & { dst_ip?: string }).dst_ip,
                      destinationHost: undefined,
                      destinationPort: (alert as AlertRecord & { dst_port?: string | number }).dst_port ? String((alert as AlertRecord & { dst_port?: string | number }).dst_port) : undefined,
                    });
                    return (
                      <Link key={alert.alert_id} to={`/alerts/${alert.alert_id}`} className="block rounded-[24px] border border-border/70 bg-background/35 p-4 transition-colors hover:bg-muted/45">
                        <div className="flex flex-wrap items-center gap-2"><Badge variant={severityVariant(alert.severity)}>{alert.severity}</Badge><Badge variant={statusVariant(alert.status as unknown as CaseStatus)}>{alert.status.replace(/_/g, ' ')}</Badge></div>
                        <div className="mt-3 font-medium text-foreground">{title}</div>
                        <div className="mt-2 flex flex-wrap gap-3 text-sm text-muted-foreground"><span>{host}</span>{user && <span>{user}</span>}{process && <span>{process}</span>}{network && <span>{network}</span>}<span>{rel(alert.last_seen)}</span></div>
                      </Link>
                    );
                  })}
                  {caseData.alert_ids.filter((id) => !alerts.find((alert) => alert.alert_id === id)).map((id) => <div key={id} className="rounded-[24px] border border-border/70 bg-background/35 p-4 text-sm text-muted-foreground">{id} is linked but its detail record could not be resolved.</div>)}
                </>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-4"><CardTitle>Activity timeline</CardTitle><CardDescription>Recent audit and linked-alert activity associated with this case.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              {!timeline.length ? <WorkspaceEmptyState title="No activity yet" body="Case and linked alert actions will appear here as the investigation progresses." className="min-h-[220px]" /> : timeline.map((entry) => (
                <div key={entry.audit_id} className="flex gap-4 rounded-[24px] border border-border/70 bg-background/35 p-4">
                  <div className="mt-1 flex h-9 w-9 items-center justify-center rounded-2xl border border-primary/20 bg-primary/10 text-primary"><History className="h-4 w-4" /></div>
                  <div className="min-w-0">
                    <div className="font-medium text-foreground">{entry.action}</div>
                    <div className="mt-1 text-sm text-muted-foreground">by {entry.actor} · {abs(entry.timestamp)}</div>
                    <div className="mt-1 text-sm text-muted-foreground">{entry.entity_type}:{entry.entity_id.slice(0, 8)}</div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader className="pb-4"><CardTitle>Case context</CardTitle><CardDescription>Assignment, tags, and close-state details for the current investigation container.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Assignee</div><div className="mt-2 text-sm text-foreground">{caseData.assignee ?? 'Unassigned'}</div></div>
              <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Tags</div><div className="mt-3 flex flex-wrap gap-2">{caseData.tags.length ? caseData.tags.map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>) : <span className="text-sm text-muted-foreground">No tags set.</span>}</div></div>
              {caseData.close_note && <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Close note</div><div className="mt-2 text-sm text-muted-foreground">{caseData.close_note}</div></div>}
              {caseData.sla_due_at && <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">SLA health</div><div className="mt-3 h-2 overflow-hidden rounded-full bg-muted/60"><div className={cn('h-full rounded-full', sla.breached ? 'bg-destructive' : 'bg-primary')} style={{ width: `${Math.max(sla.pct, 4)}%` }} /></div><div className="mt-2 text-sm text-muted-foreground">{sla.breached ? 'SLA breached' : `${sla.label} remaining`}</div></div>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-4"><CardTitle>MITRE ATT&CK</CardTitle><CardDescription>Techniques surfaced across all linked alerts.</CardDescription></CardHeader>
            <CardContent className="space-y-3">
              {!mitre.length ? <WorkspaceEmptyState title="No ATT&CK mapping yet" body="Technique coverage appears here once linked alerts include MITRE enrichment." className="min-h-[220px]" /> : mitre.map((item) => <div key={item.technique_id} className="rounded-[20px] border border-border/70 bg-background/35 px-4 py-3"><div className="font-medium text-foreground">{item.technique_id}</div><div className="mt-1 text-sm text-muted-foreground">{item.technique_name}</div><div className="mt-1 text-xs uppercase tracking-[0.2em] text-muted-foreground">{item.tactic.replace(/-/g, ' ')}</div></div>)}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-4"><CardTitle>Affected assets</CardTitle><CardDescription>Hosts currently implicated by the alerts attached to this case.</CardDescription></CardHeader>
            <CardContent className="space-y-3">
              {!assets.length ? <WorkspaceEmptyState title="No assets identified" body="Host context appears here once linked alerts carry agent or event-host metadata." className="min-h-[220px]" /> : assets.map(([hostname, info]) => <div key={hostname} className="flex items-center gap-3 rounded-[20px] border border-border/70 bg-background/35 px-4 py-3"><div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-border/70 bg-card/70 text-primary"><Monitor className="h-4 w-4" /></div><div><div className="font-medium text-foreground">{hostname}</div><div className="text-sm text-muted-foreground">{info.os}{info.ip ? ` · ${info.ip}` : ''}</div></div></div>)}
            </CardContent>
          </Card>
        </div>
      </section>

      <WorkspaceModal open={showClose} title="Close case" description="Pick the final case resolution and capture any closing note for the record." onClose={() => setShowClose(false)} panelClassName="max-w-xl">
        <div className="grid gap-3 sm:grid-cols-2">{(Object.keys(RESOLUTION_LABELS) as CaseResolution[]).map((item) => <button key={item} type="button" className={cn('rounded-[24px] border px-4 py-4 text-left transition-colors', resolution === item ? 'border-primary/40 bg-primary/10 text-foreground' : 'border-border/70 bg-background/35 text-muted-foreground hover:bg-muted/40')} onClick={() => setResolution(item)}><div className="font-medium text-foreground">{RESOLUTION_LABELS[item]}</div></button>)}</div>
        <div><div className="mb-2 text-sm font-medium text-foreground">Close note</div><Textarea value={closeNote} onChange={(event) => setCloseNote(event.target.value)} rows={4} placeholder="Summarize findings, containment, and remaining follow-up." /></div>
        <div className="flex flex-wrap justify-end gap-3"><Button type="button" variant="outline" onClick={() => setShowClose(false)}>Cancel</Button><Button type="button" onClick={() => void handleClose()}>Close case</Button></div>
      </WorkspaceModal>
    </div>
  );
}
