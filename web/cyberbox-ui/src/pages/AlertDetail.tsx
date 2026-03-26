import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Bot,
  CheckCircle2,
  Clock3,
  ExternalLink,
  FileText,
  Fingerprint,
  Loader2,
  Monitor,
  Network,
  RefreshCcw,
  Search,
  Shield,
  Sparkles,
  User,
  Workflow,
  XCircle,
} from 'lucide-react';

import {
  acknowledgeAlert,
  assignAlert,
  closeAlert,
  createCase,
  explainAlert,
  falsePositiveAlert,
  getAlert,
  getRules,
  runSearch,
  type AlertRecord,
  type AlertResolution,
  type DetectionRule,
  type ExplainAlertResult,
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
import { useAuth } from '@/contexts/AuthContext';
import { aggregateEventContexts, extractEventContext, formatNetworkFlow, limitValues } from '@/lib/logContext';
import { cn } from '@/lib/utils';

interface AlertDetailProps {
  alertId: string;
  onBack?: () => void;
}

type EvidenceRow = Record<string, unknown>;
type Tone = 'default' | 'secondary' | 'outline' | 'destructive' | 'success' | 'warning' | 'info';

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

function span(alert: AlertRecord): string {
  const ms = new Date(alert.last_seen).getTime() - new Date(alert.first_seen).getTime();
  if (!Number.isFinite(ms) || ms <= 0) return 'Instantaneous';
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) return `${Math.floor(ms / 1000)}s`;
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

function loadError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const normalized = message.toLowerCase();
  if (message.includes('API 404')) return 'Alert not found.';
  if (message.includes('API 401') || normalized.includes('authentication failed')) {
    return 'Your session expired or you are not authorized to load this alert. Please sign in again and retry.';
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

function statusVariant(status: AlertRecord['status']): Tone {
  if (status === 'closed') return 'secondary';
  if (status === 'acknowledged') return 'info';
  if (status === 'in_progress') return 'warning';
  return 'default';
}

function resolutionLabel(resolution?: AlertResolution): string {
  if (resolution === 'true_positive') return 'True positive';
  if (resolution === 'false_positive') return 'False positive';
  if (resolution === 'informational') return 'Informational';
  return 'Open';
}

function fpTone(value: string): string {
  if (value === 'high') return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-200';
  if (value === 'medium') return 'border-amber-500/20 bg-amber-500/10 text-amber-100';
  return 'border-rose-500/20 bg-rose-500/10 text-rose-100';
}

function ChipGroup({
  label,
  values,
  icon: Icon,
}: {
  label: string;
  values: string[];
  icon: React.ComponentType<{ className?: string }>;
}) {
  if (!values.length) return null;
  return (
    <div className="rounded-lg border border-border/70 bg-background/35 p-4">
      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">
        <Icon className="h-4 w-4 text-primary" />
        <span>{label}</span>
      </div>
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

export function AlertDetail({ alertId, onBack }: AlertDetailProps) {
  const navigate = useNavigate();
  const { userId } = useAuth();
  const actor = userId || 'soc-admin';
  const [alert, setAlert] = useState<AlertRecord | null>(null);
  const [rule, setRule] = useState<DetectionRule | null>(null);
  const [explain, setExplain] = useState<ExplainAlertResult | null>(null);
  const [evidenceRows, setEvidenceRows] = useState<EvidenceRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [ruleYamlOpen, setRuleYamlOpen] = useState(false);
  const [closeOpen, setCloseOpen] = useState(false);
  const [assignOpen, setAssignOpen] = useState(false);
  const [caseOpen, setCaseOpen] = useState(false);
  const [closeResolution, setCloseResolution] = useState<AlertResolution>('true_positive');
  const [closeNote, setCloseNote] = useState('');
  const [assignName, setAssignName] = useState('');
  const [caseName, setCaseName] = useState('');

  const load = useCallback(async (showLoader: boolean) => {
    if (showLoader) setLoading(true);
    setError(null);
    try {
      setAlert(await getAlert(alertId));
    } catch (err) {
      setAlert(null);
      setError(loadError(err));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [alertId]);

  const loadEvidence = useCallback(async (current: AlertRecord) => {
    if (!current.evidence_refs.length) {
      setEvidenceRows([]);
      return;
    }
    setEvidenceLoading(true);
    try {
      const ids = current.evidence_refs.slice(0, 8).map((ref) => ref.replace(/^event:/, '').trim()).filter(Boolean);
      const now = new Date();
      const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const rows = await runSearch({
        sql: `event_id IN (${ids.map((id) => `'${id.replace(/'/g, "''")}'`).join(', ')})`,
        time_range: { start: weekAgo.toISOString(), end: now.toISOString() },
        pagination: { page: 1, page_size: 16 },
      });
      setEvidenceRows(rows.rows ?? []);
    } catch {
      setEvidenceRows([]);
    } finally {
      setEvidenceLoading(false);
    }
  }, []);

  useEffect(() => { void load(true); }, [load]);

  useEffect(() => {
    setMessage(null);
    setExplain(null);
    setEvidenceRows([]);
    setRule(null);
    setEvidenceOpen(false);
    setRuleYamlOpen(false);
    setCloseOpen(false);
    setAssignOpen(false);
    setCaseOpen(false);
    setCloseResolution('true_positive');
    setCloseNote('');
    setAssignName('');
    setCaseName('');
  }, [alertId]);

  useEffect(() => {
    if (!alert?.rule_id) return;
    let cancelled = false;
    void getRules().then((rules) => {
      if (!cancelled) setRule(rules.find((item) => item.rule_id === alert.rule_id) ?? null);
    }).catch(() => {
      if (!cancelled) setRule(null);
    });
    return () => { cancelled = true; };
  }, [alert?.rule_id]);

  useEffect(() => {
    if (!alert) return;
    let cancelled = false;
    setExplainLoading(true);
    setExplainError(null);
    void explainAlert(alert.alert_id).then((result) => {
      if (!cancelled) setExplain(result);
    }).catch((err) => {
      if (!cancelled) setExplainError(loadError(err));
    }).finally(() => {
      if (!cancelled) setExplainLoading(false);
    });
    void loadEvidence(alert);
    return () => { cancelled = true; };
  }, [alert, loadEvidence]);

  const evidenceContexts = useMemo(() => evidenceRows.map((row) => extractEventContext(row)), [evidenceRows]);
  const evidenceAggregate = useMemo(() => aggregateEventContexts(evidenceContexts), [evidenceContexts]);
  const evidenceById = useMemo(() => {
    const next = new Map<string, ReturnType<typeof extractEventContext>>();
    evidenceContexts.forEach((item) => { if (item.eventId) next.set(item.eventId, item); });
    return next;
  }, [evidenceContexts]);

  const extra = alert as (AlertRecord & {
    process_name?: string;
    src_ip?: string;
    dst_ip?: string;
    dst_port?: number | string;
  }) | null;
  const hosts = useMemo(() => limitValues(mergeUnique([alert?.agent_meta?.hostname], evidenceAggregate.hosts), 5), [alert?.agent_meta?.hostname, evidenceAggregate.hosts]);
  const users = useMemo(() => limitValues(evidenceAggregate.users, 5), [evidenceAggregate.users]);
  const processes = useMemo(() => limitValues(mergeUnique(evidenceAggregate.processes, [extra?.process_name]), 5), [evidenceAggregate.processes, extra?.process_name]);
  const networks = useMemo(() => limitValues(mergeUnique(evidenceAggregate.networkFlows, [extra ? formatNetworkFlow({ sourceIp: extra.src_ip, destinationIp: extra.dst_ip, destinationHost: undefined, destinationPort: extra.dst_port ? String(extra.dst_port) : undefined }) : undefined]), 5), [evidenceAggregate.networkFlows, extra]);
  const artifacts = useMemo(() => limitValues(mergeUnique(evidenceAggregate.domains, evidenceAggregate.files, evidenceAggregate.registryPaths, evidenceAggregate.services), 6), [evidenceAggregate.domains, evidenceAggregate.files, evidenceAggregate.registryPaths, evidenceAggregate.services]);
  const notes = useMemo(() => limitValues(evidenceAggregate.messages, 4), [evidenceAggregate.messages]);

  if (loading) return <Card><CardContent className="h-[320px] animate-pulse p-6" /></Card>;
  if (error || !alert) return (
    <Card><CardContent className="flex min-h-[320px] flex-col items-center justify-center p-8 text-center">
      <AlertTriangle className="h-8 w-8 text-destructive" />
      <div className="mt-4 font-display text-2xl font-semibold text-foreground">{error ?? 'Alert not found.'}</div>
      <Button type="button" className="mt-6" onClick={onBack ?? (() => navigate('/alerts'))}><ArrowLeft className="h-4 w-4" />Back to alerts</Button>
    </CardContent></Card>
  );

  const title = alert.rule_title || ((rule?.compiled_plan as { title?: string } | undefined)?.title) || `Rule ${alert.rule_id.slice(0, 8)}`;
  const linkedCase = alert.case_id;
  const fpClass = explain ? fpTone(explain.false_positive_likelihood) : '';

  const ack = async () => { setMessage('Acknowledging alert...'); try { setAlert(await acknowledgeAlert(alert.alert_id, actor)); setMessage('Alert acknowledged.'); } catch (err) { setMessage(loadError(err)); } };
  const markFp = async () => { setMessage('Marking false positive...'); try { setAlert(await falsePositiveAlert(alert.alert_id, actor)); setMessage('Alert marked as false positive.'); } catch (err) { setMessage(loadError(err)); } };
  const saveClose = async () => { setMessage('Closing alert...'); try { setAlert(await closeAlert(alert.alert_id, closeResolution, actor, closeNote.trim() || undefined)); setCloseOpen(false); setCloseNote(''); setMessage(`Alert closed as ${resolutionLabel(closeResolution).toLowerCase()}.`); } catch (err) { setMessage(loadError(err)); } };
  const saveAssign = async () => { setMessage('Saving assignment...'); try { const next = assignName.trim(); setAlert(await assignAlert(alert.alert_id, next || null, actor)); setAssignOpen(false); setAssignName(''); setMessage(next ? `Assigned to ${next}.` : 'Assignment cleared.'); } catch (err) { setMessage(loadError(err)); } };
  const saveCase = async () => { setMessage('Creating case...'); try { const created = await createCase({ title: caseName.trim() || title, severity: alert.severity, alert_ids: [alert.alert_id] }); navigate(`/cases/${created.case_id}`); } catch (err) { setMessage(loadError(err)); } };

  return (
    <div className="space-y-6">
      <section className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <Button type="button" variant="ghost" className="mb-4 rounded-full px-0 hover:bg-transparent" onClick={onBack ?? (() => navigate('/alerts'))}><ArrowLeft className="h-4 w-4" />Back to alert queue</Button>
          <div className="flex flex-wrap gap-2">
            <Badge variant={severityVariant(alert.severity)}>{alert.severity}</Badge>
            <Badge variant={statusVariant(alert.status)}>{alert.status.replace(/_/g, ' ')}</Badge>
            {alert.assignee && <Badge variant="secondary">Owner {alert.assignee}</Badge>}
            {linkedCase && <Badge variant="outline">Case {linkedCase.slice(0, 8)}</Badge>}
          </div>
          <h1 className="mt-4 max-w-4xl font-display text-4xl font-semibold tracking-[-0.05em] text-foreground">{title}</h1>
          <p className="mt-3 max-w-3xl text-base leading-7 text-muted-foreground">
            Alert {alert.alert_id.slice(0, 8)} has fired {alert.hit_count} time{alert.hit_count === 1 ? '' : 's'} over a {span(alert).toLowerCase()} window. This view pulls the evidence, AI summary, routing, and case linkage into one console.
          </p>
        </div>
        <div className="flex flex-wrap gap-3 lg:max-w-md lg:justify-end">
          <Button type="button" variant="outline" onClick={() => { setRefreshing(true); void load(false); }} disabled={refreshing}><RefreshCcw className={cn('h-4 w-4', refreshing && 'animate-spin')} />Refresh</Button>
          {alert.status === 'open' && <Button type="button" variant="outline" onClick={() => void ack()}><CheckCircle2 className="h-4 w-4" />Acknowledge</Button>}
          {alert.status !== 'closed' && <Button type="button" variant="outline" onClick={() => { setAssignName(alert.assignee ?? ''); setAssignOpen(true); }}><User className="h-4 w-4" />Assign</Button>}
          {alert.status !== 'closed' && <Button type="button" variant="outline" onClick={() => setCloseOpen(true)}><CheckCircle2 className="h-4 w-4" />Close</Button>}
          {alert.status !== 'closed' && <Button type="button" variant="destructive" onClick={() => void markFp()}><XCircle className="h-4 w-4" />False positive</Button>}
          {linkedCase ? <Button asChild><Link to={`/cases/${linkedCase}`}>View case<ExternalLink className="h-4 w-4" /></Link></Button> : <Button type="button" onClick={() => setCaseOpen(true)}><Shield className="h-4 w-4" />Create case</Button>}
        </div>
      </section>

      {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="First Seen" value={rel(alert.first_seen)} hint={abs(alert.first_seen)} icon={Clock3} />
        <WorkspaceMetricCard label="Last Seen" value={rel(alert.last_seen)} hint={abs(alert.last_seen)} icon={Activity} />
        <WorkspaceMetricCard label="Hits" value={String(alert.hit_count)} hint={`${alert.evidence_refs.length} evidence reference${alert.evidence_refs.length === 1 ? '' : 's'}`} icon={Fingerprint} />
        <WorkspaceMetricCard label="Resolution" value={resolutionLabel(alert.resolution)} hint={alert.close_note || (linkedCase ? `Escalated into case ${linkedCase.slice(0, 8)}` : 'Awaiting analyst decision')} icon={Shield} />
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_380px]">
        <div className="space-y-6">
          <Card>
            <CardHeader className="pb-4"><CardTitle>Investigation snapshot</CardTitle><CardDescription>High-signal entities and artifacts pulled from the alert record and matching evidence rows.</CardDescription></CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              {hosts.length || users.length || processes.length || networks.length || artifacts.length || notes.length ? (
                <>
                  <ChipGroup label="Observed hosts" values={hosts} icon={Monitor} />
                  <ChipGroup label="Observed users" values={users} icon={User} />
                  <ChipGroup label="Processes" values={processes} icon={FileText} />
                  <ChipGroup label="Network paths" values={networks} icon={Network} />
                  <ChipGroup label="Artifacts" values={artifacts} icon={Fingerprint} />
                  <ChipGroup label="Message highlights" values={notes} icon={Sparkles} />
                </>
              ) : <WorkspaceEmptyState title="Evidence context is still light" body="As matching event rows become available, the host, process, and network snapshot will fill in here." className="min-h-[220px]" />}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-4"><CardTitle>Evidence</CardTitle><CardDescription>Referenced events with quick pivots into the search workspace.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              {!alert.evidence_refs.length ? <WorkspaceEmptyState title="No evidence attached" body="This alert has not been linked to event references yet." className="min-h-[220px]" /> : (
                <>
                  {alert.evidence_refs.slice(0, 8).map((ref) => {
                    const eventId = ref.replace(/^event:/, '');
                    const ctx = evidenceById.get(eventId);
                    const params = new URLSearchParams({ q: `event_id = '${eventId.replace(/'/g, "''")}'`, from: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), to: new Date().toISOString() });
                    return (
                      <div key={ref} className="flex flex-col gap-4 rounded-lg border border-border/70 bg-background/35 p-4 lg:flex-row lg:items-start lg:justify-between">
                        <div className="min-w-0">
                          <div className="text-xs uppercase tracking-[0.22em] text-muted-foreground">{ref}</div>
                          <div className="mt-2 font-medium text-foreground">{ctx?.summary ?? 'Reference captured, matching event row not loaded yet.'}</div>
                          <div className="mt-2 flex flex-wrap gap-3 text-sm text-muted-foreground">
                            {ctx?.host && <span>{ctx.host}</span>}
                            {ctx?.user && <span>{ctx.user}</span>}
                            {ctx?.time && <span>{abs(ctx.time)}</span>}
                          </div>
                        </div>
                        <Button asChild size="sm" variant="outline"><a href={`/search?${params.toString()}`} target="_blank" rel="noopener noreferrer">Pivot in search<Search className="h-4 w-4" /></a></Button>
                      </div>
                    );
                  })}
                  <div className="flex flex-wrap gap-3">
                    <Button type="button" variant="outline" onClick={() => setEvidenceOpen((value) => !value)} disabled={evidenceLoading}>{evidenceLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}{evidenceOpen ? 'Hide parsed events' : 'Show parsed events'}</Button>
                    <Button type="button" variant="ghost" onClick={() => void loadEvidence(alert)} disabled={evidenceLoading}><RefreshCcw className={cn('h-4 w-4', evidenceLoading && 'animate-spin')} />Reload evidence</Button>
                  </div>
                  {evidenceOpen && (
                    <div className="space-y-4">
                      {!evidenceContexts.length && !evidenceLoading && <WorkspaceEmptyState title="No matching events found" body="The references exist, but no matching event rows were found in the last seven days." className="min-h-[220px]" />}
                      {evidenceContexts.map((ctx, index) => (
                        <div key={ctx.eventId ?? `${ctx.summary}-${index}`} className="rounded-lg border border-border/70 bg-background/35 p-4">
                          <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                            <div>
                              <div className="font-medium text-foreground">{ctx.summary}</div>
                              <div className="mt-2 flex flex-wrap gap-2">{ctx.eventName && <Badge variant="outline">{ctx.eventName}</Badge>}{ctx.source && <Badge variant="secondary">{ctx.source}</Badge>}{ctx.host && <Badge variant="secondary">{ctx.host}</Badge>}</div>
                            </div>
                            {ctx.time && <div className="text-sm text-muted-foreground">{abs(ctx.time)}</div>}
                          </div>
                          {ctx.message && <p className="mt-4 text-sm leading-6 text-muted-foreground">{ctx.message}</p>}
                          <div className="mt-4 grid gap-3 sm:grid-cols-2">
                            {ctx.user && <ChipGroup label="User" values={[ctx.user]} icon={User} />}
                            {ctx.process && <ChipGroup label="Process" values={[ctx.process]} icon={FileText} />}
                            {formatNetworkFlow(ctx) && <ChipGroup label="Network" values={[formatNetworkFlow(ctx)!]} icon={Network} />}
                            {ctx.filePath && <ChipGroup label="File" values={[ctx.filePath]} icon={FileText} />}
                          </div>
                          <details className="mt-4 rounded-lg border border-border/70 bg-card/65 px-4 py-3"><summary className="cursor-pointer text-sm font-medium text-foreground">Raw JSON</summary><pre className="mt-3 overflow-auto rounded-lg bg-slate-950/70 p-4 text-xs text-slate-100">{JSON.stringify(evidenceRows[index], null, 2)}</pre></details>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-4"><CardTitle>Detection rule</CardTitle><CardDescription>Mode, compiled metadata, and the Sigma source that produced this alert.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              {rule ? (
                <>
                  <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Mode</div><div className="mt-2 text-sm text-foreground">{rule.schedule_or_stream}</div></div>
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Enabled</div><div className="mt-2 text-sm text-foreground">{rule.enabled ? 'Yes' : 'No'}</div></div>
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Rule severity</div><div className="mt-2"><Badge variant={severityVariant(rule.severity)}>{rule.severity}</Badge></div></div>
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Schedule</div><div className="mt-2 text-sm text-foreground">{rule.schedule ? `${rule.schedule.interval_seconds}s every run` : 'Stream rule'}</div></div>
                  </div>
                  <Button type="button" variant="outline" onClick={() => setRuleYamlOpen((value) => !value)}><Workflow className="h-4 w-4" />{ruleYamlOpen ? 'Hide Sigma source' : 'Show Sigma source'}</Button>
                  {ruleYamlOpen && <pre className="overflow-auto rounded-lg border border-border/70 bg-slate-950/70 p-5 text-xs text-slate-100">{rule.sigma_source}</pre>}
                </>
              ) : <WorkspaceEmptyState title="Rule metadata unavailable" body="The alert loaded, but the backing rule could not be resolved from the current rule set." className="min-h-[220px]" />}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader className="pb-4"><CardTitle>AI analysis</CardTitle><CardDescription>Machine-generated context to accelerate triage.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              {explainLoading && <div className="flex min-h-[220px] items-center justify-center rounded-lg border border-border/70 bg-background/35 text-sm text-muted-foreground"><Loader2 className="mr-3 h-4 w-4 animate-spin" />Building analyst summary</div>}
              {!explainLoading && explainError && <WorkspaceStatusBanner tone="warning">{explainError}</WorkspaceStatusBanner>}
              {!explainLoading && explain && (
                <>
                  <div className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground"><Bot className="h-4 w-4 text-primary" /><span>Summary</span></div><p className="mt-3 text-sm leading-6 text-foreground">{explain.summary}</p></div>
                  <div className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Why suspicious</div><p className="mt-3 text-sm leading-6 text-muted-foreground">{explain.why_suspicious}</p></div>
                  <div className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Likely cause</div><p className="mt-3 text-sm leading-6 text-muted-foreground">{explain.likely_cause}</p></div>
                  <div className={cn('inline-flex rounded-full border px-3 py-1.5 text-sm font-medium', fpClass)}>{explain.false_positive_likelihood} false-positive likelihood</div>
                  <div className="space-y-2">{explain.recommended_actions.map((item) => <div key={item} className="flex gap-3 rounded-lg border border-border/60 bg-card/65 px-3 py-3 text-sm text-foreground"><Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-primary" /><span>{item}</span></div>)}</div>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-4"><CardTitle>Context</CardTitle><CardDescription>Agent, routing, ATT&CK mapping, and record metadata.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3 text-sm text-foreground"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Alert ID</div><div className="mt-2 break-all">{alert.alert_id}</div></div>
              {alert.agent_meta && <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Agent</div><div className="mt-2 text-sm text-foreground">{alert.agent_meta.hostname}</div><div className="mt-1 text-sm text-muted-foreground">{alert.agent_meta.os} · {alert.agent_meta.group}</div><div className="mt-3 flex flex-wrap gap-2">{alert.agent_meta.tags.map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>)}</div></div>}
              <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Routing</div><div className="mt-2 space-y-1 text-sm text-muted-foreground"><div>Dedupe: {alert.routing_state?.dedupe_key || 'Not set'}</div><div>Destinations: {alert.routing_state?.destinations?.length ? alert.routing_state.destinations.join(', ') : 'None'}</div><div>Suppression: {alert.routing_state?.suppression_until ? abs(alert.routing_state.suppression_until) : 'Not suppressed'}</div></div></div>
              {!!alert.mitre_attack.length && <div className="space-y-2">{alert.mitre_attack.map((item) => <div key={item.technique_id} className="rounded-lg border border-border/70 bg-background/35 px-4 py-3"><div className="font-medium text-foreground">{item.technique_id}</div><div className="mt-1 text-sm text-muted-foreground">{item.technique_name}</div><div className="mt-1 text-xs uppercase tracking-[0.2em] text-muted-foreground">{(item.tactic ?? '').replace(/-/g, ' ')}</div></div>)}</div>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-4"><CardTitle>Timeline</CardTitle><CardDescription>The key points in the life of this alert.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-4"><div className="mt-1 flex h-9 w-9 items-center justify-center rounded-2xl border border-primary/20 bg-primary/10 text-primary"><Clock3 className="h-4 w-4" /></div><div><div className="font-medium text-foreground">First detection</div><div className="mt-1 text-sm text-muted-foreground">{abs(alert.first_seen)}</div></div></div>
              {alert.hit_count > 1 && <div className="flex gap-4"><div className="mt-1 flex h-9 w-9 items-center justify-center rounded-2xl border border-amber-500/20 bg-amber-500/10 text-amber-100"><Workflow className="h-4 w-4" /></div><div><div className="font-medium text-foreground">{alert.hit_count - 1} additional hit(s)</div><div className="mt-1 text-sm text-muted-foreground">Pattern remained active for {span(alert).toLowerCase()}.</div></div></div>}
              <div className="flex gap-4"><div className="mt-1 flex h-9 w-9 items-center justify-center rounded-2xl border border-border/70 bg-background/45 text-foreground"><AlertTriangle className="h-4 w-4" /></div><div><div className="font-medium text-foreground">Last observation</div><div className="mt-1 text-sm text-muted-foreground">{abs(alert.last_seen)} ({rel(alert.last_seen)})</div></div></div>
              {alert.status === 'closed' && <div className="flex gap-4"><div className="mt-1 flex h-9 w-9 items-center justify-center rounded-2xl border border-border/70 bg-background/45 text-muted-foreground"><CheckCircle2 className="h-4 w-4" /></div><div><div className="font-medium text-foreground">Closed</div><div className="mt-1 text-sm text-muted-foreground">{resolutionLabel(alert.resolution)}</div></div></div>}
            </CardContent>
          </Card>
        </div>
      </section>

      <WorkspaceModal open={closeOpen} title="Close alert" description="Pick a resolution and capture the final analyst note." onClose={() => setCloseOpen(false)} panelClassName="max-w-lg">
        <div className="grid gap-3 sm:grid-cols-3">{(['true_positive', 'false_positive', 'informational'] as AlertResolution[]).map((item) => <button key={item} type="button" className={cn('rounded-lg border px-4 py-4 text-left transition-colors', closeResolution === item ? 'border-primary/40 bg-primary/10 text-foreground' : 'border-border/70 bg-background/35 text-muted-foreground hover:bg-muted/40')} onClick={() => setCloseResolution(item)}><div className="font-medium text-foreground">{resolutionLabel(item)}</div></button>)}</div>
        <div><div className="mb-2 text-sm font-medium text-foreground">Close note</div><Textarea value={closeNote} onChange={(event) => setCloseNote(event.target.value)} rows={4} placeholder="Add findings, remediation, or supporting context." /></div>
        <div className="flex flex-wrap justify-end gap-3"><Button type="button" variant="outline" onClick={() => setCloseOpen(false)}>Cancel</Button><Button type="button" onClick={() => void saveClose()}>Close alert</Button></div>
      </WorkspaceModal>

      <WorkspaceModal open={assignOpen} title="Assign alert" description="Hand this alert to an owner or clear the assignment." onClose={() => setAssignOpen(false)} panelClassName="max-w-lg">
        <div><div className="mb-2 text-sm font-medium text-foreground">Assignee</div><Input value={assignName} onChange={(event) => setAssignName(event.target.value)} placeholder="analyst-1" autoFocus /></div>
        <div className="flex flex-wrap justify-end gap-3"><Button type="button" variant="outline" onClick={() => setAssignOpen(false)}>Cancel</Button><Button type="button" onClick={() => void saveAssign()} disabled={!assignName.trim() && !alert.assignee}>{assignName.trim() ? 'Save assignment' : 'Clear assignment'}</Button></div>
      </WorkspaceModal>

      <WorkspaceModal open={caseOpen} title="Create case" description="Create a case from this alert and carry the severity forward." onClose={() => setCaseOpen(false)} panelClassName="max-w-lg">
        <div><div className="mb-2 text-sm font-medium text-foreground">Case title</div><Input value={caseName} onChange={(event) => setCaseName(event.target.value)} placeholder={title} autoFocus /></div>
        <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3 text-sm text-muted-foreground">The new case will attach alert {alert.alert_id.slice(0, 8)} as its first linked alert.</div>
        <div className="flex flex-wrap justify-end gap-3"><Button type="button" variant="outline" onClick={() => setCaseOpen(false)}>Cancel</Button><Button type="button" onClick={() => void saveCase()}>Create case</Button></div>
      </WorkspaceModal>
    </div>
  );
}
