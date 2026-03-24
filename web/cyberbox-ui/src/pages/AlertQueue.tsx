import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  RefreshCcw,
  Server,
  Sparkles,
  UserRound,
  XCircle,
} from 'lucide-react';

import { explainAlert, falsePositiveAlert, getRules, type AlertRecord, type ExplainAlertResult } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';
import { useAlertStream } from '@/hooks/useAlertStream';

type StatusFilter = 'open' | 'acknowledged' | 'in_progress' | 'all';
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

const STATUS_KEYS: StatusFilter[] = ['open', 'acknowledged', 'in_progress', 'all'];
const SEVERITY_KEYS: SeverityFilter[] = ['all', 'critical', 'high', 'medium', 'low'];

function rel(ts: string) {
  const mins = Math.round((Date.now() - new Date(ts).getTime()) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / 1440)}d ago`;
}

function sevVariant(sev: string): 'destructive' | 'warning' | 'info' | 'secondary' {
  if (sev === 'critical') return 'destructive';
  if (sev === 'high') return 'warning';
  if (sev === 'medium') return 'info';
  return 'secondary';
}

function statusVariant(status: string): 'destructive' | 'warning' | 'info' | 'success' {
  if (status === 'open') return 'destructive';
  if (status === 'in_progress') return 'warning';
  if (status === 'acknowledged') return 'info';
  return 'success';
}

function titleFor(alert: AlertRecord, titles: Record<string, string>) {
  if (alert.rule_title) return alert.rule_title;
  const plan = (alert as unknown as Record<string, unknown>).compiled_plan;
  if (plan && typeof plan === 'object') {
    const title = (plan as Record<string, unknown>).title;
    if (typeof title === 'string' && title) return title;
  }
  return titles[alert.rule_id] ?? `Rule ${alert.rule_id.slice(0, 8)}`;
}

function field(alert: AlertRecord, key: string) {
  const value = (alert as unknown as Record<string, unknown>)[key];
  return typeof value === 'string' && value ? value : null;
}

export function AlertQueue() {
  const { alerts, connected, error, refresh } = useAlertStream();
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('open');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<string | null>(null);
  const [titles, setTitles] = useState<Record<string, string>>({});
  const [statusText, setStatusText] = useState('');
  const [explainId, setExplainId] = useState<string | null>(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [explainResult, setExplainResult] = useState<ExplainAlertResult | null>(null);

  useEffect(() => {
    void getRules().then((rules) => {
      const next: Record<string, string> = {};
      for (const rule of rules) {
        const title = (rule.compiled_plan as Record<string, unknown>)?.title;
        if (typeof title === 'string' && title) next[rule.rule_id] = title;
      }
      setTitles(next);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!statusText) return;
    const id = window.setTimeout(() => setStatusText(''), 4000);
    return () => window.clearTimeout(id);
  }, [statusText]);

  const stats = useMemo(() => ({
    open: alerts.filter((a) => a.status === 'open').length,
    acknowledged: alerts.filter((a) => a.status === 'acknowledged').length,
    in_progress: alerts.filter((a) => a.status === 'in_progress').length,
    critical: alerts.filter((a) => a.severity === 'critical' && a.status !== 'closed').length,
    high: alerts.filter((a) => a.severity === 'high' && a.status !== 'closed').length,
    medium: alerts.filter((a) => a.severity === 'medium' && a.status !== 'closed').length,
    low: alerts.filter((a) => a.severity === 'low' && a.status !== 'closed').length,
    unassigned: alerts.filter((a) => !a.assignee && a.status !== 'closed').length,
  }), [alerts]);

  const filtered = useMemo(() => alerts.filter((alert) => {
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false;
    if (severityFilter !== 'all' && alert.severity !== severityFilter) return false;
    return true;
  }), [alerts, severityFilter, statusFilter]);

  const allSelected = filtered.length > 0 && filtered.every((a) => selected.has(a.alert_id));
  const activeExplainAlert = filtered.find((a) => a.alert_id === explainId) ?? alerts.find((a) => a.alert_id === explainId) ?? null;

  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(filtered.map((a) => a.alert_id)));
  const toggleOne = (id: string) => setSelected((curr) => {
    const next = new Set(curr);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  const markFalsePositive = useCallback(async (ids: string[]) => {
    if (ids.length === 0) return;
    setStatusText(ids.length === 1 ? 'Marking alert as false positive...' : `Marking ${ids.length} alerts as false positive...`);
    try {
      await Promise.all(ids.map((id) => falsePositiveAlert(id, 'soc-admin')));
      setSelected(new Set());
      await refresh();
      setStatusText(ids.length === 1 ? 'Alert marked as false positive.' : `Marked ${ids.length} alerts as false positive.`);
    } catch (cause) {
      setStatusText(`False positive failed: ${String(cause)}`);
    }
  }, [refresh]);

  const openExplain = useCallback(async (id: string) => {
    setExplainId(id);
    setExplainLoading(true);
    setExplainError(null);
    setExplainResult(null);
    try {
      setExplainResult(await explainAlert(id));
    } catch (cause) {
      setExplainError(String(cause));
    } finally {
      setExplainLoading(false);
    }
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(320px,0.9fr)]">
        <Card className="overflow-hidden border-primary/15 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.16),transparent_40%),linear-gradient(145deg,hsl(var(--card)),hsl(var(--card)/0.82))]">
          <CardContent className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.2fr)_minmax(220px,0.8fr)]">
            <div>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant={connected ? 'success' : 'outline'}>{connected ? 'Live queue' : 'Offline queue'}</Badge>
                <Badge variant="secondary">{filtered.length} visible alerts</Badge>
              </div>
              <div className="font-display text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-foreground sm:text-[3rem]">Triage with less friction.</div>
              <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">The queue now centers on expandable analyst cards, fast status filters, and inline AI context so we can move detections without bouncing around the app.</p>
            <div className="mt-6 flex flex-wrap gap-3">
              <Button type="button" onClick={() => void refresh()}><RefreshCcw className="h-4 w-4" />Refresh queue</Button>
              <Button asChild variant="outline"><Link to="/cases">Open cases<ExternalLink className="h-4 w-4" /></Link></Button>
            </div>
          </div>
          <div className="grid gap-3 rounded-lg border border-border/70 bg-background/35 p-4">
            <WorkspaceStatusBanner tone={connected ? 'success' : 'warning'} className="rounded-lg">
              {connected ? 'Real-time alert stream connected.' : 'Realtime stream unavailable right now.'}
            </WorkspaceStatusBanner>
            {error && <WorkspaceStatusBanner tone="warning" className="rounded-lg">{error}</WorkspaceStatusBanner>}
            {statusText && <WorkspaceStatusBanner className="rounded-lg">{statusText}</WorkspaceStatusBanner>}
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border border-border/70 bg-card/75 p-4"><div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Open</div><div className="mt-2 font-display text-3xl font-semibold text-foreground">{stats.open}</div></div>
              <div className="rounded-lg border border-border/70 bg-card/75 p-4"><div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Unassigned</div><div className="mt-2 font-display text-3xl font-semibold text-foreground">{stats.unassigned}</div></div>
            </div>
          </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Filter focus</CardTitle><CardDescription>Slice the queue by workflow stage or severity.</CardDescription></CardHeader>
          <CardContent className="space-y-5">
            <div><div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Status</div><div className="flex flex-wrap gap-2">{STATUS_KEYS.map((key) => <Button key={key} type="button" variant={statusFilter === key ? 'default' : 'outline'} size="sm" className="rounded-full" onClick={() => setStatusFilter(key)}>{key.replace('_', ' ')}<span className="rounded-full bg-background/25 px-2 py-0.5 text-[10px]">{key === 'all' ? alerts.length : stats[key]}</span></Button>)}</div></div>
            <div><div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Severity</div><div className="flex flex-wrap gap-2">{SEVERITY_KEYS.map((key) => <Button key={key} type="button" variant={severityFilter === key ? 'default' : 'outline'} size="sm" className="rounded-full" onClick={() => setSeverityFilter(key)}>{key === 'all' ? 'all severities' : key}{key !== 'all' && <span className="rounded-full bg-background/25 px-2 py-0.5 text-[10px]">{stats[key]}</span>}</Button>)}</div></div>
            <div className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Selection</div><div className="flex items-center justify-between gap-3 text-sm"><span className="text-muted-foreground">{selected.size} selected</span><Button type="button" variant="outline" size="sm" onClick={toggleAll}>{allSelected ? 'Clear all' : 'Select visible'}</Button></div></div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <WorkspaceMetricCard label="Critical" value={String(stats.critical)} hint="Highest-severity detections still in the queue." icon={AlertTriangle} iconClassName="text-destructive" />
        <WorkspaceMetricCard label="High" value={String(stats.high)} hint="Priority detections that still need analyst action." icon={AlertTriangle} iconClassName="text-amber-300" />
        <WorkspaceMetricCard label="Medium" value={String(stats.medium)} hint="Detections that may need validation or enrichment." icon={Sparkles} iconClassName="text-sky-300" />
        <WorkspaceMetricCard label="Low" value={String(stats.low)} hint="Lower-risk alerts waiting for a decision." icon={CheckCircle2} iconClassName="text-muted-foreground" />
        <WorkspaceMetricCard label="Unassigned" value={String(stats.unassigned)} hint="Alerts that do not have an analyst owner yet." icon={UserRound} />
      </section>

      {selected.size > 0 && <Card className="border-primary/20 bg-primary/10"><CardContent className="flex flex-col gap-3 p-5 sm:flex-row sm:items-center sm:justify-between"><div><div className="font-medium text-foreground">{selected.size} alerts selected</div><div className="text-sm text-muted-foreground">Bulk false-positive action is ready.</div></div><div className="flex gap-2"><Button type="button" variant="outline" onClick={() => setSelected(new Set())}>Clear</Button><Button type="button" variant="destructive" onClick={() => void markFalsePositive(Array.from(selected))}>Mark false positive</Button></div></CardContent></Card>}

      <section className={cn('grid gap-4', explainId ? 'xl:grid-cols-[minmax(0,1fr)_360px]' : '')}>
        <div className="space-y-4">
          {filtered.length === 0 ? (
            <WorkspaceEmptyState title="No alerts match this slice" body="Try a broader filter or wait for new detections to arrive." className="min-h-[260px]" />
          ) : filtered.map((alert) => {
            const open = expanded === alert.alert_id;
            const src = field(alert, 'src_ip') ?? alert.agent_meta?.hostname ?? 'Unavailable';
            const dst = field(alert, 'dst_ip');
            const proc = field(alert, 'process_name');
            return (
              <Card key={alert.alert_id} className="overflow-hidden">
                <CardContent className="p-0">
                  <div className={cn('h-1 bg-gradient-to-r', alert.severity === 'critical' ? 'from-red-500 via-orange-400 to-amber-300' : alert.severity === 'high' ? 'from-orange-500 via-amber-400 to-yellow-300' : alert.severity === 'medium' ? 'from-emerald-400 via-teal-400 to-cyan-300' : 'from-slate-400 via-slate-300 to-slate-200')} />
                  <div className="p-5">
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="flex min-w-0 items-start gap-4">
                        <input type="checkbox" className="mt-1 h-4 w-4 rounded border-border bg-background" checked={selected.has(alert.alert_id)} onChange={() => toggleOne(alert.alert_id)} />
                        <div className="min-w-0">
                          <div className="flex flex-wrap gap-2"><Badge variant={sevVariant(alert.severity)}>{alert.severity}</Badge><Badge variant={statusVariant(alert.status)}>{alert.status.replace('_', ' ')}</Badge>{alert.hit_count > 1 && <Badge variant="secondary">{alert.hit_count} hits</Badge>}</div>
                          <div className="mt-3 font-display text-2xl font-semibold tracking-[-0.03em] text-foreground">{titleFor(alert, titles)}</div>
                          <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground"><span className="inline-flex items-center gap-2"><Server className="h-4 w-4" />{alert.agent_meta?.hostname ?? 'Unknown host'}</span><span>{alert.assignee ?? 'Unassigned'}</span><span>{rel(alert.last_seen)}</span></div>
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Button type="button" variant="outline" size="sm" onClick={() => void openExplain(alert.alert_id)}><Bot className="h-4 w-4" />AI explain</Button>
                        {alert.status !== 'closed' && <Button type="button" variant="outline" size="sm" onClick={() => void markFalsePositive([alert.alert_id])}><XCircle className="h-4 w-4" />False positive</Button>}
                        <Button asChild variant="ghost" size="sm"><Link to={`/alerts/${alert.alert_id}`}>Full detail<ExternalLink className="h-4 w-4" /></Link></Button>
                        <Button type="button" variant="ghost" size="sm" onClick={() => setExpanded(open ? null : alert.alert_id)}>{open ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}{open ? 'Collapse' : 'Expand'}</Button>
                      </div>
                    </div>
                    <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-lg border border-border/70 bg-background/35 p-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Source</div><div className="mt-2 text-sm text-foreground">{src}</div></div>
                      <div className="rounded-lg border border-border/70 bg-background/35 p-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Destination</div><div className="mt-2 text-sm text-foreground">{dst ?? 'Unavailable'}</div></div>
                      <div className="rounded-lg border border-border/70 bg-background/35 p-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Process</div><div className="mt-2 truncate text-sm text-foreground">{proc ?? 'Not provided'}</div></div>
                      <div className="rounded-lg border border-border/70 bg-background/35 p-3"><div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">MITRE</div><div className="mt-2 flex flex-wrap gap-2">{alert.mitre_attack.length ? alert.mitre_attack.slice(0, 2).map((m) => <Badge key={m.technique_id} variant="outline">{m.technique_id}</Badge>) : <span className="text-sm text-muted-foreground">No mapping</span>}</div></div>
                    </div>
                    {open && <div className="mt-4 grid gap-4 rounded-lg border border-border/70 bg-background/30 p-4 xl:grid-cols-3"><div className="space-y-3 text-sm"><div><div className="text-muted-foreground">Alert ID</div><div className="break-all font-mono text-xs text-foreground">{alert.alert_id}</div></div><div><div className="text-muted-foreground">Rule ID</div><div className="break-all font-mono text-xs text-foreground">{alert.rule_id}</div></div><div><div className="text-muted-foreground">First seen</div><div className="text-foreground">{new Date(alert.first_seen).toLocaleString()}</div></div></div><div className="space-y-3 text-sm"><div><div className="text-muted-foreground">OS</div><div className="text-foreground">{alert.agent_meta?.os ?? 'Unavailable'}</div></div><div><div className="text-muted-foreground">Group</div><div className="text-foreground">{alert.agent_meta?.group ?? 'Unavailable'}</div></div><div><div className="text-muted-foreground">Assignee</div><div className="inline-flex items-center gap-2 text-foreground"><UserRound className="h-4 w-4 text-muted-foreground" />{alert.assignee ?? 'Unassigned'}</div></div></div><div className="space-y-3">{alert.case_id ? <Button asChild variant="outline" className="w-full justify-between rounded-lg"><Link to={`/cases/${alert.case_id}`}>Open linked case<ExternalLink className="h-4 w-4" /></Link></Button> : <div className="rounded-lg border border-dashed border-border/80 px-4 py-3 text-sm text-muted-foreground">No case linked yet.</div>}{alert.mitre_attack.map((m) => <div key={`${m.technique_id}-${m.tactic}`} className="rounded-lg border border-border/70 bg-card/70 p-3 text-sm"><div className="font-medium text-foreground">{m.technique_id}</div><div className="text-muted-foreground">{m.tactic} · {m.technique_name}</div></div>)}</div></div>}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {explainId && <Card className="h-fit xl:sticky xl:top-28"><CardHeader><div className="flex items-start justify-between gap-3"><div><CardTitle>AI explanation</CardTitle><CardDescription>{activeExplainAlert ? titleFor(activeExplainAlert, titles) : 'Alert context'}</CardDescription></div><Button type="button" variant="ghost" size="icon" onClick={() => setExplainId(null)}><XCircle className="h-4 w-4" /></Button></div></CardHeader><CardContent className="space-y-4">{explainLoading && <div className="rounded-lg border border-border/70 bg-background/35 p-4 text-sm text-muted-foreground">Generating analyst summary...</div>}{explainError && <WorkspaceStatusBanner tone="danger" className="rounded-lg">{explainError}</WorkspaceStatusBanner>}{!explainLoading && !explainError && explainResult && <><div className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-primary"><Sparkles className="h-4 w-4" />Summary</div><p className="text-sm leading-6 text-foreground">{explainResult.summary}</p></div><div className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Why suspicious</div><p className="text-sm leading-6 text-foreground">{explainResult.why_suspicious}</p></div><div className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Likely cause</div><p className="text-sm leading-6 text-foreground">{explainResult.likely_cause}</p></div><div className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">False positive likelihood</div><Badge variant="outline">{explainResult.false_positive_likelihood}</Badge></div><div className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Recommended actions</div><div className="space-y-3">{explainResult.recommended_actions.map((action) => <div key={action} className="flex items-start gap-3 text-sm text-foreground"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-primary" /><span>{action}</span></div>)}</div></div></>}{!explainLoading && !explainError && !explainResult && <WorkspaceEmptyState title="No explanation ready" body="Choose an alert and run AI Explain to open an analyst summary here." className="min-h-[180px]" />}</CardContent></Card>}
      </section>
    </div>
  );
}
