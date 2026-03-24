import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Bot,
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
    <div className="flex flex-col gap-3">
      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}
        {statusText && <WorkspaceStatusBanner>{statusText}</WorkspaceStatusBanner>}

        <Badge variant={connected ? 'success' : 'outline'} className="mr-1">{connected ? 'Live' : 'Offline'}</Badge>
        <span className="text-xs text-muted-foreground">{filtered.length} alerts</span>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          {/* Status filter */}
          <div className="flex items-center gap-1 rounded-lg border border-border/70 bg-card/60 p-0.5">
            {STATUS_KEYS.map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => setStatusFilter(key)}
                className={cn(
                  'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                  statusFilter === key
                    ? 'bg-primary text-primary-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {key === 'in_progress' ? 'wip' : key}
                <span className="ml-1 text-[10px] opacity-70">{key === 'all' ? alerts.length : stats[key]}</span>
              </button>
            ))}
          </div>

          {/* Severity filter */}
          <div className="flex items-center gap-1 rounded-lg border border-border/70 bg-card/60 p-0.5">
            {SEVERITY_KEYS.map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => setSeverityFilter(key)}
                className={cn(
                  'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                  severityFilter === key
                    ? 'bg-primary text-primary-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {key === 'all' ? 'all' : key}
                {key !== 'all' && <span className="ml-1 text-[10px] opacity-70">{stats[key]}</span>}
              </button>
            ))}
          </div>

          <Button type="button" size="sm" variant="outline" onClick={() => void refresh()}>
            <RefreshCcw className="h-3.5 w-3.5" /> Refresh
          </Button>
        </div>
      </div>

      {/* ── KPI row ──────────────────────────────────────────────────── */}
      <section className="grid gap-3 sm:grid-cols-3 xl:grid-cols-5">
        <WorkspaceMetricCard label="Critical" value={String(stats.critical)} hint="Highest severity in queue" />
        <WorkspaceMetricCard label="High" value={String(stats.high)} hint="Needs analyst action" />
        <WorkspaceMetricCard label="Medium" value={String(stats.medium)} hint="May need validation" />
        <WorkspaceMetricCard label="Low" value={String(stats.low)} hint="Waiting for decision" />
        <WorkspaceMetricCard label="Unassigned" value={String(stats.unassigned)} hint="No analyst owner" />
      </section>

      {/* ── Bulk action bar ──────────────────────────────────────────── */}
      {selected.size > 0 && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-primary/20 bg-primary/8 px-3 py-2">
          <span className="text-sm text-foreground">{selected.size} selected</span>
          <div className="flex gap-2">
            <Button type="button" variant="outline" size="sm" onClick={() => setSelected(new Set())}>Clear</Button>
            <Button type="button" variant="destructive" size="sm" onClick={() => void markFalsePositive(Array.from(selected))}>False positive</Button>
          </div>
        </div>
      )}

      {/* ── Select all row ───────────────────────────────────────────── */}
      {filtered.length > 0 && !selected.size && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <button type="button" className="hover:text-foreground transition-colors" onClick={toggleAll}>Select all {filtered.length}</button>
        </div>
      )}

      {/* ── Alert list + explain panel ───────────────────────────────── */}
      <section className={cn('grid gap-3', explainId ? 'xl:grid-cols-[minmax(0,1fr)_340px]' : '')}>
        <div className="space-y-2">
          {filtered.length === 0 ? (
            <WorkspaceEmptyState title="No alerts match" body="Try a broader filter or wait for new detections." />
          ) : filtered.map((alert) => {
            const open = expanded === alert.alert_id;
            const src = field(alert, 'src_ip') ?? alert.agent_meta?.hostname ?? 'Unavailable';
            const dst = field(alert, 'dst_ip');
            const proc = field(alert, 'process_name');
            return (
              <Card key={alert.alert_id} className="overflow-hidden">
                <CardContent className="p-0">
                  <div className={cn('h-0.5', alert.severity === 'critical' ? 'bg-destructive' : alert.severity === 'high' ? 'bg-[hsl(24_95%_62%)]' : alert.severity === 'medium' ? 'bg-accent' : 'bg-chart-2')} />
                  <div className="px-3 py-2.5">
                    <div className="flex items-center gap-3">
                      <input type="checkbox" className="h-3.5 w-3.5 rounded border-border bg-background" checked={selected.has(alert.alert_id)} onChange={() => toggleOne(alert.alert_id)} />
                      <div className="flex items-center gap-1.5">
                        <Badge variant={sevVariant(alert.severity)}>{alert.severity}</Badge>
                        <Badge variant={statusVariant(alert.status)}>{alert.status.replace('_', ' ')}</Badge>
                        {alert.hit_count > 1 && <span className="text-[10px] text-muted-foreground">{alert.hit_count} hits</span>}
                      </div>
                      <span className="min-w-0 truncate text-sm font-medium text-foreground">{titleFor(alert, titles)}</span>
                      <div className="ml-auto flex items-center gap-1.5 shrink-0">
                        <span className="hidden text-xs text-muted-foreground sm:inline"><Server className="mr-1 inline h-3 w-3" />{alert.agent_meta?.hostname ?? '?'}</span>
                        <span className="text-[10px] text-muted-foreground">{rel(alert.last_seen)}</span>
                        <Button type="button" variant="ghost" size="sm" className="h-7 px-2" onClick={() => void openExplain(alert.alert_id)}><Bot className="h-3.5 w-3.5" /></Button>
                        {alert.status !== 'closed' && <Button type="button" variant="ghost" size="sm" className="h-7 px-2" onClick={() => void markFalsePositive([alert.alert_id])}><XCircle className="h-3.5 w-3.5" /></Button>}
                        <Button asChild variant="ghost" size="sm" className="h-7 px-2"><Link to={`/alerts/${alert.alert_id}`}><ExternalLink className="h-3.5 w-3.5" /></Link></Button>
                        <Button type="button" variant="ghost" size="sm" className="h-7 px-2" onClick={() => setExpanded(open ? null : alert.alert_id)}>{open ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}</Button>
                      </div>
                    </div>

                    {/* Inline detail row */}
                    <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-muted-foreground">
                      <span>src: {src}</span>
                      <span>dst: {dst ?? '—'}</span>
                      <span>proc: {proc ?? '—'}</span>
                      {alert.mitre_attack.length > 0 && alert.mitre_attack.slice(0, 2).map((m) => <Badge key={m.technique_id} variant="outline" className="text-[9px]">{m.technique_id}</Badge>)}
                    </div>

                    {/* Expanded detail */}
                    {open && (
                      <div className="mt-3 grid gap-3 rounded-lg border border-border/70 bg-background/30 p-3 text-xs xl:grid-cols-3">
                        <div className="space-y-2">
                          <div><span className="text-muted-foreground">Alert ID</span><div className="break-all font-mono text-[10px] text-foreground">{alert.alert_id}</div></div>
                          <div><span className="text-muted-foreground">Rule ID</span><div className="break-all font-mono text-[10px] text-foreground">{alert.rule_id}</div></div>
                          <div><span className="text-muted-foreground">First seen</span><div className="text-foreground">{new Date(alert.first_seen).toLocaleString()}</div></div>
                        </div>
                        <div className="space-y-2">
                          <div><span className="text-muted-foreground">OS</span><div className="text-foreground">{alert.agent_meta?.os ?? '—'}</div></div>
                          <div><span className="text-muted-foreground">Group</span><div className="text-foreground">{alert.agent_meta?.group ?? '—'}</div></div>
                          <div><span className="text-muted-foreground">Assignee</span><div className="flex items-center gap-1 text-foreground"><UserRound className="h-3 w-3 text-muted-foreground" />{alert.assignee ?? 'Unassigned'}</div></div>
                        </div>
                        <div className="space-y-2">
                          {alert.case_id ? (
                            <Button asChild variant="outline" size="sm" className="w-full justify-between"><Link to={`/cases/${alert.case_id}`}>Open case<ExternalLink className="h-3 w-3" /></Link></Button>
                          ) : (
                            <div className="rounded-lg border border-dashed border-border/80 px-3 py-2 text-muted-foreground">No case linked</div>
                          )}
                          {alert.mitre_attack.map((m) => (
                            <div key={`${m.technique_id}-${m.tactic}`} className="rounded-lg border border-border/70 bg-card/70 px-3 py-2">
                              <div className="font-medium text-foreground">{m.technique_id}</div>
                              <div className="text-muted-foreground">{m.tactic} · {m.technique_name}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* ── AI explain panel ────────────────────────────────────────── */}
        {explainId && (
          <Card className="h-fit xl:sticky xl:top-4">
            <CardHeader>
              <div className="flex items-start justify-between gap-2">
                <div>
                  <CardTitle>AI explanation</CardTitle>
                  <CardDescription>{activeExplainAlert ? titleFor(activeExplainAlert, titles) : 'Alert context'}</CardDescription>
                </div>
                <Button type="button" variant="ghost" size="icon" className="h-7 w-7" onClick={() => setExplainId(null)}><XCircle className="h-3.5 w-3.5" /></Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              {explainLoading && <div className="rounded-lg border border-border/70 bg-background/35 p-3 text-xs text-muted-foreground">Generating analyst summary...</div>}
              {explainError && <WorkspaceStatusBanner tone="danger">{explainError}</WorkspaceStatusBanner>}
              {!explainLoading && !explainError && explainResult && (
                <>
                  <div className="rounded-lg border border-border/70 bg-background/35 p-3">
                    <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.2em] text-primary"><Sparkles className="h-3 w-3" />Summary</div>
                    <p className="text-xs leading-5 text-foreground">{explainResult.summary}</p>
                  </div>
                  <div className="rounded-lg border border-border/70 bg-background/35 p-3">
                    <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Why suspicious</div>
                    <p className="text-xs leading-5 text-foreground">{explainResult.why_suspicious}</p>
                  </div>
                  <div className="rounded-lg border border-border/70 bg-background/35 p-3">
                    <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Likely cause</div>
                    <p className="text-xs leading-5 text-foreground">{explainResult.likely_cause}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">FP likelihood</span>
                    <Badge variant="outline">{explainResult.false_positive_likelihood}</Badge>
                  </div>
                  <div className="rounded-lg border border-border/70 bg-background/35 p-3">
                    <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Actions</div>
                    <div className="space-y-2">
                      {explainResult.recommended_actions.map((action) => (
                        <div key={action} className="flex items-start gap-2 text-xs text-foreground">
                          <span className="mt-0.5 text-primary">·</span>
                          <span>{action}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
              {!explainLoading && !explainError && !explainResult && (
                <WorkspaceEmptyState title="No explanation" body="Run AI Explain on an alert." />
              )}
            </CardContent>
          </Card>
        )}
      </section>
    </div>
  );
}
