import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowRight,
  Clock3,
  FolderKanban,
  Plus,
  RefreshCcw,
  Search,
  ShieldAlert,
  UserRound,
} from 'lucide-react';

import {
  createCase,
  getCases,
  getSlaBreaches,
  updateCase,
  type CaseCreateInput,
  type CaseRecord,
  type CaseResolution,
  type CaseStatus,
  type Severity,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceModal } from '@/components/workspace/modal-shell';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';

type FilterTab = 'all' | 'open' | 'in_progress' | 'resolved' | 'closed';
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

const FILTER_TABS: FilterTab[] = ['all', 'open', 'in_progress', 'resolved', 'closed'];

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

function slaInfo(slaDueAt?: string): { label: string; pct: number; breached: boolean } {
  if (!slaDueAt) return { label: 'No SLA', pct: 100, breached: false };
  const remaining = new Date(slaDueAt).getTime() - Date.now();
  if (remaining <= 0) return { label: 'Breached', pct: 0, breached: true };
  const hours = Math.floor(remaining / 3_600_000);
  const minutes = Math.floor((remaining % 3_600_000) / 60_000);
  return {
    label: hours > 0 ? `${hours}h ${minutes}m left` : `${minutes}m left`,
    pct: Math.min(100, (remaining / (24 * 3_600_000)) * 100),
    breached: false,
  };
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

export function Cases() {
  const navigate = useNavigate();
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [slaBreaches, setSlaBreaches] = useState<CaseRecord[]>([]);
  const [filter, setFilter] = useState<FilterTab>('all');
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all');
  const [searchValue, setSearchValue] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState<Severity>('medium');
  const [newAssignee, setNewAssignee] = useState('');
  const [newTags, setNewTags] = useState('');
  const [newAlertIds, setNewAlertIds] = useState('');
  const [closeCaseId, setCloseCaseId] = useState<string | null>(null);
  const [closeResolution, setCloseResolution] = useState<CaseResolution>('tp_contained');
  const [closeNote, setCloseNote] = useState('');
  const [assignCaseId, setAssignCaseId] = useState<string | null>(null);
  const [assignName, setAssignName] = useState('');

  const loadCases = useCallback(async (showLoader: boolean) => {
    if (showLoader) setLoading(true);
    setError('');
    try {
      const [caseRows, breachRows] = await Promise.all([
        getCases().catch(() => []),
        getSlaBreaches().catch(() => []),
      ]);
      setCases(caseRows ?? []);
      setSlaBreaches(breachRows ?? []);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { void loadCases(true); }, [loadCases]);

  const filteredCases = useMemo(() => {
    const search = searchValue.trim().toLowerCase();
    return [...cases]
      .sort((left, right) => new Date(right.updated_at).getTime() - new Date(left.updated_at).getTime())
      .filter((record) => {
        if (filter !== 'all' && record.status !== filter) return false;
        if (severityFilter !== 'all' && record.severity !== severityFilter) return false;
        if (!search) return true;
        const haystack = [
          record.case_id,
          record.title,
          record.description,
          record.assignee,
          ...(record.tags ?? []),
          ...(record.alert_ids ?? []),
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        return haystack.includes(search);
      });
  }, [cases, filter, severityFilter, searchValue]);

  const stats = useMemo(() => {
    const open = cases.filter((item) => item.status === 'open').length;
    const inProgress = cases.filter((item) => item.status === 'in_progress').length;
    const resolved = cases.filter((item) => item.status === 'resolved').length;
    const unassigned = cases.filter((item) => !item.assignee && item.status !== 'closed').length;
    return { open, inProgress, resolved, unassigned, breached: slaBreaches.length };
  }, [cases, slaBreaches]);

  const closeTarget = closeCaseId ? cases.find((item) => item.case_id === closeCaseId) ?? null : null;
  const assignTarget = assignCaseId ? cases.find((item) => item.case_id === assignCaseId) ?? null : null;
  const canSubmitAssign = Boolean(assignCaseId) && (assignName.trim().length > 0 || Boolean(assignTarget?.assignee));

  const create = async () => {
    if (!newTitle.trim()) return;
    setCreating(true);
    setMessage('Creating case...');
    try {
      const body: CaseCreateInput = {
        title: newTitle.trim(),
        severity: newSeverity,
      };
      if (newDescription.trim()) body.description = newDescription.trim();
      if (newAssignee.trim()) body.assignee = newAssignee.trim();
      if (newTags.trim()) body.tags = newTags.split(',').map((tag) => tag.trim()).filter(Boolean);
      if (newAlertIds.trim()) body.alert_ids = newAlertIds.split(',').map((id) => id.trim()).filter(Boolean);
      const created = await createCase(body);
      setShowCreate(false);
      setNewTitle('');
      setNewDescription('');
      setNewSeverity('medium');
      setNewAssignee('');
      setNewTags('');
      setNewAlertIds('');
      await loadCases(false);
      setMessage('Case created.');
      navigate(`/cases/${created.case_id}`);
    } catch (err) {
      setMessage(String(err));
    } finally {
      setCreating(false);
    }
  };

  const moveCase = async (caseId: string, status: CaseStatus) => {
    if (status === 'closed') {
      setCloseCaseId(caseId);
      setCloseResolution('tp_contained');
      setCloseNote('');
      return;
    }
    setMessage(`Moving case to ${status.replace(/_/g, ' ')}...`);
    try {
      await updateCase(caseId, { status });
      await loadCases(false);
      setMessage(`Case moved to ${status.replace(/_/g, ' ')}.`);
    } catch (err) {
      setMessage(String(err));
    }
  };

  const closeCase = async () => {
    if (!closeCaseId) return;
    setMessage('Closing case...');
    try {
      await updateCase(closeCaseId, {
        status: 'closed',
        resolution: closeResolution,
        close_note: closeNote.trim() || null,
      });
      setCloseCaseId(null);
      setCloseNote('');
      await loadCases(false);
      setMessage('Case closed.');
    } catch (err) {
      setMessage(String(err));
    }
  };

  const assignCase = async () => {
    if (!assignCaseId) return;
    const next = assignName.trim();
    setMessage('Saving assignee...');
    try {
      await updateCase(assignCaseId, { assignee: next || null });
      setAssignCaseId(null);
      setAssignName('');
      await loadCases(false);
      setMessage(next ? `Case assigned to ${next}.` : 'Case unassigned.');
    } catch (err) {
      setMessage(String(err));
    }
  };

  return (
    <div className="space-y-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.45fr)_360px]">
        <Card className="overflow-hidden border-primary/15 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.15),transparent_40%),linear-gradient(145deg,hsl(var(--card)),hsl(var(--card)/0.85))]">
          <CardContent className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(250px,0.85fr)]">
            <div>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant="outline" className="border-primary/25 bg-primary/10 text-primary">Case management workspace</Badge>
                <Badge variant="secondary" className="bg-background/55">{filteredCases.length} visible</Badge>
              </div>
              <div className="max-w-2xl font-display text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-foreground sm:text-[3rem]">
                Keep the investigation queue tight, visible, and moving.
              </div>
              <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
                The new case board highlights SLA pressure, ownership gaps, and the cases that still need analyst momentum.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button type="button" onClick={() => setShowCreate(true)}>
                  <Plus className="h-4 w-4" />
                  New case
                </Button>
                <Button type="button" variant="outline" onClick={() => { setRefreshing(true); void loadCases(false); }} disabled={refreshing}>
                  <RefreshCcw className={cn('h-4 w-4', refreshing && 'animate-spin')} />
                  Refresh board
                </Button>
              </div>
            </div>
            <div className="grid gap-3 rounded-[28px] border border-border/70 bg-background/35 p-4">
              <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Pressure points</div>
                <div className="mt-3 text-sm text-foreground">{stats.breached} SLA breach{stats.breached === 1 ? '' : 'es'} need attention.</div>
              </div>
              <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-1">
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Open</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats.open}</div>
                </div>
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">In Progress</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats.inProgress}</div>
                </div>
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Unassigned</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats.unassigned}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Filters</CardTitle>
            <CardDescription>Trim the board down to the exact set of cases you want to review.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid grid-cols-2 gap-3">
              {FILTER_TABS.map((tab) => (
                <Button
                  key={tab}
                  type="button"
                  variant={filter === tab ? 'default' : 'outline'}
                  className="rounded-[22px]"
                  onClick={() => setFilter(tab)}
                >
                  {tab === 'all' ? 'All' : tab.replace(/_/g, ' ')}
                </Button>
              ))}
            </div>
            <div>
              <div className="mb-2 text-sm font-medium text-foreground">Severity</div>
              <Select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as 'all' | Severity)}>
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </Select>
            </div>
            <div>
              <div className="mb-2 text-sm font-medium text-foreground">Search</div>
              <div className="relative">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input className="pl-11" value={searchValue} onChange={(event) => setSearchValue(event.target.value)} placeholder="title, tag, assignee, alert ID..." />
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {!!slaBreaches.length && (
        <Card className="border-destructive/20 bg-[linear-gradient(120deg,hsl(var(--destructive)/0.12),transparent_60%)]">
          <CardContent className="flex flex-col gap-4 p-5 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm font-medium text-destructive">
                <ShieldAlert className="h-4 w-4" />
                SLA breach detected
              </div>
              <p className="mt-2 text-sm text-muted-foreground">
                {slaBreaches.length} case{slaBreaches.length === 1 ? '' : 's'} have crossed their SLA boundary.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {slaBreaches.slice(0, 5).map((item) => (
                <Button key={item.case_id} asChild size="sm" variant="outline">
                  <Link to={`/cases/${item.case_id}`}>{item.title}</Link>
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}
      {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Open" value={String(stats.open)} hint="Fresh cases waiting for analyst ownership or action." icon={FolderKanban} />
        <WorkspaceMetricCard label="In Progress" value={String(stats.inProgress)} hint="Active investigations currently moving." icon={RefreshCcw} />
        <WorkspaceMetricCard label="Resolved" value={String(stats.resolved)} hint="Ready for closure or final review." icon={ShieldAlert} />
        <WorkspaceMetricCard label="Unassigned" value={String(stats.unassigned)} hint="Cases that still need a named owner." icon={UserRound} />
      </section>

      <section className="space-y-4">
        {loading ? (
          <Card><CardContent className="h-[320px] animate-pulse p-6" /></Card>
        ) : filteredCases.length === 0 ? (
          <WorkspaceEmptyState title="No cases match the current view" body="Try widening the filter set or create a new case to seed the board." />
        ) : (
          filteredCases.map((item) => {
            const sla = slaInfo(item.sla_due_at);
            const nextStatuses = STATUS_TRANSITIONS[item.status] ?? [];
            return (
              <Card key={item.case_id} className="overflow-hidden">
                <CardContent className="grid gap-5 p-5 lg:grid-cols-[minmax(0,1.35fr)_minmax(240px,0.65fr)]">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={severityVariant(item.severity)}>{item.severity}</Badge>
                      <Badge variant={statusVariant(item.status)}>{item.status.replace(/_/g, ' ')}</Badge>
                      {item.resolution && <Badge variant="outline">{RESOLUTION_LABELS[item.resolution]}</Badge>}
                      {item.assignee && <Badge variant="secondary">{item.assignee}</Badge>}
                    </div>
                    <div className="mt-4 flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="font-display text-2xl font-semibold tracking-[-0.03em] text-foreground">{item.title}</div>
                        {item.description && <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">{item.description}</p>}
                      </div>
                      <Button asChild size="sm" variant="outline">
                        <Link to={`/cases/${item.case_id}`}>
                          Open case
                          <ArrowRight className="h-4 w-4" />
                        </Link>
                      </Button>
                    </div>
                    <div className="mt-4 flex flex-wrap gap-2">
                      {(item.tags ?? []).map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>)}
                    </div>
                    <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3">
                        <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Alerts</div>
                        <div className="mt-2 text-sm font-medium text-foreground">{item.alert_ids.length}</div>
                      </div>
                      <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3">
                        <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Updated</div>
                        <div className="mt-2 text-sm font-medium text-foreground">{rel(item.updated_at)}</div>
                      </div>
                      <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3">
                        <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Assignee</div>
                        <div className="mt-2 text-sm font-medium text-foreground">{item.assignee ?? 'Unassigned'}</div>
                      </div>
                      <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3">
                        <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Created</div>
                        <div className="mt-2 text-sm font-medium text-foreground">{rel(item.created_at)}</div>
                      </div>
                    </div>
                  </div>

                  <div className="grid gap-4 rounded-[28px] border border-border/70 bg-background/35 p-4">
                    <div>
                      <div className="flex items-center justify-between gap-3 text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">
                        <span>SLA</span>
                        <span className={cn(sla.breached ? 'text-destructive' : 'text-foreground')}>{sla.label}</span>
                      </div>
                      {item.sla_due_at && (
                        <>
                          <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted/60">
                            <div className={cn('h-full rounded-full', sla.breached ? 'bg-destructive' : 'bg-primary')} style={{ width: `${Math.max(sla.pct, 4)}%` }} />
                          </div>
                          <div className="mt-2 text-sm text-muted-foreground">Due {abs(item.sla_due_at)}</div>
                        </>
                      )}
                    </div>
                    <div className="space-y-3">
                      {nextStatuses.map((status) => (
                        <Button key={status} type="button" variant="outline" className="w-full justify-center rounded-[22px]" onClick={() => void moveCase(item.case_id, status)}>
                          {status.replace(/_/g, ' ')}
                        </Button>
                      ))}
                      {item.status !== 'closed' && (
                        <Button
                          type="button"
                          variant="ghost"
                          className="w-full justify-center rounded-[22px]"
                          onClick={() => { setAssignCaseId(item.case_id); setAssignName(item.assignee ?? ''); }}
                        >
                          {item.assignee ? 'Reassign' : 'Assign'}
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })
        )}
      </section>

      <WorkspaceModal
        open={showCreate}
        title="Create case"
        description="Stand up a fresh investigation container and optionally seed it with initial alert IDs."
        onClose={() => setShowCreate(false)}
        panelClassName="max-w-2xl"
      >
        <div className="grid gap-4 md:grid-cols-2">
          <div className="md:col-span-2">
            <div className="mb-2 text-sm font-medium text-foreground">Title</div>
            <Input value={newTitle} onChange={(event) => setNewTitle(event.target.value)} placeholder="Suspicious workstation outbound beaconing" autoFocus />
          </div>
          <div className="md:col-span-2">
            <div className="mb-2 text-sm font-medium text-foreground">Description</div>
            <Textarea value={newDescription} onChange={(event) => setNewDescription(event.target.value)} rows={4} placeholder="Capture the scope, what triggered this case, and any first hypotheses." />
          </div>
          <div>
            <div className="mb-2 text-sm font-medium text-foreground">Severity</div>
            <Select value={newSeverity} onChange={(event) => setNewSeverity(event.target.value as Severity)}>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </Select>
          </div>
          <div>
            <div className="mb-2 text-sm font-medium text-foreground">Assignee</div>
            <Input value={newAssignee} onChange={(event) => setNewAssignee(event.target.value)} placeholder="analyst-1" />
          </div>
          <div>
            <div className="mb-2 text-sm font-medium text-foreground">Tags</div>
            <Input value={newTags} onChange={(event) => setNewTags(event.target.value)} placeholder="phishing, workstation" />
          </div>
          <div>
            <div className="mb-2 text-sm font-medium text-foreground">Alert IDs</div>
            <Input value={newAlertIds} onChange={(event) => setNewAlertIds(event.target.value)} placeholder="alert-1, alert-2" />
          </div>
        </div>
        <div className="flex flex-wrap justify-end gap-3">
          <Button type="button" variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
          <Button type="button" onClick={() => void create()} disabled={creating || !newTitle.trim()}>
            {creating ? 'Creating...' : 'Create case'}
          </Button>
        </div>
      </WorkspaceModal>

      <WorkspaceModal
        open={Boolean(closeCaseId)}
        title="Close case"
        description={`Choose a final resolution for ${closeTarget?.title ?? 'this case'} and capture a closing note.`}
        onClose={() => setCloseCaseId(null)}
        panelClassName="max-w-2xl"
      >
        <div className="grid gap-3 sm:grid-cols-2">
          {(Object.keys(RESOLUTION_LABELS) as CaseResolution[]).map((item) => (
            <button
              key={item}
              type="button"
              className={cn(
                'rounded-[24px] border px-4 py-4 text-left transition-colors',
                closeResolution === item ? 'border-primary/40 bg-primary/10 text-foreground' : 'border-border/70 bg-background/35 text-muted-foreground hover:bg-muted/40',
              )}
              onClick={() => setCloseResolution(item)}
            >
              <div className="font-medium text-foreground">{RESOLUTION_LABELS[item]}</div>
            </button>
          ))}
        </div>
        <div>
          <div className="mb-2 text-sm font-medium text-foreground">Close note</div>
          <Textarea value={closeNote} onChange={(event) => setCloseNote(event.target.value)} rows={4} placeholder="Summarize findings, containment, and any follow-up still required." />
        </div>
        <div className="flex flex-wrap justify-end gap-3">
          <Button type="button" variant="outline" onClick={() => setCloseCaseId(null)}>Cancel</Button>
          <Button type="button" onClick={() => void closeCase()}>Close case</Button>
        </div>
      </WorkspaceModal>

      <WorkspaceModal
        open={Boolean(assignCaseId)}
        title="Assign case"
        description={`Set ownership for ${assignTarget?.title ?? 'this case'} or clear the current assignee.`}
        onClose={() => setAssignCaseId(null)}
        panelClassName="max-w-2xl"
      >
        <div>
          <div className="mb-2 text-sm font-medium text-foreground">Assignee</div>
          <Input value={assignName} onChange={(event) => setAssignName(event.target.value)} placeholder="analyst-1" autoFocus />
        </div>
        <div className="flex flex-wrap justify-end gap-3">
          <Button type="button" variant="outline" onClick={() => setAssignCaseId(null)}>Cancel</Button>
          <Button type="button" onClick={() => void assignCase()} disabled={!canSubmitAssign}>
            {assignName.trim() ? 'Save assignee' : 'Clear assignee'}
          </Button>
        </div>
      </WorkspaceModal>
    </div>
  );
}
