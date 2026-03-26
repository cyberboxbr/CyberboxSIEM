import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowRight,
  Plus,
  RefreshCcw,
  Search,
  ShieldAlert,
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
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceModal } from '@/components/workspace/modal-shell';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { exportCsv, exportPdf } from '@/lib/export';
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
  if (!iso) return '—';
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
  if (!iso) return '—';
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
        const haystack = [record.case_id, record.title, record.description, record.assignee, ...(record.tags ?? []), ...(record.alert_ids ?? [])]
          .filter(Boolean).join(' ').toLowerCase();
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
      const body: CaseCreateInput = { title: newTitle.trim(), severity: newSeverity };
      if (newDescription.trim()) body.description = newDescription.trim();
      if (newAssignee.trim()) body.assignee = newAssignee.trim();
      if (newTags.trim()) body.tags = newTags.split(',').map((tag) => tag.trim()).filter(Boolean);
      if (newAlertIds.trim()) body.alert_ids = newAlertIds.split(',').map((id) => id.trim()).filter(Boolean);
      const created = await createCase(body);
      setShowCreate(false);
      setNewTitle(''); setNewDescription(''); setNewSeverity('medium'); setNewAssignee(''); setNewTags(''); setNewAlertIds('');
      await loadCases(false);
      setMessage('Case created.');
      navigate(`/cases/${created.case_id}`);
    } catch (err) { setMessage(String(err)); } finally { setCreating(false); }
  };

  const moveCase = async (caseId: string, status: CaseStatus) => {
    if (status === 'closed') { setCloseCaseId(caseId); setCloseResolution('tp_contained'); setCloseNote(''); return; }
    setMessage(`Moving case to ${status.replace(/_/g, ' ')}...`);
    try { await updateCase(caseId, { status }); await loadCases(false); setMessage(`Case moved to ${status.replace(/_/g, ' ')}.`); }
    catch (err) { setMessage(String(err)); }
  };

  const closeCase = async () => {
    if (!closeCaseId) return;
    setMessage('Closing case...');
    try { await updateCase(closeCaseId, { status: 'closed', resolution: closeResolution, close_note: closeNote.trim() || null }); setCloseCaseId(null); setCloseNote(''); await loadCases(false); setMessage('Case closed.'); }
    catch (err) { setMessage(String(err)); }
  };

  const assignCase = async () => {
    if (!assignCaseId) return;
    const next = assignName.trim();
    setMessage('Saving assignee...');
    try { await updateCase(assignCaseId, { assignee: next || null }); setAssignCaseId(null); setAssignName(''); await loadCases(false); setMessage(next ? `Case assigned to ${next}.` : 'Case unassigned.'); }
    catch (err) { setMessage(String(err)); }
  };

  return (
    <div className="flex flex-col gap-3">
      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}
        {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}

        <span className="text-xs text-muted-foreground">{filteredCases.length} cases</span>

        <div className="relative ml-2">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            placeholder="Search..."
            className="h-7 rounded-md border border-border/70 bg-card/60 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
          />
        </div>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          {/* Status filter */}
          <div className="flex items-center gap-1 rounded-lg border border-border/70 bg-card/60 p-0.5">
            {FILTER_TABS.map((tab) => (
              <button
                key={tab}
                type="button"
                onClick={() => setFilter(tab)}
                className={cn(
                  'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                  filter === tab ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {tab === 'in_progress' ? 'wip' : tab}
              </button>
            ))}
          </div>

          {/* Severity filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as 'all' | Severity)}
            className="h-7 rounded-md border border-border/70 bg-card/60 px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
          >
            <option value="all">All sev</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <Button type="button" size="sm" variant="outline" onClick={() => { setRefreshing(true); void loadCases(false); }} disabled={refreshing}>
            <RefreshCcw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} /> Refresh
          </Button>
          <Button type="button" size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="h-3.5 w-3.5" /> New case
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={() => {
            exportCsv(
              filteredCases.map((c) => ({
                case_id: c.case_id, severity: c.severity, status: c.status,
                title: c.title, assignee: c.assignee ?? '',
                alert_count: c.alert_ids.length,
                created_at: c.created_at, updated_at: c.updated_at,
                resolution: c.resolution ?? '',
              })),
              ['case_id', 'severity', 'status', 'title', 'assignee', 'alert_count', 'created_at', 'updated_at', 'resolution'],
              `cyberbox-cases-${Date.now()}`,
            );
          }} disabled={filteredCases.length === 0}>CSV</Button>
          <Button type="button" size="sm" variant="outline" onClick={() => {
            exportPdf({
              title: 'Case Report',
              subtitle: `${filteredCases.length} cases — Generated ${new Date().toLocaleString()}`,
              filename: `cyberbox-case-report-${Date.now()}`,
              kpis: [
                { label: 'Open', value: String(stats.open) },
                { label: 'In Progress', value: String(stats.inProgress) },
                { label: 'Resolved', value: String(stats.resolved) },
                { label: 'SLA Breaches', value: String(stats.breached) },
              ],
              columns: ['Severity', 'Status', 'Title', 'Assignee', 'Alerts', 'Updated'],
              rows: filteredCases.map((c) => ({
                Severity: c.severity, Status: c.status, Title: c.title,
                Assignee: c.assignee ?? 'Unassigned', Alerts: c.alert_ids.length,
                Updated: c.updated_at,
              })),
            });
          }} disabled={filteredCases.length === 0}>PDF</Button>
        </div>
      </div>

      {/* ── KPI row ──────────────────────────────────────────────────── */}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <WorkspaceMetricCard label="Open" value={String(stats.open)} hint="Waiting for action" />
        <WorkspaceMetricCard label="In Progress" value={String(stats.inProgress)} hint="Active investigations" />
        <WorkspaceMetricCard label="Resolved" value={String(stats.resolved)} hint="Ready for closure" />
        <WorkspaceMetricCard label="Unassigned" value={String(stats.unassigned)} hint="Needs an owner" />
        <WorkspaceMetricCard label="SLA breaches" value={String(stats.breached)} hint={stats.breached > 0 ? 'Needs immediate attention' : 'All within SLA'} />
      </section>

      {/* ── SLA breach banner ────────────────────────────────────────── */}
      {!!slaBreaches.length && (
        <div className="flex items-center gap-3 rounded-lg border border-destructive/20 bg-destructive/8 px-3 py-2">
          <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-destructive" />
          <span className="text-xs text-destructive">{slaBreaches.length} SLA breach{slaBreaches.length === 1 ? '' : 'es'}</span>
          <div className="ml-auto flex flex-wrap gap-1.5">
            {slaBreaches.slice(0, 4).map((item) => (
              <Button key={item.case_id} asChild size="sm" variant="outline" className="h-6 text-[10px]">
                <Link to={`/cases/${item.case_id}`}>{item.title}</Link>
              </Button>
            ))}
          </div>
        </div>
      )}

      {/* ── Case list ────────────────────────────────────────────────── */}
      <section className="space-y-2">
        {loading ? (
          <Card><CardContent className="h-[200px] animate-pulse" /></Card>
        ) : filteredCases.length === 0 ? (
          <WorkspaceEmptyState title="No cases match" body="Widen the filter or create a new case." />
        ) : (
          filteredCases.map((item) => {
            const sla = slaInfo(item.sla_due_at);
            const nextStatuses = STATUS_TRANSITIONS[item.status] ?? [];
            return (
              <Card key={item.case_id} className="overflow-hidden">
                <CardContent className="p-0">
                  <div className={cn('h-0.5', item.severity === 'critical' ? 'bg-destructive' : item.severity === 'high' ? 'bg-[hsl(24_95%_62%)]' : item.severity === 'medium' ? 'bg-accent' : 'bg-chart-2')} />
                  <div className="px-3 py-2.5">
                    {/* Main row */}
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-1.5">
                        <Badge variant={severityVariant(item.severity)}>{item.severity}</Badge>
                        <Badge variant={statusVariant(item.status)}>{item.status.replace(/_/g, ' ')}</Badge>
                        {item.resolution && <Badge variant="outline">{RESOLUTION_LABELS[item.resolution]}</Badge>}
                      </div>
                      <span className="min-w-0 truncate text-sm font-medium text-foreground">{item.title}</span>
                      <div className="ml-auto flex items-center gap-2 shrink-0">
                        <span className="text-[10px] text-muted-foreground">{item.alert_ids.length} alerts</span>
                        <span className="text-[10px] text-muted-foreground">{item.assignee ?? 'unassigned'}</span>
                        <span className="text-[10px] text-muted-foreground">{rel(item.updated_at)}</span>
                        {item.sla_due_at && <span className={cn('text-[10px] font-medium', sla.breached ? 'text-destructive' : 'text-muted-foreground')}>{sla.label}</span>}
                        {nextStatuses.map((status) => (
                          <Button key={status} type="button" variant="ghost" size="sm" className="h-6 px-2 text-[10px]" onClick={() => void moveCase(item.case_id, status)}>
                            {status === 'in_progress' ? 'Start' : status === 'resolved' ? 'Resolve' : status === 'closed' ? 'Close' : status}
                          </Button>
                        ))}
                        {item.status !== 'closed' && (
                          <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-[10px]" onClick={() => { setAssignCaseId(item.case_id); setAssignName(item.assignee ?? ''); }}>
                            {item.assignee ? 'Reassign' : 'Assign'}
                          </Button>
                        )}
                        <Button asChild variant="ghost" size="sm" className="h-6 px-2">
                          <Link to={`/cases/${item.case_id}`}><ArrowRight className="h-3 w-3" /></Link>
                        </Button>
                      </div>
                    </div>

                    {/* Detail row */}
                    {item.description && <p className="mt-1.5 max-w-3xl truncate text-xs text-muted-foreground">{item.description}</p>}
                    {(item.tags ?? []).length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {(item.tags ?? []).map((tag) => <Badge key={tag} variant="outline" className="text-[9px]">{tag}</Badge>)}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })
        )}
      </section>

      {/* ── Create case modal ────────────────────────────────────────── */}
      <WorkspaceModal open={showCreate} title="Create case" description="Stand up a fresh investigation." onClose={() => setShowCreate(false)} panelClassName="max-w-2xl">
        <div className="grid gap-3 md:grid-cols-2">
          <div className="md:col-span-2"><div className="mb-1 text-xs font-medium text-foreground">Title</div><Input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Suspicious outbound beaconing" autoFocus /></div>
          <div className="md:col-span-2"><div className="mb-1 text-xs font-medium text-foreground">Description</div><Textarea value={newDescription} onChange={(e) => setNewDescription(e.target.value)} rows={3} placeholder="Scope, trigger, and initial hypotheses." /></div>
          <div><div className="mb-1 text-xs font-medium text-foreground">Severity</div><Select value={newSeverity} onChange={(e) => setNewSeverity(e.target.value as Severity)}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></Select></div>
          <div><div className="mb-1 text-xs font-medium text-foreground">Assignee</div><Input value={newAssignee} onChange={(e) => setNewAssignee(e.target.value)} placeholder="analyst-1" /></div>
          <div><div className="mb-1 text-xs font-medium text-foreground">Tags</div><Input value={newTags} onChange={(e) => setNewTags(e.target.value)} placeholder="phishing, workstation" /></div>
          <div><div className="mb-1 text-xs font-medium text-foreground">Alert IDs</div><Input value={newAlertIds} onChange={(e) => setNewAlertIds(e.target.value)} placeholder="alert-1, alert-2" /></div>
        </div>
        <div className="flex justify-end gap-2"><Button type="button" variant="outline" size="sm" onClick={() => setShowCreate(false)}>Cancel</Button><Button type="button" size="sm" onClick={() => void create()} disabled={creating || !newTitle.trim()}>{creating ? 'Creating...' : 'Create'}</Button></div>
      </WorkspaceModal>

      {/* ── Close case modal ─────────────────────────────────────────── */}
      <WorkspaceModal open={Boolean(closeCaseId)} title="Close case" description={`Resolution for ${closeTarget?.title ?? 'this case'}.`} onClose={() => setCloseCaseId(null)} panelClassName="max-w-2xl">
        <div className="grid gap-2 sm:grid-cols-2">
          {(Object.keys(RESOLUTION_LABELS) as CaseResolution[]).map((item) => (
            <button key={item} type="button" className={cn('rounded-lg border px-3 py-3 text-left text-sm transition-colors', closeResolution === item ? 'border-primary/40 bg-primary/10 text-foreground' : 'border-border/70 bg-background/35 text-muted-foreground hover:bg-muted/40')} onClick={() => setCloseResolution(item)}>
              {RESOLUTION_LABELS[item]}
            </button>
          ))}
        </div>
        <div><div className="mb-1 text-xs font-medium text-foreground">Close note</div><Textarea value={closeNote} onChange={(e) => setCloseNote(e.target.value)} rows={3} placeholder="Findings, containment, follow-up." /></div>
        <div className="flex justify-end gap-2"><Button type="button" variant="outline" size="sm" onClick={() => setCloseCaseId(null)}>Cancel</Button><Button type="button" size="sm" onClick={() => void closeCase()}>Close case</Button></div>
      </WorkspaceModal>

      {/* ── Assign case modal ────────────────────────────────────────── */}
      <WorkspaceModal open={Boolean(assignCaseId)} title="Assign case" description={`Set owner for ${assignTarget?.title ?? 'this case'}.`} onClose={() => setAssignCaseId(null)} panelClassName="max-w-md">
        <div><div className="mb-1 text-xs font-medium text-foreground">Assignee</div><Input value={assignName} onChange={(e) => setAssignName(e.target.value)} placeholder="analyst-1" autoFocus /></div>
        <div className="flex justify-end gap-2"><Button type="button" variant="outline" size="sm" onClick={() => setAssignCaseId(null)}>Cancel</Button><Button type="button" size="sm" onClick={() => void assignCase()} disabled={!canSubmitAssign}>{assignName.trim() ? 'Save' : 'Clear'}</Button></div>
      </WorkspaceModal>
    </div>
  );
}
