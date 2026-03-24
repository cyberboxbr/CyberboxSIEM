import { useCallback, useMemo, useState, type FormEvent } from 'react';
import {
  Activity,
  Clock3,
  FileDiff,
  Filter,
  History,
  Search,
  ShieldCheck,
  UserRound,
} from 'lucide-react';

import { getAuditLogs, type AuditLogRecord, type AuditLogsQuery } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';

interface DiffRow {
  path: string;
  before: string;
  after: string;
}

function ser(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return '(missing)';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

function flatten(value: unknown, prefix = '', out: Record<string, unknown> = {}): Record<string, unknown> {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      out[prefix || '$'] = [];
      return out;
    }
    value.forEach((item, index) => flatten(item, prefix ? `${prefix}[${index}]` : `[${index}]`, out));
    return out;
  }

  if (value !== null && typeof value === 'object') {
    const objectValue = value as Record<string, unknown>;
    const keys = Object.keys(objectValue);
    if (keys.length === 0) {
      out[prefix || '$'] = {};
      return out;
    }
    keys.forEach((key) => flatten(objectValue[key], prefix ? `${prefix}.${key}` : key, out));
    return out;
  }

  out[prefix || '$'] = value;
  return out;
}

function buildDiff(before: unknown, after: unknown): DiffRow[] {
  const beforeFlat = flatten(before);
  const afterFlat = flatten(after);
  const keys = Array.from(new Set([...Object.keys(beforeFlat), ...Object.keys(afterFlat)])).sort();
  return keys
    .filter((key) => JSON.stringify(beforeFlat[key]) !== JSON.stringify(afterFlat[key]))
    .map((key) => ({ path: key, before: ser(beforeFlat[key]), after: ser(afterFlat[key]) }));
}

function isoFromLocal(value: string): string | undefined {
  if (!value.trim()) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function relativeTime(value: string): string {
  const delta = Date.now() - new Date(value).getTime();
  if (Number.isNaN(delta)) return value;
  if (delta < 60_000) return `${Math.max(1, Math.floor(delta / 1000))}s ago`;
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h ago`;
  return `${Math.floor(delta / 86_400_000)}d ago`;
}

function actionVariant(action: string): 'default' | 'secondary' | 'outline' | 'destructive' | 'success' | 'warning' | 'info' {
  const normalized = action.toLowerCase();
  if (/(delete|remove|revoke|purge)/.test(normalized)) return 'destructive';
  if (/(create|grant|assign|register|restore)/.test(normalized)) return 'success';
  if (/(close|ack|update|edit|patch|sync)/.test(normalized)) return 'info';
  return 'outline';
}

export function AuditLogs() {
  const [entries, setEntries] = useState<AuditLogRecord[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [hasSearched, setHasSearched] = useState(false);

  const [actionFilter, setActionFilter] = useState('');
  const [actorFilter, setActorFilter] = useState('');
  const [entityTypeFilter, setEntityTypeFilter] = useState('');
  const [fromFilter, setFromFilter] = useState('');
  const [toFilter, setToFilter] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const load = useCallback(async (opts?: { append?: boolean; cursor?: string }) => {
    setLoading(true);
    setError('');

    try {
      const query: AuditLogsQuery = {
        action: actionFilter.trim() || undefined,
        actor: actorFilter.trim() || undefined,
        entity_type: entityTypeFilter.trim() || undefined,
        from: isoFromLocal(fromFilter),
        to: isoFromLocal(toFilter),
        cursor: opts?.cursor,
        limit: 50,
      };

      const response = await getAuditLogs(query);
      setHasSearched(true);
      setNextCursor(response.next_cursor);

      if (opts?.append) {
        setEntries((current) => [...current, ...response.entries]);
      } else {
        setEntries(response.entries);
        setExpandedId(null);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [actionFilter, actorFilter, entityTypeFilter, fromFilter, toFilter]);

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    void load();
  };

  const onReset = () => {
    setActionFilter('');
    setActorFilter('');
    setEntityTypeFilter('');
    setFromFilter('');
    setToFilter('');
    setEntries([]);
    setNextCursor(undefined);
    setExpandedId(null);
    setError('');
    setHasSearched(false);
  };

  const stats = useMemo(() => {
    const actors = new Set<string>();
    const actions = new Set<string>();
    let changedFields = 0;

    entries.forEach((entry) => {
      actors.add(entry.actor);
      actions.add(entry.action);
      changedFields += buildDiff(entry.before, entry.after).length;
    });

    return {
      actors: actors.size,
      actions: actions.size,
      changedFields,
    };
  }, [entries]);

  const hasFilters = Boolean(
    actionFilter.trim() || actorFilter.trim() || entityTypeFilter.trim() || fromFilter.trim() || toFilter.trim(),
  );

  return (
    <div className="space-y-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.45fr)_380px]">
        <Card className="overflow-hidden border-primary/15 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.15),transparent_40%),linear-gradient(145deg,hsl(var(--card)),hsl(var(--card)/0.85))]">
          <CardContent className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(260px,0.85fr)]">
            <div>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant="outline" className="border-primary/25 bg-primary/10 text-primary">Audit workspace</Badge>
                <Badge variant="secondary" className="bg-background/55">
                  {hasSearched ? `${entries.length} loaded entries` : 'Ready to query'}
                </Badge>
              </div>
              <div className="max-w-2xl font-display text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-foreground sm:text-[3rem]">
                Inspect every admin-side change without dropping into raw JSON.
              </div>
              <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
                Review who changed what, track before and after values, and page through the audit trail with filters that stay close to the actual control plane actions.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button type="button" onClick={() => void load()} disabled={loading}>
                  <Search className="h-4 w-4" />
                  {loading ? 'Loading...' : hasSearched ? 'Refresh results' : 'Load recent activity'}
                </Button>
                <Button type="button" variant="outline" onClick={onReset} disabled={loading && !hasFilters}>
                  <Filter className="h-4 w-4" />
                  Clear filters
                </Button>
              </div>
            </div>
            <div className="grid gap-3 rounded-[28px] border border-border/70 bg-background/35 p-4">
              <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Diff coverage</div>
                <div className="mt-3 font-display text-4xl font-semibold tracking-[-0.04em] text-foreground">{stats.changedFields}</div>
                <div className="mt-2 text-sm text-muted-foreground">Field-level changes surfaced in the current result set.</div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Actors</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats.actors}</div>
                </div>
                <div className="rounded-[24px] border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Actions</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats.actions}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Filters</CardTitle>
            <CardDescription>Query by action, actor, entity type, or time window. Results stay paginated at 50 rows per page.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="grid gap-4" onSubmit={onSubmit}>
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <div className="mb-2 text-sm font-medium text-foreground">Action</div>
                  <Input value={actionFilter} onChange={(event) => setActionFilter(event.target.value)} placeholder="rule.create" />
                </div>
                <div>
                  <div className="mb-2 text-sm font-medium text-foreground">Actor</div>
                  <Input value={actorFilter} onChange={(event) => setActorFilter(event.target.value)} placeholder="soc-admin" />
                </div>
                <div>
                  <div className="mb-2 text-sm font-medium text-foreground">Entity type</div>
                  <Input value={entityTypeFilter} onChange={(event) => setEntityTypeFilter(event.target.value)} placeholder="rule, alert, agent" />
                </div>
                <div>
                  <div className="mb-2 text-sm font-medium text-foreground">From</div>
                  <Input type="datetime-local" value={fromFilter} onChange={(event) => setFromFilter(event.target.value)} />
                </div>
                <div className="sm:col-span-2">
                  <div className="mb-2 text-sm font-medium text-foreground">To</div>
                  <Input type="datetime-local" value={toFilter} onChange={(event) => setToFilter(event.target.value)} />
                </div>
              </div>
              <div className="flex flex-wrap justify-end gap-3">
                <Button type="button" variant="outline" onClick={onReset}>Reset</Button>
                <Button type="submit" disabled={loading}>
                  {loading ? 'Searching...' : 'Search audit logs'}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </section>

      {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Loaded" value={String(entries.length)} hint="Entries currently loaded into the workspace." icon={History} />
        <WorkspaceMetricCard label="Actors" value={String(stats.actors)} hint="Distinct identities present in the loaded result set." icon={UserRound} />
        <WorkspaceMetricCard label="Actions" value={String(stats.actions)} hint="Unique control-plane actions represented in view." icon={ShieldCheck} />
        <WorkspaceMetricCard label="Changes" value={String(stats.changedFields)} hint="Field-level before/after deltas available for review." icon={FileDiff} />
      </section>

      <section className="space-y-4">
        {loading && !entries.length ? (
          <Card className="animate-pulse">
            <CardContent className="h-[240px] p-6" />
          </Card>
        ) : !entries.length ? (
          <WorkspaceEmptyState
            title={hasSearched ? 'No audit log entries match the current query' : 'No audit activity loaded yet'}
            body={
              hasSearched
                ? 'Try widening the filters or adjust the time window to pull more admin-side activity into view.'
                : 'Use the filter panel or the quick action above to load recent audit activity.'
            }
          />
        ) : (
          entries.map((entry) => {
            const isExpanded = expandedId === entry.audit_id;
            const diffRows = buildDiff(entry.before, entry.after);

            return (
              <Card key={entry.audit_id}>
                <CardContent className="space-y-5 p-5">
                  <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant={actionVariant(entry.action)}>{entry.action}</Badge>
                        <Badge variant="secondary">{entry.entity_type}</Badge>
                        {entry.tenant_id && <Badge variant="outline">{entry.tenant_id}</Badge>}
                        <Badge variant="outline">{relativeTime(entry.timestamp)}</Badge>
                      </div>
                      <div className="mt-4 font-display text-2xl font-semibold tracking-[-0.03em] text-foreground">
                        {formatTimestamp(entry.timestamp)}
                      </div>
                      <div className="mt-2 max-w-3xl text-sm text-muted-foreground">
                        Audit entry <code className="text-foreground">{entry.audit_id}</code> was recorded for <span className="text-foreground">{entry.actor}</span> on <span className="text-foreground">{entry.entity_type}</span>.
                      </div>
                    </div>
                    <div className="flex shrink-0 flex-wrap gap-3">
                      <Button type="button" variant="outline" onClick={() => setExpandedId(isExpanded ? null : entry.audit_id)}>
                        <FileDiff className="h-4 w-4" />
                        {isExpanded ? 'Hide diff' : 'Show diff'}
                      </Button>
                    </div>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Actor</div>
                      <div className="mt-2 text-sm font-medium text-foreground">{entry.actor}</div>
                    </div>
                    <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Entity ID</div>
                      <code className="mt-2 block break-all text-sm text-foreground">{entry.entity_id}</code>
                    </div>
                    <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Changed fields</div>
                      <div className="mt-2 text-sm font-medium text-foreground">{diffRows.length}</div>
                    </div>
                    <div className="rounded-[22px] border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Recorded</div>
                      <div className="mt-2 flex items-center gap-2 text-sm font-medium text-foreground">
                        <Clock3 className="h-4 w-4 text-muted-foreground" />
                        {formatTimestamp(entry.timestamp)}
                      </div>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="rounded-[24px] border border-border/70 bg-background/35 p-4">
                      <div className="mb-4 flex items-center justify-between gap-3">
                        <div>
                          <div className="font-medium text-foreground">Field-level diff</div>
                          <div className="mt-1 text-sm text-muted-foreground">
                            {diffRows.length ? `${diffRows.length} changed field${diffRows.length === 1 ? '' : 's'} in this entry.` : 'No field-level changes were detected for this record.'}
                          </div>
                        </div>
                        <Badge variant="outline">{diffRows.length} deltas</Badge>
                      </div>

                      {!diffRows.length ? (
                        <WorkspaceEmptyState title="No diff rows detected" body="This entry was captured without a before-and-after field delta." />
                      ) : (
                        <div className="space-y-3">
                          {diffRows.map((row) => (
                            <div key={row.path} className="grid gap-3 rounded-[22px] border border-border/70 bg-card/65 p-4 lg:grid-cols-[minmax(180px,0.7fr)_minmax(0,1fr)_auto_minmax(0,1fr)] lg:items-start">
                              <div>
                                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Path</div>
                                <code className="mt-2 block break-all text-sm text-foreground">{row.path}</code>
                              </div>
                              <div>
                                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Before</div>
                                <div className="mt-2 break-all rounded-[18px] border border-border/60 bg-background/35 px-3 py-3 font-mono text-xs text-muted-foreground">{row.before}</div>
                              </div>
                              <div className="hidden items-center justify-center text-sm font-semibold text-muted-foreground lg:flex">to</div>
                              <div>
                                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">After</div>
                                <div className="mt-2 break-all rounded-[18px] border border-primary/20 bg-primary/10 px-3 py-3 font-mono text-xs text-foreground">{row.after}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })
        )}
      </section>

      {nextCursor && (
        <div className="flex justify-center">
          <Button type="button" variant="outline" onClick={() => void load({ append: true, cursor: nextCursor })} disabled={loading}>
            <Activity className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
            {loading ? 'Loading more...' : 'Load more audit entries'}
          </Button>
        </div>
      )}
    </div>
  );
}
