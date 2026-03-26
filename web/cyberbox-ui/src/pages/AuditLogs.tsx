import { useCallback, useMemo, useState } from 'react';
import {
  Activity,
  Clock3,
  FileDiff,
  RefreshCcw,
  Search,
} from 'lucide-react';

import { getAuditLogs, type AuditLogRecord, type AuditLogsQuery } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { exportCsv } from '@/lib/export';
import { cn } from '@/lib/utils';

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
    <div className="flex flex-col gap-3">
      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

        <span className="text-xs text-muted-foreground">
          {hasSearched ? `${entries.length} entries` : 'Not yet loaded'}
        </span>

        <div className="relative ml-2">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={actionFilter}
            onChange={(event) => setActionFilter(event.target.value)}
            placeholder="action..."
            className="h-7 rounded-md border border-border/70 bg-card/60 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
          />
        </div>

        <input
          type="text"
          value={actorFilter}
          onChange={(event) => setActorFilter(event.target.value)}
          placeholder="actor..."
          className="h-7 rounded-md border border-border/70 bg-card/60 px-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
        />

        <input
          type="text"
          value={entityTypeFilter}
          onChange={(event) => setEntityTypeFilter(event.target.value)}
          placeholder="entity type..."
          className="h-7 rounded-md border border-border/70 bg-card/60 px-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
        />

        <input
          type="datetime-local"
          value={fromFilter}
          onChange={(event) => setFromFilter(event.target.value)}
          className="h-7 rounded-md border border-border/70 bg-card/60 px-3 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
        />

        <input
          type="datetime-local"
          value={toFilter}
          onChange={(event) => setToFilter(event.target.value)}
          className="h-7 rounded-md border border-border/70 bg-card/60 px-3 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
        />

        <div className="ml-auto flex items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={onReset} disabled={loading && !hasFilters}>
            Reset
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCcw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            {loading ? 'Loading...' : hasSearched ? 'Refresh' : 'Load'}
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={() => {
            exportCsv(
              entries.map((e) => ({
                timestamp: e.timestamp, actor: e.actor, action: e.action,
                entity_type: e.entity_type, entity_id: e.entity_id,
              })),
              ['timestamp', 'actor', 'action', 'entity_type', 'entity_id'],
              `cyberbox-audit-log-${Date.now()}`,
            );
          }} disabled={entries.length === 0}>CSV</Button>
        </div>
      </div>

      {/* ── KPI row ──────────────────────────────────────────────────── */}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Loaded" value={String(entries.length)} hint="Entries in the current result set." />
        <WorkspaceMetricCard label="Actors" value={String(stats.actors)} hint="Distinct identities in view." />
        <WorkspaceMetricCard label="Actions" value={String(stats.actions)} hint="Unique control-plane actions in view." />
        <WorkspaceMetricCard label="Changes" value={String(stats.changedFields)} hint="Field-level before/after deltas." />
      </section>

      <section className="space-y-2">
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
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Actor</div>
                      <div className="mt-2 text-sm font-medium text-foreground">{entry.actor}</div>
                    </div>
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Entity ID</div>
                      <code className="mt-2 block break-all text-sm text-foreground">{entry.entity_id}</code>
                    </div>
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Changed fields</div>
                      <div className="mt-2 text-sm font-medium text-foreground">{diffRows.length}</div>
                    </div>
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Recorded</div>
                      <div className="mt-2 flex items-center gap-2 text-sm font-medium text-foreground">
                        <Clock3 className="h-4 w-4 text-muted-foreground" />
                        {formatTimestamp(entry.timestamp)}
                      </div>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="rounded-lg border border-border/70 bg-background/35 p-4">
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
                            <div key={row.path} className="grid gap-3 rounded-lg border border-border/70 bg-card/65 p-4 lg:grid-cols-[minmax(180px,0.7fr)_minmax(0,1fr)_auto_minmax(0,1fr)] lg:items-start">
                              <div>
                                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Path</div>
                                <code className="mt-2 block break-all text-sm text-foreground">{row.path}</code>
                              </div>
                              <div>
                                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Before</div>
                                <div className="mt-2 break-all rounded-lg border border-border/60 bg-background/35 px-3 py-3 font-mono text-xs text-muted-foreground">{row.before}</div>
                              </div>
                              <div className="hidden items-center justify-center text-sm font-semibold text-muted-foreground lg:flex">to</div>
                              <div>
                                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">After</div>
                                <div className="mt-2 break-all rounded-lg border border-primary/20 bg-primary/10 px-3 py-3 font-mono text-xs text-foreground">{row.after}</div>
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
