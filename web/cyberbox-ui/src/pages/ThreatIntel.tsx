import { type FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import {
  DatabaseZap,
  Globe,
  Plus,
  RefreshCcw,
  Search,
  ShieldAlert,
  Trash2,
} from 'lucide-react';

import {
  createThreatIntelFeed,
  deleteThreatIntelFeed,
  getThreatIntelFeeds,
  syncThreatIntelFeed,
  type FeedType,
  type ThreatIntelFeed,
  type ThreatIntelFeedCreateInput,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceModal } from '@/components/workspace/modal-shell';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';

const FEED_TYPES: Array<'all' | FeedType> = ['all', 'taxii', 'stix', 'csv', 'json'];

function rel(iso?: string): string {
  if (!iso) return 'Never';
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return 'just now';
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function abs(iso?: string): string {
  if (!iso) return 'Never';
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toLocaleString();
}

function typeVariant(type: FeedType): 'default' | 'secondary' | 'outline' | 'destructive' | 'success' | 'warning' | 'info' {
  if (type === 'taxii') return 'warning';
  if (type === 'stix') return 'info';
  if (type === 'csv') return 'success';
  return 'secondary';
}

export function ThreatIntel() {
  const [feeds, setFeeds] = useState<ThreatIntelFeed[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [typeFilter, setTypeFilter] = useState<'all' | FeedType>('all');
  const [searchValue, setSearchValue] = useState('');
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState<FeedType>('stix');
  const [newUrl, setNewUrl] = useState('');
  const [newInterval, setNewInterval] = useState(3600);
  const [newEnabled, setNewEnabled] = useState(true);
  const [creating, setCreating] = useState(false);

  const loadFeeds = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setFeeds(await getThreatIntelFeeds());
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadFeeds(); }, [loadFeeds]);

  const filteredFeeds = useMemo(() => {
    const query = searchValue.trim().toLowerCase();
    return feeds.filter((feed) => {
      if (typeFilter !== 'all' && feed.feed_type !== typeFilter) return false;
      if (!query) return true;
      return [feed.name, feed.feed_type, feed.url]
        .join(' ')
        .toLowerCase()
        .includes(query);
    });
  }, [feeds, searchValue, typeFilter]);

  const stats = useMemo(() => {
    const enabled = feeds.filter((feed) => feed.enabled).length;
    const manual = feeds.filter((feed) => feed.auto_sync_interval_secs <= 0).length;
    const totalIocs = feeds.reduce((sum, feed) => sum + feed.ioc_count, 0);
    return { enabled, manual, totalIocs };
  }, [feeds]);

  const onSync = async (feedId: string) => {
    setSyncingId(feedId);
    setMessage('Syncing feed...');
    try {
      await syncThreatIntelFeed(feedId);
      await loadFeeds();
      setMessage('Feed synced.');
    } catch (err) {
      setMessage(String(err));
    } finally {
      setSyncingId(null);
    }
  };

  const onDelete = async (feedId: string) => {
    if (!window.confirm('Delete this threat intelligence feed?')) return;
    try {
      await deleteThreatIntelFeed(feedId);
      setFeeds((current) => current.filter((feed) => feed.feed_id !== feedId));
      setMessage('Feed deleted.');
    } catch (err) {
      setError(String(err));
    }
  };

  const onAddFeed = async (event: FormEvent) => {
    event.preventDefault();
    setCreating(true);
    setMessage('Creating feed...');
    try {
      const input: ThreatIntelFeedCreateInput = {
        name: newName,
        feed_type: newType,
        url: newUrl,
        auto_sync_interval_secs: newInterval,
        enabled: newEnabled,
      };
      await createThreatIntelFeed(input);
      setNewName('');
      setNewUrl('');
      setNewInterval(3600);
      setNewEnabled(true);
      setShowAddForm(false);
      await loadFeeds();
      setMessage('Feed created.');
    } catch (err) {
      setMessage(String(err));
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.45fr)_360px]">
        <Card className="overflow-hidden border-primary/15 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.15),transparent_40%),linear-gradient(145deg,hsl(var(--card)),hsl(var(--card)/0.85))]">
          <CardContent className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(250px,0.85fr)]">
            <div>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant="outline" className="border-primary/25 bg-primary/10 text-primary">Threat intelligence workspace</Badge>
                <Badge variant="secondary" className="bg-background/55">{feeds.length} feeds configured</Badge>
              </div>
              <div className="max-w-2xl font-display text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-foreground sm:text-[3rem]">
                Keep your external intel sources fresh and visible.
              </div>
              <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
                This board shows feed health, sync cadence, IOC volume, and gives you a direct way to add or refresh external intel sources.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button type="button" onClick={() => setShowAddForm(true)}>
                  <Plus className="h-4 w-4" />
                  Add feed
                </Button>
                <Button type="button" variant="outline" onClick={() => void loadFeeds()} disabled={loading}>
                  <RefreshCcw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
                  Refresh feeds
                </Button>
              </div>
            </div>
            <div className="grid gap-3 rounded-xl border border-border/70 bg-background/35 p-4">
              <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Total IOCs</div>
                <div className="mt-3 font-display text-4xl font-semibold tracking-[-0.04em] text-foreground">{stats.totalIocs.toLocaleString()}</div>
              </div>
              <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-1">
                <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Enabled</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats.enabled}</div>
                </div>
                <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Manual</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats.manual}</div>
                </div>
                <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Visible</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{filteredFeeds.length}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Filters</CardTitle>
            <CardDescription>Focus on one feed type or quickly search the catalog by name or URL.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div>
              <div className="mb-2 text-sm font-medium text-foreground">Feed type</div>
              <Select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value as 'all' | FeedType)}>
                {FEED_TYPES.map((type) => <option key={type} value={type}>{type === 'all' ? 'All types' : type.toUpperCase()}</option>)}
              </Select>
            </div>
            <div>
              <div className="mb-2 text-sm font-medium text-foreground">Search</div>
              <div className="relative">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input className="pl-11" value={searchValue} onChange={(event) => setSearchValue(event.target.value)} placeholder="abuse.ch, taxii, url..." />
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}
      {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Feeds" value={String(feeds.length)} hint="Total configured intelligence sources." icon={Globe} />
        <WorkspaceMetricCard label="Enabled" value={String(stats.enabled)} hint="Feeds currently active and eligible for sync." icon={ShieldAlert} />
        <WorkspaceMetricCard label="IOCs" value={stats.totalIocs.toLocaleString()} hint="Indicators currently stored across all feeds." icon={DatabaseZap} />
        <WorkspaceMetricCard label="Manual" value={String(stats.manual)} hint="Feeds that only sync when triggered manually." icon={RefreshCcw} />
      </section>

      <section className="space-y-4">
        {!filteredFeeds.length && !loading ? (
          <WorkspaceEmptyState title="No feeds match the current view" body="Adjust the filters or add a new feed to start collecting external threat intelligence." />
        ) : (
          filteredFeeds.map((feed) => (
            <Card key={feed.feed_id}>
              <CardContent className="grid gap-5 p-5 lg:grid-cols-[minmax(0,1.3fr)_minmax(240px,0.7fr)]">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={typeVariant(feed.feed_type)}>{feed.feed_type}</Badge>
                    <Badge variant={feed.enabled ? 'success' : 'secondary'}>{feed.enabled ? 'enabled' : 'disabled'}</Badge>
                    <Badge variant="outline">{feed.ioc_count.toLocaleString()} IOCs</Badge>
                  </div>
                  <div className="mt-4 font-display text-2xl font-semibold tracking-[-0.03em] text-foreground">{feed.name}</div>
                  <div className="mt-2 break-all text-sm text-muted-foreground">{feed.url}</div>
                  <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Last synced</div>
                      <div className="mt-2 text-sm font-medium text-foreground">{rel(feed.last_synced_at)}</div>
                    </div>
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Sync interval</div>
                      <div className="mt-2 text-sm font-medium text-foreground">{feed.auto_sync_interval_secs > 0 ? `${feed.auto_sync_interval_secs}s` : 'Manual'}</div>
                    </div>
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Enabled</div>
                      <div className="mt-2 text-sm font-medium text-foreground">{feed.enabled ? 'Yes' : 'No'}</div>
                    </div>
                    <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Feed ID</div>
                      <div className="mt-2 truncate text-sm font-medium text-foreground">{feed.feed_id}</div>
                    </div>
                  </div>
                </div>

                <div className="grid gap-4 rounded-xl border border-border/70 bg-background/35 p-4">
                  <div>
                    <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Sync health</div>
                    <div className="mt-3 text-sm text-muted-foreground">
                      {feed.last_synced_at ? `Last sync at ${abs(feed.last_synced_at)}` : 'This feed has not synced yet.'}
                    </div>
                  </div>
                  <div className="space-y-3">
                    <Button type="button" className="w-full justify-center rounded-lg" onClick={() => void onSync(feed.feed_id)} disabled={syncingId === feed.feed_id}>
                      <RefreshCcw className={syncingId === feed.feed_id ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
                      {syncingId === feed.feed_id ? 'Syncing...' : 'Sync now'}
                    </Button>
                    <Button type="button" variant="outline" className="w-full justify-center rounded-lg" onClick={() => void onDelete(feed.feed_id)}>
                      <Trash2 className="h-4 w-4" />
                      Delete feed
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </section>

      <WorkspaceModal
        open={showAddForm}
        title="Add threat intel feed"
        description="Define a new external source and how often Cyberbox should sync it."
        onClose={() => setShowAddForm(false)}
        panelClassName="max-w-2xl"
      >
        <form className="grid gap-4 md:grid-cols-2" onSubmit={(event) => void onAddFeed(event)}>
          <div>
            <div className="mb-2 text-sm font-medium text-foreground">Name</div>
            <Input value={newName} onChange={(event) => setNewName(event.target.value)} placeholder="Abuse.ch URLhaus" required />
          </div>
          <div>
            <div className="mb-2 text-sm font-medium text-foreground">Type</div>
            <Select value={newType} onChange={(event) => setNewType(event.target.value as FeedType)}>
              {FEED_TYPES.filter((type): type is FeedType => type !== 'all').map((type) => <option key={type} value={type}>{type.toUpperCase()}</option>)}
            </Select>
          </div>
          <div className="md:col-span-2">
            <div className="mb-2 text-sm font-medium text-foreground">URL</div>
            <Input value={newUrl} onChange={(event) => setNewUrl(event.target.value)} placeholder="https://urlhaus.abuse.ch/downloads/csv/" required />
          </div>
          <div>
            <div className="mb-2 text-sm font-medium text-foreground">Sync interval (seconds)</div>
            <Input type="number" min={0} value={String(newInterval)} onChange={(event) => setNewInterval(Number(event.target.value))} />
          </div>
          <label className="flex items-center gap-3 rounded-lg border border-border/70 bg-background/35 px-4 py-3 text-sm text-foreground">
            <input type="checkbox" checked={newEnabled} onChange={(event) => setNewEnabled(event.target.checked)} />
            Enabled
          </label>
          <div className="md:col-span-2 flex flex-wrap justify-end gap-3">
            <Button type="button" variant="outline" onClick={() => setShowAddForm(false)}>Cancel</Button>
            <Button type="submit" disabled={creating || !newName.trim() || !newUrl.trim()}>
              {creating ? 'Creating...' : 'Create feed'}
            </Button>
          </div>
        </form>
      </WorkspaceModal>
    </div>
  );
}
