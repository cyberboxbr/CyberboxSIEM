import { type FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Clock,
  Database,
  Globe,
  History,
  Plus,
  RefreshCcw,
  ScanSearch,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Zap,
} from 'lucide-react';

import {
  createThreatIntelFeed,
  deleteThreatIntelFeed,
  enrichIoc,
  getThreatIntelFeeds,
  getThreatIntelProviders,
  runSearch,
  syncAbuseIpDbBlacklist,
  syncThreatIntelFeed,
  toggleThreatIntelProvider,
  type EnrichmentResult,
  type FeedType,
  type ThreatIntelFeed,
  type ThreatIntelFeedCreateInput,
  type ThreatIntelProvider,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceModal } from '@/components/workspace/modal-shell';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';

const FEED_TYPES: Array<'all' | FeedType> = ['all', 'taxii', 'stix', 'csv', 'json'];

function rel(iso?: string | null): string {
  if (!iso) return 'Never';
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function typeVariant(type: FeedType): 'default' | 'secondary' | 'outline' | 'destructive' | 'success' | 'warning' | 'info' {
  if (type === 'taxii') return 'warning';
  if (type === 'stix') return 'info';
  if (type === 'csv') return 'success';
  return 'secondary';
}

function feedHealthColor(feed: ThreatIntelFeed): string {
  if (!feed.enabled) return 'bg-muted-foreground';
  if (!feed.last_synced_at) return 'bg-destructive';
  const hours = (Date.now() - new Date(feed.last_synced_at).getTime()) / 3_600_000;
  const expectedInterval = Math.max(feed.auto_sync_interval_secs / 3600, 1);
  if (hours < expectedInterval * 2) return 'bg-accent';
  if (hours < expectedInterval * 6) return 'bg-[hsl(43_96%_58%)]';
  return 'bg-destructive';
}

const IOC_HISTORY_KEY = 'cyberbox-ioc-history';
const MAX_IOC_HISTORY = 10;

function loadIocHistory(): string[] {
  try { return JSON.parse(localStorage.getItem(IOC_HISTORY_KEY) ?? '[]'); } catch { return []; }
}
function saveIocHistory(entries: string[]) {
  localStorage.setItem(IOC_HISTORY_KEY, JSON.stringify(entries.slice(0, MAX_IOC_HISTORY)));
}

export function ThreatIntel() {
  // Providers
  const [providers, setProviders] = useState<ThreatIntelProvider[]>([]);
  const [providersLoading, setProvidersLoading] = useState(true);

  // IOC lookup
  const [iocQuery, setIocQuery] = useState('');
  const [iocLoading, setIocLoading] = useState(false);
  const [iocResult, setIocResult] = useState<EnrichmentResult | null>(null);
  const [iocError, setIocError] = useState('');
  const [iocHistory, setIocHistory] = useState<string[]>(() => loadIocHistory());

  // Retro-hunt
  const [retroQuery, setRetroQuery] = useState('');
  const [retroLoading, setRetroLoading] = useState(false);
  const [retroResults, setRetroResults] = useState<Array<Record<string, unknown>>>([]);
  const [retroCount, setRetroCount] = useState(0);

  // Blacklist
  const [syncingBlacklist, setSyncingBlacklist] = useState(false);

  // Feeds
  const [feeds, setFeeds] = useState<ThreatIntelFeed[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | FeedType>('all');
  const [searchValue, setSearchValue] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState<FeedType>('taxii');
  const [newUrl, setNewUrl] = useState('');
  const [newInterval, setNewInterval] = useState(3600);
  const [newEnabled, setNewEnabled] = useState(true);

  const loadProviders = useCallback(async () => {
    setProvidersLoading(true);
    try { setProviders(await getThreatIntelProviders()); } catch { /* ignore */ }
    finally { setProvidersLoading(false); }
  }, []);

  const loadFeeds = useCallback(async () => {
    setLoading(true);
    setError('');
    try { setFeeds(await getThreatIntelFeeds()); }
    catch (err) { setError(String(err)); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void loadProviders(); void loadFeeds(); }, [loadProviders, loadFeeds]);

  const filteredFeeds = useMemo(() => {
    const query = searchValue.toLowerCase();
    return feeds.filter((feed) => {
      if (typeFilter !== 'all' && feed.feed_type !== typeFilter) return false;
      if (!query) return true;
      return [feed.name, feed.url, feed.feed_type].join(' ').toLowerCase().includes(query);
    });
  }, [feeds, typeFilter, searchValue]);

  const abuseipdb = providers.find((p) => p.id === 'abuseipdb');
  const virustotal = providers.find((p) => p.id === 'virustotal');
  const totalIocs = feeds.reduce((sum, f) => sum + (f.ioc_count ?? 0), 0);
  const activeFeeds = feeds.filter((f) => f.enabled).length;
  const staleFeeds = feeds.filter((f) => {
    if (!f.enabled || !f.last_synced_at) return false;
    const hours = (Date.now() - new Date(f.last_synced_at).getTime()) / 3_600_000;
    return hours > Math.max(f.auto_sync_interval_secs / 3600, 1) * 6;
  }).length;

  const handleToggle = async (id: string, enabled: boolean) => {
    try {
      await toggleThreatIntelProvider(id, enabled);
      await loadProviders();
      setMessage(`${id} ${enabled ? 'enabled' : 'disabled'}.`);
    } catch (err) { setMessage(String(err)); }
  };

  const handleSyncBlacklist = async () => {
    setSyncingBlacklist(true);
    setMessage('');
    try {
      const result = await syncAbuseIpDbBlacklist();
      await loadProviders();
      setMessage(`AbuseIPDB blacklist synced: ${result.count} IPs.`);
    } catch (err) { setMessage(String(err)); }
    finally { setSyncingBlacklist(false); }
  };

  const handleIocSearch = async (indicator?: string) => {
    const q = (indicator ?? iocQuery).trim();
    if (!q) return;
    setIocLoading(true);
    setIocError('');
    setIocResult(null);
    try {
      const result = await enrichIoc(q);
      setIocResult(result);
      const next = [q, ...iocHistory.filter((h) => h !== q)].slice(0, MAX_IOC_HISTORY);
      setIocHistory(next);
      saveIocHistory(next);
    } catch (err) { setIocError(String(err)); }
    finally { setIocLoading(false); }
  };

  const handleRetroHunt = async (indicator?: string) => {
    const q = (indicator ?? retroQuery).trim();
    if (!q) return;
    setRetroLoading(true);
    setRetroResults([]);
    setRetroCount(0);
    try {
      const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q);
      const isHash = /^[a-f0-9]{32,64}$/i.test(q);
      let where: string;
      if (isIp) {
        where = `(src_ip = '${q}' OR dst_ip = '${q}')`;
      } else if (isHash) {
        where = `raw_payload LIKE '%${q}%'`;
      } else {
        where = `(raw_payload LIKE '%${q}%' OR dst_ip LIKE '%${q}%')`;
      }
      const sql = `SELECT event_id, event_time, computer_name, src_ip, dst_ip, substring(raw_payload, 1, 200) as payload_preview FROM events_hot WHERE ${where} AND event_time > now() - INTERVAL 7 DAY ORDER BY event_time DESC LIMIT 50`;
      const result = await runSearch({ sql, time_range: { start: '', end: '' } });
      setRetroResults(result.rows ?? []);
      setRetroCount(result.total ?? (result.rows?.length ?? 0));
    } catch {
      setRetroCount(0);
    }
    finally { setRetroLoading(false); }
  };

  const onAddFeed = async (event: FormEvent) => {
    event.preventDefault();
    setCreating(true);
    setMessage('Creating feed...');
    try {
      const input: ThreatIntelFeedCreateInput = { name: newName, feed_type: newType, url: newUrl, auto_sync_interval_secs: newInterval, enabled: newEnabled };
      await createThreatIntelFeed(input);
      setNewName(''); setNewUrl(''); setNewInterval(3600); setNewEnabled(true); setShowAddForm(false);
      await loadFeeds();
      setMessage('Feed created.');
    } catch (err) { setMessage(String(err)); }
    finally { setCreating(false); }
  };

  return (
    <div className="flex flex-col gap-3">
      {/* ── Status bar ─────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}
        {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}
        <div className="ml-auto flex items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={() => { void loadProviders(); void loadFeeds(); }}>
            <RefreshCcw className="h-3.5 w-3.5" /> Refresh
          </Button>
        </div>
      </div>

      {/* ── KPI row ────────────────────────────────────────────────── */}
      <section className="grid gap-2 grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardContent className="flex items-center gap-2.5 px-3 py-2">
            <Database className="h-4 w-4 shrink-0 text-primary" />
            <div>
              <div className="text-lg font-semibold text-foreground">{totalIocs.toLocaleString()}</div>
              <div className="text-[10px] text-muted-foreground">Total IOCs</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-2.5 px-3 py-2">
            <Activity className="h-4 w-4 shrink-0 text-accent" />
            <div>
              <div className="text-lg font-semibold text-foreground">{activeFeeds}</div>
              <div className="text-[10px] text-muted-foreground">Active feeds</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-2.5 px-3 py-2">
            <AlertTriangle className={cn('h-4 w-4 shrink-0', staleFeeds > 0 ? 'text-destructive' : 'text-muted-foreground')} />
            <div>
              <div className={cn('text-lg font-semibold', staleFeeds > 0 ? 'text-destructive' : 'text-foreground')}>{staleFeeds}</div>
              <div className="text-[10px] text-muted-foreground">Stale feeds</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-2.5 px-3 py-2">
            <ShieldCheck className={cn('h-4 w-4 shrink-0', abuseipdb?.enabled ? 'text-accent' : 'text-muted-foreground')} />
            <div>
              <div className="text-lg font-semibold text-foreground">{abuseipdb?.blacklist_count?.toLocaleString() ?? 0}</div>
              <div className="text-[10px] text-muted-foreground">Blacklisted IPs</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-2.5 px-3 py-2">
            <Globe className="h-4 w-4 shrink-0 text-primary" />
            <div>
              <div className="text-lg font-semibold text-foreground">{providers.filter((p) => p.enabled).length}/{providers.length}</div>
              <div className="text-[10px] text-muted-foreground">Providers active</div>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* ── Global IOC Search ──────────────────────────────────────── */}
      <Card>
        <CardContent className="px-3 py-2.5">
          <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); void handleIocSearch(); }}>
            <ScanSearch className="h-4 w-4 shrink-0 text-muted-foreground" />
            <input
              type="text"
              value={iocQuery}
              onChange={(e) => setIocQuery(e.target.value)}
              placeholder="Search any IP, domain, or hash — enrichment + retro-hunt across all events..."
              className="h-7 flex-1 rounded-md border border-border/70 bg-background/45 px-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
            />
            <Button type="submit" size="sm" className="h-7 text-xs" disabled={iocLoading || !iocQuery.trim()}>
              {iocLoading ? 'Checking...' : 'Lookup'}
            </Button>
            <Button type="button" size="sm" variant="outline" className="h-7 text-xs" disabled={retroLoading || !iocQuery.trim()} onClick={() => { setRetroQuery(iocQuery); void handleRetroHunt(iocQuery); }}>
              <History className="h-3 w-3" /> Retro-hunt
            </Button>
          </form>

          {iocHistory.length > 0 && !iocResult && !iocLoading && !retroLoading && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {iocHistory.map((h) => (
                <button key={h} type="button" className="rounded border border-border/70 bg-background/35 px-1.5 py-0.5 text-[10px] text-muted-foreground transition-colors hover:text-foreground" onClick={() => { setIocQuery(h); void handleIocSearch(h); }}>
                  {h}
                </button>
              ))}
            </div>
          )}

          {iocError && <WorkspaceStatusBanner tone="danger" className="mt-2">{iocError}</WorkspaceStatusBanner>}

          {/* Enrichment results */}
          {iocResult && (
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              <div className="flex items-center gap-2 sm:col-span-2">
                <Badge variant="outline">{iocResult.indicator_type}</Badge>
                <code className="font-mono text-xs text-foreground">{iocResult.indicator}</code>
                <Button type="button" size="sm" variant="ghost" className="ml-auto h-5 text-[10px]" onClick={() => setIocResult(null)}>Clear</Button>
              </div>

              {iocResult.abuseipdb && (
                <div className="rounded-lg border border-border/70 bg-background/35 px-3 py-2">
                  <div className="mb-1.5 text-[9px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">AbuseIPDB</div>
                  <div className="grid gap-1 text-[11px]">
                    <div className="flex justify-between"><span className="text-muted-foreground">Confidence</span><Badge variant={iocResult.abuseipdb.abuse_confidence_score > 50 ? 'destructive' : iocResult.abuseipdb.abuse_confidence_score > 20 ? 'warning' : 'success'} className="text-[9px] px-1 py-0">{iocResult.abuseipdb.abuse_confidence_score}%</Badge></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Reports</span><span className="text-foreground">{iocResult.abuseipdb.total_reports}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Country</span><span className="text-foreground">{iocResult.abuseipdb.country_code || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">ISP</span><span className="truncate text-foreground">{iocResult.abuseipdb.isp || '—'}</span></div>
                    {iocResult.abuseipdb.is_whitelisted && <Badge variant="success" className="text-[9px]">Whitelisted</Badge>}
                  </div>
                </div>
              )}

              {iocResult.virustotal && (
                <div className="rounded-lg border border-border/70 bg-background/35 px-3 py-2">
                  <div className="mb-1.5 text-[9px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">VirusTotal</div>
                  <div className="grid gap-1 text-[11px]">
                    <div className="flex justify-between"><span className="text-muted-foreground">Malicious</span><Badge variant={iocResult.virustotal.malicious > 0 ? 'destructive' : 'success'} className="text-[9px] px-1 py-0">{iocResult.virustotal.malicious}</Badge></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Suspicious</span><span className="text-foreground">{iocResult.virustotal.suspicious}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Harmless</span><span className="text-foreground">{iocResult.virustotal.harmless}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Reputation</span><span className="text-foreground">{iocResult.virustotal.reputation}</span></div>
                    {iocResult.virustotal.tags.length > 0 && <div className="flex flex-wrap gap-1 mt-0.5">{iocResult.virustotal.tags.map((tag) => <Badge key={tag} variant="outline" className="text-[8px]">{tag}</Badge>)}</div>}
                  </div>
                </div>
              )}

              {!iocResult.abuseipdb && !iocResult.virustotal && (
                <div className="rounded-lg border border-border/70 bg-background/35 px-3 py-2 text-xs text-muted-foreground sm:col-span-2">
                  No enrichment data. Providers may be disabled or keys not configured.
                </div>
              )}
            </div>
          )}

          {/* Retro-hunt results */}
          {(retroLoading || retroResults.length > 0) && (
            <div className="mt-2">
              <div className="flex items-center gap-2 mb-1.5">
                <Zap className="h-3.5 w-3.5 text-primary" />
                <span className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Retro-hunt (7 days)</span>
                {!retroLoading && <Badge variant={retroCount > 0 ? 'destructive' : 'success'} className="text-[9px] px-1 py-0">{retroCount} matches</Badge>}
                {retroLoading && <span className="text-[10px] text-muted-foreground animate-pulse">Scanning events...</span>}
              </div>
              {retroResults.length > 0 && (
                <div className="max-h-[200px] overflow-auto rounded-lg border border-border/70">
                  <table className="w-full text-[10px]">
                    <thead className="sticky top-0 bg-card text-muted-foreground">
                      <tr>
                        <th className="px-2 py-1 text-left font-medium">Time</th>
                        <th className="px-2 py-1 text-left font-medium">Host</th>
                        <th className="px-2 py-1 text-left font-medium">Src IP</th>
                        <th className="px-2 py-1 text-left font-medium">Dst IP</th>
                        <th className="px-2 py-1 text-left font-medium">Payload</th>
                      </tr>
                    </thead>
                    <tbody>
                      {retroResults.map((row, i) => (
                        <tr key={i} className="border-t border-border/50 hover:bg-muted/30">
                          <td className="whitespace-nowrap px-2 py-1 text-foreground">{String(row.event_time ?? '').slice(0, 19)}</td>
                          <td className="px-2 py-1 text-foreground">{String(row.computer_name ?? '—')}</td>
                          <td className="px-2 py-1 font-mono text-foreground">{String(row.src_ip ?? '—')}</td>
                          <td className="px-2 py-1 font-mono text-foreground">{String(row.dst_ip ?? '—')}</td>
                          <td className="max-w-[300px] truncate px-2 py-1 text-muted-foreground">{String(row.payload_preview ?? '')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {!retroLoading && retroResults.length === 0 && retroCount === 0 && (
                <div className="text-[10px] text-muted-foreground">No matches found in the last 7 days.</div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Providers + Blacklist row ──────────────────────────────── */}
      <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {[abuseipdb, virustotal].filter(Boolean).map((provider) => {
          const p = provider!;
          return (
            <Card key={p.id}>
              <CardContent className="px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5">
                    <div className={cn('h-1.5 w-1.5 rounded-full', p.configured ? (p.enabled ? 'bg-accent' : 'bg-[hsl(43_96%_58%)]') : 'bg-destructive')} />
                    <span className="text-xs font-medium text-foreground">{p.name}</span>
                    <Badge variant={p.configured ? (p.enabled ? 'success' : 'secondary') : 'destructive'} className="text-[9px] px-1 py-0">
                      {!p.configured ? 'No key' : p.enabled ? 'Active' : 'Off'}
                    </Badge>
                  </div>
                  {p.configured && (
                    <Button type="button" size="sm" variant={p.enabled ? 'outline' : 'default'} className="h-5 text-[9px] px-2" onClick={() => void handleToggle(p.id, !p.enabled)}>
                      {p.enabled ? 'Disable' : 'Enable'}
                    </Button>
                  )}
                </div>
                <div className="mt-1 flex flex-wrap gap-1.5 text-[9px] text-muted-foreground">
                  {p.capabilities.map((cap) => <span key={cap} className="rounded bg-muted/50 px-1 py-0.5">{cap.replace(/_/g, ' ')}</span>)}
                  {p.id === 'abuseipdb' && p.last_sync && <span>· Synced {rel(p.last_sync)}</span>}
                </div>
              </CardContent>
            </Card>
          );
        })}

        {/* Blacklist card */}
        {abuseipdb?.configured && (
          <Card>
            <CardContent className="flex items-center gap-2 px-3 py-2">
              <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
              <div className="min-w-0 flex-1">
                <div className="text-xs font-medium text-foreground">AbuseIPDB Blacklist</div>
                <div className="text-[9px] text-muted-foreground">
                  {abuseipdb.blacklist_count > 0 ? `${abuseipdb.blacklist_count.toLocaleString()} IPs` : 'Not synced'}
                  {abuseipdb.last_sync && ` · ${rel(abuseipdb.last_sync)}`}
                  {' · Auto 4h'}
                </div>
              </div>
              <Button type="button" size="sm" variant="outline" className="h-5 text-[9px] px-2 shrink-0" onClick={() => void handleSyncBlacklist()} disabled={syncingBlacklist}>
                <RefreshCcw className={cn('h-3 w-3', syncingBlacklist && 'animate-spin')} />
                Sync
              </Button>
            </CardContent>
          </Card>
        )}
      </section>

      {/* ── Feed Health Grid ───────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-foreground">Feeds</span>
        <span className="text-[10px] text-muted-foreground">{filteredFeeds.length} configured</span>
        <div className="relative ml-2">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
          <input type="text" value={searchValue} onChange={(e) => setSearchValue(e.target.value)} placeholder="Search..." className="h-6 w-36 rounded border border-border/70 bg-card/60 pl-7 pr-2 text-[10px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring" />
        </div>
        <div className="ml-auto flex items-center gap-2">
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value as 'all' | FeedType)} className="h-6 rounded border border-border/70 bg-card/60 px-1.5 text-[10px] text-foreground focus:outline-none focus:ring-1 focus:ring-ring">
            {FEED_TYPES.map((type) => <option key={type} value={type}>{type === 'all' ? 'All' : type.toUpperCase()}</option>)}
          </select>
          <Button type="button" size="sm" className="h-6 text-[10px] px-2" onClick={() => setShowAddForm(true)}>
            <Plus className="h-3 w-3" /> Add
          </Button>
        </div>
      </div>

      <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {!filteredFeeds.length && !loading ? (
          <div className="col-span-full"><WorkspaceEmptyState title="No feeds" body="Add a TAXII, STIX, CSV, or JSON feed to start collecting external intelligence." /></div>
        ) : (
          filteredFeeds.map((feed) => (
            <Card key={feed.feed_id} className="overflow-hidden">
              <CardContent className="p-0">
                <div className={cn('h-0.5', feedHealthColor(feed))} />
                <div className="px-3 py-2">
                  <div className="flex items-center gap-1.5">
                    <Badge variant={typeVariant(feed.feed_type)} className="text-[8px] px-1 py-0">{feed.feed_type}</Badge>
                    <span className="truncate text-xs font-medium text-foreground">{feed.name}</span>
                    <div className="ml-auto flex items-center gap-1 shrink-0">
                      <Button type="button" variant="ghost" size="sm" className="h-5 w-5 p-0" onClick={() => { setMessage('Syncing...'); void syncThreatIntelFeed(feed.feed_id).then(() => { void loadFeeds(); setMessage('Feed synced.'); }).catch((err) => setMessage(String(err))); }}>
                        <RefreshCcw className="h-3 w-3" />
                      </Button>
                      <Button type="button" variant="ghost" size="sm" className="h-5 w-5 p-0 text-destructive hover:text-destructive" onClick={() => { if (window.confirm(`Delete feed "${feed.name}"?`)) void deleteThreatIntelFeed(feed.feed_id).then(() => { void loadFeeds(); setMessage('Feed deleted.'); }).catch((err) => setMessage(String(err))); }}>
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-[9px] text-muted-foreground">
                    <span>{feed.ioc_count ?? 0} IOCs</span>
                    <span>·</span>
                    <Clock className="h-2.5 w-2.5" />
                    <span>{rel(feed.last_synced_at)}</span>
                    {!feed.enabled && <Badge variant="secondary" className="text-[8px] px-1 py-0">disabled</Badge>}
                  </div>
                  <div className="mt-0.5 truncate text-[9px] text-muted-foreground/60">{feed.url}</div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </section>

      {/* ── Add feed modal ──────────────────────────────────────────── */}
      <WorkspaceModal open={showAddForm} title="Add feed" description="Connect an external threat intelligence source." onClose={() => setShowAddForm(false)} panelClassName="max-w-lg">
        <form onSubmit={(e) => void onAddFeed(e)} className="space-y-3">
          <div><div className="mb-1 text-xs font-medium text-foreground">Name</div><Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="abuse.ch URLhaus" autoFocus /></div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div><div className="mb-1 text-xs font-medium text-foreground">Type</div><Select value={newType} onChange={(e) => setNewType(e.target.value as FeedType)}><option value="taxii">TAXII</option><option value="stix">STIX</option><option value="csv">CSV</option><option value="json">JSON</option></Select></div>
            <div><div className="mb-1 text-xs font-medium text-foreground">Sync interval (sec)</div><Input type="number" value={newInterval} onChange={(e) => setNewInterval(Number(e.target.value))} min={0} /></div>
          </div>
          <div><div className="mb-1 text-xs font-medium text-foreground">URL</div><Input value={newUrl} onChange={(e) => setNewUrl(e.target.value)} placeholder="https://..." /></div>
          <div className="flex items-center gap-2">
            <input type="checkbox" checked={newEnabled} onChange={(e) => setNewEnabled(e.target.checked)} id="feed-enabled" />
            <label htmlFor="feed-enabled" className="text-xs text-foreground">Enabled</label>
          </div>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" size="sm" onClick={() => setShowAddForm(false)}>Cancel</Button>
            <Button type="submit" size="sm" disabled={creating || !newName.trim() || !newUrl.trim()}>{creating ? 'Creating...' : 'Add feed'}</Button>
          </div>
        </form>
      </WorkspaceModal>
    </div>
  );
}
