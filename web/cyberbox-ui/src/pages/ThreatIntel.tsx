import { type FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Clock,
  ExternalLink,
  History,
  Plus,
  RefreshCcw,
  ScanSearch,
  Search,
  ShieldAlert,
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

/* ── Suggested free feeds ──────────────────────────────────────────────── */
const SUGGESTED_FEEDS = [
  { name: 'ThreatFox IOCs', type: 'json' as FeedType, url: 'https://threatfox-api.abuse.ch/api/v1/', desc: 'IPs, domains, URLs, hashes — tagged by malware family' },
  { name: 'Feodo Tracker C2', type: 'csv' as FeedType, url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv', desc: 'Botnet C2 IPs (Emotet, QakBot, Dridex)' },
  { name: 'URLhaus', type: 'csv' as FeedType, url: 'https://urlhaus.abuse.ch/downloads/csv_recent/', desc: 'Malware distribution URLs (last 30 days)' },
  { name: 'Spamhaus DROP', type: 'csv' as FeedType, url: 'https://www.spamhaus.org/drop/drop.txt', desc: 'Criminal netblocks — very high confidence' },
  { name: 'IPsum Level 3+', type: 'csv' as FeedType, url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt', desc: 'Aggregated bad IPs from 30+ sources' },
  { name: 'Emerging Threats', type: 'csv' as FeedType, url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', desc: 'Compromised IPs (Proofpoint)' },
  { name: 'Blocklist.de All', type: 'csv' as FeedType, url: 'https://lists.blocklist.de/lists/all.txt', desc: 'Attacker IPs from 700+ fail2ban sensors' },
  { name: 'PhishTank', type: 'json' as FeedType, url: 'http://data.phishtank.com/data/online-valid.json.bz2', desc: 'Verified phishing URLs' },
  { name: 'Tor Exit Nodes', type: 'csv' as FeedType, url: 'https://check.torproject.org/torbulkexitlist', desc: 'Active Tor exit node IPs' },
  { name: 'AlienVault OTX', type: 'taxii' as FeedType, url: 'https://otx.alienvault.com/taxii/', desc: 'Community threat exchange — TAXII 2.1' },
];

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

function feedHealthDot(feed: ThreatIntelFeed): string {
  if (!feed.enabled) return 'bg-muted-foreground/50';
  if (!feed.last_synced_at) return 'bg-destructive';
  const hours = (Date.now() - new Date(feed.last_synced_at).getTime()) / 3_600_000;
  const expected = Math.max(feed.auto_sync_interval_secs / 3600, 1);
  if (hours < expected * 2) return 'bg-accent';
  if (hours < expected * 6) return 'bg-[hsl(43_96%_58%)]';
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
  const [providers, setProviders] = useState<ThreatIntelProvider[]>([]);
  const [iocQuery, setIocQuery] = useState('');
  const [iocLoading, setIocLoading] = useState(false);
  const [iocResult, setIocResult] = useState<EnrichmentResult | null>(null);
  const [iocError, setIocError] = useState('');
  const [iocHistory, setIocHistory] = useState<string[]>(() => loadIocHistory());
  const [retroLoading, setRetroLoading] = useState(false);
  const [retroResults, setRetroResults] = useState<Array<Record<string, unknown>>>([]);
  const [retroCount, setRetroCount] = useState(0);
  const [syncingBlacklist, setSyncingBlacklist] = useState(false);
  const [feeds, setFeeds] = useState<ThreatIntelFeed[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | FeedType>('all');
  const [searchValue, setSearchValue] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState<FeedType>('taxii');
  const [newUrl, setNewUrl] = useState('');
  const [newInterval, setNewInterval] = useState(3600);
  const [newEnabled, setNewEnabled] = useState(true);

  const loadProviders = useCallback(async () => {
    try { setProviders(await getThreatIntelProviders()); } catch { /* */ }
  }, []);
  const loadFeeds = useCallback(async () => {
    setLoading(true); setError('');
    try { setFeeds(await getThreatIntelFeeds()); }
    catch (err) { setError(String(err)); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void loadProviders(); void loadFeeds(); }, [loadProviders, loadFeeds]);

  const filteredFeeds = useMemo(() => {
    const q = searchValue.toLowerCase();
    return feeds.filter((f) => {
      if (typeFilter !== 'all' && f.feed_type !== typeFilter) return false;
      return !q || [f.name, f.url, f.feed_type].join(' ').toLowerCase().includes(q);
    });
  }, [feeds, typeFilter, searchValue]);

  const abuseipdb = providers.find((p) => p.id === 'abuseipdb');
  const virustotal = providers.find((p) => p.id === 'virustotal');
  const totalIocs = feeds.reduce((s, f) => s + (f.ioc_count ?? 0), 0);
  const staleFeeds = feeds.filter((f) => {
    if (!f.enabled || !f.last_synced_at) return false;
    return (Date.now() - new Date(f.last_synced_at).getTime()) / 3_600_000 > Math.max(f.auto_sync_interval_secs / 3600, 1) * 6;
  }).length;

  const handleToggle = async (id: string, enabled: boolean) => {
    try { await toggleThreatIntelProvider(id, enabled); await loadProviders(); setMessage(`${id} ${enabled ? 'enabled' : 'disabled'}.`); }
    catch (err) { setMessage(String(err)); }
  };
  const handleSyncBlacklist = async () => {
    setSyncingBlacklist(true); setMessage('');
    try { const r = await syncAbuseIpDbBlacklist(); await loadProviders(); setMessage(`Synced ${r.count} IPs.`); }
    catch (err) { setMessage(String(err)); }
    finally { setSyncingBlacklist(false); }
  };
  const handleIocSearch = async (indicator?: string) => {
    const q = (indicator ?? iocQuery).trim();
    if (!q) return;
    setIocLoading(true); setIocError(''); setIocResult(null);
    try {
      const result = await enrichIoc(q);
      setIocResult(result);
      const next = [q, ...iocHistory.filter((h) => h !== q)].slice(0, MAX_IOC_HISTORY);
      setIocHistory(next); saveIocHistory(next);
    } catch (err) { setIocError(String(err)); }
    finally { setIocLoading(false); }
  };
  const handleRetroHunt = async (indicator?: string) => {
    const q = (indicator ?? iocQuery).trim();
    if (!q) return;
    setRetroLoading(true); setRetroResults([]); setRetroCount(0);
    try {
      const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q);
      const isHash = /^[a-f0-9]{32,64}$/i.test(q);
      const where = isIp ? `(src_ip = '${q}' OR dst_ip = '${q}')` : isHash ? `raw_payload LIKE '%${q}%'` : `(raw_payload LIKE '%${q}%' OR dst_ip LIKE '%${q}%')`;
      const sql = `SELECT event_id, event_time, computer_name, src_ip, dst_ip, substring(raw_payload, 1, 200) as payload_preview FROM events_hot WHERE ${where} AND event_time > now() - INTERVAL 7 DAY ORDER BY event_time DESC LIMIT 50`;
      const result = await runSearch({ sql, time_range: { start: '', end: '' } });
      setRetroResults(result.rows ?? []); setRetroCount(result.total ?? (result.rows?.length ?? 0));
    } catch { setRetroCount(0); }
    finally { setRetroLoading(false); }
  };
  const onAddFeed = async (event: FormEvent) => {
    event.preventDefault(); setCreating(true); setMessage('Creating...');
    try {
      await createThreatIntelFeed({ name: newName, feed_type: newType, url: newUrl, auto_sync_interval_secs: newInterval, enabled: newEnabled });
      setNewName(''); setNewUrl(''); setNewInterval(3600); setNewEnabled(true); setShowAddForm(false);
      await loadFeeds(); setMessage('Feed created.');
    } catch (err) { setMessage(String(err)); }
    finally { setCreating(false); }
  };
  const addSuggested = (s: typeof SUGGESTED_FEEDS[0]) => {
    setNewName(s.name); setNewType(s.type); setNewUrl(s.url); setNewInterval(3600); setNewEnabled(true);
    setShowSuggestions(false); setShowAddForm(true);
  };

  return (
    <div className="flex flex-col gap-3">
      {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}
      {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

      {/* ── Stats strip ────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <div><span className="font-semibold text-foreground">{totalIocs.toLocaleString()}</span> <span className="text-muted-foreground">IOCs</span></div>
        <div><span className="font-semibold text-foreground">{feeds.filter((f) => f.enabled).length}</span> <span className="text-muted-foreground">feeds active</span></div>
        {staleFeeds > 0 && <div><span className="font-semibold text-destructive">{staleFeeds}</span> <span className="text-destructive">stale</span></div>}
        <div><span className="font-semibold text-foreground">{abuseipdb?.blacklist_count?.toLocaleString() ?? 0}</span> <span className="text-muted-foreground">blacklisted IPs</span></div>
        <div><span className="font-semibold text-foreground">{providers.filter((p) => p.enabled).length}/{providers.length}</span> <span className="text-muted-foreground">providers</span></div>
        <Button type="button" size="sm" variant="ghost" className="ml-auto h-6 text-[10px]" onClick={() => { void loadProviders(); void loadFeeds(); }}>
          <RefreshCcw className="h-3 w-3" />
        </Button>
      </div>

      {/* ── Global search bar ──────────────────────────────────────── */}
      <div className="rounded-lg border border-border/70 bg-card/80 px-3 py-2.5">
        <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); void handleIocSearch(); }}>
          <ScanSearch className="h-4 w-4 shrink-0 text-muted-foreground" />
          <input
            type="text"
            value={iocQuery}
            onChange={(e) => setIocQuery(e.target.value)}
            placeholder="Search any IP, domain, or hash — enrichment + retro-hunt..."
            className="h-7 flex-1 bg-transparent text-xs text-foreground placeholder:text-muted-foreground focus:outline-none"
          />
          <Button type="submit" size="sm" className="h-6 text-[10px] px-2.5" disabled={iocLoading || !iocQuery.trim()}>
            {iocLoading ? '...' : 'Enrich'}
          </Button>
          <Button type="button" size="sm" variant="outline" className="h-6 text-[10px] px-2.5" disabled={retroLoading || !iocQuery.trim()} onClick={() => void handleRetroHunt()}>
            <History className="h-3 w-3" /> Retro-hunt
          </Button>
        </form>

        {iocHistory.length > 0 && !iocResult && !iocLoading && !retroLoading && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {iocHistory.map((h) => (
              <button key={h} type="button" className="rounded bg-muted/40 px-1.5 py-0.5 text-[9px] text-muted-foreground hover:text-foreground" onClick={() => { setIocQuery(h); void handleIocSearch(h); }}>
                {h}
              </button>
            ))}
          </div>
        )}

        {iocError && <div className="mt-2 text-[10px] text-destructive">{iocError}</div>}

        {/* Enrichment results */}
        {iocResult && (
          <div className="mt-2 space-y-2">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-[9px]">{iocResult.indicator_type}</Badge>
              <code className="font-mono text-[11px] text-foreground">{iocResult.indicator}</code>
              <button type="button" className="ml-auto text-[9px] text-muted-foreground hover:text-foreground" onClick={() => setIocResult(null)}>Clear</button>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              {iocResult.abuseipdb && (
                <div className="space-y-1.5 rounded-md bg-muted/30 px-3 py-2">
                  <div className="text-[9px] font-semibold uppercase tracking-widest text-muted-foreground">AbuseIPDB</div>
                  <div className="flex items-baseline gap-2">
                    <span className={cn('text-xl font-bold', iocResult.abuseipdb.abuse_confidence_score > 50 ? 'text-destructive' : iocResult.abuseipdb.abuse_confidence_score > 20 ? 'text-[hsl(43_96%_58%)]' : 'text-accent')}>{iocResult.abuseipdb.abuse_confidence_score}%</span>
                    <span className="text-[10px] text-muted-foreground">confidence · {iocResult.abuseipdb.total_reports} reports</span>
                  </div>
                  <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-muted-foreground">
                    <span>{iocResult.abuseipdb.country_code || '—'}</span>
                    <span className="truncate">{iocResult.abuseipdb.isp || '—'}</span>
                    {iocResult.abuseipdb.is_whitelisted && <span className="text-accent">Whitelisted</span>}
                  </div>
                </div>
              )}
              {iocResult.virustotal && (
                <div className="space-y-1.5 rounded-md bg-muted/30 px-3 py-2">
                  <div className="text-[9px] font-semibold uppercase tracking-widest text-muted-foreground">VirusTotal</div>
                  <div className="flex items-baseline gap-2">
                    <span className={cn('text-xl font-bold', iocResult.virustotal.malicious > 0 ? 'text-destructive' : 'text-accent')}>{iocResult.virustotal.malicious}</span>
                    <span className="text-[10px] text-muted-foreground">malicious · {iocResult.virustotal.suspicious} suspicious · {iocResult.virustotal.harmless} clean</span>
                  </div>
                  <div className="flex flex-wrap gap-1 text-[10px]">
                    <span className="text-muted-foreground">Rep: {iocResult.virustotal.reputation}</span>
                    {iocResult.virustotal.tags.map((t) => <span key={t} className="rounded bg-primary/10 px-1 py-0.5 text-[8px] text-primary">{t}</span>)}
                  </div>
                </div>
              )}
              {!iocResult.abuseipdb && !iocResult.virustotal && (
                <div className="rounded-md bg-muted/30 px-3 py-2 text-[10px] text-muted-foreground sm:col-span-2">No data. Providers may be disabled.</div>
              )}
            </div>
          </div>
        )}

        {/* Retro-hunt results */}
        {(retroLoading || retroResults.length > 0 || retroCount === 0 && !retroLoading && retroResults.length === 0 && iocQuery && retroCount === 0 && retroResults !== undefined && retroLoading === false && document.querySelector('[data-retro-ran]') !== null) && retroLoading || retroResults.length > 0 ? (
          <div className="mt-2">
            <div className="flex items-center gap-2 mb-1">
              <Zap className="h-3 w-3 text-primary" />
              <span className="text-[9px] font-semibold uppercase tracking-widest text-muted-foreground">Retro-hunt · 7 days</span>
              {!retroLoading && <Badge variant={retroCount > 0 ? 'destructive' : 'success'} className="text-[8px] px-1 py-0">{retroCount} hits</Badge>}
              {retroLoading && <span className="text-[9px] text-muted-foreground animate-pulse">Scanning...</span>}
            </div>
            {retroResults.length > 0 && (
              <div className="max-h-[180px] overflow-auto rounded border border-border/50 text-[10px]">
                <table className="w-full">
                  <thead className="sticky top-0 bg-card text-muted-foreground">
                    <tr><th className="px-2 py-1 text-left">Time</th><th className="px-2 py-1 text-left">Host</th><th className="px-2 py-1 text-left">Src</th><th className="px-2 py-1 text-left">Dst</th><th className="px-2 py-1 text-left">Payload</th></tr>
                  </thead>
                  <tbody>
                    {retroResults.map((row, i) => (
                      <tr key={i} className="border-t border-border/30 hover:bg-muted/20">
                        <td className="whitespace-nowrap px-2 py-0.5">{String(row.event_time ?? '').slice(0, 19)}</td>
                        <td className="px-2 py-0.5">{String(row.computer_name ?? '—')}</td>
                        <td className="px-2 py-0.5 font-mono">{String(row.src_ip ?? '—')}</td>
                        <td className="px-2 py-0.5 font-mono">{String(row.dst_ip ?? '—')}</td>
                        <td className="max-w-[250px] truncate px-2 py-0.5 text-muted-foreground">{String(row.payload_preview ?? '')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ) : null}
      </div>

      {/* ── Providers ──────────────────────────────────────────────── */}
      <div className="grid gap-2 sm:grid-cols-3">
        {[abuseipdb, virustotal].filter(Boolean).map((p) => (
          <div key={p!.id} className="flex items-center gap-2 rounded-lg border border-border/50 px-3 py-2">
            <div className={cn('h-2 w-2 rounded-full shrink-0', p!.enabled ? 'bg-accent' : p!.configured ? 'bg-muted-foreground' : 'bg-destructive')} />
            <div className="min-w-0 flex-1">
              <div className="text-xs font-medium text-foreground">{p!.name}</div>
              <div className="text-[9px] text-muted-foreground">{!p!.configured ? 'No API key' : p!.enabled ? 'Active' : 'Disabled'}</div>
            </div>
            {p!.configured && (
              <button type="button" className={cn('text-[9px] font-medium', p!.enabled ? 'text-muted-foreground hover:text-foreground' : 'text-primary')} onClick={() => void handleToggle(p!.id, !p!.enabled)}>
                {p!.enabled ? 'Disable' : 'Enable'}
              </button>
            )}
          </div>
        ))}

        {abuseipdb?.configured && (
          <div className="flex items-center gap-2 rounded-lg border border-border/50 px-3 py-2">
            <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            <div className="min-w-0 flex-1">
              <div className="text-xs font-medium text-foreground">Blacklist</div>
              <div className="text-[9px] text-muted-foreground">
                {abuseipdb.blacklist_count > 0 ? `${abuseipdb.blacklist_count.toLocaleString()} IPs` : 'Not synced'}
                {abuseipdb.last_sync && ` · ${rel(abuseipdb.last_sync)}`}
              </div>
            </div>
            <button type="button" className="text-[9px] font-medium text-primary" onClick={() => void handleSyncBlacklist()} disabled={syncingBlacklist}>
              {syncingBlacklist ? 'Syncing...' : 'Sync'}
            </button>
          </div>
        )}
      </div>

      {/* ── Feeds section ──────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        <span className="text-xs font-medium text-foreground">Feeds</span>
        <span className="text-[10px] text-muted-foreground">{filteredFeeds.length}</span>
        <div className="relative ml-1">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
          <input type="text" value={searchValue} onChange={(e) => setSearchValue(e.target.value)} placeholder="Filter..." className="h-6 w-28 rounded border border-border/50 bg-transparent pl-6 pr-2 text-[10px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring" />
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value as 'all' | FeedType)} className="h-6 rounded border border-border/50 bg-transparent px-1 text-[10px] text-foreground focus:outline-none">
            {FEED_TYPES.map((t) => <option key={t} value={t}>{t === 'all' ? 'All' : t.toUpperCase()}</option>)}
          </select>
          <Button type="button" size="sm" variant="outline" className="h-6 text-[10px] px-2" onClick={() => setShowSuggestions(true)}>
            <Zap className="h-3 w-3" /> Browse
          </Button>
          <Button type="button" size="sm" className="h-6 text-[10px] px-2" onClick={() => setShowAddForm(true)}>
            <Plus className="h-3 w-3" /> Add
          </Button>
        </div>
      </div>

      {/* Feed grid */}
      <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
        {!filteredFeeds.length && !loading ? (
          <div className="col-span-full py-6">
            <WorkspaceEmptyState title="No feeds configured" body="Browse suggested feeds or add a custom TAXII/STIX/CSV/JSON source." />
          </div>
        ) : (
          filteredFeeds.map((feed) => (
            <div key={feed.feed_id} className="group flex items-center gap-2 rounded-lg border border-border/50 px-2.5 py-2 transition-colors hover:border-border">
              <div className={cn('h-1.5 w-1.5 rounded-full shrink-0', feedHealthDot(feed))} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1">
                  <span className="truncate text-[11px] font-medium text-foreground">{feed.name}</span>
                  <Badge variant={typeVariant(feed.feed_type)} className="text-[7px] px-1 py-0 shrink-0">{feed.feed_type}</Badge>
                </div>
                <div className="flex items-center gap-1.5 text-[9px] text-muted-foreground">
                  <span>{feed.ioc_count ?? 0} IOCs</span>
                  <span>·</span>
                  <span>{rel(feed.last_synced_at)}</span>
                  {!feed.enabled && <span className="text-muted-foreground/50">· off</span>}
                </div>
              </div>
              <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                <button type="button" className="rounded p-1 text-muted-foreground hover:text-foreground" onClick={() => { setMessage('Syncing...'); void syncThreatIntelFeed(feed.feed_id).then(() => { void loadFeeds(); setMessage('Synced.'); }).catch((err) => setMessage(String(err))); }}>
                  <RefreshCcw className="h-3 w-3" />
                </button>
                <button type="button" className="rounded p-1 text-muted-foreground hover:text-destructive" onClick={() => { if (window.confirm(`Delete "${feed.name}"?`)) void deleteThreatIntelFeed(feed.feed_id).then(() => { void loadFeeds(); setMessage('Deleted.'); }).catch((err) => setMessage(String(err))); }}>
                  <Trash2 className="h-3 w-3" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* ── Suggested feeds modal ──────────────────────────────────── */}
      <WorkspaceModal open={showSuggestions} title="Free threat intel feeds" description="One-click add popular community feeds." onClose={() => setShowSuggestions(false)} panelClassName="max-w-2xl">
        <div className="grid gap-1.5 sm:grid-cols-2">
          {SUGGESTED_FEEDS.map((s) => (
            <button key={s.name} type="button" className="flex items-start gap-2 rounded-lg border border-border/50 px-3 py-2 text-left transition-colors hover:border-primary/30 hover:bg-primary/5" onClick={() => addSuggested(s)}>
              <Badge variant={typeVariant(s.type)} className="mt-0.5 text-[7px] px-1 py-0 shrink-0">{s.type}</Badge>
              <div className="min-w-0">
                <div className="text-xs font-medium text-foreground">{s.name}</div>
                <div className="text-[10px] text-muted-foreground">{s.desc}</div>
              </div>
              <Plus className="h-3.5 w-3.5 shrink-0 text-muted-foreground mt-0.5" />
            </button>
          ))}
        </div>
      </WorkspaceModal>

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
