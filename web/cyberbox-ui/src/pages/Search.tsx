import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Bot, Columns3, Download, Pause, Play, Radio, RefreshCcw, Search as SearchIcon, Sparkles, Square, X } from 'lucide-react';

import { connectEventSSE, naturalLanguageQuery, runSearch, type SearchQueryResponse, type TimeRange } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { WorkspaceTableShell } from '@/components/workspace/table-shell';
import { cn } from '@/lib/utils';

type Mode = 'sql' | 'nlq' | 'live';
type HistoryEntry = { mode: 'sql' | 'nlq'; query: string; ts: number };

const HISTORY_KEY = 'cyberbox-search-history';
const MAX_HISTORY = 20;
const LIVE_TAIL_MAX = 500;
const QUICK_RANGES = [{ label: '15m', hours: 0.25 }, { label: '1h', hours: 1 }, { label: '4h', hours: 4 }, { label: '12h', hours: 12 }, { label: '24h', hours: 24 }, { label: '7d', hours: 168 }, { label: '30d', hours: 720 }];
const SAVED_QUERIES = [
  { label: 'Failed Logins', sql: "raw_payload LIKE '%login%' AND raw_payload LIKE '%failed%'" },
  { label: 'Suspicious Processes', sql: "raw_payload LIKE '%mimikatz%' OR raw_payload LIKE '%certutil%' OR raw_payload LIKE '%rundll32%' OR raw_payload LIKE '%wmic%'" },
  { label: 'Lateral Movement', sql: "raw_payload LIKE '%445%' OR raw_payload LIKE '%3389%' OR raw_payload LIKE '%5985%'" },
  { label: 'Encoded PowerShell', sql: "raw_payload LIKE '%powershell%' AND raw_payload LIKE '%-enc%'" },
];
const fieldClass = 'flex h-8 w-full rounded-lg border border-border/80 bg-background/45 px-3 py-1 text-xs text-foreground transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring';

function loadHistory(): HistoryEntry[] { try { return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]') as HistoryEntry[]; } catch { return []; } }
function saveHistory(entries: HistoryEntry[]) { localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, MAX_HISTORY))); }
function defaultRange() { const now = new Date(); const from = new Date(now.getTime() - 3600000); const fmt = (d: Date) => d.toISOString().slice(0, 16); return { from: fmt(from), to: fmt(now) }; }
function normalizeLocal(value: string | null, fallback: string) { const parsed = value ? new Date(value) : null; return parsed && !Number.isNaN(parsed.getTime()) ? parsed.toISOString().slice(0, 16) : fallback; }
function parseCursor(cursor?: string) { const page = Number.parseInt(cursor ?? '1', 10); return Number.isFinite(page) && page > 0 ? page : 1; }
function relativeTime(ts: number) { const diff = Date.now() - ts; if (diff < 60000) return 'just now'; if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`; if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`; return `${Math.floor(diff / 86400000)}d ago`; }
function searchError(error: unknown) { const message = error instanceof Error ? error.message : String(error); return message.toLowerCase().includes('authentication') || message.includes('API 401') ? 'Your session expired or you are not authorized to search.' : message; }
function formatTimestamp(ts: string) { try { const d = new Date(ts); return `${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })} ${d.toLocaleDateString([], { month: 'short', day: 'numeric' })}`; } catch { return ts; } }
function exportCsv(rows: Array<Record<string, unknown>>, columns: string[]) { const header = columns.join(','); const body = rows.map((row) => columns.map((col) => { const value = row[col]; const text = typeof value === 'object' ? JSON.stringify(value) : String(value ?? ''); return text.includes(',') || text.includes('"') ? `"${text.replace(/"/g, '""')}"` : text; }).join(',')).join('\n'); const blob = new Blob([`${header}\n${body}`], { type: 'text/csv' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `cyberbox-search-${Date.now()}.csv`; link.click(); }
function filterRows(rows: Array<Record<string, unknown>>, value: string) { if (!value.trim()) return rows; const query = value.toLowerCase(); return rows.filter((row) => Object.values(row).some((item) => String(item ?? '').toLowerCase().includes(query))); }
function sevVariant(value: string): 'destructive' | 'warning' | 'info' | 'secondary' { if (value === 'critical') return 'destructive'; if (value === 'high') return 'warning'; if (value === 'medium') return 'info'; return 'secondary'; }
function DetailDrawer({ row, columns, onClose }: { row: Record<string, unknown>; columns: string[]; onClose: () => void }) {
  return <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm" onClick={onClose}><div className="absolute inset-y-4 right-4 w-[min(48rem,calc(100vw-2rem))] overflow-auto rounded-xl border border-border/80 bg-popover/95 p-5 shadow-shell backdrop-blur-2xl" onClick={(e) => e.stopPropagation()}><div className="mb-4 flex items-center justify-between gap-3"><div><div className="font-display text-2xl font-semibold text-popover-foreground">Event detail</div><div className="text-sm text-muted-foreground">Inspect the raw fields for this result row.</div></div><Button type="button" variant="ghost" size="icon" onClick={onClose}><X className="h-4 w-4" /></Button></div><div className="space-y-3">{columns.map((col) => <div key={col} className="rounded-lg border border-border/70 bg-background/35 p-4"><div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">{col}</div>{row[col] !== null && typeof row[col] === 'object' ? <pre className="overflow-x-auto text-xs text-foreground">{JSON.stringify(row[col], null, 2)}</pre> : <div className="break-all text-sm text-foreground">{String(row[col] ?? '')}</div>}</div>)}</div></div></div>;
}
export function Search() {
  const [searchParams, setSearchParams] = useSearchParams();
  const defaults = useMemo(defaultRange, []);
  const queryParam = searchParams.get('q') ?? '';
  const queryFromParam = searchParams.get('from');
  const queryToParam = searchParams.get('to');
  const [mode, setMode] = useState<Mode>('sql');
  const [sqlText, setSqlText] = useState(queryParam);
  const [nlqText, setNlqText] = useState('');
  const [timeFrom, setTimeFrom] = useState(() => normalizeLocal(queryFromParam, defaults.from));
  const [timeTo, setTimeTo] = useState(() => normalizeLocal(queryToParam, defaults.to));
  const [activeQuickRange, setActiveQuickRange] = useState('1h');
  const [rows, setRows] = useState<Array<Record<string, unknown>>>([]);
  const [hasMore, setHasMore] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [total, setTotal] = useState<number | undefined>();
  const [generatedFilter, setGeneratedFilter] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);
  const [sortCol, setSortCol] = useState<string | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const [selectedRow, setSelectedRow] = useState<Record<string, unknown> | null>(null);
  const [hiddenCols, setHiddenCols] = useState<Set<string>>(new Set());
  const [columnPanelOpen, setColumnPanelOpen] = useState(false);
  const [queryDuration, setQueryDuration] = useState<number | null>(null);
  const [liveTailActive, setLiveTailActive] = useState(false);
  const [liveTailPaused, setLiveTailPaused] = useState(false);
  const [liveTailFilter, setLiveTailFilter] = useState('');
  const [liveTailCount, setLiveTailCount] = useState(0);
  const [liveTailEps, setLiveTailEps] = useState(0);
  const liveRowsRef = useRef<Array<Record<string, unknown>>>([]);
  const sseRef = useRef<EventSource | null>(null);
  const epsWindowRef = useRef<number[]>([]);
  const liveFilterRef = useRef(liveTailFilter);
  const livePausedRef = useRef(liveTailPaused);
  const autoRunQueryRef = useRef<string | null>(null);

  useEffect(() => { saveHistory(history); }, [history]);
  useEffect(() => { liveFilterRef.current = liveTailFilter; if (mode === 'live') setRows(filterRows(liveRowsRef.current, liveTailFilter)); }, [liveTailFilter, mode]);
  useEffect(() => { livePausedRef.current = liveTailPaused; }, [liveTailPaused]);

  const buildTimeRange = useCallback((): TimeRange => ({ start: new Date(timeFrom).toISOString(), end: new Date(timeTo).toISOString() }), [timeFrom, timeTo]);
  const pushHistory = useCallback((nextMode: 'sql' | 'nlq', query: string) => setHistory((curr) => [{ mode: nextMode, query, ts: Date.now() }, ...curr.filter((entry) => entry.query !== query)].slice(0, MAX_HISTORY)), []);

  const stopLiveTail = useCallback(() => { if (sseRef.current) sseRef.current.close(); sseRef.current = null; setLiveTailActive(false); setLiveTailPaused(false); setLiveTailEps(0); }, []);
  const startLiveTail = useCallback(async () => {
    stopLiveTail();
    liveRowsRef.current = [];
    epsWindowRef.current = [];
    setRows([]);
    setLiveTailCount(0);
    setLiveTailEps(0);
    setLiveTailActive(true);
    setError('');
    try {
      const sse = await connectEventSSE();
      sseRef.current = sse;
      sse.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data) as Record<string, unknown>;
          liveRowsRef.current = [event, ...liveRowsRef.current].slice(0, LIVE_TAIL_MAX);
          epsWindowRef.current.push(Date.now());
          epsWindowRef.current = epsWindowRef.current.filter((ts) => ts > Date.now() - 1000);
          setLiveTailEps(epsWindowRef.current.length);
          setLiveTailCount((value) => value + 1);
          if (!livePausedRef.current) setRows(filterRows(liveRowsRef.current, liveFilterRef.current));
        } catch {}
      };
      sse.onerror = () => {
        setError('Live tail connection lost. Reconnecting...');
        if (sseRef.current) sseRef.current.close();
        sseRef.current = null;
        window.setTimeout(() => { void startLiveTail(); }, 2000);
      };
    } catch {
      setError('Failed to start live tail. The API may be unreachable.');
      setLiveTailActive(false);
    }
  }, [stopLiveTail]);

  useEffect(() => () => { if (sseRef.current) sseRef.current.close(); }, []);
  useEffect(() => { if (mode === 'live' && !liveTailActive) void startLiveTail(); if (mode !== 'live' && liveTailActive) stopLiveTail(); }, [liveTailActive, mode, startLiveTail, stopLiveTail]);

  const applyQuickRange = (hours: number, label: string) => {
    const now = new Date();
    const from = new Date(now.getTime() - hours * 3600000);
    const fmt = (d: Date) => d.toISOString().slice(0, 16);
    setTimeFrom(fmt(from));
    setTimeTo(fmt(now));
    setActiveQuickRange(label);
  };

  const executeSqlSearch = useCallback(async (query: string, page = 1, append = false, updateUrl = true, override?: TimeRange) => {
    const startedAt = Date.now();
    setLoading(true);
    setError('');
    try {
      const response: SearchQueryResponse = await runSearch({ sql: query, time_range: override ?? buildTimeRange(), pagination: { page, page_size: 50 } });
      setRows((current) => append ? [...current, ...response.rows] : response.rows);
      setHasMore(response.has_more);
      setNextCursor(response.next_cursor);
      setTotal(response.total);
      setGeneratedFilter(null);
      if (!append) pushHistory('sql', query);
      if (updateUrl) query ? setSearchParams({ q: query, from: new Date(timeFrom).toISOString(), to: new Date(timeTo).toISOString() }, { replace: true }) : setSearchParams(new URLSearchParams(), { replace: true });
    } catch (cause) {
      setError(searchError(cause));
    } finally {
      setLoading(false);
      setQueryDuration(Date.now() - startedAt);
    }
  }, [buildTimeRange, pushHistory, setSearchParams, timeFrom, timeTo]);

  const executeNlqSearch = useCallback(async (query: string) => {
    const startedAt = Date.now();
    setLoading(true);
    setError('');
    try {
      const response = await naturalLanguageQuery({ query, time_range: buildTimeRange() });
      setRows(response.rows);
      setHasMore(false);
      setNextCursor(undefined);
      setTotal(response.total);
      setGeneratedFilter(response.generated_where);
      pushHistory('nlq', query);
      setSearchParams(new URLSearchParams(), { replace: true });
    } catch (cause) {
      setError(searchError(cause));
    } finally {
      setLoading(false);
      setQueryDuration(Date.now() - startedAt);
    }
  }, [buildTimeRange, pushHistory, setSearchParams]);

  const executeSearch = useCallback(async (cursor?: string) => {
    if (mode === 'sql') await executeSqlSearch(sqlText, parseCursor(cursor), Boolean(cursor));
    else if (mode === 'nlq') await executeNlqSearch(nlqText);
  }, [executeNlqSearch, executeSqlSearch, mode, nlqText, sqlText]);

  useEffect(() => {
    if (!queryParam) { autoRunQueryRef.current = null; return; }
    if (autoRunQueryRef.current === queryParam) return;
    autoRunQueryRef.current = queryParam;
    const nextFrom = normalizeLocal(queryFromParam, defaults.from);
    const nextTo = normalizeLocal(queryToParam, defaults.to);
    setMode('sql');
    setSqlText(queryParam);
    setTimeFrom(nextFrom);
    setTimeTo(nextTo);
    setActiveQuickRange('');
    void executeSqlSearch(queryParam, 1, false, false, { start: new Date(nextFrom).toISOString(), end: new Date(nextTo).toISOString() });
  }, [defaults.from, defaults.to, executeSqlSearch, queryFromParam, queryParam, queryToParam]);

  const columns = useMemo(() => {
    const keys = new Set<string>();
    rows.forEach((row) => Object.keys(row).forEach((key) => keys.add(key)));
    const sorted = Array.from(keys).filter((key) => key !== '_time' && key !== 'event_time').sort();
    if (keys.has('_time')) sorted.unshift('_time'); else if (keys.has('event_time')) sorted.unshift('event_time');
    return sorted;
  }, [rows]);
  const visibleColumns = useMemo(() => columns.filter((column) => !hiddenCols.has(column)), [columns, hiddenCols]);
  const sortedRows = useMemo(() => !sortCol ? rows : [...rows].sort((left, right) => { const a = left[sortCol] ?? ''; const b = right[sortCol] ?? ''; const cmp = String(a).localeCompare(String(b), undefined, { numeric: true }); return sortAsc ? cmp : -cmp; }), [rows, sortAsc, sortCol]);
  const uniqueHosts = useMemo(() => new Set(rows.map((row) => String(row.hostname ?? '')).filter(Boolean)).size, [rows]);
  const uniqueSources = useMemo(() => new Set(rows.map((row) => String(row.source ?? row.log_source ?? '')).filter(Boolean)).size, [rows]);
  const severityCounts = useMemo(() => rows.reduce<Record<string, number>>((acc, row) => { const sev = String(row.severity ?? '').toLowerCase(); if (sev) acc[sev] = (acc[sev] ?? 0) + 1; return acc; }, {}), [rows]);

  const onSubmit = (event: FormEvent) => { event.preventDefault(); void executeSearch(); };
  const onHistorySelect = (entry: HistoryEntry) => { if (entry.mode === 'sql') { setMode('sql'); setSqlText(entry.query); } else { setMode('nlq'); setNlqText(entry.query); } };
  const toggleColumn = (column: string) => setHiddenCols((current) => { const next = new Set(current); if (next.has(column)) next.delete(column); else next.add(column); return next; });

  return (
    <div className="flex flex-col gap-2">
      {/* ── Query bar ────────────────────────────────────────────────── */}
      <form onSubmit={onSubmit}>
        <div className="flex items-center gap-2 border-b border-border/50 pb-2">
          <div className="flex items-center gap-1 rounded-lg border border-border/70 bg-card/60 p-0.5">
            {(['sql', 'nlq', 'live'] as Mode[]).map((value) => (
              <button key={value} type="button" onClick={() => setMode(value)} className={cn('rounded-md px-2.5 py-1 text-xs font-medium transition-colors', mode === value ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}>
                {value === 'sql' ? 'SQL' : value === 'nlq' ? 'AI' : 'Live'}{value === 'live' && liveTailActive && <span className="ml-1 inline-block h-1.5 w-1.5 rounded-full bg-accent" />}
              </button>
            ))}
          </div>

          {mode !== 'live' && (
            <div className="flex items-center gap-1 rounded-lg border border-border/70 bg-card/60 p-0.5">
              {QUICK_RANGES.map((range) => (
                <button key={range.label} type="button" onClick={() => applyQuickRange(range.hours, range.label)} className={cn('rounded-md px-2 py-1 text-[10px] font-medium transition-colors', activeQuickRange === range.label ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}>
                  {range.label}
                </button>
              ))}
            </div>
          )}

          {mode !== 'live' && (
            <>
              <input type="datetime-local" value={timeFrom} onChange={(e) => { setTimeFrom(e.target.value); setActiveQuickRange(''); }} className="h-7 rounded-md border border-border/70 bg-card/60 px-2 text-[10px] text-foreground focus:outline-none focus:ring-1 focus:ring-ring" />
              <input type="datetime-local" value={timeTo} onChange={(e) => { setTimeTo(e.target.value); setActiveQuickRange(''); }} className="h-7 rounded-md border border-border/70 bg-card/60 px-2 text-[10px] text-foreground focus:outline-none focus:ring-1 focus:ring-ring" />
            </>
          )}

          {mode !== 'live' ? (
            <Button type="submit" size="sm" disabled={loading}><SearchIcon className="h-3.5 w-3.5" />{loading ? 'Running...' : mode === 'sql' ? 'Search' : 'Ask AI'}</Button>
          ) : (
            <div className="flex items-center gap-2">
              <Badge variant={liveTailActive ? 'success' : 'outline'}>{liveTailActive ? 'Live' : 'Stopped'}</Badge>
              <span className="text-[10px] text-muted-foreground">{liveTailEps} eps · {liveTailCount.toLocaleString()}</span>
              {liveTailActive && <Button type="button" variant="outline" size="sm" onClick={() => setLiveTailPaused((v) => { if (v) setRows(filterRows(liveRowsRef.current, liveFilterRef.current)); return !v; })}>{liveTailPaused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}</Button>}
              {!liveTailActive ? <Button type="button" size="sm" onClick={() => void startLiveTail()}><Radio className="h-3 w-3" />Start</Button> : <Button type="button" variant="destructive" size="sm" onClick={stopLiveTail}><Square className="h-3 w-3" />Stop</Button>}
            </div>
          )}

          {/* Saved query dropdown */}
          <div className="ml-auto flex items-center gap-1.5">
            {SAVED_QUERIES.map((q) => (
              <button key={q.label} type="button" onClick={() => { setMode('sql'); setSqlText(q.sql); }} className="rounded-md border border-border/70 bg-card/60 px-2 py-1 text-[10px] text-muted-foreground transition-colors hover:text-foreground" title={q.sql}>
                {q.label}
              </button>
            ))}
          </div>
        </div>

        {/* Query input */}
        {mode === 'sql' && <Textarea value={sqlText} onChange={(e) => setSqlText(e.target.value)} className="mt-2 min-h-[60px] rounded-lg border-border/50 bg-card/40 font-mono text-[11px] focus:border-primary/40" placeholder="raw_payload LIKE '%failed%'  (empty = all events, Ctrl+Enter to run)" spellCheck={false} onKeyDown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); void executeSearch(); } }} />}
        {mode === 'nlq' && <Textarea value={nlqText} onChange={(e) => setNlqText(e.target.value)} className="mt-2 min-h-[48px] rounded-lg border-border/50 bg-card/40 text-xs focus:border-primary/40" placeholder="Show me failed SSH logins from the last 4 hours" spellCheck={false} onKeyDown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); void executeSearch(); } }} />}
        {mode === 'live' && <input value={liveTailFilter} onChange={(e) => setLiveTailFilter(e.target.value)} placeholder="Filter live events..." className="mt-2 h-8 w-full rounded-lg border border-border/50 bg-card/40 px-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring" />}
      </form>

      {generatedFilter && (
        <div className="rounded-md border border-primary/20 bg-primary/5 px-3 py-1.5">
          <span className="text-[10px] text-primary">AI generated:</span>
          <code className="ml-2 font-mono text-[10px] text-foreground">{generatedFilter}</code>
        </div>
      )}
      {error && <WorkspaceStatusBanner tone="danger">{error}</WorkspaceStatusBanner>}

      {/* ── Results toolbar ───────────────────────────────────────────── */}
      <div className="flex items-center gap-3 border-b border-border/50 pb-2">
        <span className="text-xs text-foreground">{rows.length.toLocaleString()} results</span>
        {total && total > rows.length && <span className="text-[10px] text-muted-foreground">of {total.toLocaleString()}</span>}
        <span className="text-[10px] text-muted-foreground">{uniqueHosts} hosts · {uniqueSources} sources</span>
        {queryDuration != null && <span className="text-[10px] text-muted-foreground">{queryDuration}ms</span>}
        {Object.keys(severityCounts).length > 0 && Object.entries(severityCounts).map(([sev, count]) => <Badge key={sev} variant={sevVariant(sev)} className="text-[9px]">{count} {sev}</Badge>)}
        <div className="ml-auto flex items-center gap-1.5">
          <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-[10px]" onClick={() => setColumnPanelOpen((v) => !v)}><Columns3 className="h-3 w-3" />Columns</Button>
          <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-[10px]" onClick={() => exportCsv(rows, visibleColumns)} disabled={rows.length === 0}><Download className="h-3 w-3" />CSV</Button>
          <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-[10px]" onClick={() => void executeSearch()} disabled={mode === 'live' || loading}><RefreshCcw className="h-3 w-3" /></Button>
        </div>
      </div>

      {columnPanelOpen && (
        <div className="flex flex-wrap gap-1.5 pb-2">
          {columns.map((col) => (
            <label key={col} className="flex items-center gap-1.5 rounded-md border border-border/70 px-2 py-1 text-[10px] text-foreground">
              <input type="checkbox" className="h-3 w-3" checked={!hiddenCols.has(col)} onChange={() => toggleColumn(col)} />{col}
            </label>
          ))}
        </div>
      )}

      {/* ── Results table ─────────────────────────────────────────────── */}
      {rows.length === 0 && !loading ? (
        <div className="flex min-h-[200px] items-center justify-center text-sm text-muted-foreground">
          {mode === 'live' ? 'Start the live tail to see events' : 'Run a query to explore events'}
        </div>
      ) : loading && rows.length === 0 ? (
        <div className="flex min-h-[200px] items-center justify-center text-sm text-muted-foreground">Searching...</div>
      ) : (
        <WorkspaceTableShell className="bg-transparent">
          <table className="min-w-full text-xs">
            <thead>
              <tr className="border-b border-border/50">
                <th className="px-2 py-1.5 text-left text-[10px] uppercase tracking-[0.2em] text-muted-foreground">#</th>
                {visibleColumns.map((col) => (
                  <th key={col} className="cursor-pointer px-2 py-1.5 text-left text-[10px] uppercase tracking-[0.2em] text-muted-foreground hover:text-foreground" onClick={() => { if (sortCol === col) setSortAsc((v) => !v); else { setSortCol(col); setSortAsc(true); } }}>
                    {col}{sortCol === col && <span className="ml-1">{sortAsc ? '▲' : '▼'}</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sortedRows.map((row, i) => (
                <tr key={`${i}-${String(row._time ?? row.event_time ?? '')}`} className="cursor-pointer border-b border-border/30 transition-colors hover:bg-muted/30" onClick={() => setSelectedRow(row)}>
                  <td className="px-2 py-1.5 text-muted-foreground">{i + 1}</td>
                  {visibleColumns.map((col) => (
                    <td key={col} className="max-w-[280px] px-2 py-1.5 align-top text-foreground">
                      {col === 'severity' && typeof row[col] === 'string' ? <Badge variant={sevVariant(String(row[col]))}>{String(row[col])}</Badge>
                        : (col === '_time' || col === 'event_time') && typeof row[col] === 'string' ? <span className="text-muted-foreground">{formatTimestamp(String(row[col]))}</span>
                        : row[col] !== null && typeof row[col] === 'object' ? <span className="text-muted-foreground">{'{...}'}</span>
                        : <span className="line-clamp-2 break-all">{String(row[col] ?? '')}</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </WorkspaceTableShell>
      )}

      {hasMore && nextCursor && (
        <div className="flex justify-center py-2">
          <Button type="button" variant="outline" size="sm" onClick={() => void executeSqlSearch(sqlText, parseCursor(nextCursor), true)} disabled={loading}>{loading ? 'Loading...' : 'Load more'}</Button>
        </div>
      )}

      {selectedRow && <DetailDrawer row={selectedRow} columns={columns} onClose={() => setSelectedRow(null)} />}
    </div>
  );
}
