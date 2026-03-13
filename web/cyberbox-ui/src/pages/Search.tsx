import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  connectEventSSE,
  naturalLanguageQuery,
  NlqResponse,
  runSearch,
  SearchQueryResponse,
  TimeRange,
} from '../api/client';

/* ── SVG Icons ──────────────────────────────────── */

const searchIcon = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>
);
const playIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="5 3 19 12 5 21 5 3"/>
  </svg>
);
const clockIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
  </svg>
);
const expandIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/>
  </svg>
);
const collapseIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="14" y1="10" x2="21" y2="3"/><line x1="3" y1="21" x2="10" y2="14"/>
  </svg>
);
const downloadIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
  </svg>
);
const columnsIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="3" x2="9" y2="21"/><line x1="15" y1="3" x2="15" y2="21"/>
  </svg>
);
const chevronDown = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="6 9 12 15 18 9"/>
  </svg>
);
const chevronRight = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="9 18 15 12 9 6"/>
  </svg>
);
const xIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
  </svg>
);
const terminalIcon = (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
  </svg>
);
const sparkleIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 2l2.09 6.26L20 10l-5.91 1.74L12 18l-2.09-6.26L4 10l5.91-1.74L12 2z"/>
  </svg>
);

const radioIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
  </svg>
);
const pauseIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>
  </svg>
);
const stopIcon = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="18" height="18" rx="2"/>
  </svg>
);

/* ── Constants ──────────────────────────────────── */

const HISTORY_KEY = 'cyberbox-search-history';
const MAX_HISTORY = 20;
const LIVE_TAIL_MAX = 500;

const QUICK_RANGES = [
  { label: '15m', hours: 0.25 },
  { label: '1h', hours: 1 },
  { label: '4h', hours: 4 },
  { label: '12h', hours: 12 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
  { label: '30d', hours: 720 },
];

const SAVED_QUERIES = [
  { label: 'Failed Logins', sql: "SELECT * FROM events WHERE event_type = 'LoginAttempt' AND status = 'failed' ORDER BY _time DESC LIMIT 100" },
  { label: 'Suspicious Processes', sql: "SELECT * FROM events WHERE process_name IN ('mimikatz.exe','certutil.exe','rundll32.exe','wmic.exe') ORDER BY _time DESC LIMIT 50" },
  { label: 'Lateral Movement', sql: "SELECT * FROM events WHERE dst_port IN (445, 3389, 5985) AND src_ip != dst_ip ORDER BY _time DESC LIMIT 100" },
  { label: 'DNS Exfiltration', sql: "SELECT * FROM events WHERE log_source = 'dns' AND LENGTH(query) > 60 ORDER BY _time DESC LIMIT 50" },
  { label: 'Encoded PowerShell', sql: "SELECT * FROM events WHERE process_name = 'powershell.exe' AND command_line LIKE '%-enc%' ORDER BY _time DESC LIMIT 50" },
  { label: 'High Severity Events', sql: "SELECT * FROM events WHERE severity IN ('high','critical') ORDER BY _time DESC LIMIT 100" },
];

/* ── Helpers ────────────────────────────────────── */

interface HistoryEntry {
  mode: 'sql' | 'nlq';
  query: string;
  ts: number;
}

function loadHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
  } catch { return []; }
}

function saveHistory(entries: HistoryEntry[]) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, MAX_HISTORY)));
}

function relativeTime(ts: number): string {
  const diff = Date.now() - ts;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function defaultTimeRange(): { from: string; to: string } {
  const now = new Date();
  const from = new Date(now.getTime() - 3_600_000);
  const fmt = (d: Date) => d.toISOString().slice(0, 16);
  return { from: fmt(from), to: fmt(now) };
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  } catch { return ts; }
}

function severityClass(sev: string): string {
  switch (sev?.toLowerCase()) {
    case 'critical': return 'sq-sev sq-sev--critical';
    case 'high': return 'sq-sev sq-sev--high';
    case 'medium': return 'sq-sev sq-sev--medium';
    case 'low': return 'sq-sev sq-sev--low';
    default: return 'sq-sev sq-sev--info';
  }
}

function exportCsv(rows: Array<Record<string, unknown>>, columns: string[]) {
  const header = columns.join(',');
  const lines = rows.map((r) =>
    columns.map((c) => {
      const v = r[c];
      const s = typeof v === 'object' ? JSON.stringify(v) : String(v ?? '');
      return s.includes(',') || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
    }).join(','),
  );
  const blob = new Blob([header + '\n' + lines.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `cyberbox-search-${Date.now()}.csv`;
  a.click();
}

/* ── Row Detail Drawer ─────────────────────────── */

function RowDetail({ row, columns, onClose }: {
  row: Record<string, unknown>;
  columns: string[];
  onClose: () => void;
}) {
  return (
    <div className="sq-drawer-overlay" onClick={onClose}>
      <div className="sq-drawer" onClick={(e) => e.stopPropagation()}>
        <div className="sq-drawer-header">
          <span className="sq-drawer-title">Event Detail</span>
          <button type="button" className="sq-drawer-close" onClick={onClose}>{xIcon}</button>
        </div>
        <div className="sq-drawer-body">
          {columns.map((col) => {
            const val = row[col];
            const isObj = val !== null && typeof val === 'object';
            return (
              <div key={col} className="sq-field-row">
                <span className="sq-field-key">{col}</span>
                {isObj ? (
                  <pre className="sq-field-json">{JSON.stringify(val, null, 2)}</pre>
                ) : (
                  <span className="sq-field-val">{String(val ?? '')}</span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ── CellValue ─────────────────────────────────── */

function CellValue({ value, col }: { value: unknown; col: string }) {
  if (value === null || value === undefined) {
    return <span className="sq-null">null</span>;
  }
  if (col === 'severity' && typeof value === 'string') {
    return <span className={severityClass(value)}>{value}</span>;
  }
  if (col === '_time' && typeof value === 'string') {
    return <span className="sq-time-val">{formatTimestamp(value)}</span>;
  }
  if (typeof value === 'object') {
    return <span className="sq-json-badge">{'{...}'}</span>;
  }
  return <span>{String(value)}</span>;
}

/* ── Component ──────────────────────────────────── */

export function Search() {
  const [mode, setMode] = useState<'sql' | 'nlq' | 'live'>('sql');
  const [sqlText, setSqlText] = useState('SELECT * FROM events ORDER BY _time DESC LIMIT 50');
  const [nlqText, setNlqText] = useState('');
  const { from: defaultFrom, to: defaultTo } = useMemo(defaultTimeRange, []);
  const [timeFrom, setTimeFrom] = useState(defaultFrom);
  const [timeTo, setTimeTo] = useState(defaultTo);
  const [activeQuickRange, setActiveQuickRange] = useState<string>('1h');
  const [rows, setRows] = useState<Array<Record<string, unknown>>>([]);
  const [hasMore, setHasMore] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [total, setTotal] = useState<number | undefined>();
  const [generatedSql, setGeneratedSql] = useState<string | null>(null);
  const [genSqlOpen, setGenSqlOpen] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [sortCol, setSortCol] = useState<string | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const [selectedRow, setSelectedRow] = useState<Record<string, unknown> | null>(null);
  const [editorExpanded, setEditorExpanded] = useState(false);
  const [hiddenCols, setHiddenCols] = useState<Set<string>>(new Set());
  const [colPickerOpen, setColPickerOpen] = useState(false);
  const [queryStartTime, setQueryStartTime] = useState<number | null>(null);
  const [queryDuration, setQueryDuration] = useState<number | null>(null);
  const [savedQueriesOpen, setSavedQueriesOpen] = useState(false);

  // Live tail state
  const [liveTailActive, setLiveTailActive] = useState(false);
  const [liveTailPaused, setLiveTailPaused] = useState(false);
  const [liveTailFilter, setLiveTailFilter] = useState('');
  const [liveTailCount, setLiveTailCount] = useState(0);
  const [liveTailEps, setLiveTailEps] = useState(0);
  const liveTailRows = useRef<Array<Record<string, unknown>>>([]);
  const sseRef = useRef<EventSource | null>(null);
  const epsWindow = useRef<number[]>([]);

  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => { saveHistory(history); }, [history]);

  const buildTimeRange = useCallback((): TimeRange => ({
    start: new Date(timeFrom).toISOString(),
    end: new Date(timeTo).toISOString(),
  }), [timeFrom, timeTo]);

  const pushHistory = useCallback((m: 'sql' | 'nlq', q: string) => {
    setHistory((prev) => {
      const next = [{ mode: m, query: q, ts: Date.now() }, ...prev.filter((h) => h.query !== q)];
      return next.slice(0, MAX_HISTORY);
    });
  }, []);

  // Live tail management
  const startLiveTail = useCallback(() => {
    if (sseRef.current) sseRef.current.close();
    liveTailRows.current = [];
    setRows([]);
    setLiveTailCount(0);
    setLiveTailEps(0);
    epsWindow.current = [];
    setLiveTailActive(true);
    setLiveTailPaused(false);
    setError('');

    try {
      const sse = connectEventSSE();
      sseRef.current = sse;

      sse.onmessage = (msg) => {
        try {
          const event = JSON.parse(msg.data) as Record<string, unknown>;
          // Apply filter if set
          if (liveTailFilter) {
            const filterLc = liveTailFilter.toLowerCase();
            const matches = Object.values(event).some((v) =>
              String(v ?? '').toLowerCase().includes(filterLc),
            );
            if (!matches) return;
          }

          // Track EPS
          epsWindow.current.push(Date.now());
          const oneSecAgo = Date.now() - 1000;
          epsWindow.current = epsWindow.current.filter((t) => t > oneSecAgo);
          setLiveTailEps(epsWindow.current.length);

          setLiveTailCount((c) => c + 1);

          // Prepend (newest first), cap at LIVE_TAIL_MAX
          liveTailRows.current = [event, ...liveTailRows.current].slice(0, LIVE_TAIL_MAX);
          if (!liveTailPaused) {
            setRows([...liveTailRows.current]);
          }
        } catch { /* ignore parse errors */ }
      };

      sse.onerror = () => {
        setError('Live tail connection lost. Reconnecting...');
        // EventSource auto-reconnects
      };
    } catch {
      setError('Failed to start live tail — API may be unreachable');
      setLiveTailActive(false);
    }
  }, [liveTailFilter, liveTailPaused]);

  const stopLiveTail = useCallback(() => {
    if (sseRef.current) {
      sseRef.current.close();
      sseRef.current = null;
    }
    setLiveTailActive(false);
    setLiveTailPaused(false);
    setLiveTailEps(0);
  }, []);

  const togglePauseLiveTail = useCallback(() => {
    setLiveTailPaused((p) => {
      if (p) {
        // Resuming — sync display with buffer
        setRows([...liveTailRows.current]);
      }
      return !p;
    });
  }, []);

  // Cleanup SSE on unmount
  useEffect(() => {
    return () => {
      if (sseRef.current) sseRef.current.close();
    };
  }, []);

  // When switching away from live mode, stop the tail
  useEffect(() => {
    if (mode !== 'live' && liveTailActive) stopLiveTail();
  }, [mode, liveTailActive, stopLiveTail]);

  const applyQuickRange = (hours: number, label: string) => {
    const now = new Date();
    const from = new Date(now.getTime() - hours * 3_600_000);
    const fmt = (d: Date) => d.toISOString().slice(0, 16);
    setTimeFrom(fmt(from));
    setTimeTo(fmt(now));
    setActiveQuickRange(label);
  };

  const executeSearch = useCallback(async (cursor?: string) => {
    setLoading(true);
    setError('');
    if (!cursor) setQueryStartTime(Date.now());
    try {
      if (mode === 'sql') {
        const resp: SearchQueryResponse = await runSearch({
          sql: sqlText,
          time_range: buildTimeRange(),
          pagination: { page_size: 50, cursor },
        });
        if (cursor) {
          setRows((prev) => [...prev, ...resp.rows]);
        } else {
          setRows(resp.rows);
          pushHistory('sql', sqlText);
        }
        setHasMore(resp.has_more);
        setNextCursor(resp.next_cursor);
        setTotal(resp.total);
        setGeneratedSql(null);
      } else {
        const resp: NlqResponse = await naturalLanguageQuery({
          query: nlqText,
          time_range: buildTimeRange(),
        });
        setRows(resp.rows);
        setGeneratedSql(resp.generated_sql);
        setGenSqlOpen(true);
        setHasMore(resp.has_more);
        setNextCursor(undefined);
        setTotal(resp.total);
        pushHistory('nlq', nlqText);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
      setQueryDuration(queryStartTime ? Date.now() - queryStartTime : null);
    }
  }, [mode, sqlText, nlqText, buildTimeRange, pushHistory, queryStartTime]);

  const onSubmit = (e: FormEvent) => { e.preventDefault(); executeSearch(); };
  const onLoadMore = () => { if (nextCursor) executeSearch(nextCursor); };

  const onHistorySelect = (entry: HistoryEntry) => {
    if (entry.mode === 'sql') { setMode('sql'); setSqlText(entry.query); }
    else { setMode('nlq'); setNlqText(entry.query); }
    setHistoryOpen(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      executeSearch();
    }
  };

  // Column discovery + sorting
  const columns = useMemo(() => {
    const keys = new Set<string>();
    rows.forEach((r) => Object.keys(r).forEach((k) => keys.add(k)));
    // Put _time first, then sort the rest
    const sorted = Array.from(keys).filter((k) => k !== '_time').sort();
    if (keys.has('_time')) sorted.unshift('_time');
    return sorted;
  }, [rows]);

  const visibleColumns = useMemo(() => columns.filter((c) => !hiddenCols.has(c)), [columns, hiddenCols]);

  const sortedRows = useMemo(() => {
    if (!sortCol) return rows;
    return [...rows].sort((a, b) => {
      const va = a[sortCol] ?? '';
      const vb = b[sortCol] ?? '';
      const cmp = String(va).localeCompare(String(vb), undefined, { numeric: true });
      return sortAsc ? cmp : -cmp;
    });
  }, [rows, sortCol, sortAsc]);

  const onSort = (col: string) => {
    if (sortCol === col) setSortAsc((v) => !v);
    else { setSortCol(col); setSortAsc(true); }
  };

  const toggleCol = (col: string) => {
    setHiddenCols((prev) => {
      const next = new Set(prev);
      if (next.has(col)) next.delete(col); else next.add(col);
      return next;
    });
  };

  // Stats
  const uniqueHosts = useMemo(() => {
    const s = new Set<string>();
    rows.forEach((r) => { if (r.hostname) s.add(String(r.hostname)); });
    return s.size;
  }, [rows]);
  const uniqueSources = useMemo(() => {
    const s = new Set<string>();
    rows.forEach((r) => { if (r.log_source) s.add(String(r.log_source)); });
    return s.size;
  }, [rows]);
  const severityCounts = useMemo(() => {
    const m: Record<string, number> = {};
    rows.forEach((r) => {
      const sev = String(r.severity ?? 'unknown').toLowerCase();
      m[sev] = (m[sev] || 0) + 1;
    });
    return m;
  }, [rows]);

  return (
    <div className="page sq-page">
      {/* ── Header ────────────────────────────────── */}
      <div className="re-header">
        <div className="re-header-left">
          <h1 className="re-title">Event Search</h1>
          <div className="re-stats">
            <span className="re-stat">{terminalIcon} Threat Hunting &amp; Forensics</span>
          </div>
        </div>
        <div className="re-header-actions">
          <button
            type="button"
            className={`cd-action-btn cd-action-btn--secondary ${savedQueriesOpen ? 'active' : ''}`}
            onClick={() => setSavedQueriesOpen((v) => !v)}
          >
            {searchIcon} Saved Queries
          </button>
          <button
            type="button"
            className={`cd-action-btn cd-action-btn--secondary ${historyOpen ? 'active' : ''}`}
            onClick={() => setHistoryOpen((v) => !v)}
          >
            {clockIcon} History ({history.length})
          </button>
        </div>
      </div>

      {/* ── Saved Queries Dropdown ────────────────── */}
      {savedQueriesOpen && (
        <div className="sq-dropdown-panel">
          <div className="sq-dropdown-title">Saved Queries</div>
          <div className="sq-dropdown-list">
            {SAVED_QUERIES.map((q, i) => (
              <div
                key={i}
                className="sq-dropdown-item"
                onClick={() => {
                  setMode('sql');
                  setSqlText(q.sql);
                  setSavedQueriesOpen(false);
                }}
              >
                <span className="sq-dropdown-item-label">{q.label}</span>
                <span className="sq-dropdown-item-sql">{q.sql.slice(0, 80)}...</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── History Dropdown ──────────────────────── */}
      {historyOpen && history.length > 0 && (
        <div className="sq-dropdown-panel">
          <div className="sq-dropdown-title">Recent Queries</div>
          <div className="sq-dropdown-list">
            {history.map((h, i) => (
              <div key={i} className="sq-dropdown-item" onClick={() => onHistorySelect(h)}>
                <span className={`sq-dropdown-mode sq-dropdown-mode--${h.mode}`}>{h.mode.toUpperCase()}</span>
                <span className="sq-dropdown-item-sql">
                  {h.query.length > 80 ? h.query.slice(0, 80) + '...' : h.query}
                </span>
                <span className="sq-dropdown-time">{relativeTime(h.ts)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Query Editor ─────────────────────────── */}
      <form onSubmit={onSubmit} className={`sq-editor ${editorExpanded ? 'sq-editor--expanded' : ''}`}>
        {/* Mode tabs */}
        <div className="sq-editor-tabs">
          <button
            type="button"
            className={`sq-tab ${mode === 'sql' ? 'sq-tab--active' : ''}`}
            onClick={() => setMode('sql')}
          >
            {terminalIcon} SQL
          </button>
          <button
            type="button"
            className={`sq-tab ${mode === 'nlq' ? 'sq-tab--active' : ''}`}
            onClick={() => setMode('nlq')}
          >
            {sparkleIcon} AI Ask
          </button>
          <button
            type="button"
            className={`sq-tab ${mode === 'live' ? 'sq-tab--active sq-tab--live' : ''}`}
            onClick={() => setMode('live')}
          >
            {radioIcon} Live Tail
            {liveTailActive && <span className="sq-live-dot" />}
          </button>
          <div className="sq-editor-tab-spacer" />
          <button
            type="button"
            className="sq-expand-btn"
            onClick={() => setEditorExpanded(!editorExpanded)}
            title={editorExpanded ? 'Collapse' : 'Expand'}
          >
            {editorExpanded ? collapseIcon : expandIcon}
          </button>
        </div>

        {/* Query input */}
        <div className="sq-input-area">
          {mode === 'sql' && (
            <textarea
              ref={textareaRef}
              className="sq-textarea"
              value={sqlText}
              onChange={(e) => setSqlText(e.target.value)}
              onKeyDown={handleKeyDown}
              rows={editorExpanded ? 12 : 4}
              placeholder="SELECT * FROM events WHERE severity = 'critical' ORDER BY _time DESC LIMIT 100"
              spellCheck={false}
            />
          )}
          {mode === 'nlq' && (
            <textarea
              className="sq-textarea sq-textarea--nlq"
              value={nlqText}
              onChange={(e) => setNlqText(e.target.value)}
              onKeyDown={handleKeyDown}
              rows={2}
              placeholder="Show me all failed SSH logins from external IPs in the last 4 hours"
              spellCheck={false}
            />
          )}
          {mode === 'live' && (
            <div className="sq-live-controls">
              <div className="sq-live-filter-row">
                {searchIcon}
                <input
                  className="sq-live-filter-input"
                  value={liveTailFilter}
                  onChange={(e) => setLiveTailFilter(e.target.value)}
                  placeholder="Filter events in real-time (hostname, IP, process, user...)"
                />
              </div>
            </div>
          )}
        </div>

        {/* Time range + execute */}
        <div className="sq-controls">
          {mode !== 'live' ? (
            <>
              <div className="sq-quick-ranges">
                {QUICK_RANGES.map((r) => (
                  <button
                    key={r.label}
                    type="button"
                    className={`sq-quick-btn ${activeQuickRange === r.label ? 'sq-quick-btn--active' : ''}`}
                    onClick={() => applyQuickRange(r.hours, r.label)}
                  >
                    {r.label}
                  </button>
                ))}
              </div>
              <div className="sq-time-inputs">
                <div className="sq-time-field">
                  <label className="sq-time-label">From</label>
                  <input
                    type="datetime-local"
                    className="sq-time-input"
                    value={timeFrom}
                    onChange={(e) => { setTimeFrom(e.target.value); setActiveQuickRange(''); }}
                  />
                </div>
                <div className="sq-time-field">
                  <label className="sq-time-label">To</label>
                  <input
                    type="datetime-local"
                    className="sq-time-input"
                    value={timeTo}
                    onChange={(e) => { setTimeTo(e.target.value); setActiveQuickRange(''); }}
                  />
                </div>
              </div>
              <button type="submit" className="sq-run-btn" disabled={loading}>
                {loading ? (
                  <span className="sq-spinner" />
                ) : playIcon}
                {loading ? 'Running...' : mode === 'sql' ? 'Run Query' : 'Ask AI'}
                {mode === 'sql' && <span className="sq-kbd">Ctrl+Enter</span>}
              </button>
            </>
          ) : (
            <>
              <div className="sq-live-status">
                {liveTailActive && (
                  <>
                    <span className="sq-live-indicator">
                      <span className="sq-live-dot" />
                      LIVE
                    </span>
                    <span className="sq-stats-chip">{liveTailEps} eps</span>
                    <span className="sq-stats-chip">{liveTailCount.toLocaleString()} events received</span>
                  </>
                )}
              </div>
              <div className="sq-live-actions">
                {liveTailActive && (
                  <button
                    type="button"
                    className="cd-action-btn cd-action-btn--secondary"
                    onClick={togglePauseLiveTail}
                  >
                    {liveTailPaused ? playIcon : pauseIcon}
                    {liveTailPaused ? 'Resume' : 'Pause'}
                  </button>
                )}
                {!liveTailActive ? (
                  <button
                    type="button"
                    className="sq-run-btn"
                    onClick={startLiveTail}
                  >
                    {radioIcon} Start Live Tail
                  </button>
                ) : (
                  <button
                    type="button"
                    className="sq-stop-btn"
                    onClick={stopLiveTail}
                  >
                    {stopIcon} Stop
                  </button>
                )}
              </div>
            </>
          )}
        </div>
      </form>

      {/* ── Generated SQL (NLQ) ──────────────────── */}
      {generatedSql !== null && (
        <div className="sq-gen-sql">
          <div className="sq-gen-sql-header" onClick={() => setGenSqlOpen((v) => !v)}>
            <span>{sparkleIcon} Generated SQL</span>
            <span>{genSqlOpen ? chevronDown : chevronRight}</span>
          </div>
          {genSqlOpen && (
            <pre className="sq-gen-sql-code">{generatedSql}</pre>
          )}
        </div>
      )}

      {/* ── Error ────────────────────────────────── */}
      {error && <div className="cd-error">{error}</div>}

      {/* ── Result Stats Bar ─────────────────────── */}
      {rows.length > 0 && (
        <div className="sq-stats-bar">
          <div className="sq-stats-left">
            <span className="sq-stats-count">
              {rows.length.toLocaleString()} events
              {total && total > rows.length ? ` of ${total.toLocaleString()}` : ''}
            </span>
            {queryDuration !== null && (
              <span className="sq-stats-duration">{queryDuration}ms</span>
            )}
            {uniqueHosts > 0 && <span className="sq-stats-chip">{uniqueHosts} hosts</span>}
            {uniqueSources > 0 && <span className="sq-stats-chip">{uniqueSources} sources</span>}
            {Object.entries(severityCounts).map(([sev, count]) => (
              <span key={sev} className={`sq-stats-sev ${severityClass(sev)}`}>
                {count} {sev}
              </span>
            ))}
          </div>
          <div className="sq-stats-right">
            <div className="sq-col-picker-wrap">
              <button
                type="button"
                className="cd-action-btn cd-action-btn--secondary"
                onClick={() => setColPickerOpen((v) => !v)}
              >
                {columnsIcon} Columns ({visibleColumns.length}/{columns.length})
              </button>
              {colPickerOpen && (
                <div className="sq-col-picker">
                  {columns.map((col) => (
                    <label key={col} className="sq-col-picker-item">
                      <input
                        type="checkbox"
                        checked={!hiddenCols.has(col)}
                        onChange={() => toggleCol(col)}
                      />
                      <span>{col}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
            <button
              type="button"
              className="cd-action-btn cd-action-btn--secondary"
              onClick={() => exportCsv(rows, visibleColumns)}
            >
              {downloadIcon} Export CSV
            </button>
          </div>
        </div>
      )}

      {/* ── Results Table ────────────────────────── */}
      <div className="sq-results-panel">
        {rows.length === 0 && !loading ? (
          <div className="sq-empty">
            <div className="sq-empty-icon">{searchIcon}</div>
            <h3 className="sq-empty-title">Run a query to explore events</h3>
            <p className="sq-empty-desc">
              Write SQL or ask a natural language question to search across all ingested events.
              Use Ctrl+Enter to execute.
            </p>
          </div>
        ) : rows.length === 0 && loading ? (
          <div className="sq-loading">
            <span className="sq-spinner sq-spinner--lg" />
            <span>Searching events...</span>
          </div>
        ) : (
          <div className="sq-table-wrap">
            <table className="sq-table">
              <thead>
                <tr>
                  <th className="sq-th sq-th--row-num">#</th>
                  {visibleColumns.map((col) => (
                    <th
                      key={col}
                      className={`sq-th ${sortCol === col ? 'sq-th--sorted' : ''}`}
                      onClick={() => onSort(col)}
                    >
                      <span className="sq-th-label">{col}</span>
                      {sortCol === col && (
                        <span className="sq-th-arrow">{sortAsc ? '\u25B2' : '\u25BC'}</span>
                      )}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sortedRows.map((row, ri) => (
                  <tr
                    key={ri}
                    className={`sq-tr ${ri % 2 === 1 ? 'sq-tr--alt' : ''}`}
                    onClick={() => setSelectedRow(row)}
                  >
                    <td className="sq-td sq-td--row-num">{ri + 1}</td>
                    {visibleColumns.map((col) => (
                      <td key={col} className="sq-td">
                        <CellValue value={row[col]} col={col} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Load More */}
        {hasMore && nextCursor && (
          <div className="sq-load-more">
            <button
              type="button"
              className="cd-action-btn cd-action-btn--primary"
              onClick={onLoadMore}
              disabled={loading}
            >
              {loading ? 'Loading...' : `Load more events (${rows.length} of ${total?.toLocaleString() ?? '?'})`}
            </button>
          </div>
        )}
      </div>

      {/* ── Row Detail Drawer ────────────────────── */}
      {selectedRow && (
        <RowDetail
          row={selectedRow}
          columns={columns}
          onClose={() => setSelectedRow(null)}
        />
      )}
    </div>
  );
}
