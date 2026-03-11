import { FormEvent, useCallback, useState } from 'react';
import {
  AuditLogRecord,
  AuditLogsQuery,
  getAuditLogs,
} from '../api/client';

// ---------------------------------------------------------------------------
// Dark theme tokens
// ---------------------------------------------------------------------------

const s = {
  panelBg: 'rgba(9,21,35,0.82)',
  border: 'rgba(88,143,186,0.35)',
  inputBg: 'rgba(4,12,21,0.75)',
  text: '#dbe4f3',
  dim: 'rgba(219,228,243,0.5)',
  accent: '#4a9eda',
  good: '#58d68d',
  bad: '#f45d5d',
} as const;

// ---------------------------------------------------------------------------
// Diff helpers (same logic as existing Audit.tsx)
// ---------------------------------------------------------------------------

interface DiffRow {
  path: string;
  before: string;
  after: string;
}

function ser(v: unknown): string {
  if (v === null) return 'null';
  if (v === undefined) return '(missing)';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(v);
}

function flatten(value: unknown, prefix = '', out: Record<string, unknown> = {}): Record<string, unknown> {
  if (Array.isArray(value)) {
    if (value.length === 0) { out[prefix || '$'] = []; return out; }
    value.forEach((item, i) => flatten(item, prefix ? `${prefix}[${i}]` : `[${i}]`, out));
    return out;
  }
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);
    if (keys.length === 0) { out[prefix || '$'] = {}; return out; }
    keys.forEach((k) => flatten(obj[k], prefix ? `${prefix}.${k}` : k, out));
    return out;
  }
  out[prefix || '$'] = value;
  return out;
}

function buildDiff(before: unknown, after: unknown): DiffRow[] {
  const bf = flatten(before);
  const af = flatten(after);
  const keys = Array.from(new Set([...Object.keys(bf), ...Object.keys(af)])).sort();
  return keys
    .filter((k) => JSON.stringify(bf[k]) !== JSON.stringify(af[k]))
    .map((k) => ({ path: k, before: ser(bf[k]), after: ser(af[k]) }));
}

function isoFromLocal(value: string): string | undefined {
  if (!value.trim()) return undefined;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AuditLogs() {
  const [entries, setEntries] = useState<AuditLogRecord[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Filters
  const [actionFilter, setActionFilter] = useState('');
  const [actorFilter, setActorFilter] = useState('');
  const [entityTypeFilter, setEntityTypeFilter] = useState('');
  const [fromFilter, setFromFilter] = useState('');
  const [toFilter, setToFilter] = useState('');

  // Expanded diff rows
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const load = useCallback(async (opts?: { append?: boolean; cursor?: string }) => {
    setLoading(true);
    setError('');
    try {
      const query: AuditLogsQuery = {
        action: actionFilter || undefined,
        actor: actorFilter || undefined,
        entity_type: entityTypeFilter || undefined,
        from: isoFromLocal(fromFilter),
        to: isoFromLocal(toFilter),
        cursor: opts?.cursor || undefined,
        limit: 50,
      };
      const resp = await getAuditLogs(query);
      setNextCursor(resp.next_cursor);
      if (opts?.append) {
        setEntries((prev) => [...prev, ...resp.entries]);
      } else {
        setEntries(resp.entries);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [actionFilter, actorFilter, entityTypeFilter, fromFilter, toFilter]);

  const onSubmit = (e: FormEvent) => { e.preventDefault(); load(); };
  const onLoadMore = () => { if (nextCursor) load({ append: true, cursor: nextCursor }); };

  // ─── table styles ────────────────────────────────────────────────────────

  const th: React.CSSProperties = {
    textAlign: 'left',
    padding: '8px 10px',
    borderBottom: `1px solid ${s.border}`,
    color: s.accent,
    fontWeight: 600,
    fontSize: 12,
    whiteSpace: 'nowrap',
  };

  const td: React.CSSProperties = {
    padding: '8px 10px',
    fontSize: 13,
    borderBottom: `1px solid ${s.border}`,
    verticalAlign: 'top',
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Audit Logs</h1>
      </div>

      {/* Filters */}
      <form className="panel" onSubmit={onSubmit}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr) auto', gap: 10, alignItems: 'end' }}>
          <label>
            Action
            <input value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} placeholder="rule.create" />
          </label>
          <label>
            Actor
            <input value={actorFilter} onChange={(e) => setActorFilter(e.target.value)} placeholder="soc-admin" />
          </label>
          <label>
            Entity Type
            <input value={entityTypeFilter} onChange={(e) => setEntityTypeFilter(e.target.value)} placeholder="rule / alert" />
          </label>
          <label>
            From
            <input type="datetime-local" value={fromFilter} onChange={(e) => setFromFilter(e.target.value)} />
          </label>
          <label>
            To
            <input type="datetime-local" value={toFilter} onChange={(e) => setToFilter(e.target.value)} />
          </label>
          <button type="submit" disabled={loading} style={{ padding: '10px 20px' }}>
            {loading ? 'Loading...' : 'Search'}
          </button>
        </div>
      </form>

      {error && <p style={{ color: s.bad, fontSize: 13, margin: 0 }}>{error}</p>}

      {/* Results table */}
      <div className="panel wide" style={{ overflowX: 'auto' }}>
        <div className="panel-title">
          Results
          <span style={{ fontWeight: 400, fontSize: 12, color: s.dim, marginLeft: 8 }}>
            {entries.length} entries{nextCursor ? ' (more available)' : ''}
          </span>
        </div>

        {entries.length === 0 ? (
          <p className="empty-state">No audit log entries. Apply filters and search.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={th}>Timestamp</th>
                <th style={th}>Actor</th>
                <th style={th}>Action</th>
                <th style={th}>Entity Type</th>
                <th style={th}>Entity ID</th>
                <th style={th}>Diff</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => {
                const isExpanded = expandedId === entry.audit_id;
                const diffRows = isExpanded ? buildDiff(entry.before, entry.after) : [];
                return (
                  <tr key={entry.audit_id}>
                    <td colSpan={6} style={{ padding: 0, border: 'none' }}>
                      {/* Main row */}
                      <div
                        style={{
                          display: 'grid',
                          gridTemplateColumns: '160px 100px 140px 80px 120px auto',
                          alignItems: 'center',
                          borderBottom: isExpanded ? 'none' : `1px solid ${s.border}`,
                        }}
                      >
                        <span style={td}>{new Date(entry.timestamp).toLocaleString()}</span>
                        <span style={td}>{entry.actor}</span>
                        <span style={{ ...td, fontWeight: 600, color: '#9fd3ff' }}>{entry.action}</span>
                        <span style={td}>{entry.entity_type}</span>
                        <span style={td}>
                          <code
                            style={{
                              fontSize: 11,
                              cursor: 'pointer',
                              color: s.accent,
                              textDecoration: 'underline',
                            }}
                            title={`Navigate to ${entry.entity_type}/${entry.entity_id}`}
                          >
                            {entry.entity_id.slice(0, 12)}
                          </code>
                        </span>
                        <span style={td}>
                          <button
                            type="button"
                            onClick={() => setExpandedId(isExpanded ? null : entry.audit_id)}
                            style={{ padding: '2px 10px', fontSize: 11 }}
                          >
                            {isExpanded ? 'Hide diff' : 'Show diff'}
                          </button>
                        </span>
                      </div>

                      {/* Diff expansion */}
                      {isExpanded && (
                        <div
                          style={{
                            padding: '8px 12px 12px',
                            background: 'rgba(4,12,21,0.5)',
                            borderBottom: `1px solid ${s.border}`,
                          }}
                        >
                          {diffRows.length === 0 ? (
                            <p style={{ fontSize: 12, color: s.dim, margin: 0 }}>No field-level changes detected.</p>
                          ) : (
                            <ul className="audit-diff-list">
                              {diffRows.map((row) => (
                                <li key={row.path}>
                                  <code>{row.path}</code>
                                  <span className="audit-before">{row.before}</span>
                                  <span className="audit-arrow">{'->'}</span>
                                  <span className="audit-after">{row.after}</span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {nextCursor && (
          <button
            type="button"
            onClick={onLoadMore}
            disabled={loading}
            style={{ marginTop: 12, padding: '8px 20px' }}
          >
            {loading ? 'Loading...' : 'Load more'}
          </button>
        )}
      </div>
    </div>
  );
}
