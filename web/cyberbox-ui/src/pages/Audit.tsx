import { FormEvent, useState } from 'react';
import { AuditLogRecord, getAuditLogs } from '../api/client';

interface AuditDiffRow {
  path: string;
  beforeValue: string;
  afterValue: string;
}

function serializeDiffValue(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return '(missing)';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

function flattenObject(
  value: unknown,
  prefix = '',
  out: Record<string, unknown> = {},
): Record<string, unknown> {
  if (Array.isArray(value)) {
    if (value.length === 0) { out[prefix || '$'] = []; return out; }
    value.forEach((item, index) => {
      flattenObject(item, prefix ? `${prefix}[${index}]` : `[${index}]`, out);
    });
    return out;
  }
  if (value !== null && typeof value === 'object') {
    const objectValue = value as Record<string, unknown>;
    const keys = Object.keys(objectValue);
    if (keys.length === 0) { out[prefix || '$'] = {}; return out; }
    keys.forEach((key) => {
      flattenObject(objectValue[key], prefix ? `${prefix}.${key}` : key, out);
    });
    return out;
  }
  out[prefix || '$'] = value;
  return out;
}

function buildAuditDiff(before: unknown, after: unknown): AuditDiffRow[] {
  const beforeFlat = flattenObject(before);
  const afterFlat = flattenObject(after);
  const keys = Array.from(new Set([...Object.keys(beforeFlat), ...Object.keys(afterFlat)])).sort();
  return keys
    .filter((key) => JSON.stringify(beforeFlat[key]) !== JSON.stringify(afterFlat[key]))
    .map((key) => ({
      path: key,
      beforeValue: serializeDiffValue(beforeFlat[key]),
      afterValue: serializeDiffValue(afterFlat[key]),
    }));
}

function isoFromLocalInput(value: string): string | undefined {
  if (!value.trim()) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

export function Audit() {
  const [auditLogs, setAuditLogs] = useState<AuditLogRecord[]>([]);
  const [auditNextCursor, setAuditNextCursor] = useState<string | undefined>(undefined);
  const [auditActionFilter, setAuditActionFilter] = useState('');
  const [auditEntityTypeFilter, setAuditEntityTypeFilter] = useState('');
  const [auditActorFilter, setAuditActorFilter] = useState('');
  const [auditFromFilter, setAuditFromFilter] = useState('');
  const [auditToFilter, setAuditToFilter] = useState('');
  const [auditCursorFilter, setAuditCursorFilter] = useState('');
  const [auditLimit, setAuditLimit] = useState(50);
  const [statusText, setStatusText] = useState('');

  const loadAuditLogs = async (options?: { append?: boolean; cursor?: string }) => {
    const response = await getAuditLogs({
      action: auditActionFilter || undefined,
      entity_type: auditEntityTypeFilter || undefined,
      actor: auditActorFilter || undefined,
      from: isoFromLocalInput(auditFromFilter),
      to: isoFromLocalInput(auditToFilter),
      cursor: (options?.cursor ?? auditCursorFilter) || undefined,
      limit: auditLimit,
    });
    setAuditNextCursor(response.next_cursor);
    setAuditLogs((current) =>
      options?.append ? [...current, ...response.entries] : response.entries,
    );
  };

  const onApplyAuditFilters = async (event: FormEvent) => {
    event.preventDefault();
    setStatusText('Loading audit trail...');
    try {
      await loadAuditLogs();
      setStatusText('Audit trail updated.');
    } catch (err) {
      setStatusText(`Audit filter failed: ${String(err)}`);
    }
  };

  const onLoadOlderAudit = async () => {
    if (!auditNextCursor) return;
    setStatusText('Loading older audit entries...');
    try {
      await loadAuditLogs({ append: true, cursor: auditNextCursor });
      setStatusText('Older audit entries loaded.');
    } catch (err) {
      setStatusText(`Load older audits failed: ${String(err)}`);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Audit Trail</h1>
      </div>

      <section className="panel wide">
        <form className="audit-filters" onSubmit={onApplyAuditFilters}>
          <label>
            Action
            <input
              value={auditActionFilter}
              onChange={(e) => setAuditActionFilter(e.target.value)}
              placeholder="rule.create"
            />
          </label>
          <label>
            Entity Type
            <input
              value={auditEntityTypeFilter}
              onChange={(e) => setAuditEntityTypeFilter(e.target.value)}
              placeholder="rule / alert"
            />
          </label>
          <label>
            Actor
            <input
              value={auditActorFilter}
              onChange={(e) => setAuditActorFilter(e.target.value)}
              placeholder="soc-admin"
            />
          </label>
          <label>
            From
            <input
              type="datetime-local"
              value={auditFromFilter}
              onChange={(e) => setAuditFromFilter(e.target.value)}
            />
          </label>
          <label>
            To
            <input
              type="datetime-local"
              value={auditToFilter}
              onChange={(e) => setAuditToFilter(e.target.value)}
            />
          </label>
          <label>
            Cursor
            <input
              value={auditCursorFilter}
              onChange={(e) => setAuditCursorFilter(e.target.value)}
              placeholder="timestamp_ms|audit_id"
            />
          </label>
          <label>
            Limit
            <input
              type="number"
              min={1}
              max={1000}
              value={auditLimit}
              onChange={(e) => setAuditLimit(Number(e.target.value))}
            />
          </label>
          <button type="submit">Apply Filters</button>
        </form>
        <p className="status">
          {statusText || `Showing ${auditLogs.length} entries${auditNextCursor ? ' (more available)' : ''}`}
        </p>
        <ul className="list audit-list">
          {auditLogs.map((entry) => {
            const diffRows = buildAuditDiff(entry.before, entry.after);
            return (
              <li key={entry.audit_id}>
                <div className="audit-header">
                  <span>
                    <strong>{entry.action}</strong> {entry.entity_type}:
                    {entry.entity_id.slice(0, 8)}
                  </span>
                  <span>
                    {new Date(entry.timestamp).toLocaleString()} by {entry.actor}
                  </span>
                </div>
                <details>
                  <summary>Field Diff</summary>
                  {diffRows.length === 0 ? (
                    <p className="status">No field-level changes detected.</p>
                  ) : (
                    <ul className="audit-diff-list">
                      {diffRows.slice(0, 20).map((row) => (
                        <li key={`${entry.audit_id}-${row.path}`}>
                          <code>{row.path}</code>
                          <span className="audit-before">{row.beforeValue}</span>
                          <span className="audit-arrow">{'->'}</span>
                          <span className="audit-after">{row.afterValue}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </details>
              </li>
            );
          })}
        </ul>
        {auditNextCursor && (
          <button type="button" onClick={onLoadOlderAudit}>
            Load Older Entries
          </button>
        )}
      </section>
    </div>
  );
}
