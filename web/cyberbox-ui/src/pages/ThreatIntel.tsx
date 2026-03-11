import { FormEvent, useCallback, useEffect, useState } from 'react';
import {
  createThreatIntelFeed,
  deleteThreatIntelFeed,
  FeedType,
  getThreatIntelFeeds,
  syncThreatIntelFeed,
  ThreatIntelFeed,
  ThreatIntelFeedCreateInput,
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
// Helpers
// ---------------------------------------------------------------------------

function relativeTime(iso?: string): string {
  if (!iso) return 'Never';
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return 'just now';
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function feedTypeBadge(ft: string): React.CSSProperties {
  const colors: Record<string, string> = {
    taxii: '#c084fc',
    stix: '#4a9eda',
    csv: '#58d68d',
    json: '#f5a623',
  };
  const c = colors[ft] || s.dim;
  return {
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 700,
    color: c,
    background: `${c}18`,
    border: `1px solid ${c}44`,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.04em',
  };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const FEED_TYPES: FeedType[] = ['taxii', 'stix', 'csv', 'json'];

export function ThreatIntel() {
  const [feeds, setFeeds] = useState<ThreatIntelFeed[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);

  // Add feed form state
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState<FeedType>('stix');
  const [newUrl, setNewUrl] = useState('');
  const [newInterval, setNewInterval] = useState(3600);
  const [newEnabled, setNewEnabled] = useState(true);
  const [addStatus, setAddStatus] = useState('');

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

  useEffect(() => { loadFeeds(); }, [loadFeeds]);

  const onSync = async (feedId: string) => {
    setSyncingId(feedId);
    try {
      await syncThreatIntelFeed(feedId);
      await loadFeeds();
    } catch (err) {
      setError(String(err));
    } finally {
      setSyncingId(null);
    }
  };

  const onDelete = async (feedId: string) => {
    try {
      await deleteThreatIntelFeed(feedId);
      setFeeds((prev) => prev.filter((f) => f.feed_id !== feedId));
    } catch (err) {
      setError(String(err));
    }
  };

  const onAddFeed = async (e: FormEvent) => {
    e.preventDefault();
    setAddStatus('');
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
    } catch (err) {
      setAddStatus(`Error: ${String(err)}`);
    }
  };

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
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Threat Intelligence Feeds</h1>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn-refresh" onClick={loadFeeds} disabled={loading}>
            {loading ? 'Loading...' : 'Refresh'}
          </button>
          <button
            onClick={() => setShowAddForm((v) => !v)}
            style={{
              padding: '6px 14px',
              fontSize: 13,
              background: 'rgba(74,158,218,0.2)',
              borderColor: s.accent,
            }}
          >
            {showAddForm ? 'Cancel' : 'Add Feed'}
          </button>
        </div>
      </div>

      {error && <p style={{ color: s.bad, fontSize: 13, margin: 0 }}>{error}</p>}

      {/* Add Feed Form */}
      {showAddForm && (
        <form className="panel" onSubmit={onAddFeed}>
          <div className="panel-title">New Feed</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <label>
              Name
              <input value={newName} onChange={(e) => setNewName(e.target.value)} required placeholder="Abuse.ch URLhaus" />
            </label>
            <label>
              Type
              <select value={newType} onChange={(e) => setNewType(e.target.value as FeedType)}>
                {FEED_TYPES.map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}
              </select>
            </label>
            <label style={{ gridColumn: 'span 2' }}>
              URL
              <input value={newUrl} onChange={(e) => setNewUrl(e.target.value)} required placeholder="https://urlhaus.abuse.ch/downloads/csv/" />
            </label>
            <label>
              Sync Interval (seconds)
              <input type="number" min={0} value={newInterval} onChange={(e) => setNewInterval(Number(e.target.value))} />
            </label>
            <label style={{ flexDirection: 'row', alignItems: 'center', gap: 10, display: 'flex' }}>
              <input
                type="checkbox"
                checked={newEnabled}
                onChange={(e) => setNewEnabled(e.target.checked)}
                style={{ width: 18, height: 18 }}
              />
              <span>Enabled</span>
            </label>
          </div>
          {addStatus && <p style={{ color: s.bad, fontSize: 12, margin: '8px 0 0' }}>{addStatus}</p>}
          <button
            type="submit"
            style={{
              marginTop: 12,
              padding: '8px 24px',
              background: 'rgba(88,214,141,0.2)',
              borderColor: s.good,
              fontWeight: 700,
            }}
          >
            Create Feed
          </button>
        </form>
      )}

      {/* Feed table */}
      <div className="panel wide" style={{ overflowX: 'auto' }}>
        {feeds.length === 0 && !loading ? (
          <p className="empty-state">No threat intelligence feeds configured.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={th}>Name</th>
                <th style={th}>Type</th>
                <th style={th}>URL</th>
                <th style={th}>IoC Count</th>
                <th style={th}>Last Synced</th>
                <th style={th}>Enabled</th>
                <th style={th}>Sync Interval</th>
                <th style={th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {feeds.map((feed) => (
                <tr key={feed.feed_id}>
                  <td style={td}>{feed.name}</td>
                  <td style={td}><span style={feedTypeBadge(feed.feed_type)}>{feed.feed_type}</span></td>
                  <td style={{ ...td, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={feed.url}>
                    {feed.url}
                  </td>
                  <td style={{ ...td, fontWeight: 700, color: s.accent }}>{feed.ioc_count.toLocaleString()}</td>
                  <td style={td} title={feed.last_synced_at || ''}>{relativeTime(feed.last_synced_at)}</td>
                  <td style={td}>
                    <span style={{
                      width: 10,
                      height: 10,
                      borderRadius: '50%',
                      display: 'inline-block',
                      background: feed.enabled ? s.good : s.bad,
                      boxShadow: `0 0 6px ${feed.enabled ? s.good : s.bad}`,
                    }} />
                  </td>
                  <td style={td}>{feed.auto_sync_interval_secs > 0 ? `${feed.auto_sync_interval_secs}s` : 'Manual'}</td>
                  <td style={td}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button
                        type="button"
                        onClick={() => onSync(feed.feed_id)}
                        disabled={syncingId === feed.feed_id}
                        style={{ padding: '4px 12px', fontSize: 11 }}
                      >
                        {syncingId === feed.feed_id ? 'Syncing...' : 'Sync Now'}
                      </button>
                      <button
                        type="button"
                        onClick={() => onDelete(feed.feed_id)}
                        style={{
                          padding: '4px 12px',
                          fontSize: 11,
                          color: s.bad,
                          borderColor: `${s.bad}55`,
                        }}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
