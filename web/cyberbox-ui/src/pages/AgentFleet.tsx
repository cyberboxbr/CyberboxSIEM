import { FormEvent, useCallback, useEffect, useState } from 'react';
import {
  AgentRecord,
  AgentUpdateInput,
  getAgents,
  pushAgentConfig,
  updateAgent,
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
  warn: '#f5a623',
  bad: '#f45d5d',
} as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return 'just now';
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function statusColor(status: string): string {
  if (status === 'active') return s.good;
  if (status === 'stale') return s.warn;
  return s.bad;
}

function statusBadge(status: string): React.CSSProperties {
  const c = statusColor(status);
  return {
    display: 'inline-block',
    padding: '2px 10px',
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 700,
    color: c,
    background: `${c}22`,
    border: `1px solid ${c}55`,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.05em',
  };
}

function countBadge(count: number, color: string): React.CSSProperties {
  return {
    display: 'inline-block',
    padding: '2px 10px',
    borderRadius: 999,
    fontSize: 12,
    fontWeight: 700,
    color,
    background: `${color}18`,
    border: `1px solid ${color}44`,
  };
}

// ---------------------------------------------------------------------------
// OS icons (inline SVG)
// ---------------------------------------------------------------------------

const FIREWALL_HINTS = ['opnsense', 'pfsense', 'fortinet', 'fortigate', 'sophos', 'paloalto', 'firewall', 'fw.', 'asa'];

function resolveOsType(agent: AgentRecord): 'windows' | 'linux' | 'firewall' | 'mac' | 'unknown' {
  const os = (agent.os || '').toLowerCase();
  const host = (agent.hostname || '').toLowerCase();
  const id = (agent.agent_id || '').toLowerCase();

  if (os === 'windows' || os === 'windows_sysmon') return 'windows';
  if (os === 'macos' || os === 'darwin') return 'mac';

  // Check for firewall hints in hostname / agent_id
  if (FIREWALL_HINTS.some(h => host.includes(h) || id.includes(h))) return 'firewall';
  if (os === 'firewall') return 'firewall';

  // syslog sources on linux
  if (os === 'linux' || os === 'syslog' || os === 'journald') return 'linux';

  return 'unknown';
}

function OsIcon({ agent }: { agent: AgentRecord }) {
  const type = resolveOsType(agent);
  const size = 20;
  const iconStyle: React.CSSProperties = { verticalAlign: 'middle', flexShrink: 0 };

  if (type === 'windows') {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" style={iconStyle}>
        <path d="M3 5.5L10.5 4.4V11.4H3V5.5Z" fill="#4a9eda" />
        <path d="M11.5 4.2L21 3V11.4H11.5V4.2Z" fill="#4a9eda" />
        <path d="M3 12.6H10.5V19.6L3 18.5V12.6Z" fill="#4a9eda" />
        <path d="M11.5 12.6H21V21L11.5 19.8V12.6Z" fill="#4a9eda" />
      </svg>
    );
  }

  if (type === 'linux') {
    return <img src="/tux.svg" width={size} height={size} alt="Linux" style={iconStyle} />;
  }

  if (type === 'firewall') {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" style={iconStyle}>
        <rect x="2" y="4" width="20" height="6" rx="1.5" stroke="#f45d5d" strokeWidth="1.5" fill="rgba(244,93,93,0.1)" />
        <rect x="2" y="14" width="20" height="6" rx="1.5" stroke="#f45d5d" strokeWidth="1.5" fill="rgba(244,93,93,0.1)" />
        <circle cx="5.5" cy="7" r="1" fill="#58d68d" />
        <circle cx="5.5" cy="17" r="1" fill="#58d68d" />
        <line x1="8" y1="7" x2="14" y2="7" stroke="#f45d5d" strokeWidth="1" strokeLinecap="round" />
        <line x1="8" y1="17" x2="14" y2="17" stroke="#f45d5d" strokeWidth="1" strokeLinecap="round" />
        <path d="M12 10V14" stroke="rgba(219,228,243,0.3)" strokeWidth="1.5" strokeDasharray="2 1" />
      </svg>
    );
  }

  if (type === 'mac') {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" style={iconStyle}>
        <path d="M18.7 12.4C18.7 15.8 16.2 19.8 13.5 19.8C12.7 19.8 12.2 19.4 11.5 19.4C10.8 19.4 10.2 19.8 9.5 19.8C7 19.8 4.3 16 4.3 12.4C4.3 9.2 6.5 7.5 8.5 7.5C9.4 7.5 10.2 8 11 8C11.7 8 12.6 7.4 13.7 7.5C15.5 7.5 16.8 8.5 17.5 10C16 10.8 15.2 12.2 15.2 13.5" stroke={s.text} strokeWidth="1.3" />
        <path d="M14 4C14 5.5 12.8 7.2 11 7.5C11 6 12.2 4.2 14 4Z" fill={s.text} />
      </svg>
    );
  }

  // Unknown
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" style={iconStyle}>
      <rect x="3" y="4" width="18" height="12" rx="2" stroke={s.dim} strokeWidth="1.5" />
      <line x1="12" y1="16" x2="12" y2="19" stroke={s.dim} strokeWidth="1.5" />
      <line x1="8" y1="19" x2="16" y2="19" stroke={s.dim} strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AgentFleet() {
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [groupFilter, setGroupFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'stale' | 'offline'>('all');
  const [textSearch, setTextSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [configToml, setConfigToml] = useState('');
  const [configStatus, setConfigStatus] = useState('');
  const [editGroup, setEditGroup] = useState('');
  const [editTags, setEditTags] = useState('');

  const loadAgents = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const resp = await getAgents(groupFilter || undefined);
      setAgents(resp);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [groupFilter]);

  useEffect(() => { loadAgents(); }, [loadAgents]);

  // Compute groups for dropdown
  const groups = Array.from(new Set(agents.map((a) => a.group).filter(Boolean))) as string[];

  // Filtered view
  const filtered = agents.filter((a) => {
    if (statusFilter !== 'all' && a.status !== statusFilter) return false;
    if (textSearch) {
      const q = textSearch.toLowerCase();
      const fields = [a.agent_id, a.hostname, a.os, a.version, ...(a.tags || [])].join(' ').toLowerCase();
      if (!fields.includes(q)) return false;
    }
    return true;
  });

  const counts = {
    active: agents.filter((a) => a.status === 'active').length,
    stale: agents.filter((a) => a.status === 'stale').length,
    offline: agents.filter((a) => a.status === 'offline').length,
  };

  // Expand handler
  const onExpand = (agent: AgentRecord) => {
    if (expandedId === agent.agent_id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(agent.agent_id);
    setConfigToml('');
    setConfigStatus('');
    setEditGroup(agent.group || '');
    setEditTags((agent.tags || []).join(', '));
  };

  const onPushConfig = async (agentId: string) => {
    setConfigStatus('Pushing config...');
    try {
      await pushAgentConfig(agentId, configToml);
      setConfigStatus('Config pushed successfully.');
    } catch (err) {
      setConfigStatus(`Error: ${String(err)}`);
    }
  };

  const onSaveGroupTags = async (e: FormEvent, agentId: string) => {
    e.preventDefault();
    try {
      const body: AgentUpdateInput = {
        group: editGroup || undefined,
        tags: editTags ? editTags.split(',').map((t) => t.trim()).filter(Boolean) : [],
      };
      await updateAgent(agentId, body);
      setConfigStatus('Group/tags updated.');
      loadAgents();
    } catch (err) {
      setConfigStatus(`Error: ${String(err)}`);
    }
  };

  // ─── table cell style ────────────────────────────────────────────────────

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
    whiteSpace: 'nowrap',
  };

  return (
    <div className="page">
      {/* Header */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <h1 className="page-title">Agent Fleet</h1>
          <span style={{ fontSize: 13, color: s.dim }}>{agents.length} total</span>
          <span style={countBadge(counts.active, s.good)}>{counts.active} active</span>
          <span style={countBadge(counts.stale, s.warn)}>{counts.stale} stale</span>
          <span style={countBadge(counts.offline, s.bad)}>{counts.offline} offline</span>
        </div>
        <button className="btn-refresh" onClick={loadAgents} disabled={loading}>
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {/* Filters */}
      <div
        className="panel"
        style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 2fr', gap: 12, alignItems: 'end' }}
      >
        <label>
          Group
          <select value={groupFilter} onChange={(e) => setGroupFilter(e.target.value)}>
            <option value="">All groups</option>
            {groups.map((g) => (
              <option key={g} value={g}>{g}</option>
            ))}
          </select>
        </label>
        <label>
          Status
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as 'all' | 'active' | 'stale' | 'offline')}
          >
            <option value="all">All</option>
            <option value="active">Active</option>
            <option value="stale">Stale</option>
            <option value="offline">Offline</option>
          </select>
        </label>
        <label>
          Search
          <input
            value={textSearch}
            onChange={(e) => setTextSearch(e.target.value)}
            placeholder="hostname, agent_id, tag..."
          />
        </label>
      </div>

      {error && <p style={{ color: s.bad, fontSize: 13, margin: 0 }}>{error}</p>}

      {/* Agent table */}
      <div className="panel wide" style={{ overflowX: 'auto' }}>
        {filtered.length === 0 ? (
          <p className="empty-state">No agents match current filters.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={th}>Agent ID</th>
                <th style={th}>Hostname</th>
                <th style={th}>Platform</th>
                <th style={th}>Version</th>
                <th style={th}>Last Seen</th>
                <th style={th}>Status</th>
                <th style={th}>Group</th>
                <th style={th}>Tags</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((agent) => {
                const isExpanded = expandedId === agent.agent_id;
                return (
                  <tr key={agent.agent_id} style={{ cursor: 'pointer' }}>
                    <td colSpan={8} style={{ padding: 0, border: 'none' }}>
                      {/* Row */}
                      <div
                        onClick={() => onExpand(agent)}
                        style={{
                          display: 'grid',
                          gridTemplateColumns: 'minmax(120px,1.5fr) 1fr 0.6fr 0.6fr 0.8fr 0.6fr 0.7fr 1fr',
                          alignItems: 'center',
                          borderBottom: isExpanded ? 'none' : `1px solid ${s.border}`,
                          background: isExpanded ? 'rgba(74,158,218,0.06)' : 'transparent',
                        }}
                      >
                        <span style={td}>
                          <code style={{ fontSize: 11 }}>{agent.agent_id.slice(0, 12)}</code>
                        </span>
                        <span style={td}>{agent.hostname}</span>
                        <span style={{ ...td, display: 'flex', alignItems: 'center', gap: 6 }}>
                          <OsIcon agent={agent} />
                          {resolveOsType(agent)}
                        </span>
                        <span style={td}>{agent.version}</span>
                        <span style={td} title={agent.last_seen}>{relativeTime(agent.last_seen)}</span>
                        <span style={td}><span style={statusBadge(agent.status)}>{agent.status}</span></span>
                        <span style={td}>{agent.group || '-'}</span>
                        <span style={td}>
                          {(agent.tags || []).map((t) => (
                            <span
                              key={t}
                              style={{
                                display: 'inline-block',
                                padding: '1px 6px',
                                marginRight: 4,
                                borderRadius: 4,
                                fontSize: 11,
                                background: 'rgba(88,143,186,0.15)',
                                border: `1px solid ${s.border}`,
                              }}
                            >
                              {t}
                            </span>
                          ))}
                        </span>
                      </div>

                      {/* Expanded detail panel */}
                      {isExpanded && (
                        <div
                          style={{
                            padding: 16,
                            background: 'rgba(4,12,21,0.5)',
                            borderBottom: `1px solid ${s.border}`,
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 14,
                          }}
                        >
                          {/* Full info */}
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, fontSize: 13 }}>
                            <div><strong style={{ color: s.dim }}>Agent ID:</strong> {agent.agent_id}</div>
                            <div><strong style={{ color: s.dim }}>Tenant:</strong> {agent.tenant_id}</div>
                            <div><strong style={{ color: s.dim }}>IP:</strong> {agent.ip || 'N/A'}</div>
                            <div><strong style={{ color: s.dim }}>Hostname:</strong> {agent.hostname}</div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <strong style={{ color: s.dim }}>OS:</strong> <OsIcon agent={agent} /> {resolveOsType(agent)}
                            </div>
                            <div><strong style={{ color: s.dim }}>Version:</strong> {agent.version}</div>
                            <div><strong style={{ color: s.dim }}>Last Seen:</strong> {new Date(agent.last_seen).toLocaleString()}</div>
                            <div><strong style={{ color: s.dim }}>Status:</strong> <span style={statusBadge(agent.status)}>{agent.status}</span></div>
                            <div><strong style={{ color: s.dim }}>Group:</strong> {agent.group || '-'}</div>
                          </div>

                          {/* Edit group / tags */}
                          <form
                            onSubmit={(e) => onSaveGroupTags(e, agent.agent_id)}
                            style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 10, alignItems: 'end' }}
                          >
                            <label style={{ fontSize: 12 }}>
                              Group
                              <input
                                value={editGroup}
                                onChange={(e) => setEditGroup(e.target.value)}
                                placeholder="production"
                              />
                            </label>
                            <label style={{ fontSize: 12 }}>
                              Tags (comma-separated)
                              <input
                                value={editTags}
                                onChange={(e) => setEditTags(e.target.value)}
                                placeholder="linux, prod, us-east-1"
                              />
                            </label>
                            <button type="submit" style={{ padding: '10px 16px' }}>Save</button>
                          </form>

                          {/* Push config */}
                          <div>
                            <label style={{ fontSize: 12 }}>
                              Push Config (TOML)
                              <textarea
                                value={configToml}
                                onChange={(e) => setConfigToml(e.target.value)}
                                rows={6}
                                placeholder={'[agent]\ncollector_url = "http://collector:9090"\n\n[[sources]]\ntype = "file"\npath = "/var/log/syslog"'}
                                style={{
                                  fontFamily: '"IBM Plex Mono", monospace',
                                  fontSize: 12,
                                  width: '100%',
                                  resize: 'vertical',
                                }}
                              />
                            </label>
                            <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginTop: 8 }}>
                              <button
                                type="button"
                                onClick={() => onPushConfig(agent.agent_id)}
                                disabled={!configToml.trim()}
                                style={{
                                  padding: '8px 20px',
                                  background: configToml.trim() ? 'rgba(74,158,218,0.25)' : s.inputBg,
                                  borderColor: s.accent,
                                }}
                              >
                                Push Config
                              </button>
                              {configStatus && (
                                <span style={{ fontSize: 12, color: configStatus.startsWith('Error') ? s.bad : s.good }}>
                                  {configStatus}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
