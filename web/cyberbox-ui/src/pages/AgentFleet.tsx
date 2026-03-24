import { type FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Cloud,
  Network,
  RefreshCcw,
  Save,
  Search,
  Send,
  ServerCog,
  Shield,
  Trash2,
} from 'lucide-react';

import {
  deleteAgent,
  getAgents,
  pushAgentConfig,
  updateAgent,
  type AgentRecord,
  type AgentUpdateInput,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';

type AgentFilterStatus = 'all' | 'active' | 'stale' | 'offline';
type Tone = 'default' | 'secondary' | 'outline' | 'destructive' | 'success' | 'warning' | 'info';
type AgentKind = 'windows' | 'linux' | 'firewall' | 'mac' | 'entra_id' | 'o365' | 'unknown';

const FIREWALL_HINTS = ['opnsense', 'pfsense', 'fortinet', 'fortigate', 'sophos', 'paloalto', 'firewall', 'fw.', 'asa'];

function rel(iso?: string): string {
  if (!iso) return 'Unknown';
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return 'just now';
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function abs(iso?: string): string {
  if (!iso) return 'Unknown';
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toLocaleString();
}

function statusVariant(status: AgentRecord['status']): Tone {
  if (status === 'active') return 'success';
  if (status === 'stale') return 'warning';
  return 'destructive';
}

function resolveAgentKind(agent: AgentRecord): AgentKind {
  const os = (agent.os || '').toLowerCase();
  const host = (agent.hostname || '').toLowerCase();
  const id = (agent.agent_id || '').toLowerCase();

  if (id.includes('entra') || host.includes('entra')) return 'entra_id';
  if (id.includes('office') || id.includes('o365') || host.includes('office 365')) return 'o365';
  if (os === 'azure') return id.includes('entra') ? 'entra_id' : 'o365';
  if (os === 'windows' || os === 'windows_sysmon') return 'windows';
  if (os === 'macos' || os === 'darwin') return 'mac';
  if (FIREWALL_HINTS.some((hint) => host.includes(hint) || id.includes(hint)) || os === 'firewall') return 'firewall';
  if (os === 'linux' || os === 'syslog' || os === 'journald') return 'linux';
  return 'unknown';
}

function AgentPlatformIcon({ agent }: { agent: AgentRecord }) {
  const kind = resolveAgentKind(agent);
  if (kind === 'entra_id') {
    return <img src="/entra-id.webp" alt="Entra ID" className="h-5 w-5 rounded-md object-cover" />;
  }
  if (kind === 'o365') {
    return <img src="/office-365.jpg" alt="Office 365" className="h-5 w-5 rounded-md object-cover" />;
  }
  if (kind === 'windows') {
    return (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
        <path d="M3 5.5L10.5 4.4V11.4H3V5.5Z" fill="#4a9eda" />
        <path d="M11.5 4.2L21 3V11.4H11.5V4.2Z" fill="#4a9eda" />
        <path d="M3 12.6H10.5V19.6L3 18.5V12.6Z" fill="#4a9eda" />
        <path d="M11.5 12.6H21V21L11.5 19.8V12.6Z" fill="#4a9eda" />
      </svg>
    );
  }
  if (kind === 'linux') {
    return <img src="/tux.png" alt="Linux" className="h-5 w-5 object-contain" />;
  }
  if (kind === 'mac') {
    return (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
        <path d="M18.7 12.4C18.7 15.8 16.2 19.8 13.5 19.8C12.7 19.8 12.2 19.4 11.5 19.4C10.8 19.4 10.2 19.8 9.5 19.8C7 19.8 4.3 16 4.3 12.4C4.3 9.2 6.5 7.5 8.5 7.5C9.4 7.5 10.2 8 11 8C11.7 8 12.6 7.4 13.7 7.5C15.5 7.5 16.8 8.5 17.5 10C16 10.8 15.2 12.2 15.2 13.5" stroke="currentColor" strokeWidth="1.3" />
        <path d="M14 4C14 5.5 12.8 7.2 11 7.5C11 6 12.2 4.2 14 4Z" fill="currentColor" />
      </svg>
    );
  }
  if (kind === 'firewall') {
    return (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
        <rect x="2" y="4" width="20" height="6" rx="1.5" stroke="#f45d5d" strokeWidth="1.5" fill="rgba(244,93,93,0.1)" />
        <rect x="2" y="14" width="20" height="6" rx="1.5" stroke="#f45d5d" strokeWidth="1.5" fill="rgba(244,93,93,0.1)" />
        <circle cx="5.5" cy="7" r="1" fill="#22c55e" />
        <circle cx="5.5" cy="17" r="1" fill="#22c55e" />
      </svg>
    );
  }
  return <ServerCog className="h-5 w-5" />;
}

export function AgentFleet() {
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [groupFilter, setGroupFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState<AgentFilterStatus>('all');
  const [searchValue, setSearchValue] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [configToml, setConfigToml] = useState('');
  const [configStatus, setConfigStatus] = useState('');
  const [editGroup, setEditGroup] = useState('');
  const [editTags, setEditTags] = useState('');
  const [editHostname, setEditHostname] = useState('');
  const [editOs, setEditOs] = useState('');
  const [editIp, setEditIp] = useState('');

  const loadAgents = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setAgents(await getAgents(groupFilter || undefined));
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [groupFilter]);

  useEffect(() => {
    void loadAgents();
    const id = window.setInterval(() => { void loadAgents(); }, 15_000);
    return () => window.clearInterval(id);
  }, [loadAgents]);

  const groups = useMemo(
    () => Array.from(new Set(agents.map((agent) => agent.group).filter(Boolean))).sort() as string[],
    [agents],
  );

  const filteredAgents = useMemo(() => {
    const query = searchValue.trim().toLowerCase();
    return agents.filter((agent) => {
      if (statusFilter !== 'all' && agent.status !== statusFilter) return false;
      if (!query) return true;
      const haystack = [agent.agent_id, agent.hostname, agent.os, agent.version, agent.ip, ...(agent.tags || [])]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [agents, searchValue, statusFilter]);

  const counts = useMemo(() => ({
    active: agents.filter((agent) => agent.status === 'active').length,
    stale: agents.filter((agent) => agent.status === 'stale').length,
    offline: agents.filter((agent) => agent.status === 'offline').length,
  }), [agents]);

  const expandedAgent = expandedId ? agents.find((agent) => agent.agent_id === expandedId) ?? null : null;

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
    setEditHostname(agent.hostname || '');
    setEditOs(agent.os || '');
    setEditIp(agent.ip || '');
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

  const onSaveAgent = async (event: FormEvent, agentId: string) => {
    event.preventDefault();
    setConfigStatus('Saving metadata...');
    try {
      const body: AgentUpdateInput = {
        group: editGroup.trim() ? editGroup.trim() : null,
        tags: editTags ? editTags.split(',').map((tag) => tag.trim()).filter(Boolean) : [],
        hostname: editHostname.trim() ? editHostname.trim() : null,
        os: editOs.trim() ? editOs.trim() : null,
        ip: editIp.trim() ? editIp.trim() : null,
      };
      await updateAgent(agentId, body);
      setConfigStatus('Agent updated.');
      void loadAgents();
    } catch (err) {
      setConfigStatus(`Error: ${String(err)}`);
    }
  };

  const onDeleteAgent = async (agentId: string) => {
    if (!window.confirm(`Remove agent "${agentId}" from the fleet?`)) return;
    try {
      await deleteAgent(agentId);
      setExpandedId(null);
      setMessage('Agent removed.');
      void loadAgents();
    } catch (err) {
      setError(`Delete failed: ${String(err)}`);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}
        {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}
        <span className="text-xs text-muted-foreground">{filteredAgents.length} agents</span>
        <div className="relative ml-2">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input type="text" value={searchValue} onChange={(e) => setSearchValue(e.target.value)} placeholder="Search agents..." className="h-7 rounded-md border border-border/70 bg-card/60 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring" />
        </div>
        <div className="ml-auto flex items-center gap-2">
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as AgentFilterStatus)} className="h-7 rounded-md border border-border/70 bg-card/60 px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring">
            <option value="all">All status</option>
            <option value="active">Active</option>
            <option value="stale">Stale</option>
            <option value="offline">Offline</option>
          </select>
          <select value={groupFilter} onChange={(e) => setGroupFilter(e.target.value)} className="h-7 rounded-md border border-border/70 bg-card/60 px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring">
            <option value="">All groups</option>
            {groups.map((group) => <option key={group} value={group}>{group}</option>)}
          </select>
          <Button type="button" size="sm" variant="outline" onClick={() => void loadAgents()} disabled={loading}>
            <RefreshCcw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} /> Refresh
          </Button>
        </div>
      </div>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Active" value={String(counts.active)} hint="Healthy agents" />
        <WorkspaceMetricCard label="Stale" value={String(counts.stale)} hint="Needs heartbeat check" />
        <WorkspaceMetricCard label="Offline" value={String(counts.offline)} hint="Not reachable" />
        <WorkspaceMetricCard label="Visible" value={String(filteredAgents.length)} hint="Matching filters" />
      </section>

      <section className="space-y-2">
        {loading && agents.length === 0 ? (
          <Card><CardContent className="h-[320px] animate-pulse p-6" /></Card>
        ) : filteredAgents.length === 0 ? (
          <WorkspaceEmptyState title="No agents match the current view" body="Try clearing a filter, changing the group selector, or waiting for the next heartbeat." />
        ) : (
          filteredAgents.map((agent) => {
            const isExpanded = expandedId === agent.agent_id;
            const platformOptions = Array.from(new Set([agent.os, 'firewall', 'windows', 'linux', 'macos', 'router', 'network', 'syslog'].map((value) => value?.trim()).filter(Boolean))) as string[];
            return (
              <Card key={agent.agent_id} className={cn('overflow-hidden transition-colors', isExpanded && 'border-primary/20')}>
                <CardContent className="p-5">
                  <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-3">
                        <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-border/70 bg-background/55 text-primary">
                          <AgentPlatformIcon agent={agent} />
                        </div>
                        <div>
                          <div className="font-display text-2xl font-semibold tracking-[-0.03em] text-foreground">{agent.hostname}</div>
                          <div className="mt-1 text-sm text-muted-foreground">{agent.agent_id}</div>
                        </div>
                      </div>
                      <div className="mt-4 flex flex-wrap gap-2">
                        <Badge variant={statusVariant(agent.status)}>{agent.status}</Badge>
                        <Badge variant="outline">{resolveAgentKind(agent).replace(/_/g, ' ')}</Badge>
                        <Badge variant="secondary">{agent.version}</Badge>
                        {agent.group && <Badge variant="secondary">{agent.group}</Badge>}
                      </div>
                      <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                        <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                          <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Last seen</div>
                          <div className="mt-2 text-sm font-medium text-foreground">{rel(agent.last_seen)}</div>
                        </div>
                        <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                          <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">OS</div>
                          <div className="mt-2 text-sm font-medium text-foreground">{agent.os || 'Unknown'}</div>
                        </div>
                        <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                          <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">IP</div>
                          <div className="mt-2 text-sm font-medium text-foreground">{agent.ip || 'Not set'}</div>
                        </div>
                        <div className="rounded-lg border border-border/70 bg-background/35 px-4 py-3">
                          <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Tags</div>
                          <div className="mt-2 text-sm font-medium text-foreground">{agent.tags.length ? agent.tags.join(', ') : 'None'}</div>
                        </div>
                      </div>
                    </div>

                    <div className="flex shrink-0 flex-wrap gap-3">
                      <Button type="button" variant="outline" onClick={() => onExpand(agent)}>
                        {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                        {isExpanded ? 'Collapse' : 'Manage'}
                      </Button>
                    </div>
                  </div>

                  {isExpanded && expandedAgent && (
                    <div className="mt-5 grid gap-5 border-t border-border/70 pt-5 xl:grid-cols-[minmax(0,1fr)_380px]">
                      <div className="space-y-5">
                        <div className="grid gap-4 sm:grid-cols-2">
                          <div className="rounded-lg border border-border/70 bg-background/35 p-4">
                            <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Tenant</div>
                            <div className="mt-3 text-sm text-foreground">{expandedAgent.tenant_id}</div>
                          </div>
                          <div className="rounded-lg border border-border/70 bg-background/35 p-4">
                            <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Heartbeat</div>
                            <div className="mt-3 text-sm text-foreground">{abs(expandedAgent.last_seen)}</div>
                          </div>
                        </div>

                        <form className="grid gap-4 md:grid-cols-2" onSubmit={(event) => void onSaveAgent(event, expandedAgent.agent_id)}>
                          <div>
                            <div className="mb-2 text-sm font-medium text-foreground">Hostname</div>
                            <Input value={editHostname} onChange={(event) => setEditHostname(event.target.value)} placeholder="hostname" />
                          </div>
                          <div>
                            <div className="mb-2 text-sm font-medium text-foreground">Platform</div>
                            <Select value={editOs} onChange={(event) => setEditOs(event.target.value)}>
                              <option value="">Clear platform</option>
                              {platformOptions.map((platform) => <option key={platform} value={platform}>{platform}</option>)}
                            </Select>
                          </div>
                          <div>
                            <div className="mb-2 text-sm font-medium text-foreground">Group</div>
                            <Input value={editGroup} onChange={(event) => setEditGroup(event.target.value)} placeholder="production" />
                          </div>
                          <div>
                            <div className="mb-2 text-sm font-medium text-foreground">IP address</div>
                            <Input value={editIp} onChange={(event) => setEditIp(event.target.value)} placeholder="10.0.0.5" />
                          </div>
                          <div className="md:col-span-2">
                            <div className="mb-2 text-sm font-medium text-foreground">Tags</div>
                            <Input value={editTags} onChange={(event) => setEditTags(event.target.value)} placeholder="linux, prod, us-east-1" />
                          </div>
                          <div className="md:col-span-2 flex flex-wrap justify-between gap-3">
                            <Button type="button" variant="destructive" onClick={() => void onDeleteAgent(expandedAgent.agent_id)}>
                              <Trash2 className="h-4 w-4" />
                              Remove agent
                            </Button>
                            <Button type="submit">
                              <Save className="h-4 w-4" />
                              Save metadata
                            </Button>
                          </div>
                        </form>
                      </div>

                      <div className="space-y-4 rounded-xl border border-border/70 bg-background/35 p-4">
                        <div>
                          <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Push config</div>
                          <p className="mt-2 text-sm text-muted-foreground">Send a TOML configuration payload directly to this agent.</p>
                        </div>
                        <Textarea
                          value={configToml}
                          onChange={(event) => setConfigToml(event.target.value)}
                          rows={10}
                          placeholder={'[agent]\ncollector_url = "http://collector:9090"\n\n[[sources]]\ntype = "file"\npath = "/var/log/syslog"'}
                          className="font-mono text-xs"
                        />
                        <Button type="button" className="w-full" onClick={() => void onPushConfig(expandedAgent.agent_id)} disabled={!configToml.trim()}>
                          <Send className="h-4 w-4" />
                          Push config
                        </Button>
                        {configStatus && (
                          <div className={cn(
                            'rounded-lg border px-4 py-3 text-sm',
                            configStatus.startsWith('Error')
                              ? 'border-amber-500/20 bg-amber-500/10 text-amber-100'
                              : 'border-primary/20 bg-primary/10 text-primary',
                          )}
                          >
                            {configStatus}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })
        )}
      </section>
    </div>
  );
}
