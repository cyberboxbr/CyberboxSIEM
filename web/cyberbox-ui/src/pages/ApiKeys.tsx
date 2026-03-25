import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Copy,
  Eye,
  EyeOff,
  Key,
  Plus,
  RefreshCcw,
  Trash2,
} from 'lucide-react';

import {
  createApiKey,
  getApiKeys,
  revokeApiKey,
  type ApiKeyCreateResult,
  type ApiKeyRecord,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceModal } from '@/components/workspace/modal-shell';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';

const AVAILABLE_ROLES = ['admin', 'analyst', 'viewer', 'ingestor'] as const;

function rel(iso?: string | null): string {
  if (!iso) return 'Never';
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function ApiKeys() {
  const [keys, setKeys] = useState<ApiKeyRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [newRoles, setNewRoles] = useState<Set<string>>(new Set(['analyst', 'viewer']));
  const [newExpiresAt, setNewExpiresAt] = useState('');
  const [createdKey, setCreatedKey] = useState<ApiKeyCreateResult | null>(null);
  const [showKey, setShowKey] = useState(false);
  const [copied, setCopied] = useState(false);

  const loadKeys = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setKeys(await getApiKeys());
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadKeys(); }, [loadKeys]);

  const stats = useMemo(() => ({
    total: keys.length,
    active: keys.filter((k) => !k.revoked_at).length,
    revoked: keys.filter((k) => k.revoked_at).length,
    expired: keys.filter((k) => k.expires_at && new Date(k.expires_at) < new Date() && !k.revoked_at).length,
  }), [keys]);

  const handleCreate = async () => {
    if (!newName.trim()) return;
    setCreating(true);
    setMessage('');
    try {
      const result = await createApiKey({
        name: newName.trim(),
        roles: Array.from(newRoles),
        expires_at: newExpiresAt || undefined,
      });
      setCreatedKey(result);
      setShowCreate(false);
      setShowKey(true);
      setNewName('');
      setNewRoles(new Set(['analyst', 'viewer']));
      setNewExpiresAt('');
      await loadKeys();
      setMessage('API key created. Copy it now — it will not be shown again.');
    } catch (err) {
      setMessage(String(err));
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (keyId: string, name: string) => {
    if (!window.confirm(`Revoke API key "${name}"? This cannot be undone.`)) return;
    setMessage('Revoking...');
    try {
      await revokeApiKey(keyId);
      await loadKeys();
      setMessage('API key revoked.');
    } catch (err) {
      setMessage(String(err));
    }
  };

  const handleCopy = () => {
    if (!createdKey) return;
    void navigator.clipboard.writeText(createdKey.key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleRole = (role: string) => {
    setNewRoles((current) => {
      const next = new Set(current);
      if (next.has(role)) next.delete(role); else next.add(role);
      return next;
    });
  };

  return (
    <div className="flex flex-col gap-3">
      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {message && <WorkspaceStatusBanner tone={message.includes('Revok') || message.includes('Error') || message.includes('API') ? 'warning' : 'primary'}>{message}</WorkspaceStatusBanner>}
        {error && <WorkspaceStatusBanner tone="danger">{error}</WorkspaceStatusBanner>}
        <span className="text-xs text-muted-foreground">{keys.length} keys</span>
        <div className="ml-auto flex items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={() => void loadKeys()} disabled={loading}>
            <RefreshCcw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} /> Refresh
          </Button>
          <Button type="button" size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="h-3.5 w-3.5" /> Create key
          </Button>
        </div>
      </div>

      {/* ── KPI row ──────────────────────────────────────────────────── */}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Total" value={String(stats.total)} hint="All API keys" />
        <WorkspaceMetricCard label="Active" value={String(stats.active)} hint="Currently valid" />
        <WorkspaceMetricCard label="Revoked" value={String(stats.revoked)} hint="Permanently disabled" />
        <WorkspaceMetricCard label="Expired" value={String(stats.expired)} hint="Past expiry date" />
      </section>

      {/* ── Key list ─────────────────────────────────────────────────── */}
      <section className="space-y-2">
        {loading && keys.length === 0 ? (
          <Card><CardContent className="h-[200px] animate-pulse" /></Card>
        ) : keys.length === 0 ? (
          <WorkspaceEmptyState title="No API keys" body="Create a key to allow external platforms to authenticate with the SIEM." />
        ) : (
          keys.map((apiKey) => {
            const isRevoked = Boolean(apiKey.revoked_at);
            const isExpired = apiKey.expires_at ? new Date(apiKey.expires_at) < new Date() : false;
            return (
              <Card key={apiKey.key_id} className={cn('overflow-hidden', isRevoked && 'opacity-60')}>
                <CardContent className="p-0">
                  <div className={cn('h-0.5', isRevoked ? 'bg-destructive' : isExpired ? 'bg-[hsl(43_96%_58%)]' : 'bg-accent')} />
                  <div className="px-3 py-2.5">
                    <div className="flex items-center gap-3">
                      <Key className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="truncate text-sm font-medium text-foreground">{apiKey.name}</span>
                        <Badge variant={isRevoked ? 'destructive' : isExpired ? 'warning' : 'success'}>
                          {isRevoked ? 'revoked' : isExpired ? 'expired' : 'active'}
                        </Badge>
                        {apiKey.roles.map((role) => (
                          <Badge key={role} variant="outline">{role}</Badge>
                        ))}
                      </div>
                      <div className="ml-auto flex items-center gap-3 shrink-0 text-[10px] text-muted-foreground">
                        <code className="font-mono">{apiKey.key_prefix}...</code>
                        <span>Created {rel(apiKey.created_at)}</span>
                        {apiKey.last_used_at && <span>Used {rel(apiKey.last_used_at)}</span>}
                        {apiKey.expires_at && <span>Expires {new Date(apiKey.expires_at).toLocaleDateString()}</span>}
                        {!isRevoked && (
                          <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-destructive hover:text-destructive" onClick={() => void handleRevoke(apiKey.key_id, apiKey.name)}>
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })
        )}
      </section>

      {/* ── Create key modal ─────────────────────────────────────────── */}
      <WorkspaceModal open={showCreate} title="Create API key" description="Generate a key for an external platform to authenticate with this SIEM." onClose={() => setShowCreate(false)} panelClassName="max-w-lg">
        <div className="space-y-3">
          <div>
            <div className="mb-1 text-xs font-medium text-foreground">Name</div>
            <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="e.g. SOAR Platform, Incident Bot" autoFocus />
          </div>
          <div>
            <div className="mb-1 text-xs font-medium text-foreground">Roles</div>
            <div className="flex flex-wrap gap-2">
              {AVAILABLE_ROLES.map((role) => (
                <button
                  key={role}
                  type="button"
                  onClick={() => toggleRole(role)}
                  className={cn(
                    'rounded-md border px-3 py-1.5 text-xs font-medium transition-colors',
                    newRoles.has(role)
                      ? 'border-primary/40 bg-primary/10 text-primary'
                      : 'border-border/70 bg-background/35 text-muted-foreground hover:text-foreground',
                  )}
                >
                  {role}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-[10px] text-muted-foreground">
              Analyst + Viewer recommended for automation platforms. Admin gives full control.
            </p>
          </div>
          <div>
            <div className="mb-1 text-xs font-medium text-foreground">Expires (optional)</div>
            <Input type="datetime-local" value={newExpiresAt} onChange={(e) => setNewExpiresAt(e.target.value)} />
          </div>
        </div>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" size="sm" onClick={() => setShowCreate(false)}>Cancel</Button>
          <Button type="button" size="sm" onClick={() => void handleCreate()} disabled={creating || !newName.trim() || newRoles.size === 0}>
            {creating ? 'Creating...' : 'Create key'}
          </Button>
        </div>
      </WorkspaceModal>

      {/* ── Show created key modal ───────────────────────────────────── */}
      <WorkspaceModal open={Boolean(createdKey)} title="API key created" description="Copy this key now. It will not be shown again." onClose={() => { setCreatedKey(null); setShowKey(false); setCopied(false); }} panelClassName="max-w-lg">
        {createdKey && (
          <div className="space-y-3">
            <div className="rounded-lg border border-accent/20 bg-accent/8 p-3">
              <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.2em] text-accent">Your API key</div>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all font-mono text-xs text-foreground">
                  {showKey ? createdKey.key : `${createdKey.key_prefix}${'•'.repeat(40)}`}
                </code>
                <Button type="button" variant="ghost" size="icon" className="h-7 w-7 shrink-0" onClick={() => setShowKey((v) => !v)}>
                  {showKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </Button>
                <Button type="button" variant="ghost" size="icon" className="h-7 w-7 shrink-0" onClick={handleCopy}>
                  <Copy className={cn('h-3.5 w-3.5', copied && 'text-accent')} />
                </Button>
              </div>
              {copied && <div className="mt-1.5 text-[10px] text-accent">Copied to clipboard</div>}
            </div>
            <div className="rounded-lg border border-border/70 bg-background/35 p-3 text-xs text-muted-foreground">
              <p>Use this key in the <code className="text-foreground">X-Api-Key</code> header or as <code className="text-foreground">Authorization: ApiKey {'<key>'}</code>.</p>
              <p className="mt-1.5">Name: <span className="text-foreground">{createdKey.name}</span> · Roles: <span className="text-foreground">{createdKey.roles.join(', ')}</span></p>
            </div>
          </div>
        )}
        <div className="flex justify-end">
          <Button type="button" size="sm" onClick={() => { setCreatedKey(null); setShowKey(false); setCopied(false); }}>Done</Button>
        </div>
      </WorkspaceModal>
    </div>
  );
}
