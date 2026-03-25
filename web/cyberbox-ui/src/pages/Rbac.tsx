import { useCallback, useEffect, useMemo, useState } from 'react';
import { Plus, RefreshCcw, Search, Trash2 } from 'lucide-react';

import { deleteRbacUser, getRbacUsers, setRbacUserRoles, type RbacEntry } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceModal } from '@/components/workspace/modal-shell';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
import { cn } from '@/lib/utils';

const ALL_ROLES = ['admin', 'analyst', 'viewer', 'ingestor'] as const;

function roleVariant(role: string): 'default' | 'secondary' | 'outline' | 'destructive' | 'success' | 'warning' | 'info' {
  if (role === 'admin') return 'warning';
  if (role === 'analyst') return 'info';
  if (role === 'ingestor') return 'success';
  return 'secondary';
}

function RoleEditor({
  currentRoles,
  onSave,
  onCancel,
}: {
  currentRoles: string[];
  onSave: (roles: string[]) => void;
  onCancel: () => void;
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set(currentRoles));

  const toggle = (role: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(role)) next.delete(role);
      else next.add(role);
      return next;
    });
  };

  return (
    <div className="space-y-4 rounded-lg border border-border/70 bg-background/35 p-4">
      <div className="grid gap-3 sm:grid-cols-2">
        {ALL_ROLES.map((role) => (
          <label key={role} className="flex items-center gap-3 rounded-lg border border-border/70 bg-card/65 px-3 py-3 text-sm text-foreground">
            <input type="checkbox" checked={selected.has(role)} onChange={() => toggle(role)} />
            <span>{role}</span>
          </label>
        ))}
      </div>
      <div className="flex flex-wrap justify-end gap-3">
        <Button type="button" variant="outline" size="sm" onClick={onCancel}>Cancel</Button>
        <Button type="button" size="sm" onClick={() => onSave(Array.from(selected))}>Save roles</Button>
      </div>
    </div>
  );
}

function CreateUserModal({
  open,
  onClose,
  onCreate,
}: {
  open: boolean;
  onClose: () => void;
  onCreate: (userId: string, roles: string[]) => void;
}) {
  const [userId, setUserId] = useState('');
  const [roles, setRoles] = useState<Set<string>>(new Set(['viewer']));

  useEffect(() => {
    if (!open) {
      setUserId('');
      setRoles(new Set(['viewer']));
    }
  }, [open]);

  if (!open) return null;

  const toggle = (role: string) => {
    setRoles((prev) => {
      const next = new Set(prev);
      if (next.has(role)) next.delete(role);
      else next.add(role);
      return next;
    });
  };

  return (
    <WorkspaceModal
      open={open}
      title="Add RBAC user"
      description="Create or update a role assignment for a specific user ID."
      onClose={onClose}
      panelClassName="max-w-xl"
    >
      <div>
        <div className="mb-2 text-sm font-medium text-foreground">User ID</div>
        <Input value={userId} onChange={(event) => setUserId(event.target.value)} placeholder="analyst@example.com" autoFocus />
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        {ALL_ROLES.map((role) => (
          <label key={role} className="flex items-center gap-3 rounded-lg border border-border/70 bg-card/65 px-3 py-3 text-sm text-foreground">
            <input type="checkbox" checked={roles.has(role)} onChange={() => toggle(role)} />
            <span>{role}</span>
          </label>
        ))}
      </div>
      <div className="flex flex-wrap justify-end gap-3">
        <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
        <Button type="button" onClick={() => onCreate(userId.trim(), Array.from(roles))} disabled={!userId.trim()}>Add user</Button>
      </div>
    </WorkspaceModal>
  );
}

export function Rbac() {
  const [users, setUsers] = useState<RbacEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [searchValue, setSearchValue] = useState('');
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setUsers(await getRbacUsers());
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadUsers(); }, [loadUsers]);

  const filteredUsers = useMemo(() => {
    const query = searchValue.trim().toLowerCase();
    return users.filter((user) => {
      if (!query) return true;
      return [user.user_id, ...user.roles].join(' ').toLowerCase().includes(query);
    });
  }, [users, searchValue]);

  const stats = useMemo(() => ({
    admins: users.filter((user) => user.roles.includes('admin')).length,
    analysts: users.filter((user) => user.roles.includes('analyst')).length,
    viewers: users.filter((user) => user.roles.includes('viewer')).length,
    ingestors: users.filter((user) => user.roles.includes('ingestor')).length,
  }), [users]);

  const onSaveRoles = async (userId: string, roles: string[]) => {
    try {
      await setRbacUserRoles(userId, roles);
      setEditingUserId(null);
      await loadUsers();
      setMessage(`Updated roles for ${userId}.`);
    } catch (err) {
      setError(String(err));
    }
  };

  const onDeleteUser = async (userId: string) => {
    if (!window.confirm(`Delete RBAC entry for "${userId}"?`)) return;
    try {
      await deleteRbacUser(userId);
      setUsers((prev) => prev.filter((user) => user.user_id !== userId));
      setMessage(`Removed ${userId}.`);
    } catch (err) {
      setError(String(err));
    }
  };

  const onAddUser = async (userId: string, roles: string[]) => {
    if (!userId) return;
    try {
      await setRbacUserRoles(userId, roles);
      setShowCreate(false);
      await loadUsers();
      setMessage(`Added ${userId}.`);
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div className="flex flex-col gap-3">
      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}
        {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

        <span className="text-xs text-muted-foreground">{users.length} entries</span>

        <div className="relative ml-2">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchValue}
            onChange={(event) => setSearchValue(event.target.value)}
            placeholder="user id, role..."
            className="h-7 rounded-md border border-border/70 bg-card/60 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
          />
        </div>

        <div className="ml-auto flex items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={() => void loadUsers()} disabled={loading}>
            <RefreshCcw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} /> Refresh
          </Button>
          <Button type="button" size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="h-3.5 w-3.5" /> Add user
          </Button>
        </div>
      </div>

      {/* ── KPI row ──────────────────────────────────────────────────── */}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Admins" value={String(stats.admins)} hint="Full administrative privileges." />
        <WorkspaceMetricCard label="Analysts" value={String(stats.analysts)} hint="Detection and operations access." />
        <WorkspaceMetricCard label="Viewers" value={String(stats.viewers)} hint="Read-only console access." />
        <WorkspaceMetricCard label="Ingestors" value={String(stats.ingestors)} hint="Ingest-only service identities." />
      </section>

      <section className="space-y-2">
        {!filteredUsers.length && !loading ? (
          <WorkspaceEmptyState title="No RBAC entries match the current view" body="Try broadening the search or add a new user assignment." />
        ) : (
          filteredUsers.map((user) => (
            <Card key={user.user_id}>
              <CardContent className="p-5">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0">
                    <div className="font-display text-2xl font-semibold tracking-[-0.03em] text-foreground">{user.user_id}</div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {user.roles.map((role) => <Badge key={role} variant={roleVariant(role)}>{role}</Badge>)}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-wrap gap-3">
                    <Button type="button" variant="outline" onClick={() => setEditingUserId(editingUserId === user.user_id ? null : user.user_id)}>
                      {editingUserId === user.user_id ? 'Hide editor' : 'Edit roles'}
                    </Button>
                    <Button type="button" variant="outline" onClick={() => void onDeleteUser(user.user_id)}>
                      <Trash2 className="h-4 w-4" />
                      Delete
                    </Button>
                  </div>
                </div>
                {editingUserId === user.user_id && (
                  <div className="mt-5 border-t border-border/70 pt-5">
                    <RoleEditor currentRoles={user.roles} onSave={(roles) => void onSaveRoles(user.user_id, roles)} onCancel={() => setEditingUserId(null)} />
                  </div>
                )}
              </CardContent>
            </Card>
          ))
        )}
      </section>

      <CreateUserModal open={showCreate} onClose={() => setShowCreate(false)} onCreate={(userId, roles) => void onAddUser(userId, roles)} />
    </div>
  );
}
