import { useCallback, useEffect, useMemo, useState } from 'react';
import { LockKeyhole, Plus, RefreshCcw, Search, Shield, Trash2, Users } from 'lucide-react';

import { deleteRbacUser, getRbacUsers, setRbacUserRoles, type RbacEntry } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { WorkspaceMetricCard } from '@/components/workspace/metric-card';
import { WorkspaceModal } from '@/components/workspace/modal-shell';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';

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
    <div className="space-y-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.45fr)_360px]">
        <Card className="overflow-hidden border-primary/15 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.15),transparent_40%),linear-gradient(145deg,hsl(var(--card)),hsl(var(--card)/0.85))]">
          <CardContent className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(250px,0.85fr)]">
            <div>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant="outline" className="border-primary/25 bg-primary/10 text-primary">RBAC administration</Badge>
                <Badge variant="secondary" className="bg-background/55">{users.length} entries</Badge>
              </div>
              <div className="max-w-2xl font-display text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-foreground sm:text-[3rem]">
                Keep access assignments explicit, reviewable, and easy to change.
              </div>
              <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
                This board lets you review who has access, adjust roles inline, and add new user mappings without dropping back to raw JSON.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button type="button" onClick={() => setShowCreate(true)}>
                  <Plus className="h-4 w-4" />
                  Add user
                </Button>
                <Button type="button" variant="outline" onClick={() => void loadUsers()} disabled={loading}>
                  <RefreshCcw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
                  Refresh roles
                </Button>
              </div>
            </div>
            <div className="grid gap-3 rounded-xl border border-border/70 bg-background/35 p-4">
              <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">User entries</div>
                <div className="mt-3 font-display text-4xl font-semibold tracking-[-0.04em] text-foreground">{users.length}</div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
                <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Admins</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats.admins}</div>
                </div>
                <div className="rounded-lg border border-border/70 bg-card/70 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Analysts</div>
                  <div className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-foreground">{stats.analysts}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle>Search</CardTitle>
            <CardDescription>Find a specific user or role assignment quickly.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div>
              <div className="mb-2 text-sm font-medium text-foreground">Search users</div>
              <div className="relative">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input className="pl-11" value={searchValue} onChange={(event) => setSearchValue(event.target.value)} placeholder="user id, admin, analyst..." />
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {message && <WorkspaceStatusBanner>{message}</WorkspaceStatusBanner>}
      {error && <WorkspaceStatusBanner tone="warning">{error}</WorkspaceStatusBanner>}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <WorkspaceMetricCard label="Admins" value={String(stats.admins)} hint="Users with full administrative privileges." icon={Shield} />
        <WorkspaceMetricCard label="Analysts" value={String(stats.analysts)} hint="Users allowed to manage detections and operations." icon={Users} />
        <WorkspaceMetricCard label="Viewers" value={String(stats.viewers)} hint="Read-only users with console visibility." icon={LockKeyhole} />
        <WorkspaceMetricCard label="Ingestors" value={String(stats.ingestors)} hint="Machine or service identities with ingest-only access." icon={LockKeyhole} />
      </section>

      <section className="space-y-4">
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
