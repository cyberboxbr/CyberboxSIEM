import { FormEvent, useCallback, useEffect, useState } from 'react';
import {
  deleteRbacUser,
  getRbacUsers,
  RbacEntry,
  setRbacUserRoles,
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

const ALL_ROLES = ['admin', 'analyst', 'viewer', 'ingestor'] as const;

function roleColor(role: string): string {
  switch (role) {
    case 'admin': return '#c084fc';
    case 'analyst': return '#4a9eda';
    case 'viewer': return 'rgba(219,228,243,0.55)';
    case 'ingestor': return '#58d68d';
    default: return s.dim;
  }
}

function roleBadge(role: string): React.CSSProperties {
  const c = roleColor(role);
  return {
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 700,
    color: c,
    background: `${c}18`,
    border: `1px solid ${c}44`,
    marginRight: 4,
    letterSpacing: '0.04em',
  };
}

// ---------------------------------------------------------------------------
// Inline role editor
// ---------------------------------------------------------------------------

function RoleEditor({
  userId,
  currentRoles,
  onSave,
  onCancel,
}: {
  userId: string;
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
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      {ALL_ROLES.map((role) => (
        <label
          key={role}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 4,
            cursor: 'pointer',
            fontSize: 12,
            flexDirection: 'row',
            color: selected.has(role) ? roleColor(role) : s.dim,
          }}
        >
          <input
            type="checkbox"
            checked={selected.has(role)}
            onChange={() => toggle(role)}
            style={{ width: 14, height: 14 }}
          />
          {role}
        </label>
      ))}
      <button
        type="button"
        onClick={() => onSave(Array.from(selected))}
        style={{ padding: '3px 10px', fontSize: 11, borderColor: s.good, color: s.good }}
      >
        Save
      </button>
      <button
        type="button"
        onClick={onCancel}
        style={{ padding: '3px 10px', fontSize: 11, color: s.dim }}
      >
        Cancel
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function Rbac() {
  const [users, setUsers] = useState<RbacEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [editingUserId, setEditingUserId] = useState<string | null>(null);

  // Add user form
  const [newUserId, setNewUserId] = useState('');
  const [newRoles, setNewRoles] = useState<Set<string>>(new Set(['viewer']));

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

  useEffect(() => { loadUsers(); }, [loadUsers]);

  const onSaveRoles = async (userId: string, roles: string[]) => {
    try {
      await setRbacUserRoles(userId, roles);
      setEditingUserId(null);
      await loadUsers();
    } catch (err) {
      setError(String(err));
    }
  };

  const onDeleteUser = async (userId: string) => {
    try {
      await deleteRbacUser(userId);
      setUsers((prev) => prev.filter((u) => u.user_id !== userId));
    } catch (err) {
      setError(String(err));
    }
  };

  const onAddUser = async (e: FormEvent) => {
    e.preventDefault();
    if (!newUserId.trim()) return;
    try {
      await setRbacUserRoles(newUserId.trim(), Array.from(newRoles));
      setNewUserId('');
      setNewRoles(new Set(['viewer']));
      await loadUsers();
    } catch (err) {
      setError(String(err));
    }
  };

  const toggleNewRole = (role: string) => {
    setNewRoles((prev) => {
      const next = new Set(prev);
      if (next.has(role)) next.delete(role);
      else next.add(role);
      return next;
    });
  };

  // ─── table styles ────────────────────────────────────────────────────────

  const th: React.CSSProperties = {
    textAlign: 'left',
    padding: '10px 12px',
    borderBottom: `1px solid ${s.border}`,
    color: s.accent,
    fontWeight: 600,
    fontSize: 12,
  };

  const td: React.CSSProperties = {
    padding: '10px 12px',
    fontSize: 13,
    borderBottom: `1px solid ${s.border}`,
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Role-Based Access Control</h1>
        <button className="btn-refresh" onClick={loadUsers} disabled={loading}>
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {error && <p style={{ color: s.bad, fontSize: 13, margin: 0 }}>{error}</p>}

      <div className="panel wide" style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={th}>User ID</th>
              <th style={th}>Roles</th>
              <th style={{ ...th, width: 100 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.user_id}>
                <td style={td}>
                  <code style={{ fontSize: 12 }}>{user.user_id}</code>
                </td>
                <td style={td}>
                  {editingUserId === user.user_id ? (
                    <RoleEditor
                      userId={user.user_id}
                      currentRoles={user.roles}
                      onSave={(roles) => onSaveRoles(user.user_id, roles)}
                      onCancel={() => setEditingUserId(null)}
                    />
                  ) : (
                    <span
                      onClick={() => setEditingUserId(user.user_id)}
                      style={{ cursor: 'pointer' }}
                      title="Click to edit roles"
                    >
                      {user.roles.map((r) => (
                        <span key={r} style={roleBadge(r)}>{r}</span>
                      ))}
                    </span>
                  )}
                </td>
                <td style={td}>
                  <button
                    type="button"
                    onClick={() => onDeleteUser(user.user_id)}
                    style={{
                      padding: '3px 10px',
                      fontSize: 11,
                      color: s.bad,
                      borderColor: `${s.bad}55`,
                    }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}

            {/* Add user row */}
            <tr>
              <td style={td}>
                <form id="add-user-form" onSubmit={onAddUser} style={{ display: 'contents' }}>
                  <input
                    value={newUserId}
                    onChange={(e) => setNewUserId(e.target.value)}
                    placeholder="new-user-id"
                    style={{ width: '100%', fontSize: 12 }}
                  />
                </form>
              </td>
              <td style={td}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {ALL_ROLES.map((role) => (
                    <label
                      key={role}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        cursor: 'pointer',
                        fontSize: 12,
                        flexDirection: 'row',
                        color: newRoles.has(role) ? roleColor(role) : s.dim,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={newRoles.has(role)}
                        onChange={() => toggleNewRole(role)}
                        style={{ width: 14, height: 14 }}
                      />
                      {role}
                    </label>
                  ))}
                </div>
              </td>
              <td style={td}>
                <button
                  type="submit"
                  form="add-user-form"
                  style={{
                    padding: '4px 14px',
                    fontSize: 11,
                    background: 'rgba(88,214,141,0.15)',
                    borderColor: s.good,
                    color: s.good,
                    fontWeight: 700,
                  }}
                >
                  Add
                </button>
              </td>
            </tr>
          </tbody>
        </table>

        {users.length === 0 && !loading && (
          <p className="empty-state">No RBAC entries configured.</p>
        )}
      </div>
    </div>
  );
}
