import { useState, useRef, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';

/* ── Icons ──────────────────────────────────────── */

const sunIcon = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="5" />
    <line x1="12" y1="1" x2="12" y2="3" /><line x1="12" y1="21" x2="12" y2="23" />
    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" /><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
    <line x1="1" y1="12" x2="3" y2="12" /><line x1="21" y1="12" x2="23" y2="12" />
    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" /><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
  </svg>
);

const moonIcon = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
  </svg>
);

const logoutIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
    <polyline points="16 17 21 12 16 7" />
    <line x1="21" y1="12" x2="9" y2="12" />
  </svg>
);

/* ── Component ──────────────────────────────────── */

interface TopBarProps {
  sidebarWidth: number;
}

export function TopBar({ sidebarWidth }: TopBarProps) {
  const { displayName, userId, tenantId, roles, signOut, isAuthenticated } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close on click outside
  useEffect(() => {
    if (!menuOpen) return;
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [menuOpen]);

  const name = displayName || userId || 'User';
  const initials = name
    .split(/[\s@]+/)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase() ?? '')
    .join('');

  return (
    <header className="topbar" style={{ left: sidebarWidth }}>
      {/* Spacer */}
      <div style={{ flex: 1 }} />

      {/* Actions */}
      <div className="topbar-actions">
        <button
          className="topbar-icon-btn"
          onClick={toggleTheme}
          title={isDark ? 'Light mode' : 'Dark mode'}
        >
          {isDark ? sunIcon : moonIcon}
        </button>

        <div className="topbar-user-wrap" ref={menuRef}>
          <button
            className="topbar-user"
            onClick={() => setMenuOpen(!menuOpen)}
            title={`${name} (${tenantId})`}
          >
            <div className="topbar-avatar-circle">{initials}</div>
            <span className="topbar-username">{name}</span>
          </button>

          {menuOpen && (
            <div className="topbar-dropdown">
              <div className="topbar-dropdown-header">
                <div className="topbar-dropdown-name">{name}</div>
                <div className="topbar-dropdown-email">{userId}</div>
                <div className="topbar-dropdown-roles">
                  {roles.map((r) => (
                    <span key={r} className="topbar-role-badge">{r}</span>
                  ))}
                </div>
              </div>
              <div className="topbar-dropdown-divider" />
              <div className="topbar-dropdown-item topbar-dropdown-tenant">
                <span style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>Tenant</span>
                <span style={{ fontSize: 12 }}>{tenantId}</span>
              </div>
              {isAuthenticated && (
                <>
                  <div className="topbar-dropdown-divider" />
                  <button
                    className="topbar-dropdown-item topbar-dropdown-signout"
                    onClick={() => signOut()}
                  >
                    {logoutIcon}
                    Sign out
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
