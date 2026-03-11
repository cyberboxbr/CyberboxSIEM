import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

/* ------------------------------------------------------------------ */
/*  Inline SVG icons (simple path-based, no library dependency)        */
/* ------------------------------------------------------------------ */

const icons = {
  grid: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" />
      <rect x="14" y="3" width="7" height="7" />
      <rect x="3" y="14" width="7" height="7" />
      <rect x="14" y="14" width="7" height="7" />
    </svg>
  ),
  bell: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  ),
  briefcase: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="7" width="20" height="14" rx="2" ry="2" />
      <path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2" />
    </svg>
  ),
  shield: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  search: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  ),
  globe: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10A15.3 15.3 0 0 1 12 2z" />
    </svg>
  ),
  server: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  ),
  settings: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1.08-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1.08 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1.08z" />
    </svg>
  ),
  chevronDown: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  ),
  chevronLeft: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="15 18 9 12 15 6" />
    </svg>
  ),
  chevronRight: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6" />
    </svg>
  ),
};

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface NavItem {
  label: string;
  icon: keyof typeof icons;
  to?: string;
  end?: boolean;
  children?: { label: string; to: string }[];
  adminOnly?: boolean;
  analystOnly?: boolean;
  dividerAfter?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', icon: 'grid', to: '/', end: true, dividerAfter: true },
  { label: 'Alerts', icon: 'bell', to: '/alerts' },
  { label: 'Cases', icon: 'briefcase', to: '/cases' },
  {
    label: 'Detection',
    icon: 'shield',
    analystOnly: true,
    dividerAfter: true,
    children: [
      { label: 'Rules', to: '/rules' },
      { label: 'MITRE Coverage', to: '/coverage' },
      { label: 'Lookup Tables', to: '/lookups' },
    ],
  },
  { label: 'Search', icon: 'search', to: '/search' },
  { label: 'Threat Intel', icon: 'globe', to: '/threat-intel', analystOnly: true },
  { label: 'Agents', icon: 'server', to: '/agents', analystOnly: true },
  {
    label: 'Administration',
    icon: 'settings',
    adminOnly: true,
    children: [
      { label: 'RBAC', to: '/admin/rbac' },
      { label: 'Audit Logs', to: '/admin/audit' },
      { label: 'LGPD Compliance', to: '/admin/lgpd' },
      { label: 'System', to: '/admin/system' },
    ],
  },
];

/* ------------------------------------------------------------------ */
/*  Styles                                                             */
/* ------------------------------------------------------------------ */

const S = {
  sidebar: (collapsed: boolean): React.CSSProperties => ({
    position: 'fixed',
    top: 0,
    left: 0,
    bottom: 0,
    width: collapsed ? 72 : 260,
    background: 'linear-gradient(180deg, var(--sidebar-gradient-from) 0%, var(--sidebar-gradient-to) 100%)',
    borderRight: '1px solid var(--sidebar-border)',
    display: 'flex',
    flexDirection: 'column',
    zIndex: 200,
    transition: 'width 0.2s ease-out',
    overflow: 'hidden',
  }),
  logoWrap: (collapsed: boolean): React.CSSProperties => ({
    height: 48,
    display: 'flex',
    alignItems: 'center',
    justifyContent: collapsed ? 'center' : 'flex-start',
    gap: 10,
    padding: collapsed ? '0 8px' : '0 16px',
    borderBottom: '1px solid var(--sidebar-divider)',
    flexShrink: 0,
    overflow: 'hidden',
    whiteSpace: 'nowrap',
  }),
  logo: { height: 72, width: 'auto', flexShrink: 0 } as React.CSSProperties,
  logoText: {
    fontSize: 15,
    fontWeight: 800,
    color: '#FFFFFF',
    letterSpacing: '0.1em',
    lineHeight: 1,
  } as React.CSSProperties,
  nav: {
    flex: 1,
    overflowY: 'auto',
    overflowX: 'hidden',
    padding: '16px 0',
  } as React.CSSProperties,
  sectionLabel: {
    padding: '20px 24px 8px',
    fontSize: 11,
    fontWeight: 600,
    color: 'var(--sidebar-section-label)',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.1em',
  } as React.CSSProperties,
  groupHeader: (collapsed: boolean, isActive: boolean): React.CSSProperties => ({
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    padding: collapsed ? '10px 0' : '10px 16px',
    margin: collapsed ? '2px 0' : '2px 12px',
    justifyContent: collapsed ? 'center' : 'flex-start',
    cursor: 'pointer',
    color: isActive ? '#fff' : 'var(--sidebar-text)',
    fontSize: 14,
    fontWeight: isActive ? 600 : 400,
    border: 'none',
    background: isActive ? 'var(--sidebar-item-active-bg)' : 'transparent',
    borderRadius: 10,
    width: collapsed ? '100%' : 'auto',
    textAlign: 'left',
    transition: 'all 0.2s ease-out',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
  }),
  link: (collapsed: boolean): React.CSSProperties => ({
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    padding: collapsed ? '10px 0' : '10px 16px',
    margin: collapsed ? '2px 0' : '2px 12px',
    justifyContent: collapsed ? 'center' : 'flex-start',
    color: 'var(--sidebar-text)',
    fontSize: 14,
    fontWeight: 400,
    textDecoration: 'none',
    borderRadius: 10,
    transition: 'all 0.2s ease-out',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
  }),
  linkActive: {
    color: '#fff',
    fontWeight: 600,
    background: 'var(--sidebar-item-active-bg)',
  } as React.CSSProperties,
  childLink: {
    display: 'block',
    padding: '7px 16px 7px 52px',
    margin: '1px 12px',
    fontSize: 13,
    color: 'var(--sidebar-text)',
    textDecoration: 'none',
    borderRadius: 8,
    transition: 'all 0.2s ease-out',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
  } as React.CSSProperties,
  childLinkActive: {
    color: 'var(--sidebar-child-active)',
    fontWeight: 500,
    background: 'rgba(255,255,255,0.04)',
  } as React.CSSProperties,
  chevron: (open: boolean): React.CSSProperties => ({
    marginLeft: 'auto',
    flexShrink: 0,
    transform: open ? 'rotate(0deg)' : 'rotate(-90deg)',
    transition: 'transform 0.2s ease-out',
    opacity: 0.4,
  }),
  toggle: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: 48,
    borderTop: '1px solid var(--sidebar-divider)',
    cursor: 'pointer',
    color: 'var(--sidebar-text)',
    background: 'transparent',
    border: 'none',
    borderTopStyle: 'solid' as const,
    borderTopWidth: 1,
    borderTopColor: 'var(--sidebar-divider)',
    flexShrink: 0,
    width: '100%',
    transition: 'color 0.2s ease-out',
  } as React.CSSProperties,
};

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { isAdmin, isAnalyst } = useAuth();
  const location = useLocation();
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({
    Detection: true,
    Administration: true,
  });

  const toggleGroup = (label: string) => {
    setOpenGroups((prev) => ({ ...prev, [label]: !prev[label] }));
  };

  const isRouteActive = (to: string, end?: boolean) => {
    if (end) return location.pathname === to;
    return location.pathname.startsWith(to);
  };

  const isGroupActive = (item: NavItem): boolean => {
    if (item.to && isRouteActive(item.to, item.end)) return true;
    if (item.children) return item.children.some((c) => isRouteActive(c.to));
    return false;
  };

  return (
    <aside style={S.sidebar(collapsed)}>
      {/* Logo */}
      <div style={S.logoWrap(collapsed)}>
        <img src="/cyberboxlogo.png" alt="CyberboxSIEM" style={{ height: collapsed ? 24 : 28, width: 'auto', flexShrink: 0 }} />
        {!collapsed && (
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={S.logoText}>CYBERBOX</span>
            <span style={{ fontSize: 15, fontWeight: 700, color: '#00F4A3', letterSpacing: '0.15em' }}>SIEM</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav style={S.nav}>
        {NAV_ITEMS.map((item) => {
          if (item.adminOnly && !isAdmin) return null;
          if (item.analystOnly && !isAnalyst && !isAdmin) return null;
          const active = isGroupActive(item);
          const hasChildren = item.children && item.children.length > 0;
          const groupOpen = openGroups[item.label] ?? false;

          // Items with children but also a direct link (e.g., Alerts)
          // or items that are purely collapsible groups (Detection, Administration)
          if (hasChildren && !item.to) {
            // Pure collapsible group
            return (
              <React.Fragment key={item.label}>
                <div>
                  <button
                    style={S.groupHeader(collapsed, active)}
                    onClick={() => !collapsed && toggleGroup(item.label)}
                    title={collapsed ? item.label : undefined}
                  >
                    {icons[item.icon]}
                    {!collapsed && (
                      <>
                        <span>{item.label}</span>
                        <span style={S.chevron(groupOpen)}>{icons.chevronDown}</span>
                      </>
                    )}
                  </button>
                  {!collapsed && groupOpen &&
                    item.children!.map((child) => (
                      <NavLink
                        key={child.to}
                        to={child.to}
                        style={({ isActive }) => ({
                          ...S.childLink,
                          ...(isActive ? S.childLinkActive : {}),
                        })}
                      >
                        {child.label}
                      </NavLink>
                    ))}
                </div>
                {item.dividerAfter && <div style={{ height: 1, background: 'var(--sidebar-divider)', margin: '6px 16px' }} />}
              </React.Fragment>
            );
          }

          if (hasChildren && item.to) {
            // Group with a direct link + children
            return (
              <div key={item.label}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    style={({ isActive }) => ({
                      ...S.link(collapsed),
                      ...(isActive ? S.linkActive : {}),
                      flex: 1,
                    })}
                    title={collapsed ? item.label : undefined}
                  >
                    {icons[item.icon]}
                    {!collapsed && <span>{item.label}</span>}
                  </NavLink>
                  {!collapsed && (
                    <button
                      style={{
                        background: 'transparent',
                        border: 'none',
                        cursor: 'pointer',
                        padding: '4px 10px 4px 0',
                        color: '#A2A9B0',
                        display: 'flex',
                        alignItems: 'center',
                      }}
                      onClick={() => toggleGroup(item.label)}
                    >
                      <span style={S.chevron(groupOpen)}>{icons.chevronDown}</span>
                    </button>
                  )}
                </div>
                {!collapsed && groupOpen &&
                  item.children!.map((child) => (
                    <NavLink
                      key={child.to}
                      to={child.to}
                      style={({ isActive }) => ({
                        ...S.childLink,
                        ...(isActive ? S.childLinkActive : {}),
                      })}
                    >
                      {child.label}
                    </NavLink>
                  ))}
              </div>
            );
          }

          // Simple link (no children)
          return (
            <React.Fragment key={item.label}>
              <NavLink
                to={item.to!}
                end={item.end}
                style={({ isActive }) => ({
                  ...S.link(collapsed),
                  ...(isActive ? S.linkActive : {}),
                })}
                title={collapsed ? item.label : undefined}
              >
                {icons[item.icon]}
                {!collapsed && <span>{item.label}</span>}
              </NavLink>
              {item.dividerAfter && <div style={{ height: 1, background: 'var(--sidebar-divider)', margin: '6px 16px' }} />}
            </React.Fragment>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <button style={S.toggle} onClick={onToggle} title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
        {collapsed ? icons.chevronRight : icons.chevronLeft}
      </button>
    </aside>
  );
}
