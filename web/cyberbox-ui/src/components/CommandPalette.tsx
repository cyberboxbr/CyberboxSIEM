import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

/* ------------------------------------------------------------------ */
/*  Data                                                               */
/* ------------------------------------------------------------------ */

interface PaletteItem {
  id: string;
  label: string;
  section: 'Navigation' | 'Actions';
  to?: string;
  action?: () => void;
  keywords?: string;
  adminOnly?: boolean;
  analystOnly?: boolean;
}

const NAV_ITEMS: PaletteItem[] = [
  { id: 'nav-dashboard', label: 'Dashboard', section: 'Navigation', to: '/', keywords: 'home overview' },
  { id: 'nav-alerts', label: 'Alerts', section: 'Navigation', to: '/alerts', keywords: 'alert queue notifications' },
  { id: 'nav-cases', label: 'Cases', section: 'Navigation', to: '/cases', keywords: 'case incident' },
  { id: 'nav-rules', label: 'Detection Rules', section: 'Navigation', to: '/rules', keywords: 'rule sigma detection', analystOnly: true },
  { id: 'nav-coverage', label: 'MITRE Coverage', section: 'Navigation', to: '/coverage', keywords: 'mitre att&ck matrix', analystOnly: true },
  { id: 'nav-lookups', label: 'Lookup Tables', section: 'Navigation', to: '/lookups', keywords: 'lookup enrichment', analystOnly: true },
  { id: 'nav-search', label: 'Search', section: 'Navigation', to: '/search', keywords: 'query investigate' },
  { id: 'nav-threatintel', label: 'Threat Intel', section: 'Navigation', to: '/threat-intel', keywords: 'threat intelligence ioc', analystOnly: true },
  { id: 'nav-agents', label: 'Agents', section: 'Navigation', to: '/agents', keywords: 'agent collector endpoint', analystOnly: true },
  { id: 'nav-rbac', label: 'RBAC', section: 'Navigation', to: '/admin/rbac', keywords: 'roles permissions access', adminOnly: true },
  { id: 'nav-audit', label: 'Audit Logs', section: 'Navigation', to: '/admin/audit', keywords: 'audit trail log', adminOnly: true },
  { id: 'nav-lgpd', label: 'LGPD Compliance', section: 'Navigation', to: '/admin/lgpd', keywords: 'privacy compliance gdpr', adminOnly: true },
  { id: 'nav-system', label: 'System', section: 'Navigation', to: '/admin/system', keywords: 'settings configuration', adminOnly: true },
];

const ACTION_ITEMS: PaletteItem[] = [
  { id: 'act-create-rule', label: 'Create Rule', section: 'Actions', to: '/rules', keywords: 'new add sigma detection', analystOnly: true },
  { id: 'act-ingest', label: 'Ingest Event', section: 'Actions', to: '/alerts', keywords: 'send submit event log' },
];

const ALL_ITEMS = [...NAV_ITEMS, ...ACTION_ITEMS];

/* ------------------------------------------------------------------ */
/*  Styles                                                             */
/* ------------------------------------------------------------------ */

const S = {
  overlay: {
    position: 'fixed',
    inset: 0,
    zIndex: 500,
    background: 'rgba(0, 0, 0, 0.7)',
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'center',
    paddingTop: 120,
  } as React.CSSProperties,
  modal: {
    width: 520,
    maxWidth: 'calc(100vw - 32px)',
    maxHeight: 'calc(100vh - 200px)',
    background: '#0a0a0a',
    border: '1px solid rgba(107, 45, 189, 0.4)',
    borderRadius: 12,
    boxShadow: '0 20px 60px rgba(0, 0, 0, 0.8)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  } as React.CSSProperties,
  inputWrap: {
    padding: '12px 16px',
    borderBottom: '1px solid rgba(107, 45, 189, 0.25)',
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  } as React.CSSProperties,
  searchIcon: {
    color: '#A2A9B0',
    flexShrink: 0,
  } as React.CSSProperties,
  input: {
    flex: 1,
    background: 'transparent',
    border: 'none',
    outline: 'none',
    color: '#F4F4F4',
    fontSize: 15,
    fontFamily: '"IBM Plex Sans", "Segoe UI", sans-serif',
  } as React.CSSProperties,
  escBadge: {
    fontSize: 11,
    color: '#A2A9B0',
    padding: '2px 6px',
    border: '1px solid rgba(107, 45, 189, 0.2)',
    borderRadius: 4,
    flexShrink: 0,
  } as React.CSSProperties,
  list: {
    overflowY: 'auto',
    padding: '8px 0',
  } as React.CSSProperties,
  sectionLabel: {
    padding: '8px 16px 4px',
    fontSize: 11,
    fontWeight: 600,
    color: '#A2A9B0',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.08em',
  } as React.CSSProperties,
  item: (active: boolean): React.CSSProperties => ({
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '8px 16px',
    cursor: 'pointer',
    background: active ? 'rgba(107, 45, 189, 0.2)' : 'transparent',
    color: active ? '#F4F4F4' : '#A2A9B0',
    fontSize: 13,
    transition: 'background 0.1s, color 0.1s',
    border: 'none',
    width: '100%',
    textAlign: 'left',
    fontFamily: '"IBM Plex Sans", "Segoe UI", sans-serif',
  }),
  itemIcon: {
    width: 18,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: '#A2A9B0',
    flexShrink: 0,
  } as React.CSSProperties,
  empty: {
    padding: '24px 16px',
    textAlign: 'center' as const,
    color: '#A2A9B0',
    fontSize: 13,
  } as React.CSSProperties,
  footer: {
    padding: '8px 16px',
    borderTop: '1px solid rgba(107, 45, 189, 0.2)',
    display: 'flex',
    gap: 16,
    fontSize: 11,
    color: 'rgba(162, 169, 176, 0.6)',
  } as React.CSSProperties,
  footerKbd: {
    display: 'inline-block',
    padding: '0px 4px',
    borderRadius: 3,
    border: '1px solid rgba(107, 45, 189, 0.2)',
    background: 'rgba(107, 45, 189, 0.1)',
    fontSize: 10,
    fontFamily: 'monospace',
    marginRight: 4,
  } as React.CSSProperties,
};

/* ------------------------------------------------------------------ */
/*  Icons for palette items                                            */
/* ------------------------------------------------------------------ */

const navIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="9 18 15 12 9 6" />
  </svg>
);

const actionIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);

const searchSvg = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" />
    <line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const { isAdmin, isAnalyst } = useAuth();
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  const availableItems = ALL_ITEMS.filter((item) => {
    if (item.adminOnly && !isAdmin) return false;
    if (item.analystOnly && !(isAdmin || isAnalyst)) return false;
    return true;
  });

  // Filter items
  const filtered = query.trim()
    ? availableItems.filter((item) => {
        const q = query.toLowerCase();
        return (
          item.label.toLowerCase().includes(q) ||
          (item.keywords && item.keywords.toLowerCase().includes(q))
        );
      })
    : availableItems;

  // Group by section
  const sections: { title: string; items: PaletteItem[] }[] = [];
  const navFiltered = filtered.filter((i) => i.section === 'Navigation');
  const actFiltered = filtered.filter((i) => i.section === 'Actions');
  if (navFiltered.length > 0) sections.push({ title: 'Navigation', items: navFiltered });
  if (actFiltered.length > 0) sections.push({ title: 'Actions', items: actFiltered });
  const flatItems = sections.flatMap((s) => s.items);

  // Reset active index on query change
  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  // Focus input on open
  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  // Global Cmd+K / Ctrl+K listener
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (!open) {
          // Parent handles opening
        } else {
          onClose();
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onClose]);

  const selectItem = useCallback(
    (item: PaletteItem) => {
      if (item.to) {
        navigate(item.to);
      }
      if (item.action) {
        item.action();
      }
      onClose();
    },
    [navigate, onClose],
  );

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((prev) => Math.min(prev + 1, flatItems.length - 1));
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((prev) => Math.max(prev - 1, 0));
      return;
    }
    if (e.key === 'Enter' && flatItems.length > 0) {
      e.preventDefault();
      selectItem(flatItems[activeIndex]);
    }
  };

  // Scroll active item into view
  useEffect(() => {
    if (!listRef.current) return;
    const el = listRef.current.querySelector(`[data-palette-index="${activeIndex}"]`) as HTMLElement | null;
    if (el) {
      el.scrollIntoView({ block: 'nearest' });
    }
  }, [activeIndex]);

  if (!open) return null;

  let flatIndex = 0;

  return (
    <div style={S.overlay} onClick={onClose}>
      <div style={S.modal} onClick={(e) => e.stopPropagation()} onKeyDown={handleKeyDown}>
        {/* Search input */}
        <div style={S.inputWrap}>
          <span style={S.searchIcon}>{searchSvg}</span>
          <input
            ref={inputRef}
            style={S.input}
            type="text"
            placeholder="Type a command or search..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <span style={S.escBadge}>ESC</span>
        </div>

        {/* Results */}
        <div style={S.list} ref={listRef}>
          {sections.length === 0 && (
            <div style={S.empty}>No results found</div>
          )}
          {sections.map((section) => (
            <div key={section.title}>
              <div style={S.sectionLabel}>{section.title}</div>
              {section.items.map((item) => {
                const idx = flatIndex++;
                return (
                  <button
                    key={item.id}
                    data-palette-index={idx}
                    style={S.item(idx === activeIndex)}
                    onClick={() => selectItem(item)}
                    onMouseEnter={() => setActiveIndex(idx)}
                  >
                    <span style={S.itemIcon}>
                      {item.section === 'Navigation' ? navIcon : actionIcon}
                    </span>
                    {item.label}
                  </button>
                );
              })}
            </div>
          ))}
        </div>

        {/* Footer hints */}
        <div style={S.footer}>
          <span>
            <kbd style={S.footerKbd}>Up</kbd>
            <kbd style={S.footerKbd}>Down</kbd>
            navigate
          </span>
          <span>
            <kbd style={S.footerKbd}>Enter</kbd>
            select
          </span>
          <span>
            <kbd style={S.footerKbd}>Esc</kbd>
            close
          </span>
        </div>
      </div>
    </div>
  );
}
