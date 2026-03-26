import { useEffect, useRef, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  ChevronDown,
  LogOut,
  Moon,
  Search,
  SunMedium,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/AuthContext';
import { useTheme } from '@/contexts/ThemeContext';

interface NavChild {
  label: string;
  to: string;
}

interface NavItem {
  label: string;
  to?: string;
  end?: boolean;
  gate?: 'admin' | 'analyst';
  children?: NavChild[];
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', to: '/', end: true },
  { label: 'Alerts', to: '/alerts' },
  { label: 'Cases', to: '/cases' },
  { label: 'Search', to: '/search' },
  {
    label: 'Detection',
    gate: 'analyst',
    children: [
      { label: 'Rules', to: '/rules' },
      { label: 'MITRE Coverage', to: '/coverage' },
      { label: 'Lookup Tables', to: '/lookups' },
    ],
  },
  { label: 'Threat Intel', to: '/threat-intel', gate: 'analyst' },
  { label: 'Agents', to: '/agents', gate: 'analyst' },
  {
    label: 'Administration',
    gate: 'admin',
    children: [
      { label: 'RBAC', to: '/admin/rbac' },
      { label: 'Audit Logs', to: '/admin/audit' },
      { label: 'LGPD Compliance', to: '/admin/lgpd' },
      { label: 'System', to: '/admin/system' },
      { label: 'API Keys', to: '/admin/api-keys' },
    ],
  },
];

interface TopNavProps {
  onOpenCommandPalette?: () => void;
  onSignOut?: () => void;
}

export function TopNav({ onOpenCommandPalette, onSignOut }: TopNavProps) {
  const location = useLocation();
  const { displayName, userId, isAdmin, isAnalyst } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const name = displayName || userId || 'SOC User';
  const initials = name
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase() ?? '')
    .join('')
    .slice(0, 2) || 'U';
  const role = isAdmin ? 'Admin' : isAnalyst ? 'Analyst' : 'Viewer';

  const visibleItems = NAV_ITEMS.filter((item) => {
    if (item.gate === 'admin') return isAdmin;
    if (item.gate === 'analyst') return isAdmin || isAnalyst;
    return true;
  });

  useEffect(() => {
    setOpenDropdown(null);
  }, [location.pathname]);

  useEffect(() => {
    if (!openDropdown) return;
    const handleClick = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setOpenDropdown(null);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [openDropdown]);

  const isChildActive = (children?: NavChild[]) =>
    children?.some((c) => location.pathname.startsWith(c.to)) ?? false;

  return (
    <header className="sticky top-0 z-50 border-b border-white/8 bg-[#000000]">
      <div className="flex h-11 items-center gap-1 px-4">
        {/* Logo */}
        <NavLink to="/" className="mr-4 flex shrink-0 items-center gap-2.5">
          <img src="/cyberboxlogo.png" alt="Cyberbox" className="h-6 w-6 object-contain" />
          <span className="hidden text-xs font-bold uppercase tracking-[0.16em] text-white/90 sm:inline">
            CYBER<span className="text-[#00F4A3]">BOX</span>
          </span>
        </NavLink>

        {/* Nav links */}
        <nav className="flex items-center gap-0.5" ref={dropdownRef}>
          {visibleItems.map((item) => {
            if (item.to) {
              return (
                <NavLink
                  key={item.label}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    cn(
                      'rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors',
                      isActive
                        ? 'bg-[#00F4A3]/12 text-[#00F4A3]'
                        : 'text-white/80 hover:bg-white/10 hover:text-white',
                    )
                  }
                >
                  {item.label}
                </NavLink>
              );
            }

            const isOpen = openDropdown === item.label;
            const childActive = isChildActive(item.children);
            return (
              <div key={item.label} className="relative">
                <button
                  type="button"
                  onClick={() => setOpenDropdown(isOpen ? null : item.label)}
                  className={cn(
                    'flex items-center gap-1 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors',
                    isOpen || childActive
                      ? 'bg-[#00F4A3]/12 text-[#00F4A3]'
                      : 'text-white/80 hover:bg-white/10 hover:text-white',
                  )}
                >
                  {item.label}
                  <ChevronDown className={cn('h-3 w-3 transition-transform', isOpen && 'rotate-180')} />
                </button>
                {isOpen && item.children && (
                  <div className="absolute left-0 top-full z-50 mt-1 min-w-[180px] rounded-lg border border-border/70 bg-popover/95 p-1 shadow-shell backdrop-blur-2xl">
                    {item.children.map((child) => (
                      <NavLink
                        key={child.to}
                        to={child.to}
                        className={({ isActive }) =>
                          cn(
                            'block rounded-md px-3 py-1.5 text-xs transition-colors',
                            isActive
                              ? 'bg-primary/12 text-primary'
                              : 'text-popover-foreground/80 hover:bg-muted/50 hover:text-popover-foreground',
                          )
                        }
                      >
                        {child.label}
                      </NavLink>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        {/* Right side */}
        <div className="ml-auto flex items-center gap-1.5">
          {onOpenCommandPalette && (
            <button
              type="button"
              onClick={onOpenCommandPalette}
              className="flex items-center gap-1.5 rounded-md px-2 py-1 text-[10px] text-white/70 transition-colors hover:bg-white/6 hover:text-white/70"
            >
              <Search className="h-3 w-3" />
              <kbd className="hidden rounded border border-white/15 bg-white/5 px-1 py-0.5 text-[9px] sm:inline">⌘K</kbd>
            </button>
          )}

          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-7 w-7 rounded-md text-white/70 hover:bg-white/10 hover:text-white"
            onClick={toggleTheme}
          >
            {isDark ? <SunMedium className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
          </Button>

          {onSignOut && (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-7 w-7 rounded-md text-white/70 hover:bg-white/10 hover:text-white"
              onClick={onSignOut}
            >
              <LogOut className="h-3.5 w-3.5" />
            </Button>
          )}

          <div className="ml-1 flex items-center gap-2 rounded-md px-2 py-1">
            <div className="flex h-6 w-6 items-center justify-center rounded-md bg-primary/20 text-[10px] font-semibold text-primary">
              {initials}
            </div>
            <div className="hidden sm:block">
              <div className="text-[11px] font-medium leading-none text-white/90">{name}</div>
              <div className="mt-0.5 text-[10px] leading-none text-white/70">{role}</div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
