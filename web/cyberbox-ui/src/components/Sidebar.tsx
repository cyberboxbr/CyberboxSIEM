import { useEffect, useMemo, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  BellRing,
  BriefcaseBusiness,
  ChevronDown,
  ChevronRight,
  Globe2,
  LayoutGrid,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  ServerCog,
  Shield,
  ShieldCheck,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/AuthContext';

type Gate = 'admin' | 'analyst';

interface NavChild {
  label: string;
  to: string;
}

interface NavItem {
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  to?: string;
  end?: boolean;
  gate?: Gate;
  children?: NavChild[];
  section: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', icon: LayoutGrid, to: '/', end: true, section: 'Operations' },
  { label: 'Alerts', icon: BellRing, to: '/alerts', section: 'Operations' },
  { label: 'Cases', icon: BriefcaseBusiness, to: '/cases', section: 'Operations' },
  {
    label: 'Detection',
    icon: Shield,
    gate: 'analyst',
    section: 'Hunt',
    children: [
      { label: 'Rules', to: '/rules' },
      { label: 'MITRE Coverage', to: '/coverage' },
      { label: 'Lookup Tables', to: '/lookups' },
    ],
  },
  { label: 'Search', icon: Search, to: '/search', section: 'Hunt' },
  { label: 'Threat Intel', icon: Globe2, to: '/threat-intel', gate: 'analyst', section: 'Hunt' },
  { label: 'Agents', icon: ServerCog, to: '/agents', gate: 'analyst', section: 'Control' },
  {
    label: 'Administration',
    icon: ShieldCheck,
    gate: 'admin',
    section: 'Control',
    children: [
      { label: 'RBAC', to: '/admin/rbac' },
      { label: 'Audit Logs', to: '/admin/audit' },
      { label: 'LGPD Compliance', to: '/admin/lgpd' },
      { label: 'System', to: '/admin/system' },
    ],
  },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen?: boolean;
  onMobileClose?: () => void;
}

function groupIsActive(pathname: string, item: NavItem) {
  if (item.to) {
    return item.end ? pathname === item.to : pathname.startsWith(item.to);
  }
  return item.children?.some((child) => pathname.startsWith(child.to)) ?? false;
}

export function Sidebar({
  collapsed,
  onToggle,
  mobileOpen = false,
  onMobileClose,
}: SidebarProps) {
  const location = useLocation();
  const { authMode, bypassIdentity, isAdmin, isAnalyst } = useAuth();
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const [flyoutLabel, setFlyoutLabel] = useState<string | null>(null);
  const activeBypassIdentity = authMode === 'bypass' ? bypassIdentity : null;

  const visibleItems = useMemo(
    () =>
      NAV_ITEMS.filter((item) => {
        if (item.gate === 'admin') return isAdmin;
        if (item.gate === 'analyst') return isAdmin || isAnalyst;
        return true;
      }),
    [isAdmin, isAnalyst],
  );

  useEffect(() => {
    setOpenGroups((current) => {
      const next = { ...current };
      for (const item of visibleItems) {
        if (item.children && groupIsActive(location.pathname, item)) {
          next[item.label] = true;
        }
      }
      return next;
    });
    setFlyoutLabel(null);
  }, [location.pathname, visibleItems]);

  const sections = useMemo(() => {
    const grouped = new Map<string, NavItem[]>();
    for (const item of visibleItems) {
      const bucket = grouped.get(item.section) ?? [];
      bucket.push(item);
      grouped.set(item.section, bucket);
    }
    return Array.from(grouped.entries());
  }, [visibleItems]);

  const desktopCollapsed = collapsed && !mobileOpen;

  return (
    <>
      <div
        className={cn(
          'fixed inset-0 z-40 bg-slate-950/60 backdrop-blur-sm transition-opacity duration-200 lg:hidden',
          mobileOpen ? 'opacity-100' : 'pointer-events-none opacity-0',
        )}
        onClick={onMobileClose}
      />

      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 flex h-screen flex-col border-r border-sidebar-border bg-[linear-gradient(180deg,hsl(var(--sidebar))_0%,hsl(228_34%_6%)_100%)] shadow-shell backdrop-blur-2xl transition-all duration-300',
          desktopCollapsed ? 'w-20' : 'w-[15rem]',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
        )}
      >
        <div className={cn('flex items-center gap-2.5 border-b border-sidebar-border/80 px-4 py-3', desktopCollapsed && 'justify-center px-2')}>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-white/5">
            <img src="/cyberboxlogo.png" alt="Cyberbox" className="h-6 w-6 object-contain" />
          </div>
          {!desktopCollapsed && (
            <div className="min-w-0">
              <div className="font-display text-xs font-semibold uppercase tracking-[0.22em] text-sidebar-accent">
                Cyberbox
              </div>
              <div className="text-[10px] text-sidebar-foreground/60">SOC console</div>
            </div>
          )}
        </div>

        <div className="flex-1 overflow-y-auto px-2 py-3">
          {sections.map(([section, items], sectionIndex) => (
            <div key={section}>
              {sectionIndex > 0 && <div className="my-2 border-t border-sidebar-border/50" />}

              <div className="space-y-0.5">
                {items.map((item) => {
                  const Icon = item.icon;
                  const active = groupIsActive(location.pathname, item);
                  const isOpen = openGroups[item.label];
                  const hasChildren = Boolean(item.children?.length);

                  if (item.to) {
                    return (
                      <NavLink
                        key={item.label}
                        end={item.end}
                        to={item.to}
                        onClick={onMobileClose}
                        className={({ isActive }) =>
                          cn(
                            'group flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-medium transition-all duration-200',
                            desktopCollapsed ? 'justify-center px-0' : 'justify-start',
                            isActive
                              ? 'bg-sidebar-accent/14 text-sidebar-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]'
                              : 'text-sidebar-foreground/68 hover:bg-white/6 hover:text-sidebar-foreground',
                          )
                        }
                      >
                        <Icon className="h-4 w-4 shrink-0" />
                        {!desktopCollapsed && <span className="truncate">{item.label}</span>}
                      </NavLink>
                    );
                  }

                  return (
                    <div
                      key={item.label}
                      className="relative"
                      onMouseLeave={() => {
                        if (desktopCollapsed) setFlyoutLabel(null);
                      }}
                    >
                      <button
                        type="button"
                        onClick={() => {
                          if (desktopCollapsed) {
                            setFlyoutLabel((current) => (current === item.label ? null : item.label));
                            return;
                          }
                          setOpenGroups((current) => ({
                            ...current,
                            [item.label]: !current[item.label],
                          }));
                        }}
                        className={cn(
                          'flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-medium transition-all duration-200',
                          desktopCollapsed ? 'justify-center px-0' : 'justify-start',
                          active
                            ? 'bg-sidebar-accent/14 text-sidebar-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]'
                            : 'text-sidebar-foreground/68 hover:bg-white/6 hover:text-sidebar-foreground',
                        )}
                      >
                        <Icon className="h-4 w-4 shrink-0" />
                        {!desktopCollapsed && <span className="truncate">{item.label}</span>}
                        {!desktopCollapsed && hasChildren && (
                          <ChevronDown
                            className={cn('ml-auto h-4 w-4 transition-transform duration-200', isOpen ? 'rotate-0' : '-rotate-90')}
                          />
                        )}
                      </button>

                      {!desktopCollapsed && hasChildren && (
                        <div className={cn('overflow-hidden transition-all duration-200', isOpen ? 'max-h-96 pt-1' : 'max-h-0')}>
                          <div className="space-y-1 pl-4">
                            {item.children?.map((child) => (
                              <NavLink
                                key={child.to}
                                to={child.to}
                                onClick={onMobileClose}
                                className={({ isActive }) =>
                                  cn(
                                    'flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm transition-colors',
                                    isActive
                                      ? 'bg-white/7 text-sidebar-accent'
                                      : 'text-sidebar-foreground/60 hover:bg-white/5 hover:text-sidebar-foreground',
                                  )
                                }
                              >
                                <ChevronRight className="h-3.5 w-3.5" />
                                <span>{child.label}</span>
                              </NavLink>
                            ))}
                          </div>
                        </div>
                      )}

                      {desktopCollapsed && flyoutLabel === item.label && hasChildren && (
                        <div className="absolute left-[calc(100%+0.5rem)] top-0 w-56 rounded-lg border border-border/70 bg-popover/95 p-2 shadow-shell backdrop-blur-2xl">
                          <div className="mb-1.5 px-2.5 pt-0.5 font-display text-sm font-semibold text-popover-foreground">
                            {item.label}
                          </div>
                          <div className="space-y-1">
                            {item.children?.map((child) => (
                              <NavLink
                                key={child.to}
                                to={child.to}
                                onClick={onMobileClose}
                                className={({ isActive }) =>
                                  cn(
                                    'flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm transition-colors',
                                    isActive
                                      ? 'bg-primary/12 text-primary'
                                      : 'text-popover-foreground/72 hover:bg-muted/70 hover:text-popover-foreground',
                                  )
                                }
                              >
                                <ChevronRight className="h-3.5 w-3.5" />
                                <span>{child.label}</span>
                              </NavLink>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        <div className="border-t border-sidebar-border/80 p-3">
          {activeBypassIdentity ? (
            <div
              className={cn(
                'mb-3 rounded-lg border border-amber-300/20 bg-[linear-gradient(145deg,rgba(245,158,11,0.16),rgba(15,23,42,0.72))] p-3 text-xs text-amber-50/90',
                desktopCollapsed && 'hidden',
              )}
            >
              <div className="mb-2 flex items-center justify-between gap-2">
                <Badge
                  variant="warning"
                  className="border-amber-300/20 bg-amber-300/12 text-amber-50"
                >
                  Bypass
                </Badge>
                <span className="text-[10px] font-semibold uppercase tracking-[0.22em] text-amber-100/80">
                  Header identity
                </span>
              </div>
              <div className="font-semibold uppercase tracking-[0.22em] text-amber-100/80">
                Development session
              </div>
              <div className="mt-2 text-sm text-sidebar-foreground">
                {activeBypassIdentity.userId}
              </div>
              <div className="mt-1 text-amber-100/75">
                Tenant {activeBypassIdentity.tenantId}
              </div>
            </div>
          ) : null}

          <Button
            type="button"
            variant="ghost"
            size="sm"
            className={cn(
              'w-full justify-center rounded-lg border-white/10 text-sidebar-foreground/60 hover:bg-white/6 hover:text-sidebar-foreground',
              desktopCollapsed && 'px-0',
            )}
            onClick={mobileOpen ? onMobileClose : onToggle}
          >
            {mobileOpen ? (
              <><ChevronRight className="h-3.5 w-3.5 rotate-180" />{!desktopCollapsed && <span>Close</span>}</>
            ) : desktopCollapsed ? (
              <PanelLeftOpen className="h-3.5 w-3.5" />
            ) : (
              <><PanelLeftClose className="h-3.5 w-3.5" /><span>Collapse</span></>
            )}
          </Button>
        </div>
      </aside>
    </>
  );
}
