import { type ComponentType, type KeyboardEvent as ReactKeyboardEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowRight,
  BellRing,
  BriefcaseBusiness,
  Globe2,
  LayoutGrid,
  Plus,
  Search,
  ServerCog,
  Shield,
  ShieldCheck,
  Sparkles,
  Table2,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { WorkspaceEmptyState } from '@/components/workspace/empty-state';
import { useAuth } from '@/contexts/AuthContext';
import { cn } from '@/lib/utils';

interface PaletteItem {
  id: string;
  label: string;
  detail: string;
  section: 'Navigation' | 'Actions';
  icon: ComponentType<{ className?: string }>;
  to?: string;
  action?: () => void;
  keywords?: string;
  badge?: string;
  adminOnly?: boolean;
  analystOnly?: boolean;
}

const ALL_ITEMS: PaletteItem[] = [
  {
    id: 'nav-dashboard',
    label: 'Dashboard',
    detail: 'Jump to the operations overview and live telemetry snapshot.',
    section: 'Navigation',
    icon: LayoutGrid,
    to: '/',
    keywords: 'home overview command center',
  },
  {
    id: 'nav-alerts',
    label: 'Alerts',
    detail: 'Open the triage queue and work active detections.',
    section: 'Navigation',
    icon: BellRing,
    to: '/alerts',
    keywords: 'alert queue notifications incidents',
  },
  {
    id: 'nav-cases',
    label: 'Cases',
    detail: 'Move into case management and response coordination.',
    section: 'Navigation',
    icon: BriefcaseBusiness,
    to: '/cases',
    keywords: 'case incident response investigations',
  },
  {
    id: 'nav-rules',
    label: 'Detection Rules',
    detail: 'Search or edit the detection rule catalog.',
    section: 'Navigation',
    icon: Shield,
    to: '/rules',
    keywords: 'rule sigma detection engineering',
    analystOnly: true,
  },
  {
    id: 'nav-coverage',
    label: 'MITRE Coverage',
    detail: 'Review ATT&CK technique coverage and open gaps.',
    section: 'Navigation',
    icon: ShieldCheck,
    to: '/coverage',
    keywords: 'mitre attack matrix coverage techniques',
    analystOnly: true,
  },
  {
    id: 'nav-lookups',
    label: 'Lookup Tables',
    detail: 'Manage enrichment tables and supporting datasets.',
    section: 'Navigation',
    icon: Table2,
    to: '/lookups',
    keywords: 'lookup enrichment tables',
    analystOnly: true,
  },
  {
    id: 'nav-search',
    label: 'Search',
    detail: 'Pivot into raw event search, NLQ, or live tail.',
    section: 'Navigation',
    icon: Search,
    to: '/search',
    keywords: 'query investigate hunt search',
  },
  {
    id: 'nav-threatintel',
    label: 'Threat Intel',
    detail: 'Open feeds, syncs, and indicator management.',
    section: 'Navigation',
    icon: Globe2,
    to: '/threat-intel',
    keywords: 'threat intelligence ioc feeds',
    analystOnly: true,
  },
  {
    id: 'nav-agents',
    label: 'Agents',
    detail: 'Inspect fleet health and collector control actions.',
    section: 'Navigation',
    icon: ServerCog,
    to: '/agents',
    keywords: 'agent fleet collector endpoint',
    analystOnly: true,
  },
  {
    id: 'nav-rbac',
    label: 'RBAC',
    detail: 'Manage user roles and access control assignments.',
    section: 'Navigation',
    icon: ShieldCheck,
    to: '/admin/rbac',
    keywords: 'roles permissions access rbac',
    badge: 'Admin',
    adminOnly: true,
  },
  {
    id: 'nav-audit',
    label: 'Audit Logs',
    detail: 'Inspect platform activity and change history.',
    section: 'Navigation',
    icon: ShieldCheck,
    to: '/admin/audit',
    keywords: 'audit logs trail compliance',
    badge: 'Admin',
    adminOnly: true,
  },
  {
    id: 'nav-lgpd',
    label: 'LGPD Compliance',
    detail: 'Handle privacy exports, anonymization, and breach reporting.',
    section: 'Navigation',
    icon: ShieldCheck,
    to: '/admin/lgpd',
    keywords: 'privacy compliance lgpd gdpr',
    badge: 'Admin',
    adminOnly: true,
  },
  {
    id: 'nav-system',
    label: 'System',
    detail: 'Open runtime health, metrics, and operational checks.',
    section: 'Navigation',
    icon: ShieldCheck,
    to: '/admin/system',
    keywords: 'system health settings metrics',
    badge: 'Admin',
    adminOnly: true,
  },
  {
    id: 'act-create-rule',
    label: 'Create Rule',
    detail: 'Open the rules workspace and start a new detection.',
    section: 'Actions',
    icon: Plus,
    to: '/rules',
    keywords: 'new add rule sigma detection',
    analystOnly: true,
  },
  {
    id: 'act-open-search',
    label: 'Start Hunt',
    detail: 'Jump directly into the search workspace.',
    section: 'Actions',
    icon: Sparkles,
    to: '/search',
    keywords: 'hunt search investigate query',
  },
];

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onOpenBypassEditor?: () => void;
}

function footerKey(label: string) {
  return (
    <span className="inline-flex min-w-[2rem] items-center justify-center rounded-full border border-border/70 bg-background/45 px-2 py-1 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
      {label}
    </span>
  );
}

export function CommandPalette({ open, onClose, onOpenBypassEditor }: CommandPaletteProps) {
  const { authMode, isAdmin, isAnalyst, resetBypassIdentity } = useAuth();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);

  const availableItems = useMemo(
    () => {
      const items = ALL_ITEMS.filter((item) => {
        if (item.adminOnly && !isAdmin) return false;
        if (item.analystOnly && !(isAdmin || isAnalyst)) return false;
        return true;
      });

      if (authMode === 'bypass' && onOpenBypassEditor) {
        items.push({
          id: 'act-edit-development-identity',
          label: 'Edit Development Identity',
          detail: 'Open the local bypass identity editor and change tenant, user, or role headers.',
          section: 'Actions',
          icon: ShieldCheck,
          action: onOpenBypassEditor,
          keywords: 'bypass development identity tenant roles headers auth',
          badge: 'Dev',
        });

        items.push({
          id: 'act-reset-development-identity',
          label: 'Reset Development Identity',
          detail: 'Return the local bypass headers to the default SOC admin profile.',
          section: 'Actions',
          icon: Shield,
          action: resetBypassIdentity,
          keywords: 'bypass development identity reset default soc admin headers auth',
          badge: 'Dev',
        });
      }

      return items;
    },
    [authMode, isAdmin, isAnalyst, onOpenBypassEditor, resetBypassIdentity],
  );

  const sections = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    const filtered = normalized
      ? availableItems.filter((item) => {
          const haystack = `${item.label} ${item.detail} ${item.keywords ?? ''}`.toLowerCase();
          return haystack.includes(normalized);
        })
      : availableItems;

    const navigation = filtered.filter((item) => item.section === 'Navigation');
    const actions = filtered.filter((item) => item.section === 'Actions');
    return [
      ...(navigation.length ? [{ title: 'Navigation', items: navigation }] : []),
      ...(actions.length ? [{ title: 'Actions', items: actions }] : []),
    ];
  }, [availableItems, query]);

  const flatItems = useMemo(() => sections.flatMap((section) => section.items), [sections]);

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

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setActiveIndex(0);
    const frame = window.requestAnimationFrame(() => inputRef.current?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, [open]);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  useEffect(() => {
    if (!open) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [open]);

  useEffect(() => {
    if (!listRef.current) return;
    const element = listRef.current.querySelector(`[data-palette-index="${activeIndex}"]`) as HTMLElement | null;
    if (element) {
      element.scrollIntoView({ block: 'nearest' });
    }
  }, [activeIndex]);

  const handleKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((current) => Math.min(current + 1, Math.max(flatItems.length - 1, 0)));
      return;
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((current) => Math.max(current - 1, 0));
      return;
    }
    if (event.key === 'Enter' && flatItems.length > 0) {
      event.preventDefault();
      selectItem(flatItems[activeIndex]);
    }
  };

  if (!open) return null;

  let flatIndex = 0;

  return (
    <div
      className="fixed inset-0 z-[120] bg-slate-950/70 px-4 py-6 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      onClick={onClose}
    >
      <div className="mx-auto flex h-full max-w-3xl items-start justify-center pt-8 sm:pt-14" onClick={(event) => event.stopPropagation()}>
        <Card className="w-full overflow-hidden border-border/80 bg-popover/95 shadow-shell backdrop-blur-2xl">
          <CardHeader className="border-b border-border/70 pb-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <Badge variant="outline" className="border-primary/20 bg-primary/10 text-primary">Command palette</Badge>
                <CardTitle className="mt-4 text-3xl">Jump anywhere fast</CardTitle>
                <CardDescription className="mt-2 max-w-2xl">
                  Search navigation targets and common actions across the Cyberbox workspace.
                </CardDescription>
              </div>
              <Button type="button" variant="outline" size="sm" className="rounded-full" onClick={onClose}>
                {footerKey('Esc')}
                Close
              </Button>
            </div>

            <div className="relative mt-6">
              <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                ref={inputRef}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search routes, admin tools, or actions..."
                className="h-12 pl-11 pr-24 text-base"
              />
              <div className="pointer-events-none absolute right-3 top-1/2 hidden -translate-y-1/2 items-center gap-2 rounded-full border border-border/70 bg-background/45 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-muted-foreground sm:inline-flex">
                {footerKey('Enter')}
                open
              </div>
            </div>
          </CardHeader>

          <CardContent ref={listRef} className="max-h-[60vh] overflow-y-auto p-0">
            {sections.length === 0 ? (
              <WorkspaceEmptyState
                title="No commands match"
                body="Try a broader search phrase or clear the current query."
                className="min-h-[240px] rounded-none border-0 bg-transparent"
              />
            ) : (
              sections.map((section) => (
                <div key={section.title} className="border-b border-border/70 last:border-b-0">
                  <div className="sticky top-0 z-10 border-b border-border/70 bg-popover/95 px-6 py-3 text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">
                    {section.title}
                  </div>
                  <div className="p-3">
                    {section.items.map((item) => {
                      const index = flatIndex++;
                      const Icon = item.icon;
                      const active = index === activeIndex;

                      return (
                        <button
                          key={item.id}
                          type="button"
                          data-palette-index={index}
                          className={cn(
                            'flex w-full items-center gap-4 rounded-lg px-3 py-3 text-left transition-colors',
                            active ? 'bg-primary/10 text-foreground' : 'text-foreground hover:bg-muted/50',
                          )}
                          onClick={() => selectItem(item)}
                          onMouseEnter={() => setActiveIndex(index)}
                        >
                          <div className={cn(
                            'flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-border/70 bg-background/45',
                            active && 'border-primary/20 bg-primary/10 text-primary',
                          )}>
                            <Icon className="h-4 w-4" />
                          </div>

                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <div className="font-medium">{item.label}</div>
                              {item.badge ? <Badge variant="outline">{item.badge}</Badge> : null}
                            </div>
                            <div className="mt-1 text-sm text-muted-foreground">{item.detail}</div>
                          </div>

                          <ArrowRight className={cn('h-4 w-4 shrink-0 text-muted-foreground transition-transform', active && 'translate-x-0.5 text-primary')} />
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))
            )}
          </CardContent>

          <div className="flex flex-wrap gap-3 border-t border-border/70 px-6 py-4 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-2">{footerKey('Ctrl K')} toggle palette</span>
            <span className="inline-flex items-center gap-2">{footerKey('Up')}</span>
            <span className="inline-flex items-center gap-2">{footerKey('Down')} navigate</span>
            <span className="inline-flex items-center gap-2">{footerKey('Enter')} open</span>
          </div>
        </Card>
      </div>
    </div>
  );
}
