import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Building2,
  ChevronsUpDown,
  Command,
  LogOut,
  Menu,
  Moon,
  Search,
  ShieldCheck,
  Sparkles,
  SunMedium,
} from 'lucide-react';

import { useAuth } from '@/contexts/AuthContext';
import { useTheme } from '@/contexts/ThemeContext';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { WorkspaceStatusBanner } from '@/components/workspace/status-banner';
interface TopBarProps {
  onOpenSidebar: () => void;
  onOpenCommandPalette: () => void;
  openBypassEditorSignal?: number;
}

const BYPASS_PRESETS = [
  {
    id: 'soc-admin',
    label: 'SOC Admin',
    tenantId: 'tenant-a',
    userId: 'soc-admin',
    roles: ['admin', 'analyst', 'viewer', 'ingestor'],
  },
  {
    id: 'soc-analyst',
    label: 'SOC Analyst',
    tenantId: 'tenant-a',
    userId: 'soc-analyst',
    roles: ['analyst', 'viewer'],
  },
  {
    id: 'soc-viewer',
    label: 'SOC Viewer',
    tenantId: 'tenant-a',
    userId: 'soc-viewer',
    roles: ['viewer'],
  },
  {
    id: 'collector',
    label: 'Collector',
    tenantId: 'tenant-a',
    userId: 'collector-ingest',
    roles: ['ingestor'],
  },
] as const;

const PAGE_META = [
  {
    match: (pathname: string) => pathname === '/',
    eyebrow: 'Command Center',
    title: 'Operations overview',
    description: 'Track ingest, detection pressure, and responder workload from one live workspace.',
  },
  {
    match: (pathname: string) => pathname.startsWith('/alerts'),
    eyebrow: 'Queue',
    title: 'Alert operations',
    description: 'Triage active detections, validate impact, and hand off the right work quickly.',
  },
  {
    match: (pathname: string) => pathname.startsWith('/cases'),
    eyebrow: 'Response',
    title: 'Case management',
    description: 'Coordinate investigations, ownership, and final outcomes across the tenant.',
  },
  {
    match: (pathname: string) => pathname.startsWith('/search'),
    eyebrow: 'Hunt',
    title: 'Search workspace',
    description: 'Pivot through telemetry with the same tenant context as the rest of the console.',
  },
  {
    match: (pathname: string) => pathname.startsWith('/agents'),
    eyebrow: 'Fleet',
    title: 'Agent control',
    description: 'Monitor collector health, enrollment, and endpoint readiness.',
  },
  {
    match: (pathname: string) => pathname.startsWith('/admin'),
    eyebrow: 'Control',
    title: 'Administration',
    description: 'Manage the platform surface carefully, with tenant-aware security controls.',
  },
];

function getPageMeta(pathname: string) {
  return (
    PAGE_META.find((entry) => entry.match(pathname)) ?? {
      eyebrow: 'Workspace',
      title: 'Cyberbox console',
      description: 'A focused operating surface for detections, investigation, and control.',
    }
  );
}

function getRoleTone(roles: string[]): 'destructive' | 'warning' | 'secondary' | 'outline' {
  if (roles.includes('admin')) return 'destructive';
  if (roles.includes('analyst')) return 'warning';
  if (roles.includes('viewer')) return 'secondary';
  return 'outline';
}

function getSingleRoleTone(role: string): 'destructive' | 'warning' | 'secondary' {
  if (role === 'admin') return 'destructive';
  if (role === 'analyst') return 'warning';
  return 'secondary';
}

function getPrimaryRole(roles: string[]) {
  if (roles.includes('admin')) return 'Admin';
  if (roles.includes('analyst')) return 'Analyst';
  if (roles.includes('viewer')) return 'Viewer';
  if (roles.includes('ingestor')) return 'Ingestor';
  return 'User';
}

function formatTenant(tenantId: string) {
  if (!tenantId) return 'default';
  return tenantId.length > 18 ? `${tenantId.slice(0, 8)}...${tenantId.slice(-6)}` : tenantId;
}

function formatRolesInput(roles: string[]) {
  return roles.join(', ');
}

function normalizeRolesInput(rolesInput: string) {
  return rolesInput
    .split(',')
    .map((role) => role.trim())
    .filter(Boolean)
    .filter((role, index, list) => list.indexOf(role) === index);
}

function getBypassPresetId(tenantId: string, userId: string, roles: string[]) {
  const normalizedRoles = [...roles].sort().join(',');
  const match = BYPASS_PRESETS.find((preset) =>
    preset.tenantId === tenantId
      && preset.userId === userId
      && [...preset.roles].sort().join(',') === normalizedRoles,
  );

  return match?.id ?? 'custom';
}

export function TopBar({
  onOpenSidebar,
  onOpenCommandPalette,
  openBypassEditorSignal = 0,
}: TopBarProps) {
  const location = useLocation();
  const {
    authMode,
    displayName,
    userId,
    tenantId,
    roles,
    signOut,
    bypassIdentity,
    setBypassIdentity,
    resetBypassIdentity,
  } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);
  const [bypassPresetId, setBypassPresetId] = useState('soc-admin');
  const [bypassTenantId, setBypassTenantId] = useState('');
  const [bypassUserId, setBypassUserId] = useState('');
  const [bypassRolesInput, setBypassRolesInput] = useState('');
  const [bypassNotice, setBypassNotice] = useState('');
  const [bypassError, setBypassError] = useState('');
  const menuRef = useRef<HTMLDivElement>(null);
  const bypassPresetRef = useRef<HTMLSelectElement>(null);

  const pageMeta = useMemo(() => getPageMeta(location.pathname), [location.pathname]);

  const name = displayName || userId || 'SOC User';
  const initials = name
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((segment) => segment[0]?.toUpperCase() ?? '')
    .join('')
    .slice(0, 2);

  const primaryRole = getPrimaryRole(roles);
  const sessionLabel = authMode === 'bypass' ? 'Development bypass' : 'Tenant-scoped access';
  const actionLabel = authMode === 'bypass' ? 'Reload workspace' : 'Sign out';
  const actionHint = authMode === 'bypass' ? 'Dev identity remains local' : 'Secure logout';

  useEffect(() => {
    if (!menuOpen) return;

    const handlePointerDown = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [menuOpen]);

  useEffect(() => {
    if (!menuOpen || authMode !== 'bypass' || !bypassIdentity) {
      return;
    }

    setBypassPresetId(getBypassPresetId(bypassIdentity.tenantId, bypassIdentity.userId, bypassIdentity.roles));
    setBypassTenantId(bypassIdentity.tenantId);
    setBypassUserId(bypassIdentity.userId);
    setBypassRolesInput(formatRolesInput(bypassIdentity.roles));
  }, [authMode, bypassIdentity, menuOpen]);

  useEffect(() => {
    if (menuOpen) {
      return;
    }

    setBypassNotice('');
    setBypassError('');
  }, [menuOpen]);

  useEffect(() => {
    if (openBypassEditorSignal === 0 || authMode !== 'bypass') {
      return;
    }

    setMenuOpen(true);
    const frame = window.requestAnimationFrame(() => {
      bypassPresetRef.current?.focus();
    });

    return () => window.cancelAnimationFrame(frame);
  }, [authMode, openBypassEditorSignal]);

  const handleBypassPresetChange = (event: ChangeEvent<HTMLSelectElement>) => {
    const nextPresetId = event.target.value;
    setBypassPresetId(nextPresetId);
    setBypassNotice('');
    setBypassError('');

    if (nextPresetId === 'custom') {
      return;
    }

    const preset = BYPASS_PRESETS.find((item) => item.id === nextPresetId);
    if (!preset) {
      return;
    }

    setBypassTenantId(preset.tenantId);
    setBypassUserId(preset.userId);
    setBypassRolesInput(formatRolesInput([...preset.roles]));
  };

  const handleApplyBypassIdentity = () => {
    const nextTenantId = bypassTenantId.trim();
    const nextUserId = bypassUserId.trim();

    if (!nextTenantId || !nextUserId) {
      setBypassError('Tenant ID and user ID are required for bypass mode.');
      setBypassNotice('');
      return;
    }

    const nextRoles = normalizeRolesInput(bypassRolesInput);

    setBypassIdentity({
      tenantId: nextTenantId,
      userId: nextUserId,
      roles: nextRoles,
    });
    setBypassPresetId(getBypassPresetId(nextTenantId, nextUserId, nextRoles));
    setBypassNotice('Development identity updated for new API requests.');
    setBypassError('');
  };

  const handleResetBypassIdentity = () => {
    resetBypassIdentity();
    setBypassNotice('Development identity reset to the default SOC admin profile.');
    setBypassError('');
  };

  return (
    <header className="sticky top-0 z-30 px-4 pt-4 sm:px-6 lg:px-8">
      <div className="rounded-xl border border-border/70 bg-card/75 p-4 shadow-card backdrop-blur-2xl sm:p-5">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div className="flex items-start gap-3">
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="mt-1 h-11 w-11 rounded-2xl border-border/80 bg-background/40 lg:hidden"
              onClick={onOpenSidebar}
            >
              <Menu className="h-4 w-4" />
            </Button>

            <div className="min-w-0">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <Badge variant="outline" className="gap-2 border-primary/20 bg-primary/10 text-primary">
                  <Sparkles className="h-3.5 w-3.5" />
                  {pageMeta.eyebrow}
                </Badge>
                <Badge variant="secondary" className="hidden sm:inline-flex">
                  Tenant {formatTenant(tenantId)}
                </Badge>
              </div>
              <div className="font-display text-[1.85rem] font-semibold leading-none tracking-[-0.03em] text-foreground">
                {pageMeta.title}
              </div>
              <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
                {pageMeta.description}
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-3 lg:min-w-[420px]">
            <button
              type="button"
              onClick={onOpenCommandPalette}
              className="group flex w-full items-center gap-3 rounded-lg border border-border/80 bg-background/35 px-4 py-3 text-left transition-colors hover:bg-muted/60"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-border/70 bg-card/80 text-muted-foreground">
                <Search className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium text-foreground">Search the workspace</div>
                <div className="truncate text-xs text-muted-foreground">
                  Open command palette, jump to routes, or start a hunt fast.
                </div>
              </div>
              <div className="hidden items-center gap-2 rounded-full border border-border/80 bg-background/70 px-3 py-1 text-xs text-muted-foreground sm:inline-flex">
                <Command className="h-3.5 w-3.5" />
                Ctrl K
              </div>
            </button>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="hidden items-center gap-2 sm:flex">
                <Badge variant={getRoleTone(roles)}>{primaryRole}</Badge>
                <div className="flex items-center gap-2 rounded-full border border-border/80 bg-background/45 px-3 py-1.5 text-xs text-muted-foreground">
                  <ShieldCheck className="h-3.5 w-3.5 text-primary" />
                  {sessionLabel}
                </div>
              </div>

              <div className="ml-auto flex items-center gap-2">
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-11 w-11 rounded-2xl border border-transparent bg-background/20"
                  onClick={toggleTheme}
                >
                  {isDark ? <SunMedium className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                </Button>

                <div className="relative" ref={menuRef}>
                  <button
                    type="button"
                    onClick={() => setMenuOpen((open) => !open)}
                    className="flex items-center gap-3 rounded-lg border border-border/80 bg-background/35 px-3 py-2.5 text-left transition-colors hover:bg-muted/60"
                  >
                    <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-primary/15 font-semibold text-primary">
                      {initials || 'SU'}
                    </div>
                    <div className="hidden min-w-0 sm:block">
                      <div className="truncate text-sm font-medium text-foreground">{name}</div>
                      <div className="truncate text-xs text-muted-foreground">{primaryRole}</div>
                    </div>
                    <ChevronsUpDown className="h-4 w-4 text-muted-foreground" />
                  </button>

                  {menuOpen && (
                    <div className={`absolute right-0 top-[calc(100%+0.75rem)] z-50 rounded-xl border border-border/80 bg-popover/95 p-4 text-popover-foreground shadow-shell backdrop-blur-2xl ${authMode === 'bypass' ? 'w-[24rem]' : 'w-[22rem]'}`}>
                      <div className="rounded-lg border border-border/70 bg-background/40 p-4">
                        <div className="flex items-start gap-3">
                          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/15 font-semibold text-primary">
                            {initials || 'SU'}
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="truncate font-display text-lg font-semibold">{name}</div>
                            <div className="truncate text-sm text-muted-foreground">{userId || 'No identity loaded'}</div>
                          </div>
                        </div>
                        <div className="mt-4 grid gap-2 sm:grid-cols-2">
                          <div className="rounded-2xl border border-border/70 bg-card/75 p-3">
                            <div className="mb-1 flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-muted-foreground">
                              <Building2 className="h-3.5 w-3.5" />
                              Tenant
                            </div>
                            <div className="break-all text-sm text-foreground">{tenantId || 'default'}</div>
                          </div>
                          <div className="rounded-2xl border border-border/70 bg-card/75 p-3">
                            <div className="mb-1 flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-muted-foreground">
                              <ShieldCheck className="h-3.5 w-3.5" />
                              Role
                            </div>
                            <div className="text-sm text-foreground">{primaryRole}</div>
                          </div>
                        </div>
                      </div>

                      <div className="mt-3 flex flex-wrap gap-2">
                        {roles.length > 0 ? (
                          roles.map((role) => (
                            <Badge
                              key={role}
                              variant={getSingleRoleTone(role)}
                              className="uppercase"
                            >
                              {role}
                            </Badge>
                          ))
                        ) : (
                          <Badge variant="outline">No app role claims</Badge>
                        )}
                      </div>

                      {authMode === 'bypass' && bypassIdentity && (
                        <div className="mt-4 rounded-lg border border-border/70 bg-background/35 p-4">
                          <div className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-primary">
                            Development Identity
                          </div>
                          <p className="text-sm text-muted-foreground">
                            Update the local bypass headers used against an `auth_disabled=true` backend.
                          </p>

                          {bypassError ? (
                            <WorkspaceStatusBanner tone="warning" className="mt-3">
                              {bypassError}
                            </WorkspaceStatusBanner>
                          ) : null}

                          {bypassNotice ? (
                            <WorkspaceStatusBanner tone="success" className="mt-3">
                              {bypassNotice}
                            </WorkspaceStatusBanner>
                          ) : null}

                          <div className="mt-3 space-y-3">
                            <div>
                              <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground" htmlFor="bypass-preset">
                                Preset
                              </label>
                              <Select
                                id="bypass-preset"
                                ref={bypassPresetRef}
                                value={bypassPresetId}
                                onChange={handleBypassPresetChange}
                              >
                                {BYPASS_PRESETS.map((preset) => (
                                  <option key={preset.id} value={preset.id}>
                                    {preset.label}
                                  </option>
                                ))}
                                <option value="custom">Custom</option>
                              </Select>
                            </div>

                            <div className="grid gap-3 sm:grid-cols-2">
                              <div>
                                <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground" htmlFor="bypass-tenant">
                                  Tenant
                                </label>
                                <Input
                                  id="bypass-tenant"
                                  value={bypassTenantId}
                                  onChange={(event) => setBypassTenantId(event.target.value)}
                                  placeholder="tenant-a"
                                />
                              </div>

                              <div>
                                <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground" htmlFor="bypass-user">
                                  User ID
                                </label>
                                <Input
                                  id="bypass-user"
                                  value={bypassUserId}
                                  onChange={(event) => setBypassUserId(event.target.value)}
                                  placeholder="soc-analyst"
                                />
                              </div>
                            </div>

                            <div>
                              <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground" htmlFor="bypass-roles">
                                Roles
                              </label>
                              <Input
                                id="bypass-roles"
                                value={bypassRolesInput}
                                onChange={(event) => setBypassRolesInput(event.target.value)}
                                placeholder="admin, analyst, viewer"
                              />
                              <p className="mt-2 text-xs text-muted-foreground">
                                Comma-separated roles. Leave blank to simulate a user with no assigned roles.
                              </p>
                            </div>
                          </div>

                          <div className="mt-4 flex flex-wrap gap-2">
                            <Button
                              type="button"
                              size="sm"
                              onClick={handleApplyBypassIdentity}
                            >
                              Apply identity
                            </Button>
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              onClick={handleResetBypassIdentity}
                            >
                              Reset default
                            </Button>
                          </div>
                        </div>
                      )}

                      <button
                        type="button"
                        onClick={() => {
                          setMenuOpen(false);
                          void signOut();
                        }}
                        className="mt-4 flex w-full items-center justify-between rounded-lg border border-border/80 bg-background/35 px-4 py-3 text-sm font-medium transition-colors hover:bg-muted/60"
                      >
                        <span className="flex items-center gap-2">
                          <LogOut className="h-4 w-4" />
                          {actionLabel}
                        </span>
                        <span className="text-xs text-muted-foreground">{actionHint}</span>
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
