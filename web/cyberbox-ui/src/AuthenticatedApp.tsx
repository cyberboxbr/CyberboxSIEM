import { Suspense, lazy, useCallback, useEffect, useState } from 'react';
import { Route, Routes, useNavigate, useParams } from 'react-router-dom';
import { Badge } from './components/ui/badge';
import { Button } from './components/ui/button';

import { ErrorBoundary } from './components/ErrorBoundary';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { useAuth } from './contexts/AuthContext';
import { useIdleTimeout } from './hooks/useIdleTimeout';

const CommandPalette = lazy(() =>
  import('./components/CommandPalette').then((module) => ({ default: module.CommandPalette })),
);
const Dashboard = lazy(() => import('./pages/Dashboard').then((module) => ({ default: module.Dashboard })));
const AlertQueue = lazy(() => import('./pages/AlertQueue').then((module) => ({ default: module.AlertQueue })));
const AlertDetail = lazy(() => import('./pages/AlertDetail').then((module) => ({ default: module.AlertDetail })));
const Cases = lazy(() => import('./pages/Cases').then((module) => ({ default: module.Cases })));
const CaseDetail = lazy(() => import('./pages/CaseDetail').then((module) => ({ default: module.CaseDetail })));
const RuleEditor = lazy(() => import('./pages/RuleEditor').then((module) => ({ default: module.RuleEditor })));
const MitreCoverage = lazy(() => import('./pages/MitreCoverage').then((module) => ({ default: module.MitreCoverage })));
const Search = lazy(() => import('./pages/Search').then((module) => ({ default: module.Search })));
const ThreatIntel = lazy(() => import('./pages/ThreatIntel').then((module) => ({ default: module.ThreatIntel })));
const AgentFleet = lazy(() => import('./pages/AgentFleet').then((module) => ({ default: module.AgentFleet })));
const Rbac = lazy(() => import('./pages/Rbac').then((module) => ({ default: module.Rbac })));
const AuditLogs = lazy(() => import('./pages/AuditLogs').then((module) => ({ default: module.AuditLogs })));
const LgpdCompliance = lazy(() => import('./pages/LgpdCompliance').then((module) => ({ default: module.LgpdCompliance })));
const SystemHealth = lazy(() => import('./pages/SystemHealth').then((module) => ({ default: module.SystemHealth })));
const LookupTables = lazy(() => import('./pages/LookupTables').then((module) => ({ default: module.LookupTables })));

function AlertDetailRoute() {
  const { alertId } = useParams<{ alertId: string }>();
  const navigate = useNavigate();
  if (!alertId) return null;
  return <AlertDetail alertId={alertId} onBack={() => navigate('/alerts')} />;
}

function DashboardRoute() {
  return <Dashboard onRefresh={async () => {}} />;
}

function RouteLoading() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center px-6 py-12">
      <div className="w-full max-w-md rounded-xl border border-border/70 bg-card/80 p-8 text-center shadow-card backdrop-blur-xl">
        <div className="font-display text-2xl font-semibold text-foreground">Loading workspace view</div>
        <div className="mt-3 text-sm text-muted-foreground">
          Pulling the next console surface into place.
        </div>
      </div>
    </div>
  );
}

function RequireRole({ allow, children }: { allow: 'admin' | 'analyst'; children: JSX.Element }) {
  const { isAdmin, isAnalyst } = useAuth();
  const allowed = allow === 'admin' ? isAdmin : isAdmin || isAnalyst;

  if (!allowed) {
    return (
      <div className="mx-auto flex min-h-[70vh] max-w-3xl items-center justify-center px-6 py-12">
        <div className="w-full rounded-xl border border-border/70 bg-card/80 p-10 text-center shadow-card backdrop-blur-xl">
          <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-primary/20 bg-primary/12 text-3xl">
            Lock
          </div>
          <div className="font-display text-2xl font-semibold text-foreground">Access denied</div>
          <div className="mt-3 text-sm text-muted-foreground">
            Your current role does not include permission to open this workspace.
          </div>
        </div>
      </div>
    );
  }

  return children;
}

const SESSION_TIMEOUT_MS = 15 * 60 * 1000;
const SESSION_WARNING_MS = 60 * 1000;

export function AuthenticatedApp() {
  const { authMode, bypassIdentity, resetBypassIdentity, signOut } = useAuth();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [sessionWarning, setSessionWarning] = useState(false);
  const [openBypassEditorSignal, setOpenBypassEditorSignal] = useState(0);
  const sessionTimeoutEnabled = authMode === 'microsoft';
  const activeBypassIdentity = authMode === 'bypass' ? bypassIdentity : null;

  const handleTimeout = useCallback(() => {
    setSessionWarning(false);
    signOut();
  }, [signOut]);

  const handleWarning = useCallback(() => {
    setSessionWarning(true);
  }, []);

  useIdleTimeout(SESSION_TIMEOUT_MS, handleTimeout, SESSION_WARNING_MS, handleWarning, sessionTimeoutEnabled);

  useEffect(() => {
    if (!sessionTimeoutEnabled) {
      setSessionWarning(false);
    }
  }, [sessionTimeoutEnabled]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandPaletteOpen((current) => !current);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div className="relative min-h-screen overflow-hidden bg-background text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_hsl(var(--primary)/0.16),_transparent_28%),radial-gradient(circle_at_85%_15%,_hsl(var(--accent)/0.12),_transparent_26%),radial-gradient(circle_at_bottom_left,_hsl(var(--chart-2)/0.14),_transparent_30%),linear-gradient(180deg,_transparent,_hsl(var(--background)/0.9)_42%,_hsl(var(--background)))]" />
      <div className="pointer-events-none absolute inset-0 bg-grid-noise bg-[size:44px_44px] opacity-25" />

      {sessionTimeoutEnabled && sessionWarning && (
        <div
          className="fixed inset-x-4 top-4 z-[90] rounded-2xl border border-primary/20 bg-card/85 px-5 py-3 text-sm text-foreground shadow-card backdrop-blur-xl sm:inset-x-auto sm:right-6 sm:w-auto"
          onClick={() => setSessionWarning(false)}
        >
          Session expires in 1 minute due to inactivity. Move your mouse to stay signed in.
        </div>
      )}

      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileSidebarOpen}
        onMobileClose={() => setMobileSidebarOpen(false)}
      />

      <div className={`relative z-10 min-h-screen transition-[padding] duration-300 ${sidebarCollapsed ? 'lg:pl-[5rem]' : 'lg:pl-[15rem]'}`}>
        <TopBar
          onOpenSidebar={() => setMobileSidebarOpen(true)}
          onOpenCommandPalette={() => setCommandPaletteOpen(true)}
          openBypassEditorSignal={openBypassEditorSignal}
        />

        <div className="px-3 pt-14 sm:px-4 lg:px-6">
          {activeBypassIdentity ? (
            <div className="mb-4 rounded-xl border border-amber-300/20 bg-[linear-gradient(145deg,rgba(245,158,11,0.18),rgba(15,23,42,0.78))] p-4 shadow-card backdrop-blur-2xl sm:p-5">
              <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge
                      variant="warning"
                      className="border-amber-300/20 bg-amber-300/12 text-amber-50"
                    >
                      Development Bypass Active
                    </Badge>
                    <Badge
                      variant="outline"
                      className="border-amber-300/20 bg-slate-950/30 text-amber-50/85"
                    >
                      Header-based identity
                    </Badge>
                  </div>
                  <p className="mt-3 max-w-3xl text-sm leading-6 text-amber-50/90">
                    This browser is sending local bypass headers instead of a Microsoft access token. Use it for development against an <code>auth_disabled=true</code> backend, not as a normal tenant session.
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs">
                    <span className="rounded-full border border-amber-300/20 bg-slate-950/25 px-3 py-1 text-amber-50/90">
                      Tenant {activeBypassIdentity.tenantId}
                    </span>
                    <span className="rounded-full border border-amber-300/20 bg-slate-950/25 px-3 py-1 text-amber-50/90">
                      {activeBypassIdentity.userId}
                    </span>
                    {activeBypassIdentity.roles.length > 0 ? (
                      activeBypassIdentity.roles.map((role) => (
                        <span
                          key={role}
                          className="rounded-full border border-amber-300/15 bg-amber-300/10 px-3 py-1 uppercase tracking-[0.2em] text-amber-50/85"
                        >
                          {role}
                        </span>
                      ))
                    ) : (
                      <span className="rounded-full border border-amber-300/15 bg-slate-950/25 px-3 py-1 text-amber-50/75">
                        No assigned roles
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 xl:justify-end">
                  <Button
                    type="button"
                    size="sm"
                    className="bg-amber-300/90 text-slate-950 hover:bg-amber-200"
                    onClick={() => setOpenBypassEditorSignal((current) => current + 1)}
                  >
                    Edit identity
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="border-amber-300/20 bg-slate-950/25 text-amber-50 hover:bg-slate-950/40"
                    onClick={resetBypassIdentity}
                  >
                    Reset default
                  </Button>
                </div>
              </div>
            </div>
          ) : null}

          <div className="pb-8 pt-4">
            <ErrorBoundary>
              <Suspense fallback={<RouteLoading />}>
                <Routes>
                  <Route path="/" element={<DashboardRoute />} />
                  <Route path="/alerts" element={<AlertQueue />} />
                  <Route path="/alerts/:alertId" element={<AlertDetailRoute />} />
                  <Route path="/cases" element={<Cases />} />
                  <Route path="/cases/:caseId" element={<CaseDetail />} />
                  <Route path="/rules" element={<RequireRole allow="analyst"><RuleEditor /></RequireRole>} />
                  <Route path="/coverage" element={<RequireRole allow="analyst"><MitreCoverage /></RequireRole>} />
                  <Route path="/lookups" element={<RequireRole allow="analyst"><LookupTables /></RequireRole>} />
                  <Route path="/search" element={<Search />} />
                  <Route path="/threat-intel" element={<RequireRole allow="analyst"><ThreatIntel /></RequireRole>} />
                  <Route path="/agents" element={<RequireRole allow="analyst"><AgentFleet /></RequireRole>} />
                  <Route path="/admin/rbac" element={<RequireRole allow="admin"><Rbac /></RequireRole>} />
                  <Route path="/admin/audit" element={<RequireRole allow="admin"><AuditLogs /></RequireRole>} />
                  <Route path="/admin/lgpd" element={<RequireRole allow="admin"><LgpdCompliance /></RequireRole>} />
                  <Route path="/admin/system" element={<RequireRole allow="admin"><SystemHealth /></RequireRole>} />
                </Routes>
              </Suspense>
            </ErrorBoundary>
          </div>
        </div>
      </div>

      {commandPaletteOpen ? (
        <Suspense fallback={null}>
          <CommandPalette
            open={commandPaletteOpen}
            onClose={() => setCommandPaletteOpen(false)}
            onOpenBypassEditor={() => setOpenBypassEditorSignal((current) => current + 1)}
          />
        </Suspense>
      ) : null}
    </div>
  );
}
