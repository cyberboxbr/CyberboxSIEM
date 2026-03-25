import { Suspense, lazy, useCallback, useEffect, useState } from 'react';
import { Route, Routes, useNavigate, useParams } from 'react-router-dom';
import { Badge } from './components/ui/badge';
import { Button } from './components/ui/button';

import { ErrorBoundary } from './components/ErrorBoundary';
import { TopNav } from './components/TopNav';
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
const ApiKeys = lazy(() => import('./pages/ApiKeys').then((module) => ({ default: module.ApiKeys })));

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
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [sessionWarning, setSessionWarning] = useState(false);
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
    <div className="min-h-screen bg-background text-foreground">
      <TopNav
        onOpenCommandPalette={() => setCommandPaletteOpen(true)}
        onSignOut={() => void signOut()}
      />

      {sessionTimeoutEnabled && sessionWarning && (
        <div
          className="fixed inset-x-4 top-14 z-[90] rounded-lg border border-primary/20 bg-card/85 px-4 py-2.5 text-sm text-foreground shadow-card backdrop-blur-xl sm:inset-x-auto sm:right-6 sm:w-auto"
          onClick={() => setSessionWarning(false)}
        >
          Session expires in 1 minute. Move your mouse to stay signed in.
        </div>
      )}

      <div className="mx-auto max-w-[1600px] px-4 py-4 sm:px-6 lg:px-8">
          {activeBypassIdentity ? (
            <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-amber-300/20 bg-amber-500/10 px-3 py-2 text-xs text-amber-50/90">
              <Badge variant="warning" className="border-amber-300/20 bg-amber-300/12 text-amber-50">Bypass</Badge>
              <span>{activeBypassIdentity.userId}</span>
              <span className="text-amber-100/60">·</span>
              <span>Tenant {activeBypassIdentity.tenantId}</span>
              {activeBypassIdentity.roles.map((role) => (
                <Badge key={role} variant="outline" className="border-amber-300/15 text-amber-50/80">{role}</Badge>
              ))}
              <Button type="button" size="sm" variant="ghost" className="ml-auto text-amber-50/70 hover:text-amber-50" onClick={resetBypassIdentity}>
                Reset
              </Button>
            </div>
          ) : null}

          <div className="pb-6">
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
                  <Route path="/admin/api-keys" element={<RequireRole allow="admin"><ApiKeys /></RequireRole>} />
                </Routes>
              </Suspense>
            </ErrorBoundary>
          </div>
        </div>
      {commandPaletteOpen ? (
        <Suspense fallback={null}>
          <CommandPalette
            open={commandPaletteOpen}
            onClose={() => setCommandPaletteOpen(false)}
            onOpenBypassEditor={() => {}}
          />
        </Suspense>
      ) : null}
    </div>
  );
}
