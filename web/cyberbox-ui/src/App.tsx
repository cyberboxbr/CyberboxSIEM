import { useCallback, useState } from 'react';
import { BrowserRouter, Route, Routes, useParams, useNavigate } from 'react-router-dom';
import { PublicClientApplication } from '@azure/msal-browser';
import { MsalProvider } from '@azure/msal-react';

import { msalConfig } from './auth/msalConfig';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { CommandPalette } from './components/CommandPalette';
import { ErrorBoundary } from './components/ErrorBoundary';
import { useIdleTimeout } from './hooks/useIdleTimeout';

import { SignIn } from './pages/SignIn';
import { Dashboard } from './pages/Dashboard';
import { AlertQueue } from './pages/AlertQueue';
import { AlertDetail } from './pages/AlertDetail';
import { Cases } from './pages/Cases';
import { CaseDetail } from './pages/CaseDetail';
import { RuleEditor } from './pages/RuleEditor';
import { MitreCoverage } from './pages/MitreCoverage';
import { Search } from './pages/Search';
import { ThreatIntel } from './pages/ThreatIntel';
import { AgentFleet } from './pages/AgentFleet';
import { Rbac } from './pages/Rbac';
import { AuditLogs } from './pages/AuditLogs';
import { LgpdCompliance } from './pages/LgpdCompliance';
import { SystemHealth } from './pages/SystemHealth';
import { LookupTables } from './pages/LookupTables';

import './styles.css';

// ── MSAL instance (created once, outside React lifecycle) ───────────────────

const msalInstance = new PublicClientApplication(msalConfig);

// ── Route wrappers ──────────────────────────────────────────────────────────

function AlertDetailRoute() {
  const { alertId } = useParams<{ alertId: string }>();
  const navigate = useNavigate();
  if (!alertId) return null;
  return <AlertDetail alertId={alertId} onBack={() => navigate('/alerts')} />;
}

function DashboardRoute() {
  return <Dashboard onRefresh={async () => {}} />;
}

// ── Role guard — shows "access denied" when the user lacks a role ───────────

function RequireRole({ allow, children }: { allow: 'admin' | 'analyst'; children: JSX.Element }) {
  const { isAdmin, isAnalyst } = useAuth();
  const allowed = allow === 'admin' ? isAdmin : (isAdmin || isAnalyst);
  if (!allowed) {
    return (
      <div style={{ padding: '64px 32px', textAlign: 'center', color: 'var(--text-tertiary)' }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>🔒</div>
        <div style={{ fontSize: 18, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>Access Denied</div>
        <div style={{ fontSize: 14 }}>You do not have permission to view this page.</div>
      </div>
    );
  }
  return children;
}

// ── Auth gate — shows sign-in page when not authenticated ───────────────────

function AuthGate() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="si-page">
        <div className="si-card" style={{ padding: '60px 40px' }}>
          <div className="si-logo-row">
            <img src="/cyberboxlogo.png" alt="Cyberbox" className="si-logo" />
            <span className="si-brand">CyberboxSIEM</span>
          </div>
          <p className="si-subtitle">Authenticating...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <SignIn />;
  }

  return <AppShell />;
}

// ── Main app shell (only rendered when authenticated) ───────────────────────

const SESSION_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
const SESSION_WARNING_MS = 60 * 1000;      // warn 1 minute before

function AppShell() {
  const { signOut } = useAuth();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [sessionWarning, setSessionWarning] = useState(false);

  const handleTimeout = useCallback(() => {
    setSessionWarning(false);
    signOut();
  }, [signOut]);

  const handleWarning = useCallback(() => {
    setSessionWarning(true);
  }, []);

  useIdleTimeout(SESSION_TIMEOUT_MS, handleTimeout, SESSION_WARNING_MS, handleWarning);

  return (
    <div className="app-shell">
      {sessionWarning && (
        <div className="session-timeout-banner" onClick={() => setSessionWarning(false)}>
          Session expires in 1 minute due to inactivity. Move your mouse to stay signed in.
        </div>
      )}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
      <div className={`app-main${sidebarCollapsed ? ' app-main--collapsed' : ''}`}>
        <TopBar
          sidebarWidth={sidebarCollapsed ? 72 : 260}
        />
        <div className="app-content">
          <ErrorBoundary>
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
          </ErrorBoundary>
        </div>
      </div>
      <CommandPalette
        open={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
      />
    </div>
  );
}

// ── Root app ────────────────────────────────────────────────────────────────

function App() {
  return (
    <ThemeProvider>
      <MsalProvider instance={msalInstance}>
        <AuthProvider>
          <BrowserRouter>
            <AuthGate />
          </BrowserRouter>
        </AuthProvider>
      </MsalProvider>
    </ThemeProvider>
  );
}

export default App;
