import { useState } from 'react';
import { BrowserRouter, Route, Routes, useParams, useNavigate } from 'react-router-dom';
import { PublicClientApplication } from '@azure/msal-browser';
import { MsalProvider } from '@azure/msal-react';

import { msalConfig } from './auth/msalConfig';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { CommandPalette } from './components/CommandPalette';

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

function AppShell() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  return (
    <div className="app-shell">
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
      <div className={`app-main${sidebarCollapsed ? ' app-main--collapsed' : ''}`}>
        <TopBar
          sidebarWidth={sidebarCollapsed ? 72 : 260}
        />
        <div className="app-content">
          <Routes>
            <Route path="/" element={<DashboardRoute />} />
            <Route path="/alerts" element={<AlertQueue />} />
            <Route path="/alerts/:alertId" element={<AlertDetailRoute />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/cases/:caseId" element={<CaseDetail />} />
            <Route path="/rules" element={<RuleEditor />} />
            <Route path="/coverage" element={<MitreCoverage />} />
            <Route path="/lookups" element={<LookupTables />} />
            <Route path="/search" element={<Search />} />
            <Route path="/threat-intel" element={<ThreatIntel />} />
            <Route path="/agents" element={<AgentFleet />} />
            <Route path="/admin/rbac" element={<Rbac />} />
            <Route path="/admin/audit" element={<AuditLogs />} />
            <Route path="/admin/lgpd" element={<LgpdCompliance />} />
            <Route path="/admin/system" element={<SystemHealth />} />
          </Routes>
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
