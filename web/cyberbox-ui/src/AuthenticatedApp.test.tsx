import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./auth/msalConfig', () => ({
  apiScopes: { scopes: [] },
  getMsalConfig: () => ({
    auth: {
      clientId: '',
      authority: 'https://login.microsoftonline.com/common',
      redirectUri: 'http://localhost:5173',
      postLogoutRedirectUri: 'http://localhost:5173',
    },
    cache: {
      cacheLocation: 'localStorage' as const,
    },
  }),
  isAuthBypassEnabled: true,
  isMicrosoftAuthConfigured: false,
  loginScopes: { scopes: ['openid', 'profile', 'email'] },
}));

vi.mock('./hooks/useIdleTimeout', () => ({
  useIdleTimeout: vi.fn(),
}));

vi.mock('./pages/Dashboard', () => ({
  Dashboard: () => <div>Dashboard smoke view</div>,
}));

vi.mock('./pages/RuleEditor', () => ({
  RuleEditor: () => <div>Rule editor smoke view</div>,
}));

vi.mock('./pages/Rbac', () => ({
  Rbac: () => <div>RBAC smoke view</div>,
}));

import { getDefaultFallbackIdentity } from '@/api/client';
import { AuthenticatedApp } from '@/AuthenticatedApp';
import { ThemeProvider } from '@/contexts/ThemeContext';
import { AuthProvider } from '@/contexts/AuthContext';

const BYPASS_IDENTITY_STORAGE_KEY = 'cyberbox_bypass_identity';

function renderAuthenticatedShell(initialEntries: string[] = ['/']) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={initialEntries}>
          <AuthenticatedApp />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe('AuthenticatedApp bypass shell', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('surfaces bypass status banner with identity details', async () => {
    window.localStorage.setItem(
      BYPASS_IDENTITY_STORAGE_KEY,
      JSON.stringify({
        tenantId: 'tenant-z',
        userId: 'qa-investigator',
        roles: ['analyst', 'viewer'],
      }),
    );

    renderAuthenticatedShell();

    expect(await screen.findByText('Dashboard smoke view')).toBeInTheDocument();
    expect(screen.getByText(/bypass/i)).toBeInTheDocument();
    expect(screen.getAllByText(/tenant-z/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText('qa-investigator').length).toBeGreaterThan(0);
  });

  it('blocks viewer-only identities from analyst routes', async () => {
    window.localStorage.setItem(
      BYPASS_IDENTITY_STORAGE_KEY,
      JSON.stringify({
        tenantId: 'tenant-a',
        userId: 'soc-viewer',
        roles: ['viewer'],
      }),
    );

    renderAuthenticatedShell(['/rules']);

    expect(await screen.findByText(/access denied/i)).toBeInTheDocument();
    expect(screen.getByText(/does not include permission to open this workspace/i)).toBeInTheDocument();
    expect(screen.queryByText('Rule editor smoke view')).not.toBeInTheDocument();
  });

  it('allows analysts into analyst routes but not admin routes', async () => {
    window.localStorage.setItem(
      BYPASS_IDENTITY_STORAGE_KEY,
      JSON.stringify({
        tenantId: 'tenant-a',
        userId: 'soc-analyst',
        roles: ['analyst', 'viewer'],
      }),
    );

    const { unmount } = renderAuthenticatedShell(['/rules']);

    expect(await screen.findByText('Rule editor smoke view')).toBeInTheDocument();
    expect(screen.queryByText(/access denied/i)).not.toBeInTheDocument();

    unmount();

    renderAuthenticatedShell(['/admin/rbac']);

    expect(await screen.findByText(/access denied/i)).toBeInTheDocument();
    expect(screen.queryByText('RBAC smoke view')).not.toBeInTheDocument();
  });

  it('allows admin identities into admin routes', async () => {
    window.localStorage.setItem(
      BYPASS_IDENTITY_STORAGE_KEY,
      JSON.stringify({
        tenantId: 'tenant-a',
        userId: 'soc-admin',
        roles: ['admin', 'analyst', 'viewer'],
      }),
    );

    renderAuthenticatedShell(['/admin/rbac']);

    expect(await screen.findByText('RBAC smoke view')).toBeInTheDocument();
    expect(screen.queryByText(/access denied/i)).not.toBeInTheDocument();
  });
});
