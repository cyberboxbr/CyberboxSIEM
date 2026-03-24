import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { setIdentitySpy, setTokenProviderSpy } = vi.hoisted(() => ({
  setIdentitySpy: vi.fn(),
  setTokenProviderSpy: vi.fn(),
}));

vi.mock('@/auth/msalConfig', () => ({
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

vi.mock('@/api/client', async () => {
  const actual = await vi.importActual<typeof import('@/api/client')>('@/api/client');
  return {
    ...actual,
    setIdentity: setIdentitySpy,
    setTokenProvider: setTokenProviderSpy,
  };
});

import { getDefaultFallbackIdentity } from '@/api/client';
import { AuthProvider, useAuth } from '@/contexts/AuthContext';

const BYPASS_IDENTITY_STORAGE_KEY = 'cyberbox_bypass_identity';

function AuthHarness() {
  const auth = useAuth();

  return (
    <div>
      <div data-testid="auth-mode">{auth.authMode}</div>
      <div data-testid="tenant">{auth.tenantId}</div>
      <div data-testid="user">{auth.userId}</div>
      <div data-testid="roles">{auth.roles.join(',')}</div>
      <button type="button" onClick={auth.resetBypassIdentity}>
        Reset identity
      </button>
    </div>
  );
}

describe('AuthProvider bypass mode', () => {
  beforeEach(() => {
    setIdentitySpy.mockReset();
    setTokenProviderSpy.mockReset();
    window.localStorage.clear();
  });

  it('loads the stored bypass identity and syncs it into dev headers', async () => {
    window.localStorage.setItem(
      BYPASS_IDENTITY_STORAGE_KEY,
      JSON.stringify({
        tenantId: 'tenant-z',
        userId: 'qa-investigator',
        roles: ['viewer', 'analyst', 'viewer'],
      }),
    );

    render(
      <AuthProvider>
        <AuthHarness />
      </AuthProvider>,
    );

    expect(screen.getByTestId('auth-mode')).toHaveTextContent('bypass');
    expect(screen.getByTestId('tenant')).toHaveTextContent('tenant-z');
    expect(screen.getByTestId('user')).toHaveTextContent('qa-investigator');
    expect(screen.getByTestId('roles')).toHaveTextContent('viewer,analyst');

    await waitFor(() => {
      expect(setIdentitySpy).toHaveBeenCalledWith('tenant-z', 'qa-investigator', ['viewer', 'analyst']);
    });

    await waitFor(() => {
      expect(JSON.parse(window.localStorage.getItem(BYPASS_IDENTITY_STORAGE_KEY) ?? 'null')).toEqual({
        tenantId: 'tenant-z',
        userId: 'qa-investigator',
        roles: ['viewer', 'analyst'],
      });
    });
  });

  it('resets the bypass identity back to the default SOC profile', async () => {
    window.localStorage.setItem(
      BYPASS_IDENTITY_STORAGE_KEY,
      JSON.stringify({
        tenantId: 'tenant-z',
        userId: 'qa-investigator',
        roles: ['viewer'],
      }),
    );

    render(
      <AuthProvider>
        <AuthHarness />
      </AuthProvider>,
    );

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /reset identity/i }));

    const defaultIdentity = getDefaultFallbackIdentity();

    await waitFor(() => {
      expect(screen.getByTestId('tenant')).toHaveTextContent(defaultIdentity.tenantId);
      expect(screen.getByTestId('user')).toHaveTextContent(defaultIdentity.userId);
      expect(screen.getByTestId('roles')).toHaveTextContent(defaultIdentity.roles.join(','));
    });

    await waitFor(() => {
      expect(setIdentitySpy).toHaveBeenLastCalledWith(
        defaultIdentity.tenantId,
        defaultIdentity.userId,
        defaultIdentity.roles,
      );
    });

    expect(JSON.parse(window.localStorage.getItem(BYPASS_IDENTITY_STORAGE_KEY) ?? 'null')).toEqual(defaultIdentity);
  });
});
