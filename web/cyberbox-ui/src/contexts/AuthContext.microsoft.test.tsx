import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const MICROSOFT_BOOTSTRAP_STORAGE_KEY = 'cyberbox_microsoft_bootstrap';

const {
  microsoftAccount,
  acquireTokenPopupSpy,
  acquireTokenSilentSpy,
  getActiveAccountSpy,
  getAllAccountsSpy,
  handleRedirectPromiseSpy,
  initializeSpy,
  loginRedirectSpy,
  logoutRedirectSpy,
  publicClientApplicationSpy,
  setActiveAccountSpy,
  setIdentitySpy,
  setTokenProviderSpy,
} = vi.hoisted(() => {
  const account = {
    homeAccountId: 'home-account',
    environment: 'login.microsoftonline.com',
    tenantId: 'tenant-a',
    username: 'analyst@example.com',
    localAccountId: 'local-account',
    name: 'Analyst Example',
    idTokenClaims: {
      roles: ['analyst', 'viewer'],
    },
  };

  return {
    microsoftAccount: account,
    acquireTokenPopupSpy: vi.fn(),
    acquireTokenSilentSpy: vi.fn(),
    getActiveAccountSpy: vi.fn(),
    getAllAccountsSpy: vi.fn(),
    handleRedirectPromiseSpy: vi.fn(),
    initializeSpy: vi.fn(),
    loginRedirectSpy: vi.fn(),
    logoutRedirectSpy: vi.fn(),
    publicClientApplicationSpy: vi.fn(),
    setActiveAccountSpy: vi.fn(),
    setIdentitySpy: vi.fn(),
    setTokenProviderSpy: vi.fn(),
  };
});

vi.mock('@/auth/msalConfig', () => ({
  apiScopes: { scopes: ['api://client-id/access'] },
  getMsalConfig: () => ({
    auth: {
      clientId: 'client-id',
      authority: 'https://login.microsoftonline.com/tenant-id',
      redirectUri: 'http://localhost:5173',
      postLogoutRedirectUri: 'http://localhost:5173',
    },
    cache: {
      cacheLocation: 'localStorage' as const,
    },
  }),
  isAuthBypassEnabled: false,
  isMicrosoftAuthConfigured: true,
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

vi.mock('@azure/msal-browser', () => ({
  PublicClientApplication: class MockPublicClientApplication {
    constructor() {
      publicClientApplicationSpy();
    }

    initialize = initializeSpy;
    handleRedirectPromise = handleRedirectPromiseSpy;
    getActiveAccount = getActiveAccountSpy;
    getAllAccounts = getAllAccountsSpy;
    setActiveAccount = setActiveAccountSpy;
    acquireTokenSilent = acquireTokenSilentSpy;
    acquireTokenPopup = acquireTokenPopupSpy;
    loginRedirect = loginRedirectSpy;
    logoutRedirect = logoutRedirectSpy;
  },
}));

async function renderMicrosoftHarness() {
  const { AuthProvider, useAuth } = await import('@/contexts/AuthContext');

  function Harness() {
    const auth = useAuth();

    return (
      <div>
        <div data-testid="loading">{auth.isLoading ? 'loading' : 'idle'}</div>
        <div data-testid="authenticated">{auth.isAuthenticated ? 'yes' : 'no'}</div>
        <div data-testid="user">{auth.userId || 'anonymous'}</div>
        <button type="button" onClick={() => void auth.signIn()}>
          Start Microsoft sign-in
        </button>
      </div>
    );
  }

  return render(
    <AuthProvider>
      <Harness />
    </AuthProvider>,
  );
}

describe('AuthProvider microsoft mode', () => {
  beforeEach(() => {
    vi.resetModules();

    setIdentitySpy.mockReset();
    setTokenProviderSpy.mockReset();
    publicClientApplicationSpy.mockReset();
    initializeSpy.mockReset();
    handleRedirectPromiseSpy.mockReset();
    getActiveAccountSpy.mockReset();
    getAllAccountsSpy.mockReset();
    setActiveAccountSpy.mockReset();
    acquireTokenSilentSpy.mockReset();
    acquireTokenPopupSpy.mockReset();
    loginRedirectSpy.mockReset();
    logoutRedirectSpy.mockReset();

    initializeSpy.mockResolvedValue(undefined);
    handleRedirectPromiseSpy.mockResolvedValue(null);
    getActiveAccountSpy.mockReturnValue(null);
    getAllAccountsSpy.mockReturnValue([]);
    acquireTokenSilentSpy.mockResolvedValue({
      accessToken: 'silent-token',
      account: microsoftAccount,
    });
    acquireTokenPopupSpy.mockResolvedValue({
      accessToken: 'popup-token',
      account: microsoftAccount,
    });
    loginRedirectSpy.mockResolvedValue(undefined);
    logoutRedirectSpy.mockResolvedValue(undefined);

    window.localStorage.clear();
    window.history.replaceState({}, '', '/');
  });

  it('defers Microsoft runtime bootstrap until sign-in is requested', async () => {
    await renderMicrosoftHarness();

    expect(screen.getByTestId('loading')).toHaveTextContent('idle');
    expect(screen.getByTestId('authenticated')).toHaveTextContent('no');
    expect(publicClientApplicationSpy).not.toHaveBeenCalled();
    expect(setIdentitySpy).not.toHaveBeenCalled();

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /start microsoft sign-in/i }));

    await waitFor(() => {
      expect(publicClientApplicationSpy).toHaveBeenCalledTimes(1);
    });
    expect(loginRedirectSpy).toHaveBeenCalledTimes(1);
    expect(window.localStorage.getItem(MICROSOFT_BOOTSTRAP_STORAGE_KEY)).toBe('1');
  });

  it('auto-bootstraps Microsoft auth when a returning-session hint exists', async () => {
    window.localStorage.setItem(MICROSOFT_BOOTSTRAP_STORAGE_KEY, '1');
    getAllAccountsSpy.mockReturnValue([microsoftAccount]);

    await renderMicrosoftHarness();

    expect(screen.getByTestId('loading')).toHaveTextContent('loading');

    await waitFor(() => {
      expect(publicClientApplicationSpy).toHaveBeenCalledTimes(1);
    });

    await waitFor(() => {
      expect(screen.getByTestId('authenticated')).toHaveTextContent('yes');
      expect(screen.getByTestId('user')).toHaveTextContent(microsoftAccount.username);
    });

    await waitFor(() => {
      const provider = setTokenProviderSpy.mock.calls.at(-1)?.[0];
      expect(typeof provider).toBe('function');
    });

    expect(setActiveAccountSpy).toHaveBeenCalledWith(microsoftAccount);
  });
});
