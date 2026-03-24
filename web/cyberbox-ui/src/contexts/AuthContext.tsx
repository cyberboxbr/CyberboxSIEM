import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import type { AccountInfo, IPublicClientApplication } from '@azure/msal-browser';

import { apiScopes, getMsalConfig, isAuthBypassEnabled, isMicrosoftAuthConfigured, loginScopes } from '../auth/msalConfig';
import {
  type FallbackIdentity,
  getDefaultFallbackIdentity,
  normalizeFallbackIdentity,
  setIdentity,
  setTokenProvider,
} from '../api/client';

export type AuthMode = 'microsoft' | 'bypass' | 'unconfigured';

const BYPASS_IDENTITY_STORAGE_KEY = 'cyberbox_bypass_identity';
const MICROSOFT_BOOTSTRAP_STORAGE_KEY = 'cyberbox_microsoft_bootstrap';
const MICROSOFT_REDIRECT_PARAM_PATTERN = /(?:[?#&])(code|error|id_token|client_info|state)=/i;

export interface AuthState {
  authMode: AuthMode;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string;
  displayName: string;
  userId: string;
  tenantId: string;
  roles: string[];
  isAdmin: boolean;
  isAnalyst: boolean;
  isViewer: boolean;
  isIngestor: boolean;
  account: AccountInfo | null;
  bypassIdentity: FallbackIdentity | null;
  setBypassIdentity: (identity: FallbackIdentity) => void;
  resetBypassIdentity: () => void;
  getAccessToken: () => Promise<string>;
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
}

interface MicrosoftAuthSnapshot {
  instance: IPublicClientApplication | null;
  account: AccountInfo | null;
  roles: string[];
  error: string;
  isLoading: boolean;
}

const authMode: AuthMode = isAuthBypassEnabled
  ? 'bypass'
  : isMicrosoftAuthConfigured
    ? 'microsoft'
    : 'unconfigured';

const AuthContext = createContext<AuthState | null>(null);

let microsoftRuntimePromise: Promise<IPublicClientApplication> | null = null;
let microsoftRuntimeInstance: IPublicClientApplication | null = null;
type MsalBrowserRuntime = Pick<typeof import('@azure/msal-browser'), 'PublicClientApplication'>;
type MicrosoftTestRuntimeFactory = () => MsalBrowserRuntime | Promise<MsalBrowserRuntime>;
type CyberboxTestWindow = Window & {
  __CYBERBOX_MSAL_BROWSER_MOCK__?: MsalBrowserRuntime | MicrosoftTestRuntimeFactory;
};

function createMicrosoftAuthSnapshot(isLoading = false): MicrosoftAuthSnapshot {
  return {
    instance: null,
    account: null,
    roles: [],
    error: '',
    isLoading,
  };
}

function getAccountRoles(account: AccountInfo | null): string[] {
  const claims = account?.idTokenClaims as Record<string, unknown> | undefined;
  const roles = claims?.roles;
  if (!Array.isArray(roles)) return [];
  return roles.filter((role): role is string => typeof role === 'string');
}

function getPreferredAccount(instance: IPublicClientApplication, preferred?: AccountInfo | null): AccountInfo | null {
  const account = preferred ?? instance.getActiveAccount() ?? instance.getAllAccounts()[0] ?? null;
  if (account) {
    instance.setActiveAccount(account);
  }
  return account;
}

function formatFallbackDisplayName(userId: string): string {
  const words = userId
    .split(/[\s@._-]+/)
    .map((word) => word.trim())
    .filter(Boolean)
    .slice(0, 3);

  if (words.length === 0) return 'Local Operator';

  return words
    .map((word) => word[0].toUpperCase() + word.slice(1))
    .join(' ');
}

function loadStoredBypassIdentity(): FallbackIdentity {
  const fallback = getDefaultFallbackIdentity();

  if (typeof window === 'undefined') {
    return fallback;
  }

  try {
    const stored = window.localStorage.getItem(BYPASS_IDENTITY_STORAGE_KEY);
    if (!stored) {
      return fallback;
    }

    const parsed = JSON.parse(stored) as Partial<FallbackIdentity>;
    return normalizeFallbackIdentity(parsed);
  } catch {
    return fallback;
  }
}

function hasMicrosoftRedirectResponse(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }

  return MICROSOFT_REDIRECT_PARAM_PATTERN.test(`${window.location.search}${window.location.hash}`);
}

function hasStoredMicrosoftBootstrapHint(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }

  try {
    return window.localStorage.getItem(MICROSOFT_BOOTSTRAP_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

function hasMsalCacheEntries(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }

  try {
    for (let index = 0; index < window.localStorage.length; index += 1) {
      const key = window.localStorage.key(index);
      if (key?.startsWith('msal.')) {
        return true;
      }
    }
  } catch {
    return false;
  }

  return false;
}

function setMicrosoftBootstrapHint(enabled: boolean): void {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    if (enabled) {
      window.localStorage.setItem(MICROSOFT_BOOTSTRAP_STORAGE_KEY, '1');
    } else {
      window.localStorage.removeItem(MICROSOFT_BOOTSTRAP_STORAGE_KEY);
    }
  } catch {
    // Ignore storage failures in restricted/private contexts.
  }
}

function shouldBootstrapMicrosoftSession(): boolean {
  return hasMicrosoftRedirectResponse() || hasStoredMicrosoftBootstrapHint() || hasMsalCacheEntries();
}

async function loadMsalBrowserRuntime(): Promise<MsalBrowserRuntime> {
  if (import.meta.env.DEV && typeof window !== 'undefined') {
    const mockRuntime = (window as CyberboxTestWindow).__CYBERBOX_MSAL_BROWSER_MOCK__;
    if (mockRuntime) {
      return typeof mockRuntime === 'function'
        ? await mockRuntime()
        : mockRuntime;
    }
  }

  return import('@azure/msal-browser');
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const bootstrapMicrosoftOnLoad = authMode === 'microsoft' && shouldBootstrapMicrosoftSession();
  const [shouldBootstrapMicrosoft, setShouldBootstrapMicrosoft] = useState(bootstrapMicrosoftOnLoad);
  const [microsoftState, setMicrosoftState] = useState<MicrosoftAuthSnapshot>(
    () => createMicrosoftAuthSnapshot(bootstrapMicrosoftOnLoad),
  );
  const [bypassIdentity, setBypassIdentityState] = useState<FallbackIdentity>(() => loadStoredBypassIdentity());
  const signInInFlightRef = useRef(false);

  const ensureMicrosoftInstance = useCallback(async (): Promise<IPublicClientApplication> => {
    if (authMode !== 'microsoft') {
      throw new Error('Microsoft SSO is not configured for this environment.');
    }

    if (microsoftRuntimeInstance) {
      return microsoftRuntimeInstance;
    }

    if (!microsoftRuntimePromise) {
      microsoftRuntimePromise = (async () => {
        const { PublicClientApplication } = await loadMsalBrowserRuntime();
        const instance = new PublicClientApplication(getMsalConfig());
        await instance.initialize();

        const redirectResult = await instance.handleRedirectPromise();
        const account = getPreferredAccount(instance, redirectResult?.account ?? null);
        if (account) {
          instance.setActiveAccount(account);
        }

        microsoftRuntimeInstance = instance;
        return instance;
      })().catch((cause) => {
        microsoftRuntimePromise = null;
        microsoftRuntimeInstance = null;
        throw cause;
      });
    }

    return microsoftRuntimePromise;
  }, []);

  const requestMicrosoftBootstrap = useCallback(() => {
    if (authMode !== 'microsoft') {
      return;
    }

    setMicrosoftBootstrapHint(true);
    setShouldBootstrapMicrosoft(true);
  }, []);

  useEffect(() => {
    if (authMode !== 'microsoft') {
      setMicrosoftState(createMicrosoftAuthSnapshot(false));
      setShouldBootstrapMicrosoft(false);
      setMicrosoftBootstrapHint(false);
      return;
    }

    if (!shouldBootstrapMicrosoft) {
      setMicrosoftState((current) => (
        current.instance || current.account || current.roles.length > 0 || current.isLoading || current.error
          ? createMicrosoftAuthSnapshot(false)
          : current
      ));
      return;
    }

    let cancelled = false;
    setMicrosoftState((current) => ({ ...current, isLoading: true, error: '' }));

    void (async () => {
      try {
        const instance = await ensureMicrosoftInstance();
        const account = getPreferredAccount(instance);
        if (cancelled) return;

        if (account) {
          signInInFlightRef.current = false;
          setMicrosoftBootstrapHint(true);
        } else if (!signInInFlightRef.current) {
          setMicrosoftBootstrapHint(false);
          setShouldBootstrapMicrosoft(false);
        }

        setMicrosoftState({
          instance,
          account,
          roles: getAccountRoles(account),
          error: '',
          isLoading: false,
        });
      } catch (cause) {
        if (cancelled) return;

        signInInFlightRef.current = false;
        setMicrosoftBootstrapHint(false);
        setShouldBootstrapMicrosoft(false);
        setMicrosoftState({
          ...createMicrosoftAuthSnapshot(false),
          error: cause instanceof Error ? cause.message : 'Microsoft authentication could not initialize.',
        });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [ensureMicrosoftInstance, shouldBootstrapMicrosoft]);

  const getAccessToken = useCallback(async (): Promise<string> => {
    if (authMode !== 'microsoft') {
      throw new Error('Access tokens are only available when Microsoft SSO is enabled.');
    }

    const instance = microsoftState.instance ?? await ensureMicrosoftInstance();
    const account = getPreferredAccount(instance, microsoftState.account);
    if (!account) {
      throw new Error('No authenticated Microsoft account.');
    }

    try {
      const response = await instance.acquireTokenSilent({
        ...apiScopes,
        account,
      });
      return response.accessToken;
    } catch {
      const response = await instance.acquireTokenPopup(apiScopes);
      const nextAccount = getPreferredAccount(instance, response.account ?? account);
      setMicrosoftState((current) => ({
        ...current,
        account: nextAccount,
        roles: getAccountRoles(nextAccount),
        error: '',
      }));
      return response.accessToken;
    }
  }, [ensureMicrosoftInstance, microsoftState.account, microsoftState.instance]);

  const signIn = useCallback(async () => {
    if (authMode !== 'microsoft') {
      throw new Error('Microsoft SSO is not configured for this environment.');
    }

    signInInFlightRef.current = true;
    requestMicrosoftBootstrap();
    setMicrosoftState((current) => ({ ...current, isLoading: true, error: '' }));

    try {
      const instance = microsoftState.instance ?? await ensureMicrosoftInstance();
      await instance.loginRedirect(loginScopes);
    } catch (cause) {
      signInInFlightRef.current = false;
      setMicrosoftBootstrapHint(false);
      setShouldBootstrapMicrosoft(false);
      setMicrosoftState((current) => ({
        ...current,
        isLoading: false,
        error: cause instanceof Error ? cause.message : 'Microsoft sign-in could not start.',
      }));
      throw cause;
    }
  }, [ensureMicrosoftInstance, microsoftState.instance, requestMicrosoftBootstrap]);

  const signOut = useCallback(async () => {
    if (authMode === 'bypass') {
      setTokenProvider(null);
      window.location.reload();
      return;
    }

    if (authMode !== 'microsoft') {
      setTokenProvider(null);
      return;
    }

    signInInFlightRef.current = false;
    setMicrosoftBootstrapHint(false);
    setShouldBootstrapMicrosoft(false);
    const instance = microsoftState.instance ?? await ensureMicrosoftInstance();
    await instance.logoutRedirect({
      postLogoutRedirectUri: window.location.origin,
    });
  }, [ensureMicrosoftInstance, microsoftState.instance]);

  const setBypassIdentity = useCallback((identity: FallbackIdentity) => {
    setBypassIdentityState(normalizeFallbackIdentity(identity));
  }, []);

  const resetBypassIdentity = useCallback(() => {
    setBypassIdentityState(getDefaultFallbackIdentity());
  }, []);

  useEffect(() => {
    if (authMode === 'microsoft' && microsoftState.account) {
      setTokenProvider(getAccessToken);
      return;
    }

    setTokenProvider(null);
  }, [getAccessToken, microsoftState.account]);

  useLayoutEffect(() => {
    if (authMode !== 'bypass') {
      return;
    }

    setIdentity(bypassIdentity.tenantId, bypassIdentity.userId, bypassIdentity.roles);

    try {
      window.localStorage.setItem(BYPASS_IDENTITY_STORAGE_KEY, JSON.stringify(bypassIdentity));
    } catch {
      // Ignore storage failures in restricted/private contexts.
    }
  }, [bypassIdentity]);

  const value: AuthState = useMemo(() => {
    const fallbackRoles = bypassIdentity.roles;
    const fallbackDisplayName = formatFallbackDisplayName(bypassIdentity.userId);

    const resolvedRoles = authMode === 'bypass' ? fallbackRoles : microsoftState.roles;
    const isAuthenticated = authMode === 'bypass'
      ? true
      : authMode === 'microsoft'
        ? Boolean(microsoftState.account)
        : false;

    return {
      authMode,
      isAuthenticated,
      isLoading: authMode === 'microsoft' ? microsoftState.isLoading : false,
      error: authMode === 'microsoft' ? microsoftState.error : '',
      displayName: authMode === 'bypass' ? fallbackDisplayName : microsoftState.account?.name ?? '',
      userId: authMode === 'bypass' ? bypassIdentity.userId : microsoftState.account?.username ?? '',
      tenantId: authMode === 'bypass'
        ? bypassIdentity.tenantId
        : (microsoftState.account?.tenantId as string | undefined) ?? '',
      roles: resolvedRoles,
      isAdmin: resolvedRoles.includes('admin'),
      isAnalyst: resolvedRoles.includes('analyst'),
      isViewer: resolvedRoles.includes('viewer'),
      isIngestor: resolvedRoles.includes('ingestor'),
      account: authMode === 'microsoft' ? microsoftState.account : null,
      bypassIdentity: authMode === 'bypass' ? bypassIdentity : null,
      setBypassIdentity,
      resetBypassIdentity,
      getAccessToken,
      signIn,
      signOut,
    };
  }, [bypassIdentity, getAccessToken, microsoftState, resetBypassIdentity, setBypassIdentity, signIn, signOut]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
