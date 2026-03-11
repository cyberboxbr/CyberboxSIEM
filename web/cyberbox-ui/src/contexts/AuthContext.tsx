import { createContext, useContext, useCallback, useEffect, useMemo, ReactNode } from 'react';
import {
  useMsal,
  useIsAuthenticated,
  useAccount,
} from '@azure/msal-react';
import type { AccountInfo } from '@azure/msal-browser';
import { apiScopes, loginScopes } from '../auth/msalConfig';
import { setTokenProvider } from '../api/client';

// ── Types ───────────────────────────────────────────────────────────────────

export interface AuthState {
  /** Whether the user is signed in via Azure AD */
  isAuthenticated: boolean;
  /** Whether MSAL is still initializing */
  isLoading: boolean;
  /** Azure AD display name */
  displayName: string;
  /** User principal name / email */
  userId: string;
  /** Azure AD tenant ID */
  tenantId: string;
  /** App roles assigned in Azure AD */
  roles: string[];
  /** Convenience booleans */
  isAdmin: boolean;
  isAnalyst: boolean;
  isViewer: boolean;
  isIngestor: boolean;
  /** Account info from MSAL */
  account: AccountInfo | null;
  /** Acquire an access token (silent with fallback to popup) */
  getAccessToken: () => Promise<string>;
  /** Sign in via redirect */
  signIn: () => Promise<void>;
  /** Sign out */
  signOut: () => Promise<void>;
}

// ── Context ─────────────────────────────────────────────────────────────────

const AuthContext = createContext<AuthState | null>(null);

// ── Provider ────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  const { instance, inProgress, accounts } = useMsal();
  const isAuthenticated = useIsAuthenticated();
  const account = useAccount(accounts[0] ?? ({} as AccountInfo));

  const isLoading = inProgress !== 'none';

  // Extract roles from idTokenClaims (Azure AD puts app roles here)
  const roles = useMemo(() => {
    const claims = account?.idTokenClaims as Record<string, unknown> | undefined;
    if (!claims) return [];
    const r = claims.roles;
    if (Array.isArray(r)) return r as string[];
    return [];
  }, [account]);

  const getAccessToken = useCallback(async (): Promise<string> => {
    if (!account) throw new Error('No authenticated account');
    try {
      const response = await instance.acquireTokenSilent({
        ...apiScopes,
        account,
      });
      return response.accessToken;
    } catch {
      // Silent failed (e.g. token expired, interaction required)
      const response = await instance.acquireTokenPopup(apiScopes);
      return response.accessToken;
    }
  }, [instance, account]);

  const signIn = useCallback(async () => {
    await instance.loginRedirect(loginScopes);
  }, [instance]);

  const signOut = useCallback(async () => {
    await instance.logoutRedirect({
      postLogoutRedirectUri: window.location.origin,
    });
  }, [instance]);

  // Wire the token provider into the API client when authenticated
  useEffect(() => {
    if (isAuthenticated && account) {
      setTokenProvider(getAccessToken);
    } else {
      setTokenProvider(null);
    }
    return () => setTokenProvider(null);
  }, [isAuthenticated, account, getAccessToken]);

  const value: AuthState = useMemo(
    () => ({
      isAuthenticated,
      isLoading,
      displayName: account?.name ?? '',
      userId: account?.username ?? '',
      tenantId: (account?.tenantId as string) ?? 'default',
      roles,
      isAdmin: roles.includes('admin'),
      isAnalyst: roles.includes('analyst'),
      isViewer: roles.includes('viewer'),
      isIngestor: roles.includes('ingestor'),
      account,
      getAccessToken,
      signIn,
      signOut,
    }),
    [isAuthenticated, isLoading, account, roles, getAccessToken, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ── Hook ────────────────────────────────────────────────────────────────────

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
