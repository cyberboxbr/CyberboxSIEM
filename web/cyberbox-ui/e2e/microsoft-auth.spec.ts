import { expect, test, type Page } from '@playwright/test';

const MICROSOFT_BOOTSTRAP_STORAGE_KEY = 'cyberbox_microsoft_bootstrap';
const MICROSOFT_ACCOUNT_STORAGE_KEY = 'cyberbox_test_microsoft_account';
const MOCK_ACCESS_TOKEN = 'mock-microsoft-access-token';

const MICROSOFT_ACCOUNT = {
  homeAccountId: 'mock-home-account',
  environment: 'login.microsoftonline.com',
  tenantId: 'cyberbox-test-tenant',
  username: 'analyst@example.com',
  localAccountId: 'mock-local-account',
  name: 'Analyst Example',
  idTokenClaims: {
    roles: ['analyst', 'viewer'],
  },
};

const DASHBOARD_STATS = {
  total_events: 12840,
  events_by_source: [
    { source: 'agent', count: '12000' },
    { source: 'syslog', count: '840' },
  ],
  events_by_host: [],
  hourly_events: [
    { bucket: '2026-03-24T10:00:00.000Z', count: '6100' },
    { bucket: '2026-03-24T11:00:00.000Z', count: '6740' },
  ],
  active_agents: 3,
  total_agents: 4,
  agents: [
    { agent_id: 'agent-01', hostname: 'workstation-01', os: 'windows', status: 'active' },
  ],
  active_rules: 12,
  open_alerts: 0,
  total_alerts: 2,
  current_eps: 42.4,
  eps_trend: [
    { bucket: '2026-03-24T10:00:00.000Z', eps: '40.0' },
    { bucket: '2026-03-24T11:00:00.000Z', eps: '44.8' },
  ],
  alerts_by_severity: {
    critical: 0,
    high: 1,
    medium: 1,
    low: 0,
  },
  top_rules: [
    { rule_id: 'rule-1', rule_title: 'Suspicious PowerShell', severity: 'high', alert_count: 2 },
  ],
  alert_trend: [
    { bucket: '2026-03-24T10:00:00.000Z', count: '1' },
    { bucket: '2026-03-24T11:00:00.000Z', count: '1' },
  ],
  mttr_seconds: 300,
};

const ALERTS_PAGE = {
  alerts: [],
  has_more: false,
  total: 0,
};

type ObservedHeaders = {
  authorization?: string;
};

async function installMicrosoftBrowserMock(page: Page) {
  await page.addInitScript(
    ({ accessToken, account, accountStorageKey, bootstrapStorageKey }) => {
      type StoredAccount = typeof account;
      type MockMsalWindow = Window & {
        __CYBERBOX_MSAL_BROWSER_MOCK__?: {
          PublicClientApplication: new () => {
            initialize: () => Promise<void>;
            handleRedirectPromise: () => Promise<{ account: StoredAccount } | null>;
            getActiveAccount: () => StoredAccount | null;
            getAllAccounts: () => StoredAccount[];
            setActiveAccount: (next: StoredAccount | null) => void;
            loginRedirect: () => Promise<void>;
            logoutRedirect: (options?: { postLogoutRedirectUri?: string }) => Promise<void>;
            acquireTokenSilent: (options?: { account?: StoredAccount | null }) => Promise<{ accessToken: string; account: StoredAccount }>;
            acquireTokenPopup: (options?: { account?: StoredAccount | null }) => Promise<{ accessToken: string; account: StoredAccount }>;
          };
        };
      };

      const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

      const readAccount = (): StoredAccount | null => {
        const stored = window.localStorage.getItem(accountStorageKey);
        return stored ? (JSON.parse(stored) as StoredAccount) : null;
      };

      const writeAccount = (next: StoredAccount | null) => {
        if (next) {
          window.localStorage.setItem(accountStorageKey, JSON.stringify(next));
        } else {
          window.localStorage.removeItem(accountStorageKey);
        }
      };

      const clearRedirectParams = () => {
        const url = new URL(window.location.href);
        let changed = false;

        ['code', 'state', 'error', 'error_description', 'id_token', 'client_info'].forEach((key) => {
          if (url.searchParams.has(key)) {
            url.searchParams.delete(key);
            changed = true;
          }
        });

        if (changed) {
          window.history.replaceState({}, '', url.toString());
        }
      };

      (window as MockMsalWindow).__CYBERBOX_MSAL_BROWSER_MOCK__ = {
        PublicClientApplication: class MockPublicClientApplication {
          async initialize() {}

          async handleRedirectPromise() {
            const url = new URL(window.location.href);
            const hasRedirectParams = ['code', 'state', 'error'].some((key) => url.searchParams.has(key));

            if (!hasRedirectParams) {
              return null;
            }

            writeAccount(account);
            window.localStorage.setItem(bootstrapStorageKey, '1');
            clearRedirectParams();
            return { account: clone(account) };
          }

          getActiveAccount() {
            return readAccount();
          }

          getAllAccounts() {
            const current = readAccount();
            return current ? [current] : [];
          }

          setActiveAccount(next: StoredAccount | null) {
            writeAccount(next ? clone(next) : null);
          }

          async loginRedirect() {
            writeAccount(account);
            window.localStorage.setItem(bootstrapStorageKey, '1');

            const url = new URL(window.location.href);
            url.searchParams.set('code', 'mock-auth-code');
            url.searchParams.set('state', 'mock-auth-state');
            window.location.assign(url.toString());
          }

          async logoutRedirect(options?: { postLogoutRedirectUri?: string }) {
            writeAccount(null);
            window.localStorage.removeItem(bootstrapStorageKey);
            window.location.assign(options?.postLogoutRedirectUri ?? window.location.origin);
          }

          async acquireTokenSilent(options?: { account?: StoredAccount | null }) {
            return {
              accessToken,
              account: clone(options?.account ?? readAccount() ?? account),
            };
          }

          async acquireTokenPopup(options?: { account?: StoredAccount | null }) {
            return {
              accessToken,
              account: clone(options?.account ?? readAccount() ?? account),
            };
          }
        },
      };
    },
    {
      accessToken: MOCK_ACCESS_TOKEN,
      account: MICROSOFT_ACCOUNT,
      accountStorageKey: MICROSOFT_ACCOUNT_STORAGE_KEY,
      bootstrapStorageKey: MICROSOFT_BOOTSTRAP_STORAGE_KEY,
    },
  );
}

async function installDashboardStubs(page: Page, observedHeaders: ObservedHeaders[]) {
  await page.route('**/api/v1/dashboard/stats*', async (route) => {
    observedHeaders.push({
      authorization: route.request().headers().authorization,
    });

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(DASHBOARD_STATS),
    });
  });

  await page.route('**/api/v1/alerts*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(ALERTS_PAGE),
    });
  });
}

test('@microsoft configured Microsoft SSO flow redirects back into the authenticated workspace', async ({ page }) => {
  const observedHeaders: ObservedHeaders[] = [];

  await installMicrosoftBrowserMock(page);
  await installDashboardStubs(page, observedHeaders);
  await page.goto('/');

  await expect(page.getByRole('button', { name: /continue with microsoft/i })).toBeVisible();
  await expect(page.getByText(/open your workspace/i)).toBeVisible();

  await page.getByRole('button', { name: /continue with microsoft/i }).click();

  await expect(page.getByText(/live soc workspace/i)).toBeVisible();
  await expect(page.getByText(/development bypass active/i)).toHaveCount(0);

  await expect
    .poll(() => observedHeaders.at(-1)?.authorization)
    .toBe(`Bearer ${MOCK_ACCESS_TOKEN}`);
});
