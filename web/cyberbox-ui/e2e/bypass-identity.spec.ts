import { expect, test, type Page } from '@playwright/test';

const BYPASS_IDENTITY_STORAGE_KEY = 'cyberbox_bypass_identity';

const INITIAL_IDENTITY = {
  tenantId: 'tenant-z',
  userId: 'qa-investigator',
  roles: ['analyst', 'viewer'],
};

const UPDATED_IDENTITY = {
  tenantId: 'tenant-red',
  userId: 'tier2-hunter',
  roles: ['admin', 'analyst', 'viewer'],
};

const DEFAULT_IDENTITY = {
  tenantId: 'tenant-a',
  userId: 'soc-admin',
  roles: ['admin', 'analyst', 'viewer', 'ingestor'],
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
  tenantId?: string;
  userId?: string;
  roles?: string;
};

async function installDashboardStubs(page: Page, observedHeaders: ObservedHeaders[]) {
  await page.route('**/api/v1/dashboard/stats*', async (route) => {
    const headers = route.request().headers();
    observedHeaders.push({
      tenantId: headers['x-tenant-id'],
      userId: headers['x-user-id'],
      roles: headers['x-roles'],
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

async function seedBypassIdentity(page: Page, identity: typeof INITIAL_IDENTITY) {
  await page.addInitScript(
    ({ storageKey, value }) => {
      if (!window.localStorage.getItem(storageKey)) {
        window.localStorage.setItem(storageKey, JSON.stringify(value));
      }
    },
    { storageKey: BYPASS_IDENTITY_STORAGE_KEY, value: identity },
  );
}

function commandPaletteShortcut() {
  return process.platform === 'darwin' ? 'Meta+K' : 'Control+K';
}

test('bypass identity persists across reloads and updates outgoing headers', async ({ page }) => {
  const observedHeaders: ObservedHeaders[] = [];

  await installDashboardStubs(page, observedHeaders);
  await seedBypassIdentity(page, INITIAL_IDENTITY);

  await page.goto('/');

  await expect(page.getByText(/development bypass active/i)).toBeVisible();
  await expect(page.getByText(new RegExp(`Tenant ${INITIAL_IDENTITY.tenantId}`, 'i')).first()).toBeVisible();
  await expect(page.getByText(INITIAL_IDENTITY.userId).first()).toBeVisible();

  await expect.poll(() => observedHeaders.at(-1)?.tenantId).toBe(INITIAL_IDENTITY.tenantId);
  await expect.poll(() => observedHeaders.at(-1)?.userId).toBe(INITIAL_IDENTITY.userId);
  await expect.poll(() => observedHeaders.at(-1)?.roles).toBe(INITIAL_IDENTITY.roles.join(','));

  await page.getByRole('button', { name: 'Edit identity' }).click();
  const tenantInput = page.getByLabel('Tenant');
  const userInput = page.getByLabel('User ID');
  const rolesInput = page.getByLabel('Roles');

  await expect(tenantInput).toHaveValue(INITIAL_IDENTITY.tenantId);
  await expect(userInput).toHaveValue(INITIAL_IDENTITY.userId);
  await expect(rolesInput).toHaveValue(INITIAL_IDENTITY.roles.join(', '));

  await tenantInput.fill(UPDATED_IDENTITY.tenantId);
  await userInput.fill(UPDATED_IDENTITY.userId);
  await rolesInput.fill(UPDATED_IDENTITY.roles.join(', '));
  await page.getByRole('button', { name: /apply identity/i }).click();

  await expect(page.getByText(/development identity updated for new api requests/i)).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate((storageKey) => {
        const value = window.localStorage.getItem(storageKey);
        return value ? JSON.parse(value).tenantId : null;
      }, BYPASS_IDENTITY_STORAGE_KEY))
    .toBe(UPDATED_IDENTITY.tenantId);

  await page.reload();

  await expect(page.getByText(new RegExp(`Tenant ${UPDATED_IDENTITY.tenantId}`, 'i')).first()).toBeVisible();
  await expect(page.getByText(UPDATED_IDENTITY.userId).first()).toBeVisible();
  await expect.poll(() => observedHeaders.at(-1)?.tenantId).toBe(UPDATED_IDENTITY.tenantId);
  await expect.poll(() => observedHeaders.at(-1)?.userId).toBe(UPDATED_IDENTITY.userId);
  await expect.poll(() => observedHeaders.at(-1)?.roles).toBe(UPDATED_IDENTITY.roles.join(','));

  await page.keyboard.press(commandPaletteShortcut());
  await expect(page.getByRole('dialog', { name: /command palette/i })).toBeVisible();
  await page.getByRole('button', { name: /reset development identity/i }).click();

  await page.reload();

  await expect(page.getByText(new RegExp(`Tenant ${DEFAULT_IDENTITY.tenantId}`, 'i')).first()).toBeVisible();
  await expect(page.getByText(DEFAULT_IDENTITY.userId).first()).toBeVisible();
  await expect.poll(() => observedHeaders.at(-1)?.tenantId).toBe(DEFAULT_IDENTITY.tenantId);
  await expect.poll(() => observedHeaders.at(-1)?.userId).toBe(DEFAULT_IDENTITY.userId);
  await expect.poll(() => observedHeaders.at(-1)?.roles).toBe(DEFAULT_IDENTITY.roles.join(','));
});
