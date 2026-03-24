import { expect, test, type Page } from '@playwright/test';

const BYPASS_IDENTITY_STORAGE_KEY = 'cyberbox_bypass_identity';

const ANALYST_IDENTITY = {
  tenantId: 'tenant-chart',
  userId: 'soc-analyst',
  roles: ['analyst', 'viewer'],
};

const DASHBOARD_STATS = {
  total_events: 20910,
  events_by_source: [
    { source: 'agent', count: '18200' },
    { source: 'syslog', count: '2710' },
  ],
  events_by_host: [],
  hourly_events: [
    { bucket: '2026-03-24T08:00:00.000Z', count: '2200' },
    { bucket: '2026-03-24T09:00:00.000Z', count: '6100' },
    { bucket: '2026-03-24T10:00:00.000Z', count: '9410' },
    { bucket: '2026-03-24T11:00:00.000Z', count: '3200' },
  ],
  active_agents: 4,
  total_agents: 5,
  agents: [
    { agent_id: 'agent-01', hostname: 'endpoint-a', os: 'windows', status: 'active' },
  ],
  active_rules: 14,
  open_alerts: 1,
  total_alerts: 4,
  current_eps: 36.2,
  eps_trend: [
    { bucket: '2026-03-24T10:00:00.000Z', eps: '38.1' },
    { bucket: '2026-03-24T11:00:00.000Z', eps: '34.3' },
  ],
  alerts_by_severity: {
    critical: 0,
    high: 1,
    medium: 0,
    low: 0,
  },
  top_rules: [
    { rule_id: 'rule-1', rule_title: 'Suspicious PowerShell', severity: 'high', alert_count: 3 },
  ],
  alert_trend: [
    { bucket: '2026-03-24T10:00:00.000Z', count: '2' },
    { bucket: '2026-03-24T11:00:00.000Z', count: '1' },
  ],
  mttr_seconds: 420,
};

const ALERTS_PAGE = {
  alerts: [],
  has_more: false,
  total: 0,
};

async function seedBypassIdentity(page: Page) {
  await page.addInitScript(
    ({ storageKey, identity }) => {
      window.localStorage.setItem(storageKey, JSON.stringify(identity));
    },
    { storageKey: BYPASS_IDENTITY_STORAGE_KEY, identity: ANALYST_IDENTITY },
  );
}

async function stubDashboard(page: Page) {
  await page.route('**/api/v1/dashboard/stats*', async (route) => {
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

test('@mobile dashboard chart responds to touch taps on mobile-sized viewports', async ({ page }) => {
  await stubDashboard(page);
  await seedBypassIdentity(page);
  await page.goto('/');

  const chart = page.getByTestId('dashboard-event-volume-chart');
  const selectedValue = page.getByTestId('dashboard-chart-selected-value');

  await expect(chart).toBeVisible();
  await expect(selectedValue).toContainText('3.2K');

  const box = await chart.boundingBox();
  if (!box) {
    throw new Error('Dashboard chart box was not available.');
  }

  await chart.tap({
    position: {
      x: 72,
      y: Math.round(box.height * 0.72),
    },
  });
  await expect(selectedValue).toContainText('2.2K');

  await chart.tap({
    position: {
      x: Math.round(box.width * 0.72),
      y: Math.round(box.height * 0.58),
    },
  });
  await expect(selectedValue).toContainText('9.4K');
});
