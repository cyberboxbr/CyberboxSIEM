import { expect, test, type Page } from '@playwright/test';

const BYPASS_IDENTITY_STORAGE_KEY = 'cyberbox_bypass_identity';

const VIEWER_IDENTITY = {
  tenantId: 'tenant-a',
  userId: 'soc-viewer',
  roles: ['viewer'],
};

const ANALYST_IDENTITY = {
  tenantId: 'tenant-a',
  userId: 'soc-analyst',
  roles: ['analyst', 'viewer'],
};

const ADMIN_IDENTITY = {
  tenantId: 'tenant-a',
  userId: 'soc-admin',
  roles: ['admin', 'analyst', 'viewer'],
};

const COVERAGE_RESPONSE = {
  total_in_framework: 201,
  total_covered: 2,
  coverage_pct: 1.0,
  covered_techniques: [
    {
      technique_id: 'T1059.001',
      technique_name: 'PowerShell',
      tactic: 'execution',
      rule_count: 2,
      rule_ids: ['rule-psh-1', 'rule-psh-2'],
    },
    {
      technique_id: 'T1055',
      technique_name: 'Process Injection',
      tactic: 'defense-evasion',
      rule_count: 1,
      rule_ids: ['rule-proc-1'],
    },
  ],
};

const RBAC_RESPONSE = {
  assignments: [
    { user_id: 'soc-admin', roles: ['admin', 'analyst', 'viewer'] },
    { user_id: 'soc-analyst', roles: ['analyst', 'viewer'] },
  ],
  total: 2,
};

async function seedBypassIdentity(page: Page, identity: typeof VIEWER_IDENTITY) {
  await page.addInitScript(
    ({ storageKey, value }) => {
      window.localStorage.setItem(storageKey, JSON.stringify(value));
    },
    { storageKey: BYPASS_IDENTITY_STORAGE_KEY, value: identity },
  );
}

async function stubCoverage(page: Page) {
  await page.route('**/api/v1/coverage', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(COVERAGE_RESPONSE),
    });
  });
}

async function stubRbac(page: Page) {
  await page.route('**/api/v1/rbac/users', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(RBAC_RESPONSE),
    });
  });
}

test.describe('role-gated browser access', () => {
  test('viewer identities lose gated navigation and hit access denied on analyst routes', async ({ page }) => {
    await seedBypassIdentity(page, VIEWER_IDENTITY);
    await page.goto('/coverage');

    await expect(page.getByText(/access denied/i)).toBeVisible();
    await expect(page.getByText(/does not include permission to open this workspace/i)).toBeVisible();
    await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Threat Intel' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Administration' })).toHaveCount(0);
  });

  test('analyst identities can open analyst routes but not admin routes', async ({ page }) => {
    await stubCoverage(page);
    await seedBypassIdentity(page, ANALYST_IDENTITY);

    await page.goto('/coverage');

    await expect(page.getByRole('heading', { name: 'ATT&CK matrix' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Threat Intel' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Administration' })).toHaveCount(0);

    await page.goto('/admin/rbac');

    await expect(page.getByText(/access denied/i)).toBeVisible();
    await expect(page.getByText(/does not include permission to open this workspace/i)).toBeVisible();
  });

  test('admin identities can open admin routes and see the administration surface', async ({ page }) => {
    await stubRbac(page);
    await seedBypassIdentity(page, ADMIN_IDENTITY);

    await page.goto('/admin/rbac');

    await expect(page.getByText(/access denied/i)).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Administration' })).toBeVisible();
    await expect(page.getByRole('button', { name: /add user/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /refresh roles/i })).toBeVisible();
    await expect(page.getByText('soc-analyst')).toBeVisible();
  });
});
