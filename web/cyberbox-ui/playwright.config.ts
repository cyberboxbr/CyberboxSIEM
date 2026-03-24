import { defineConfig, devices } from '@playwright/test';

const host = '127.0.0.1';
const bypassPort = 4174;
const microsoftPort = 4175;
const bypassBaseURL = `http://${host}:${bypassPort}`;
const microsoftBaseURL = `http://${host}:${microsoftPort}`;

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: true,
  reporter: 'list',
  use: {
    baseURL: bypassBaseURL,
    headless: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  webServer: [
    {
      command: `npm run dev -- --host ${host} --port ${bypassPort}`,
      env: {
        ...process.env,
        VITE_AUTH_BYPASS: 'true',
      },
      url: bypassBaseURL,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: `npm run dev -- --host ${host} --port ${microsoftPort}`,
      env: {
        ...process.env,
        VITE_AUTH_BYPASS: 'false',
        VITE_AZURE_CLIENT_ID: '00000000-0000-0000-0000-000000000001',
        VITE_AZURE_TENANT_ID: 'cyberbox-test-tenant',
        VITE_AZURE_REDIRECT_URI: microsoftBaseURL,
      },
      url: microsoftBaseURL,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
    },
  ],
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        baseURL: bypassBaseURL,
      },
      grepInvert: /@mobile|@microsoft/,
    },
    {
      name: 'mobile-chromium',
      use: {
        ...devices['Desktop Chrome'],
        baseURL: bypassBaseURL,
        browserName: 'chromium',
        hasTouch: true,
        isMobile: true,
        viewport: { width: 390, height: 844 },
      },
      grep: /@mobile/,
    },
    {
      name: 'chromium-microsoft',
      use: {
        ...devices['Desktop Chrome'],
        baseURL: microsoftBaseURL,
      },
      grep: /@microsoft/,
    },
  ],
});
