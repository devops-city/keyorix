import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
    testDir: './e2e',
    // e2e/real/ holds SESSION-I's real-backend specs (playwright.config.real.ts,
    // driven by scripts/e2e/web-real-smoke.sh) -- they need a real
    // keyorix-server behind VITE_API_BASE_URL, not this config's own
    // `pnpm dev` (no backend) + mocked-route fixtures. Excluded here so the
    // default `pnpm test:e2e` never silently tries to run them against mocks.
    // e2e/demo/ (DEMO-E2E-1) is the same kind of suite: real-backend demo journeys
    // (playwright.config.real.ts with KEYORIX_E2E_TEST_DIR), excluded for the same reason.
    testIgnore: ['real/**', 'demo/**'],
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : undefined,
    reporter: 'html',
    use: {
        baseURL: 'http://localhost:3000',
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
    },

    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
    ],

    webServer: {
        command: 'pnpm dev',
        url: 'http://localhost:3000',
        reuseExistingServer: !process.env.CI,
    },
});
