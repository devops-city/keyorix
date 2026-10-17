// playwright.config.real.ts — SESSION-I I4: real-backend web UI smoke.
//
// Separate from playwright.config.ts (the existing mocked-route suite,
// web/e2e/*.spec.ts) on purpose: that config's webServer starts a plain
// `pnpm dev` with no backend at all, relying on every spec intercepting API
// calls itself (web/e2e/mocks.ts). This config instead points a real Vite
// dev server's VITE_API_BASE_URL at a real, already-running keyorix-server
// (booted by scripts/e2e/web-real-smoke.sh, which sets the
// KEYORIX_E2E_BACKEND_URL/KEYORIX_E2E_ADMIN_USERNAME/
// KEYORIX_E2E_ADMIN_PASSWORD env vars this config and web/e2e/real/*.spec.ts
// both read) — never mocks a single route.
//
// Run via `scripts/e2e/web-real-smoke.sh`, not directly: that script owns
// booting the real backend first. Running `pnpm exec playwright test
// --config=playwright.config.real.ts` on its own will fail fast with a clear
// message (see the throw below) if KEYORIX_E2E_BACKEND_URL isn't set.
import { defineConfig, devices } from '@playwright/test';

const backendURL = process.env.KEYORIX_E2E_BACKEND_URL;
if (!backendURL) {
    throw new Error(
        'KEYORIX_E2E_BACKEND_URL is not set -- run scripts/e2e/web-real-smoke.sh, ' +
            'which boots a real keyorix-server and sets it, rather than invoking ' +
            'this Playwright config directly.'
    );
}

const webPort = process.env.KEYORIX_E2E_WEB_PORT || '18190';

export default defineConfig({
    // e2e/real is the suite the pull_request and merge_group jobs run; e2e/demo (DEMO-E2E-1) is the
    // demo-catalogue journeys, run by `make e2e-web-demo` in the full CI profile. The harness sets
    // KEYORIX_E2E_TEST_DIR from the directory of the spec it is running.
    testDir: process.env.KEYORIX_E2E_TEST_DIR || './e2e/real',
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    retries: 0,
    workers: 1,
    reporter: 'list',
    use: {
        baseURL: `http://localhost:${webPort}`,
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
        command: `pnpm dev --port ${webPort} --strictPort`,
        url: `http://localhost:${webPort}`,
        reuseExistingServer: false,
        timeout: 30_000,
        env: {
            // The main API client (src/services/client.ts) always uses a
            // relative baseURL and goes through vite.config.ts's dev proxy,
            // not VITE_API_BASE_URL -- KEYORIX_DEV_PROXY_TARGET is the one
            // that actually redirects real traffic to the real backend.
            // VITE_API_BASE_URL is set too since the separate, unrelated
            // unauthenticated setup-flow client (src/services/setup.ts) DOES
            // read it directly.
            KEYORIX_DEV_PROXY_TARGET: backendURL,
            VITE_API_BASE_URL: backendURL,
        },
    },
});
