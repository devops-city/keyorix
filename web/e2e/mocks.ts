import type { Page } from '@playwright/test';

// Shared Playwright API mocks for the e2e suite. The app talks to a same-origin
// backend (axios baseURL is ''), so every route below matches relative to the
// dev server's own origin — no separate backend is required to run these specs.

function json(body: unknown, status = 200) {
    return { status, contentType: 'application/json', body: JSON.stringify(body) };
}

export const MOCK_USER = {
    id: 1,
    username: 'admin',
    email: 'admin@example.com',
    display_name: 'Admin User',
    role: 'admin',
    roles: ['admin'],
    permissions: ['*'],
};

/** Registers a low-priority catch-all for every /api/v1/** and /auth/** call not
 * otherwise mocked, so unrelated background queries (dashboard widgets, etc.)
 * don't hang or throw. Register this FIRST — Playwright checks later-registered
 * routes before earlier ones, so specific mocks added after this still win. */
export async function mockApiCatchAll(page: Page) {
    await page.route('**/api/v1/**', (route) => route.fulfill(json({ data: {}, message: '', success: true })));
}

export async function mockUnauthenticated(page: Page) {
    await page.route('**/api/v1/auth/profile', (route) =>
        route.fulfill(json({ error: 'Not authenticated' }, 401))
    );
}

/** For tests that navigate straight to a protected route without going through
 * the real login form: also seeds `tokenExpiresAt` in localStorage. The axios
 * request interceptor (services/client.ts) treats a *missing* expiry as an
 * expired session and force-logs-out on the next request — a real login sets
 * this via persistAuthData(), but a bare profile mock alone doesn't. */
export async function mockAuthenticated(page: Page, overrides: Partial<typeof MOCK_USER> = {}) {
    const user = { ...MOCK_USER, ...overrides };
    await page.addInitScript(() => {
        // The app's storage helper (src/utils/index.ts) JSON-encodes values on
        // write and JSON.parses on read — a raw unquoted string here fails to
        // parse and is treated as "no expiry", making the request interceptor
        // in services/client.ts force-logout on the very next API call.
        localStorage.setItem('tokenExpiresAt', JSON.stringify(new Date(Date.now() + 3_600_000).toISOString()));
    });
    await page.route('**/api/v1/auth/profile', (route) =>
        route.fulfill(json({ data: user, message: '', success: true }))
    );
}

export async function mockLoginSuccess(page: Page) {
    await page.route('**/auth/login', (route) =>
        route.fulfill(
            json({
                data: {
                    user_id: MOCK_USER.id,
                    username: MOCK_USER.username,
                    email: MOCK_USER.email,
                    display_name: MOCK_USER.display_name,
                    role: MOCK_USER.role,
                    roles: MOCK_USER.roles,
                    permissions: MOCK_USER.permissions,
                    expires_at: new Date(Date.now() + 3_600_000).toISOString(),
                },
                message: '',
                success: true,
            })
        )
    );
}

export async function mockLoginFailure(page: Page, message = 'Invalid credentials') {
    await page.route('**/auth/login', (route) => route.fulfill(json({ error: message }, 401)));
}

export async function mockLogoutSuccess(page: Page) {
    await page.route('**/auth/logout', (route) => route.fulfill(json({ message: '', success: true })));
}

/** Mocks the background queries DashboardPage fires on mount so it renders
 * cleanly instead of sitting in permanent loading/error states. */
export async function mockDashboardData(page: Page) {
    await page.route('**/api/v1/dashboard/stats', (route) =>
        route.fulfill(
            json({
                data: {
                    totalSecrets: 0,
                    sharedSecrets: 0,
                    secretsSharedWithMe: 0,
                    activeUsers: 1,
                    auditEvents30d: 0,
                    auditLogins30d: 0,
                    auditSecretReads30d: 0,
                    failedAuthAttempts24h: 0,
                    refusedSecretReads24h: 0,
                    inactiveUsers: 0,
                },
                message: '',
                success: true,
            })
        )
    );
    await page.route('**/api/v1/dashboard/activity', (route) =>
        route.fulfill(json({ data: { items: [], total: 0, page: 1, pageSize: 10 }, success: true }))
    );
    await page.route('**/api/v1/system/info', (route) => route.fulfill(json({ data: {}, success: true })));
    await page.route('**/api/v1/system/metrics', (route) => route.fulfill(json({ data: {}, success: true })));
    await page.route('**/api/v1/audit/anomalies**', (route) => route.fulfill(json({ data: [], success: true })));
}

export interface MockSecret {
    id: number;
    name: string;
    type: string;
    environment_name?: string;
    status?: string;
    updated_at?: string;
}

/** SecretTableRow formats `lastModified` via Intl.DateTimeFormat, which
 * throws on an invalid/empty date — always provide a real ISO timestamp. */
function withDate(s: MockSecret): MockSecret {
    return { updated_at: new Date().toISOString(), ...s };
}

export async function mockSecretsList(page: Page, secrets: MockSecret[]) {
    secrets = secrets.map(withDate);
    await page.route('**/api/v1/secrets?*', (route) =>
        route.fulfill(
            json({
                data: { secrets, total: secrets.length, page: 1, page_size: 20, total_pages: 1 },
                message: '',
                success: true,
            })
        )
    );
    await page.route('**/api/v1/secrets', (route) => {
        if (route.request().method() !== 'GET') return route.fallback();
        return route.fulfill(
            json({
                data: { secrets, total: secrets.length, page: 1, page_size: 20, total_pages: 1 },
                message: '',
                success: true,
            })
        );
    });
}

export async function mockSecretsPolicy(page: Page) {
    await page.route('**/api/v1/secrets/policy', (route) =>
        route.fulfill(json({ data: { name: { enabled: false }, value: { enabled: false } }, success: true }))
    );
}

export async function mockProjectsAndEnvironments(page: Page) {
    await page.route('**/api/v1/projects', (route) => {
        if (route.request().method() !== 'GET') return route.fallback();
        return route.fulfill(
            json({ data: { projects: [{ id: 1, name: 'demo-project' }] }, success: true })
        );
    });
    await page.route('**/api/v1/projects/1/environments*', (route) =>
        route.fulfill(json({ data: { environments: [{ id: 1, name: 'production', project_id: 1 }] }, success: true }))
    );
}

export async function mockSecretCreateSuccess(page: Page, created: MockSecret) {
    const secret = withDate(created);
    await page.route('**/api/v1/secrets', (route) => {
        if (route.request().method() !== 'POST') return route.fallback();
        return route.fulfill(json({ data: secret, message: '', success: true }));
    });
}

export async function mockSecretCreateFailure(page: Page, message = 'Failed to create secret.') {
    await page.route('**/api/v1/secrets', (route) => {
        if (route.request().method() !== 'POST') return route.fallback();
        return route.fulfill(json({ message }, 500));
    });
}
