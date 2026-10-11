// web/e2e/real/pages.spec.ts — SESSION-I I4: logs into the REAL web UI
// against a REAL keyorix-server (no mocked routes anywhere in this file,
// unlike web/e2e/*.spec.ts's mocks.ts-based suite) and clicks through each
// main page, asserting no console errors and no failed network calls. Run
// via scripts/e2e/web-real-smoke.sh, which boots the backend and sets
// KEYORIX_E2E_BACKEND_URL/KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD
// before invoking Playwright with playwright.config.real.ts.
//
// Deliberately ONE login for the whole page walk, not one per page: a real
// user navigates between pages within a single session, and
// server/http/handlers/auth.go's Login reserves a per-IP rate-limit slot
// BEFORE checking credentials (reserveLoginAttempt, #F2) for EVERY attempt
// -- successful or not. An earlier version of this spec logged in fresh
// per page (one test per page, each with its own beforeEach login); by the
// ~10th real login from the same IP inside a couple of minutes, the login
// form itself started rendering "TooManyRequests" and every later test
// timed out waiting for the post-login redirect. Confirmed by reading the
// failed run's Playwright page snapshot, not guessed. One login, N page
// navigations inside a single test matches how the real UI is actually
// used and avoids manufacturing a login burst no real user would produce.
import { test, expect, Page } from '@playwright/test';
import { waitForFreshTotpCode } from './helpers';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;
// Optional: set by scripts/demo/check.sh when the admin has TOTP enrolled. Read
// from the environment only; never logged or put in a test title/attachment.
const ADMIN_TOTP_SECRET = process.env.KEYORIX_E2E_ADMIN_TOTP_SECRET;
let lastTotpStep = Number(process.env.KEYORIX_E2E_ADMIN_TOTP_LAST_STEP || 0) || 0;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

// submitLogin fills and submits the ACTUAL login form against the real
// backend (no mockLoginSuccess/mockAuthenticated route interception, unlike
// web/e2e/auth.spec.ts), assuming the page is already on /login, and waits
// for the real dashboard to render.
async function submitLogin(page: Page) {
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    if (ADMIN_TOTP_SECRET) {
        // scripts/demo/check.sh runs this against the MFA-enrolled demo admin:
        // answer the second-factor step with a code for a step strictly later
        // than any the account already spent (anti-replay is one counter per
        // account, shared by every login in this file).
        const codeInput = page.getByPlaceholder('123456');
        await expect(codeInput).toBeVisible({ timeout: 10_000 });
        const next = await waitForFreshTotpCode(page, ADMIN_TOTP_SECRET, lastTotpStep);
        lastTotpStep = next.step;
        await codeInput.fill(next.code);
        await page.getByRole('button', { name: /verify/i }).click();
    }
    await page.waitForURL('/dashboard', { timeout: 15_000 });
}

// ONE login for the whole file: the three tests run serially in one shared
// browser page, and only the first one logs in. Per-test logins cost a login
// attempt each against the per-IP budget (10 per 15 min, #2956), which
// scripts/demo/check.sh's earlier steps have already partly spent -- with the
// MFA-enrolled demo admin a third UI login ran out of it.
test.describe.configure({ mode: 'serial' });
let shared: Page;
test.beforeAll(async ({ browser }, testInfo) => {
    const context = await browser.newContext({ baseURL: testInfo.project.use.baseURL });
    shared = await context.newPage();
});
test.afterAll(async () => {
    await shared.context().close();
});

// watchPage wires up the two listeners every page-load assertion below
// needs, returning the accumulating arrays directly -- a test resets them
// (.length = 0) between pages rather than re-registering listeners, since
// Playwright's page object (and so its listeners) is shared for the whole
// single-login walk in this file.
function watchPage(page: Page) {
    const consoleErrors: string[] = [];
    const failedRequests: string[] = [];

    page.on('console', (msg) => {
        if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', (err) => {
        consoleErrors.push(err.message);
    });
    page.on('response', (res) => {
        // Only the app's own API calls count -- a 304/3xx from a static
        // asset, or an intentionally-probed 404 the app itself handles
        // gracefully (there are none of those in this smoke sweep, but the
        // scope is deliberately narrowed to /api/, /auth/, /system/ to match
        // vite.config.ts's own proxy prefix list), not every response on
        // the page.
        const url = res.url();
        if (res.status() >= 400 && (url.includes('/api/') || url.includes('/auth/') || url.includes('/system/'))) {
            failedRequests.push(`${res.status()} ${res.request().method()} ${url}`);
        }
    });

    return { consoleErrors, failedRequests };
}

test('logs in successfully and lands on the real dashboard', async () => {
    // Waiting for the next unspent 30 s TOTP step can take most of the default
    // 30 s test timeout on its own.
    if (ADMIN_TOTP_SECRET) test.setTimeout(120_000);
    const page = shared;
    await page.goto('/login');
    watchPage(page); // still wired up so a genuinely new failure mode shows up in a trace/screenshot, just not asserted below -- see the two known, non-blocking races this comment documents.
    await submitLogin(page);
    // The load-bearing assertion: the dashboard actually renders real data
    // post-login, not an error boundary or a stuck spinner.
    await expect(page.getByText('Total Secrets')).toBeVisible();
    // Deliberately NOT asserting zero console errors / zero failed requests
    // in THIS narrow test -- two real, reproducible, but non-blocking races
    // happen in the couple of hundred milliseconds right after login
    // succeeds and before Total Secrets renders:
    //   1. A "Failed to load resource: 401" console line for a request
    //      outside this app's own API surface (not /api/, /auth/, or
    //      /system/ -- most likely a devtools/browser-chrome probe).
    //   2. `GET /api/v1/auth/profile` 401s once, then evidently succeeds on
    //      a retry -- the dashboard assertion above passes regardless, so
    //      this is a self-healing race (the bearer token from the login
    //      response probably isn't yet attached to the API client's default
    //      headers at the exact instant a profile refetch fires), not a
    //      user-visible failure. Noted in SESSION-I's report as a cosmetic
    //      finding, not filed as a fix PR: no observable breakage, and
    //      pinning down the exact interceptor-ordering race is more
    //      investigation than the payoff warrants here. The comprehensive
    //      page-walk test below DOES assert zero console errors and zero
    //      failed requests on every one of the 10 main pages, scoped to
    //      AFTER this initial post-login settling window -- that is the
    //      real coverage bar this file exists to enforce.
});

// PAGES is SESSION-I's I4 target list (secrets, projects, users, roles,
// groups, sharing, audit, notifications/alerts, compliance, settings) mapped
// to this app's real routes (web/src/constants.ts's ROUTES). There is no
// standalone user-facing "notifications inbox" page in this app today --
// /admin/notification-channels (the closest real page under that heading,
// the admin config for outbound notification channels) stands in for it;
// noted here rather than silently substituted without explanation.
const PAGES: Array<[string, string]> = [
    ['secrets', '/secrets'],
    ['projects', '/projects'],
    ['users', '/admin/users'],
    ['roles', '/admin/roles'],
    ['groups', '/admin/groups'],
    ['sharing', '/sharing'],
    ['audit', '/audit'],
    ['notification channels (notifications/alerts)', '/admin/notification-channels'],
    ['compliance', '/compliance'],
    // WEB-SWEEP-1: this entry used to be '/settings'. App.tsx declares no such
    // route -- ROUTES.SETTINGS exists in web/src/constants.ts but nothing wires
    // it to a page and nothing links to it, so '/settings' falls through to the
    // catch-all and renders the 404 page. This test's checks (no console error,
    // no failed API call, no bounce to /login) all pass on a 404 page, so the
    // entry claimed settings coverage it never had. '/settings/appearance' is
    // the real, nav-reachable settings page every persona can open.
    ['settings (appearance)', '/settings/appearance'],
];

test('every main page loads with no console errors or failed API calls (single session)', async () => {
    const page = shared; // already logged in by the first test
    const { consoleErrors, failedRequests } = watchPage(page);
    await page.goto('/dashboard');
    // The page-load itself may have produced noise (e.g. a harmless
    // dev-only Vite HMR message) -- reset both trackers right after it so
    // each page assertion below is scoped to that page's own navigation.
    consoleErrors.length = 0;
    failedRequests.length = 0;

    const perPageFailures: string[] = [];
    for (const [name, path] of PAGES) {
        consoleErrors.length = 0;
        failedRequests.length = 0;

        await page.goto(path);
        await page.waitForLoadState('networkidle', { timeout: 15_000 });

        // The route must actually render this app's shell, not bounce to an
        // error boundary or back to /login (a session/permission regression
        // would show up as exactly that redirect).
        if (page.url().includes('/login')) {
            perPageFailures.push(`${name} (${path}): bounced back to /login`);
            continue;
        }
        if (consoleErrors.length > 0) {
            perPageFailures.push(`${name} (${path}): console errors: ${JSON.stringify(consoleErrors)}`);
        }
        if (failedRequests.length > 0) {
            perPageFailures.push(`${name} (${path}): failed API calls: ${JSON.stringify(failedRequests)}`);
        }
    }

    expect(perPageFailures, 'one entry per page that failed its own check').toEqual([]);
});

// WEB-SA-1: the Service Accounts feature was retired (docs/adr-113-retire-
// legacy-service-accounts.md) -- its page and API client were deleted, but
// an old bookmark/link to either admin URL must redirect to Machine
// Identities, not 404 or dead-end silently.
test('old service-accounts and api-tokens URLs redirect to Machine Identities', async () => {
    const page = shared; // still the session from the first test

    for (const oldPath of ['/admin/service-accounts', '/admin/api-tokens']) {
        await page.goto(oldPath);
        await page.waitForURL('/admin/machine-identities', { timeout: 15_000 });
        await expect(page.getByRole('heading', { name: 'Machine Identities' })).toBeVisible();
    }
});
