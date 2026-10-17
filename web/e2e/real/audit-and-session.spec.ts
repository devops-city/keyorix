// web/e2e/real/audit-and-session.spec.ts — SESSION-WEB-E2E item 4: the audit
// view shows the operations exercised elsewhere in this suite, and a session
// timeout / logout really end the session server-side (not just hide the UI)
// -- including that the browser back button can't resurrect protected data
// after logout. Real backend (scripts/e2e/web-real-smoke.sh), no mocked
// routes.
//
// Merged from two independently-produced candidates (PRs #2456 and #2457)
// that ended up covering the same scope: the audit-log test below is
// #2456's (asserts actual Created/Rotated/Deleted row content for a secret
// taken through its full lifecycle, not just "a project got created"), and
// the session-timeout/logout tests are #2457's three-separate-tests
// structure -- #2456's own combined version of this (one test doing logout
// THEN installing a second page's fake clock for the timeout check)
// reproducibly failed live (`page2.waitForURL` error:
// "net::ERR_ABORTED; maybe frame was detached?") when actually run against
// the real backend; #2457's version, with each concern as its own test
// using its own fresh login, passed reliably across multiple real runs.
// Neither candidate's admin usage mutates the shared bootstrap admin's own
// MFA/session/role/password -- login/logout/inactivity-timeout are normal,
// repeatable actions on that account, not one-way state changes the way
// enabling MFA would be (see mfa-login.spec.ts's header for that contrast).
import { test, expect, Page, request as apiRequest } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

async function realLogin(page: Page) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });
}

test("the audit log shows create/rotate/delete operations on a real secret, and this session's own login", async ({
    page,
}) => {
    const unique = Date.now();
    const projectName = `e2e-audit-${unique}`;
    const envName = `e2eenv${unique}`;
    const secretName = `e2e-secret-${unique}`;

    await realLogin(page);

    // ── Produce the operations this test asserts on ────────────────────────
    await page.goto('/projects');
    await page.getByRole('button', { name: 'New Project' }).click();
    await page.locator('#create-project-name').fill(projectName);
    await page.getByRole('button', { name: 'Create Project' }).click();
    await page.waitForURL(/\/projects\/\d+(\/secrets)?$/, { timeout: 15_000 });
    const projectUrl = page.url().replace(/\/secrets$/, '');

    await page.goto(`${projectUrl}/settings`);
    await page.getByPlaceholder('New environment name…').fill(envName);
    await page.getByRole('button', { name: 'Add' }).click();
    await expect(page.getByText(envName, { exact: false })).toBeVisible({ timeout: 10_000 });

    await page.goto(`${projectUrl}/secrets`);
    await page.getByRole('button', { name: new RegExp(`^${envName}$`, 'i') }).click();
    await expect(page).toHaveURL(new RegExp(`env=${envName}`), { timeout: 10_000 });
    await page.getByRole('button', { name: 'New Secret' }).first().click();
    await page.locator('#create-secret-name').fill(secretName);
    await page.locator('#create-secret-value').fill(`value-${unique}`);
    await page.getByRole('button', { name: 'Create Secret' }).click();
    await expect(page.getByRole('dialog')).toBeHidden({ timeout: 10_000 });

    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await row.getByTitle('View').click();
    await page.setViewportSize({ width: 1280, height: 2600 }); // see secrets-crud.spec.ts's note on this modal's scroll gap
    await page.getByRole('button', { name: 'Rotate', exact: true }).click();
    await page.getByLabel('New value').fill(`rotated-${unique}`);
    await page.getByRole('button', { name: 'Rotate secret' }).click();
    await expect(page.getByText(`Rotate ${secretName}`)).not.toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('Delete Secret')).toBeVisible();
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('Delete Secret')).not.toBeVisible({ timeout: 10_000 });

    // ── The audit log reflects all three operations on this exact secret ───
    await page.goto('/audit');
    await page.getByPlaceholder('Filter by actor…').fill(ADMIN_USERNAME as string);

    const secretRows = page.getByRole('row', { name: new RegExp(secretName) });
    await expect(secretRows).toHaveCount(3, { timeout: 10_000 });
    const rowsText = (await secretRows.allTextContents()).join(' | ');
    expect(rowsText, 'audit log must show the secret was created').toContain('Created');
    expect(rowsText, 'audit log must show the secret was rotated').toContain('Rotated');
    expect(rowsText, 'audit log must show the secret was deleted').toContain('Deleted');

    // A login this same session performed is in the log too.
    await page.getByPlaceholder('Filter by actor…').fill('');
    await expect(page.getByRole('row').filter({ hasText: /login/i }).first()).toBeVisible({ timeout: 10_000 });
});

test('an inactivity session timeout really ends the session (server-side, not just the UI)', async ({
    page,
    context,
}) => {
    // Install the clock BEFORE login -- web/src/features/auth/api.ts's useAuth
    // schedules its inactivity-timeout setTimeout the moment isAuthenticated
    // flips true (right after login), using the real Date.now() at that
    // instant as the deadline's base. Installing afterwards would leave that
    // first timer registered against the real, unmocked clock, and
    // fast-forwarding the fake one wouldn't touch it. Installed with the real
    // current time so login's own timestamps stay realistic.
    await page.clock.install({ time: Date.now() });

    await realLogin(page);

    // Capture the live session cookie before it's invalidated, to prove the
    // eventual 401 below is because the SERVER revoked the session -- not
    // just that the client forgot to send a cookie.
    const cookiesBefore = await context.cookies();
    const profileBefore = await page.context().request.get('/api/v1/auth/profile');
    expect(profileBefore.ok(), 'the session must actually be valid before the timeout').toBeTruthy();

    // web/src/constants.ts's DEFAULT_VALUES.SESSION_TIMEOUT is 1 hour; fast-
    // forward well past it so the inactivity-logout branch in useAuth fires.
    await page.clock.fastForward('01:05:00');

    await page.waitForURL('/login', { timeout: 15_000 });

    // The server, not just the client, must now reject the old session --
    // replay the captured pre-timeout cookie directly against the API.
    const freshRequest = await apiRequest.newContext({ storageState: { cookies: cookiesBefore, origins: [] } });
    const profileAfter = await freshRequest.get(`${new URL(page.url()).origin}/api/v1/auth/profile`);
    expect(profileAfter.status(), 'the pre-timeout session cookie must be rejected after the timeout').toBe(401);
    await freshRequest.dispose();
});

test("logout really ends the session: the server rejects the old cookie, and back doesn't reveal data", async ({
    page,
    context,
}) => {
    await realLogin(page);
    await expect(page.getByText('Total Secrets')).toBeVisible();

    const cookiesBefore = await context.cookies();

    await page.getByTestId('user-menu-button').click();
    await page.getByText('Sign out').click();
    await page.waitForURL('**/login', { timeout: 15_000 });

    // Server-side invalidation, not just a client-side state clear.
    const freshRequest = await apiRequest.newContext({ storageState: { cookies: cookiesBefore, origins: [] } });
    const profileAfter = await freshRequest.get(`${new URL(page.url()).origin}/api/v1/auth/profile`);
    expect(profileAfter.status(), 'the pre-logout session cookie must be rejected after logout').toBe(401);
    await freshRequest.dispose();

    // Back button after logout must not resurrect the dashboard from bfcache
    // or any other client-side cache -- it must re-request and bounce to
    // /login (checkAuth's 401 path) rather than flash real data.
    await page.goBack();
    await expect(page.getByText('Total Secrets')).not.toBeVisible();
    await page.waitForURL('**/login', { timeout: 15_000 });
});
