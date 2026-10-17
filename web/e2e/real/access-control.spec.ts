// web/e2e/real/access-control.spec.ts — SESSION-WEB-E2E item 3: creates a
// user with a limited (project_viewer) role through the real admin UI, then
// verifies that user's own UI hides what the API denies, and that a
// forbidden deep link never renders admin data.
//
// Note on "a forbidden deep link shows a proper error rather than data": the
// actual behavior of every <AdminRoute> in this app
// (web/src/components/layout/ProtectedRoute.tsx) is a SILENT redirect to
// /dashboard, not a distinct error page — `redirectOnFailure` defaults to
// `true` and no route in web/src/App.tsx overrides it, so the component's
// own `AccessDenied` fallback is unreachable dead code today. This is safe
// (no data is ever rendered) but is not the same as "a proper error" the
// brief describes. Documented here and in the report rather than asserting
// a UI state that doesn't exist.
import { test, expect, Page } from '@playwright/test';
import { randomInt } from 'node:crypto';
import { compliantPassword, personalInfoCandidates } from './support/password';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

async function submitLogin(page: Page, username: string, password: string) {
    await page.getByTestId('username-input').fill(username);
    await page.getByTestId('password-input').fill(password);
    await page.getByTestId('login-button').click();
}

async function logout(page: Page) {
    await page.getByTestId('user-menu-button').click();
    await page.getByText('Sign out').click();
    await page.waitForURL('**/login', { timeout: 15_000 });
}

test('a limited (project_viewer) user cannot see or reach what their role denies', async ({ page }) => {
    // This test used to raise the viewport to 1280x2200 to work around the
    // "New User" modal having no internal scroll container: taller than a
    // standard 1280x720 window, clipped by the shared Modal's overflow-hidden,
    // submit button unreachable. That was a real product gap (#2775), and the
    // workaround meant no test exercised the real geometry -- the suite that
    // would have caught it was hiding it. Fixed in the shared Modal
    // (web/src/components/ui/Modal.tsx: max-h + a scrollable body), so this
    // test now runs at the default Desktop Chrome viewport like everything
    // else. web/e2e/real/ui-dialog-viewport.spec.ts is what guards the
    // geometry, over every dialog in the app, at two real laptop heights.

    // Unique per run so repeat runs against a persistent dev DB don't collide.
    const stamp = randomInt(1_000_000);
    const projectName = `access-ctrl-${stamp}`;
    const limitedUsername = `limiteduser${stamp}`;
    // Deliberately NOT derived from `stamp` (or any other username/email/
    // display-name substring) -- internal/core/rules.DefaultPasswordPolicy
    // rejects a password containing the account's own username/email/display
    // name (see scripts/smoke.sh's own header comment on this exact trap, and
    // CLAUDE.md's "local-only test failures" notes). A shared stamp here
    // silently 400s the create-user call with a generic "ValidationError".
    //
    // #2815: the previous literal here, 'Quartz-Falcon-77-Ridge!-' + base-36,
    // was compliant only because of the hardcoded "77" -- its sibling in
    // mfa-login.spec.ts had no literal digit and flaked ~14% of runs. Switched
    // to the shared generator so this one is compliant by construction too,
    // rather than by a detail no future edit is obliged to preserve.
    const limitedDisplayName = `Limited User ${stamp}`;
    const limitedEmail = `${limitedUsername}@example.invalid`;
    const limitedPassword = compliantPassword(
        personalInfoCandidates({
            username: limitedUsername,
            email: limitedEmail,
            displayName: limitedDisplayName,
        })
    );

    // ── Setup as admin: a project, and a user scoped to only that project ──
    await page.goto('/login');
    await submitLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    await page.waitForURL('/dashboard', { timeout: 15_000 });

    await page.goto('/projects?new=1');
    await page.getByLabel('Project name').fill(projectName);
    await page.getByRole('button', { name: 'Create Project' }).click();
    await page.waitForURL(/\/projects\/\d+$/, { timeout: 15_000 });

    await page.goto('/admin/users');
    await page.getByRole('button', { name: 'New User' }).click();
    await page.getByLabel('Username').fill(limitedUsername);
    await page.getByLabel('Display Name').fill(limitedDisplayName);
    await page.getByLabel('Email').fill(limitedEmail);
    await page.locator('#create-password').fill(limitedPassword);
    // Default-role project assignment: the typeahead attaches project_viewer
    // (web/src/features/admin/ProjectAssignmentsPicker.tsx's DEFAULT_ROLE) --
    // deliberately left unchanged so this user's role really is read-only,
    // not elevated by the test itself.
    await page.getByPlaceholder('Search projects to add…').fill(projectName);
    await page.getByRole('button', { name: projectName, exact: true }).click();
    await page.getByRole('button', { name: 'Create User', exact: true }).click();
    // The classic (password) create path closes the modal directly on
    // success (no out-of-band artifact to relay) -- its disappearance, plus
    // the new row landing in the table, is the completion signal.
    await expect(page.getByRole('dialog')).toBeHidden({ timeout: 10_000 });
    // Scoped to the "@username" caption specifically -- a bare getByText(username)
    // also matches the email cell (which contains the username as a prefix).
    await expect(page.getByText(`@${limitedUsername}`)).toBeVisible({ timeout: 10_000 });

    await logout(page);

    // ── As the limited user ─────────────────────────────────────────────────
    // No page.goto('/login') here: logout() already waits for **/login, so the
    // browser is on it. Navigating to the URL it is already settling on raced
    // the login page's own in-flight navigation and aborted it -- intermittent
    // `page.goto: net::ERR_ABORTED at .../login`, reproduced twice on an
    // otherwise-unmodified copy of this file. The login form is simply filled
    // in where logout() left us.
    await submitLogin(page, limitedUsername, limitedPassword);
    await page.waitForURL('/dashboard', { timeout: 15_000 });

    // UI hides it: no admin-only nav group rendered at all (web/src/components/
    // layout/Sidebar.tsx filters out adminOnly groups client-side for a non-admin).
    await expect(page.getByText('Access Control')).toHaveCount(0);

    // API denies it too -- the UI hiding it isn't just cosmetic. Goes through
    // the same-origin Vite dev proxy (relative path + the context's
    // configured baseURL), so the real session cookie is attached exactly
    // like a real page navigation would send it.
    // NOT /api/v1/admin/users -- that path is unregistered (server/http/router.go
    // only ever mounts the global users collection at /api/v1/users, gated by
    // RequirePermission(permUsersRead)); web/src/constants.ts's ADMIN.USERS
    // constant pointing at /api/v1/admin/users is dead code that is never
    // actually called by any service in web/src. Hitting the wrong path would
    // "pass" via a router 404 that proves nothing about authorization.
    const adminUsersRes = await page.context().request.get('/api/v1/users');
    expect(adminUsersRes.status(), 'a project-scoped viewer must not be able to list all users').toBe(403);

    // A forbidden deep link never renders admin data. See the top-of-file
    // note: the actual behavior is a silent redirect to /dashboard, not a
    // distinct error page -- asserted as such, not as a hypothetical one.
    await page.goto('/admin/users');
    await page.waitForURL('/dashboard', { timeout: 15_000 });
    await expect(page.getByText(ADMIN_USERNAME as string)).toHaveCount(0);
    await expect(page.locator('table')).toHaveCount(0);
});
