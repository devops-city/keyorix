// e2e-server: require_mfa=true
//
// web/e2e/real/mfa-required-first-login.spec.ts -- the first login of an account on a
// deployment that REQUIRES MFA (security.require_mfa: true), driven through the real UI
// against a real server (#2924 asked for this journey; #2933 added the route it ends on).
//
// The first line of this file is not a comment for humans: scripts/e2e/web-real-smoke.sh
// greps for exactly `// e2e-server: require_mfa=true` and, for the group that runs this
// file, writes `require_mfa: true` under `security:` in that group's keyorix.yaml before
// starting the server. Every other spec file boots with require_mfa unset (false), as it
// always did. One spec per group (MAX_SPECS_PER_GROUP=1), so the policy never leaks into
// another file's server. Keep that line first and exact when editing.
//
// THE USER JOURNEY (what a human does, and what each step proves):
//   1. A fresh admin (the group's bootstrap admin: it has no MFA) logs in on /login.
//      The password is right, so login succeeds; the response carries pending_steps
//      ["enroll_mfa"] (#3155), so the SPA goes straight to enrolment: it never renders a
//      protected page and no request is refused (asserted: zero 403s, no /dashboard visit).
//   2. (The server still refuses every other endpoint with
//      403 {"error":"MFAEnrollmentRequired"}; client.ts's handle403 stays as the backstop.) The browser is at
//      /profile?tab=security&mfa=required (MFA_ENROLMENT_URL, #2933). We assert the URL
//      and that the Security tab shows the "Set up two-factor authentication to continue"
//      banner, NOT a generic "no permission" error.
//   3. Independently of the UI, a plain same-origin fetch of an authed API route returns
//      403 MFAEnrollmentRequired. This proves the server policy is really on, so step 2
//      is not satisfied by some other redirect, and gives step 6 something to flip.
//   4. The user clicks Enable, reads the setup key off the page, computes the current
//      TOTP code with the repo's own helper (helpers.ts totpCode), enters it with the
//      account password and clicks "Verify & enable". The recovery-codes dialog appears.
//   5. The user clicks Done. The Security tab now shows the Enabled badge and the banner
//      is gone.
//   6. The same fetch as step 3 no longer returns MFAEnrollmentRequired (the session that
//      enrolled is kept by ActivateMFA, and MFAEnabled is read per request), and
//      navigating to /dashboard stays on /dashboard and renders "Total Secrets".
//
// LOGIN BUDGET: the per-IP limit is 10 logins per 15 minutes per server. This group uses
// 2: the harness's own token login (used only for its health check, it seeds nothing in
// a require_mfa group because the policy would 403 the seeding calls) and the one UI
// login below. Nothing here calls apiLogin/createDedicatedUser: those would log in
// again, and would be 403'd or pointless under the policy.
//
// WHY THE SHARED ADMIN IS FINE HERE: the helpers' rule (never enable MFA on ADMIN_USERNAME)
// exists so other specs on the same server are not affected. This file is alone on its
// server, so enrolling its admin affects nobody else.
import { test, expect, Page } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME, submitLogin, totpCode } from './helpers';

// apiProbe issues an authenticated same-origin GET from inside the page (the session
// cookie rides along; GETs need no CSRF header) and returns the status plus the
// server's `error` code, if any. /api/v1/secrets is not on EnforceMFAEnrollment's
// allowlist (mfaEnrollAllowedSuffixes), so under the policy an un-enrolled session
// gets MFAEnrollmentRequired from it before any permission check.
async function apiProbe(page: Page): Promise<{ status: number; error: string | null }> {
    return page.evaluate(async () => {
        const res = await fetch('/api/v1/secrets', { credentials: 'include' });
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        return { status: res.status, error: body?.error ?? null };
    });
}

test('first login under require_mfa lands on enrolment, enrols TOTP, and reaches the dashboard', async ({ page }) => {
    // 1. Log in as the fresh admin. Deliberately NOT realLogin(): that waits for
    //    /dashboard, which this account must not be allowed to stay on.
    //    #3155: the login response (and GET /auth/profile) report `pending_steps:
    //    ["enroll_mfa"]`, so the SPA must go straight to enrolment: it never visits a protected
    //    page route and never fires a request the confinement refuses. Record both from here.
    const refused: string[] = [];
    const visited: string[] = [];
    page.on('response', (res) => {
        if (res.status() === 403) refused.push(`${res.request().method()} ${new URL(res.url()).pathname}`);
    });
    page.on('framenavigated', (frame) => {
        if (frame === page.mainFrame()) visited.push(new URL(frame.url()).pathname);
    });
    await page.goto('/login');
    await submitLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);

    // 2. The MFA-pending session is routed to the enrolment route.
    await page.waitForURL(/\/profile\?tab=security&mfa=required/, { timeout: 20_000 });
    // getByText is a case-insensitive substring match, so it also hits the enrolment banner
    // ("Set up two-factor authentication to continue") and its message. Target the section heading.
    await expect(page.getByRole('heading', { name: 'Two-Factor Authentication', exact: true })).toBeVisible();
    await expect(page.getByText('Set up two-factor authentication to continue')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('You do not have permission to perform this action.')).toHaveCount(0);
    // The Security tab's own status read has settled by the time the banner shows; nothing
    // else is in flight that could still 403, so assert the whole login-to-enrolment run.
    await page.waitForLoadState('networkidle');
    expect(visited, 'the SPA must not render any protected page on the way to enrolment').toEqual(
        expect.not.arrayContaining(['/dashboard'])
    );
    expect(
        visited.filter((p) => p !== '/login' && p !== '/profile'),
        'only the login and enrolment pages may be visited'
    ).toEqual([]);
    expect(refused, 'an MFA-pending login must not fire a single request the confinement refuses').toEqual([]);
    page.removeAllListeners('response');
    page.removeAllListeners('framenavigated');

    // 3. The server really is enforcing the policy for this session.
    const before = await apiProbe(page);
    expect(before, 'an un-enrolled session must be refused with MFAEnrollmentRequired under require_mfa').toEqual({
        status: 403,
        error: 'MFAEnrollmentRequired',
    });

    // 4. Enrol TOTP through the UI.
    await page.getByRole('button', { name: 'Enable', exact: true }).click();
    const secretLocator = page.getByTestId('mfa-setup-key');
    await expect(secretLocator).toBeVisible({ timeout: 10_000 });
    const secret = (await secretLocator.textContent())?.trim();
    expect(secret, 'enrolment must render a non-empty setup key').toBeTruthy();

    // A code computed in the last seconds of a 30s window can expire before the
    // server checks it. Wait out the boundary so the code is fresh when submitted.
    const intoWindow = (Date.now() / 1000) % 30;
    if (intoWindow > 25) {
        await page.waitForTimeout((30 - intoWindow + 1) * 1000);
    }
    await page.getByPlaceholder('123456').fill(totpCode(secret as string));
    await page.getByPlaceholder('Your current password').fill(ADMIN_PASSWORD as string);
    await page.getByRole('button', { name: 'Verify & enable' }).click();
    await expect(page.getByText('Save your recovery codes')).toBeVisible({ timeout: 10_000 });

    // 5. Finish the dialog; the Security tab reflects the enrolled state.
    await page.getByRole('button', { name: 'Done' }).click();
    await expect(page.getByText('Enabled', { exact: true }).first()).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Set up two-factor authentication to continue')).toHaveCount(0);

    // 6. The console unlocks: the API no longer refuses with MFAEnrollmentRequired, and
    //    the dashboard renders without bouncing back to enrolment.
    const after = await apiProbe(page);
    expect(after.error, 'after enrolment the session must no longer be confined to the enrolment endpoints').not.toBe(
        'MFAEnrollmentRequired'
    );

    await page.goto('/dashboard');
    await expect(page.getByText('Total Secrets')).toBeVisible({ timeout: 15_000 });
    expect(new URL(page.url()).pathname).toBe('/dashboard');
});
