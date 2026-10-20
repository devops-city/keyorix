// e2e-server: require_mfa=true
//
// web/e2e/demo/01-login-mfa-enrolment.spec.ts -- DEMO-E2E-1 journey 1 of 8: "sign in, enrol a second
// factor, sign in again with it" on a deployment that REQUIRES MFA (security.require_mfa: true, the
// demo's own setting), driven through the real UI against a real server.
//
// The first line of this file is read by scripts/e2e/web-real-smoke.sh: the group that runs this file
// boots with require_mfa on. One spec per group, so the policy never leaks into another file.
//
// WHAT IT GUARDS (docs/demo.md "login + MFA" step; the demo breaks if any of these does):
//   1. a fresh admin's first login lands on enrolment, not on a protected page;
//   2. TOTP enrolment through Profile -> Security completes and shows the recovery codes;
//   3. signing out ends the session and the next login asks for the second factor;
//   4. a WRONG second factor is refused and leaves the user on the login page;
//   5. the right one reaches the dashboard;
//   6. DASH-FAILED-SPLIT-1: the dashboard's own "Failed Second Factors (24h)" card counts that wrong
//      second factor (it is not folded into "Failed Logins (24h)", which counts wrong passwords only).
//
// NO TIMING SLEEPS. The TOTP anti-replay rule (one accepted step per account, strictly increasing)
// is the reason real/helpers.ts's waitForFreshTotpCode waits up to 30 s for the next step.
// totpInSteps (./support) gets the same ordering from arithmetic: enrol with the current step's code,
// log in with the NEXT step's code, which the server's +-1 step window accepts immediately.
//
// A wrong code BURNS the login challenge (ConsumeMFAChallenge is single-use and runs before the code
// is looked at), so after the refusal the journey goes back to the password step, exactly as a user
// has to.
//
// LOGIN BUDGET (10 per 15 minutes per server, web-real-smoke.sh): the harness's own token login (1),
// the enrolment login (2), the login that ends in the wrong code (3), the final login (4) = 4 of 10.
// This group seeds nothing (the policy would 403 the seeding calls), so no API login is needed.
import { test, expect } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME, submitLogin, totpCode } from '../real/helpers';
import { totpInSteps } from './support';

// wrongCode returns a well-formed 6-digit code that the server will refuse: the code of a step far
// outside its +-1 window, checked against the three codes it would accept so the 1-in-a-million
// collision cannot make this test flaky.
function wrongCode(secret: string): string {
    const accepted = new Set([0, -1, 1].map((s) => totpInSteps(secret, s)));
    for (let steps = 5; ; steps++) {
        const candidate = totpCode(secret, Date.now() / 1000 + steps * 30);
        if (!accepted.has(candidate)) return candidate;
    }
}

test('login, forced MFA enrolment, sign out, wrong then right second factor, and the dashboard counts the wrong one', async ({
    page,
}) => {
    test.setTimeout(120_000);

    // 1. First login: password is right, MFA is required and absent -> straight to enrolment.
    await page.goto('/login');
    await submitLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    await page.waitForURL(/\/profile\?tab=security&mfa=required/, { timeout: 20_000 });
    await expect(page.getByText('Set up two-factor authentication to continue')).toBeVisible();

    // 2. Enrol TOTP: read the setup key off the page, answer with the current step's code and the
    //    account password.
    await page.getByRole('button', { name: 'Enable', exact: true }).click();
    const setupKey = page.getByTestId('mfa-setup-key');
    await expect(setupKey).toBeVisible({ timeout: 10_000 });
    const secret = ((await setupKey.textContent()) ?? '').trim();
    expect(secret, 'enrolment must render a non-empty setup key').toBeTruthy();

    await page.getByPlaceholder('123456').fill(totpInSteps(secret, 0));
    await page.getByPlaceholder('Your current password').fill(ADMIN_PASSWORD as string);
    await page.getByRole('button', { name: 'Verify & enable' }).click();
    await expect(page.getByText('Save your recovery codes')).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Done' }).click();
    await expect(page.getByText('Enabled', { exact: true }).first()).toBeVisible({ timeout: 10_000 });

    // 3. Sign out. The old session must be gone: the next login starts from the password again.
    await page.getByTestId('user-menu-button').click();
    await page.getByText('Sign out').click();
    await page.waitForURL('**/login', { timeout: 15_000 });

    // 4. Password right, second factor WRONG: refused, still on the login page, no session.
    await submitLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    await expect(page.getByTestId('mfa-code-input')).toBeVisible({ timeout: 10_000 });
    await page.getByTestId('mfa-code-input').fill(wrongCode(secret));
    const refused = page.waitForResponse(
        (r) => new URL(r.url()).pathname === '/auth/mfa/verify' && r.request().method() === 'POST'
    );
    await page.getByTestId('mfa-verify-button').click();
    expect((await refused).status(), 'the server must refuse a wrong second factor').toBe(401);
    expect(new URL(page.url()).pathname, 'a wrong second factor must not leave the login page').toBe('/login');
    await expect(page.getByTestId('mfa-code-input')).toBeVisible();

    // 5. Back to the password step (the wrong code spent the challenge), then the RIGHT code: the
    //    NEXT step's, which is newer than the one enrolment used and valid at once.
    await page.getByRole('button', { name: 'Back to login' }).click();
    await submitLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    await expect(page.getByTestId('mfa-code-input')).toBeVisible({ timeout: 10_000 });
    await page.getByTestId('mfa-code-input').fill(totpInSteps(secret, 1));
    await page.getByTestId('mfa-verify-button').click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });

    // 6. DASH-FAILED-SPLIT-1. The dashboard loads its stats once per visit and the audit write is not
    //    guaranteed to be visible to the very first read, so look again until the card shows it.
    await expect(async () => {
        await page.goto('/dashboard');
        const card = page.getByRole('button', { name: /Failed Second Factors \(24h\)/ });
        await expect(card).toContainText(/[1-9]\d*\s*wrong code or passkey/, { timeout: 5_000 });
    }).toPass({ timeout: 60_000 });

    // The same refusal is in the audit log under its own name.
    await expect(async () => {
        await page.goto('/audit');
        await page.getByPlaceholder('Filter by actor…').fill(ADMIN_USERNAME as string);
        await expect(page.getByRole('row').filter({ hasText: 'MFA failed' }).first()).toBeVisible({ timeout: 5_000 });
    }).toPass({ timeout: 60_000 });
});
