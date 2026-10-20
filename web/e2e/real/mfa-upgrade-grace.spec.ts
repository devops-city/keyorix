// e2e-server: require_mfa=upgrade-grace
//
// web/e2e/real/mfa-upgrade-grace.spec.ts -- #2923: ADR-112's security.require_mfa upgrade
// grace period, driven through the real UI against a real server.
//
// The first line is the web-real-smoke.sh directive: this group boots and seeds with
// require_mfa: false (no enforcement marker), then restarts the server with the key
// REMOVED, i.e. an upgraded deployment that never set it. The restarted server records
// the grace start and does not enforce MFA yet (the harness checks its start-up warning).
//
// THE USER JOURNEY:
//   1. The admin (no MFA) signs in and lands on the dashboard: not confined. Every page
//      shows the persistent grace banner with the days left and an "Enrol now" link, and
//      a same-origin API probe is not refused with MFAEnrollmentRequired.
//   2. The admin follows "Enrol now" and enrols TOTP on the Security tab. That is the first
//      administrator MFA enrolment: the grace period ends on the running server, no restart.
//   3. The viewer (seeded, no MFA) signs in in a fresh browser: no banner any more, and the
//      SPA sends them straight to MFA enrolment (/profile?tab=security&mfa=required). They
//      are not locked out: the enrolment page renders and the API refuses only with
//      MFAEnrollmentRequired.
//
// LOGIN BUDGET (10 per 15 minutes per IP): the harness's token login and seeding, the
// admin UI login and the viewer UI login.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME, realLogin, submitLogin, totpCode } from './helpers';

const LOWPRIV_USERNAME = process.env.KEYORIX_E2E_LOWPRIV_USERNAME as string;
const LOWPRIV_PASSWORD = process.env.KEYORIX_E2E_LOWPRIV_PASSWORD as string;

async function apiProbe(page: Page): Promise<{ status: number; error: string | null }> {
    return page.evaluate(async () => {
        const res = await fetch('/api/v1/secrets', { credentials: 'include' });
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        return { status: res.status, error: body?.error ?? null };
    });
}

test('upgrade grace: banner with days left, first admin enrolment ends it, then users are sent to enrolment', async ({
    page,
    browser,
}) => {
    // 1. During the grace period the admin is not confined and sees the banner.
    await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const banner = page.getByTestId('mfa-grace-banner');
    await expect(banner).toBeVisible({ timeout: 15_000 });
    await expect(banner).toContainText(/Multi-factor authentication will be required in (30|29) days/);
    await expect(page.getByText('Total Secrets')).toBeVisible({ timeout: 15_000 });
    expect((await apiProbe(page)).error, 'no MFA confinement during the grace period').not.toBe(
        'MFAEnrollmentRequired'
    );
    // Persistent: still there on another page.
    await page.goto('/secrets');
    await expect(banner).toBeVisible({ timeout: 15_000 });

    // 2. The admin enrols through the banner's link.
    await banner.getByRole('link', { name: 'Enrol now' }).click();
    await page.waitForURL(/\/profile\?tab=security/, { timeout: 15_000 });
    await page.getByRole('button', { name: 'Enable', exact: true }).click();
    const secretLocator = page.getByTestId('mfa-setup-key');
    await expect(secretLocator).toBeVisible({ timeout: 10_000 });
    const secret = (await secretLocator.textContent())?.trim();
    expect(secret, 'enrolment must render a non-empty setup key').toBeTruthy();
    const intoWindow = (Date.now() / 1000) % 30;
    if (intoWindow > 25) {
        await page.waitForTimeout((30 - intoWindow + 1) * 1000);
    }
    await page.getByPlaceholder('123456').fill(totpCode(secret as string));
    await page.getByPlaceholder('Your current password').fill(ADMIN_PASSWORD as string);
    await page.getByRole('button', { name: 'Verify & enable' }).click();
    await expect(page.getByText('Save your recovery codes')).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Done' }).click();
    await expect(page.getByText('Enabled', { exact: true }).first()).toBeVisible({ timeout: 10_000 });
    await page.reload();
    await expect(page.getByTestId('mfa-grace-banner')).toHaveCount(0);

    // 3. The grace period is over: the viewer is sent to enrolment, not locked out.
    const viewerContext = await browser.newContext();
    try {
        const viewer = await viewerContext.newPage();
        await viewer.goto('/login');
        await submitLogin(viewer, LOWPRIV_USERNAME, LOWPRIV_PASSWORD);
        await viewer.waitForURL(/\/profile\?tab=security&mfa=required/, { timeout: 20_000 });
        await expect(viewer.getByText('Set up two-factor authentication to continue')).toBeVisible({
            timeout: 10_000,
        });
        await expect(viewer.getByTestId('mfa-grace-banner')).toHaveCount(0);
        await expect(viewer.getByRole('button', { name: 'Enable', exact: true })).toBeVisible();
        expect(await apiProbe(viewer), 'after the grace period the API confines to enrolment').toEqual({
            status: 403,
            error: 'MFAEnrollmentRequired',
        });
    } finally {
        await viewerContext.close();
    }
});
