// web/e2e/real/demo-text-polish.spec.ts -- DEMO-UI-1 (from DEMO-WALK-3 findings 3, 4, 8-13, 15, 31):
// what the presenter's screens SAY, against a REAL keyorix-server.
//
// The walks kept finding screens that work but read like a developer console: raw
// audit event names ("mfa.login_verified"), Go duration strings ("24h0m0s"), build
// info of "dev / none / unknown", times with no timezone, a "⌘K" hint on Linux.
// This spec pins the user-visible text on the screens that show those things.
//
// Run via scripts/e2e/web-real-smoke.sh (it boots the backend and exports the env
// vars read below), never directly.
import { test, expect, Page } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

// A server audit event type as the API spells it: "<family>.<snake_case>".
const RAW_EVENT_NAME =
    /\b(auth|mfa|secret|share|machine_identity|project|user|role|group|permission|invitation|session|admin|sso|break_glass)\.[a-z]+(_[a-z]+)*\b/;
// A Go time.Duration rendering ("24h0m0s", "15m0s").
const GO_DURATION = /\b\d+(h\d+m\d+s|m\d+s)\b/;

async function login(page: Page) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
}

async function mainText(page: Page, route: string): Promise<string> {
    await page.goto(route, { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    await page.waitForTimeout(500);
    const text = (
        (await page
            .locator('main')
            .innerText()
            .catch(() => '')) || ''
    )
        // Config keys inside audit descriptions ("sso.providers.auto_provision") are not event names.
        .replace(/\bsso\.providers[\w.]*/g, '')
        .replace(/\s+/g, ' ');
    expect(text.length, `${route}: <main> rendered nothing, so the scans below would be vacuous`).toBeGreaterThan(25);
    return text;
}

test.describe('presenter-facing text (admin)', () => {
    test.beforeEach(async ({ page }) => {
        await login(page);
    });

    test('dashboard feed and audit page show friendly event labels, never raw event names', async ({ page }) => {
        // The login above is itself an audit event, so both screens have rows to scan.
        for (const route of ['/dashboard', '/audit']) {
            const text = await mainText(page, route);
            expect(text.match(RAW_EVENT_NAME)?.[0] ?? null, `${route} shows a raw audit event name`).toBeNull();
        }
        // The audit table's Login row is the friendly label, and its time carries a timezone.
        await page.goto('/audit', { waitUntil: 'domcontentloaded' });
        const row = page.getByRole('row').filter({ hasText: 'Login' }).first();
        await expect(row).toBeVisible({ timeout: 20_000 });
        await expect(row).toContainText(/\d{4}, \d{1,2}:\d{2}:\d{2}\s?[AP]M\s+\S+/);
    });

    test('project activity shows friendly labels', async ({ page }) => {
        const text = await mainText(page, '/projects/2/activity');
        expect(text.match(RAW_EVENT_NAME)?.[0] ?? null, 'raw audit event name on project activity').toBeNull();
    });

    test('Authentication settings show durations in words, not Go strings', async ({ page }) => {
        const text = await mainText(page, '/settings/auth');
        expect(text).not.toMatch(GO_DURATION);
        expect(text).toMatch(/\b\d+ (hour|minute|day)s?\b/);
    });

    test('System Health and the footer never print unstamped build values or a made-up version', async ({ page }) => {
        const health = await mainText(page, '/settings/health');
        expect(health).not.toMatch(/Git commit\s*(none|unknown)/i);
        expect(health).not.toMatch(/Build time\s*unknown/i);
        expect(health).not.toMatch(/Max connections\s*0\b/);
        const footer = (await page.locator('aside, nav').allInnerTexts()).join(' ');
        expect(footer, 'the sidebar footer must not claim a hardcoded version').not.toContain('v0.1.0');
    });

    test('Encryption settings name the key provider', async ({ page }) => {
        const text = await mainText(page, '/settings/encryption');
        expect(text).toMatch(/key provider/i);
        // The "Type" row is never an empty dash.
        expect(text).not.toMatch(/Type\s+—/);
    });

    test('the keyboard hint matches the platform and Ctrl+K really opens the palette', async ({ page }) => {
        await page.goto('/dashboard', { waitUntil: 'domcontentloaded' });
        const isMac = await page.evaluate(() => /Mac|iPhone|iPad/i.test(navigator.platform + navigator.userAgent));
        await expect(page.locator('kbd').first()).toHaveText(isMac ? '⌘K' : 'Ctrl+K');
        await page.keyboard.press(isMac ? 'Meta+k' : 'Control+k');
        await expect(page.getByPlaceholder('Search projects and secrets…')).toBeVisible({ timeout: 5_000 });
    });
});
