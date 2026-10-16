// web/e2e/real/ui-dialog-viewport.spec.ts -- WEB-SWEEP-1: every dialog must be
// OPERABLE at a real laptop viewport, not merely present in the DOM.
//
// The failure this exists for (#2775): the shared Modal
// (web/src/components/ui/Modal.tsx) centres its panel with
// `-translate-y-1/2` and clips it with `overflow-hidden`, and had no height
// bound. A panel taller than the window therefore overflowed SYMMETRICALLY --
// half above, half below -- losing its header and its footer at the same time,
// with no scroll container to bring either back. Create User is 869px tall, so
// at 1280x720 and at 1440x800 its own submit button sat outside the viewport
// and the dialog could not be completed at all.
//
// Two complementary checks, because each misses what the other catches:
//
//   1. GEOMETRY, over every dialog in the inventory: the panel's box must lie
//      within the viewport. This is the family-wide guard -- it fails for any
//      dialog that grows past the window, including ones that do not exist yet,
//      which is the actual risk (Create User only became too tall as fields
//      were added to it).
//   2. The JOURNEY, on the one dialog that was broken: fill Create User in,
//      submit it, and see a real user land in the table. Geometry alone would
//      pass on a dialog that fits but whose submit is covered or disabled; only
//      driving it proves it is usable.
//
// Viewports are set explicitly rather than inherited: the whole point is a
// specific window height, so reading it from the Playwright device profile
// would make the assertion silently depend on a config file elsewhere.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page } from '@playwright/test';
import { randomInt } from 'node:crypto';
import { DIALOGS, type DialogCase } from './dialog-inventory';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and exports them.'
    );
}

// Two ordinary laptop sizes. 1280x720 is Playwright's Desktop Chrome default
// and the shorter real-world case; 1440x800 is a 14" MacBook-class window and
// is here because the bug survived at that height too -- a fix validated only
// against the smaller one could plausibly have been a 720-specific tweak.
const VIEWPORTS = [
    { width: 1280, height: 720 },
    { width: 1440, height: 800 },
];

// One login for the file (serial, one shared page): the per-IP login budget is
// 10 attempts per 15 minutes, spent on every attempt whether it succeeds or
// not, so a login per test would report an exhausted rate limit as broken
// dialogs. See scripts/e2e/web-real-smoke.sh's header.
test.describe.configure({ mode: 'serial' });

let shared: Page;

test.beforeAll(async ({ browser }) => {
    shared = await browser.newPage();
    await shared.goto('/login');
    await shared.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await shared.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await shared.getByTestId('login-button').click();
    await shared.waitForURL(/\/dashboard/, { timeout: 20_000 });
});

test.afterAll(async () => {
    await shared?.close();
});

async function openDialog(page: Page, c: DialogCase) {
    await page.goto(c.page, { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    const opener = page.getByRole('button', { name: c.opener, exact: true }).first();
    await expect(opener, `${c.page}: the "${c.opener}" control must exist`).toBeVisible({ timeout: 10_000 });
    await opener.click();
    const dialog = page.locator('[role="dialog"]').first();
    await expect(dialog, `${c.page}: "${c.opener}" must open a dialog`).toBeVisible({ timeout: 10_000 });
    await expect(dialog).toContainText(c.title);
    return dialog;
}

test('every dialog fits inside an ordinary laptop viewport', async () => {
    test.setTimeout(180_000);
    const tooTall: string[] = [];

    for (const vp of VIEWPORTS) {
        await shared.setViewportSize(vp);
        for (const c of DIALOGS) {
            await openDialog(shared, c);
            const box = await shared.evaluate(() => {
                const el = document.querySelector('[role="dialog"]') as HTMLElement | null;
                if (!el) return null;
                const r = el.getBoundingClientRect();
                return { top: Math.round(r.top), bottom: Math.round(r.bottom), vh: window.innerHeight };
            });
            if (!box) {
                tooTall.push(`${vp.width}x${vp.height} ${c.page} "${c.opener}": dialog vanished before measuring`);
                continue;
            }
            // A 1px tolerance for subpixel rounding on the centring transform.
            if (box.top < -1 || box.bottom > box.vh + 1) {
                tooTall.push(
                    `${vp.width}x${vp.height} ${c.page} "${c.opener}": panel spans ${box.top}..${box.bottom} ` +
                        `in a ${box.vh}px window -- clipped, with no way to scroll to the clipped part`
                );
            }
            await shared.keyboard.press('Escape');
        }
    }

    expect(tooTall, 'one entry per dialog that does not fit its viewport').toEqual([]);
});

test('the tallest dialog (Create User) can actually be filled in and submitted at 1280x720', async () => {
    test.setTimeout(120_000);
    await shared.setViewportSize({ width: 1280, height: 720 });

    // Unique per run so a repeat run against a persistent DB does not collide.
    const stamp = randomInt(1_000_000);
    const username = `viewportuser${stamp}`;
    // Deliberately shares no 3+-character word with the username, email or
    // display name -- internal/core/rules' password policy rejects a password
    // containing any of them -- and carries a digit in a LITERAL segment rather
    // than relying on a random slice to happen to contain one (the trap that
    // makes mfa-login.spec.ts's fixture flaky, #2782).
    const password = 'Quartz-Falcon-77-Ridge!-Tundra9';

    await openDialog(shared, { page: '/admin/users', opener: 'New User', title: 'Create User' });

    await shared.locator('#create-username').fill(username);
    await shared.locator('#create-display-name').fill(`Viewport User ${stamp}`);
    await shared.locator('#create-email').fill(`${username}@example.invalid`);
    await shared.locator('#create-password').fill(password);

    // The load-bearing step. A user scrolls the dialog to reach its footer;
    // before the fix there was nothing to scroll, and Playwright's own
    // scroll-into-view retried to its timeout and never made the button
    // reachable (which is how #2775 was found).
    const submit = shared.locator('[role="dialog"]').getByRole('button', { name: 'Create User', exact: true });
    await submit.scrollIntoViewIfNeeded();
    await expect(submit, 'the submit button must be reachable without resizing the window').toBeInViewport();

    await submit.click();

    // The password create path closes the dialog on success (there is no
    // out-of-band artifact to relay), so its disappearance plus the new row is
    // the completion signal.
    await expect(shared.locator('[role="dialog"]')).toBeHidden({ timeout: 15_000 });
    // Scoped to the "@username" caption: a bare text match also hits the email
    // cell, which contains the username as a prefix.
    await expect(shared.getByText(`@${username}`)).toBeVisible({ timeout: 15_000 });
});
