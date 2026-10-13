// web/e2e/real/mobile-layout.spec.ts -- #3154: at a phone viewport (390 x 844) no
// main demo page may scroll sideways. DEMO-WALK-4 measured document.scrollWidth
// above clientWidth on the project pages (441), /profile (423), /admin and
// /admin/users (394) and /secrets/expiry (392): the project and profile tab strips
// did not wrap or scroll, so they pushed the whole page wider than the screen.
//
// Drives the REAL UI against a REAL backend (scripts/e2e/web-real-smoke.sh, or the
// demo via KEYORIX_E2E_ADMIN_TOTP_SECRET like pages.spec.ts). ONE login for the whole
// file: every login spends a slot of the per-IP login budget (10 per 15 min, #2956).
//
// The assertion is the page-level one a user feels: the document itself must not
// scroll horizontally. A wide table or tab strip that scrolls INSIDE its own
// overflow-x container is fine (that is how a phone shows a wide table), so the
// failure message lists only the elements that stick out of the viewport with no
// clipping ancestor, which is what points at the culprit.
//
// With KEYORIX_E2E_SHOT_DIR set the spec also writes a screenshot per route.
import { test, expect, Page } from '@playwright/test';
import { waitForFreshTotpCode } from './helpers';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;
const ADMIN_TOTP_SECRET = process.env.KEYORIX_E2E_ADMIN_TOTP_SECRET;
let lastTotpStep = Number(process.env.KEYORIX_E2E_ADMIN_TOTP_LAST_STEP || 0) || 0;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

const PHONE = { width: 390, height: 844 };

interface Overflow {
    scrollWidth: number;
    clientWidth: number;
    offenders: string[];
}

// measure reports the document's horizontal overflow and, when there is any, the
// elements that extend past the right edge of the viewport without a clipping
// (overflow-x != visible) ancestor that keeps them inside it.
async function measure(page: Page): Promise<Overflow> {
    return page.evaluate(() => {
        const doc = document.documentElement;
        const vw = doc.clientWidth;
        const offenders: string[] = [];
        const clipped = (el: Element): boolean => {
            for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
                const ox = getComputedStyle(p).overflowX;
                if (ox !== 'visible' && p.getBoundingClientRect().right <= vw + 1) return true;
            }
            return false;
        };
        if (doc.scrollWidth > vw) {
            for (const el of Array.from(document.body.querySelectorAll('*'))) {
                const r = el.getBoundingClientRect();
                if (r.width === 0 || r.right <= vw + 1 || clipped(el)) continue;
                const cls = (el.getAttribute('class') || '').split(/\s+/).slice(0, 4).join('.');
                const text = (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 30);
                offenders.push(
                    `<${el.tagName.toLowerCase()}${cls ? '.' + cls : ''}> right=${Math.round(r.right)} "${text}"`
                );
                if (offenders.length >= 6) break;
            }
        }
        return { scrollWidth: doc.scrollWidth, clientWidth: vw, offenders };
    });
}

async function shot(page: Page, name: string) {
    const dir = process.env.KEYORIX_E2E_SHOT_DIR;
    if (dir) await page.screenshot({ path: `${dir}/${name}.png`, fullPage: false });
}

async function login(page: Page) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    if (ADMIN_TOTP_SECRET) {
        const codeInput = page.getByPlaceholder('123456');
        await expect(codeInput).toBeVisible({ timeout: 10_000 });
        const next = await waitForFreshTotpCode(page, ADMIN_TOTP_SECRET, lastTotpStep);
        lastTotpStep = next.step;
        await codeInput.fill(next.code);
        await page.getByRole('button', { name: /verify/i }).click();
    }
    await page.waitForURL('/dashboard', { timeout: 15_000 });
}

test('no main page scrolls sideways at 390 px', async ({ browser }, testInfo) => {
    if (ADMIN_TOTP_SECRET) test.setTimeout(180_000);
    const context = await browser.newContext({ baseURL: testInfo.project.use.baseURL, viewport: PHONE });
    const page = await context.newPage();
    try {
        await login(page);

        // The project routes need a real project id: open the first project in the
        // Projects list (its rows are div[role=button], not links) and read the id
        // from the URL it navigates to (the demo seed's backend-api is 2; the smoke
        // backend has the one web-real-smoke.sh created).
        await page.goto('/projects');
        await page.locator('main div[role="button"]').first().click({ timeout: 15_000 });
        await page.waitForURL(/\/projects\/\d+/, { timeout: 15_000 });
        const projectId = new URL(page.url()).pathname.match(/^\/projects\/(\d+)/)?.[1];
        expect(projectId, `could not read a project id from ${page.url()}`).toBeTruthy();

        // The routes DEMO-WALK-4 measured, plus the ones it found fitting (a
        // regression guard: they must stay that way).
        const routes: Array<[string, string]> = [
            ['dashboard', '/dashboard'],
            ['secrets', '/secrets'],
            ['projects', '/projects'],
            ['project secrets', `/projects/${projectId}/secrets`],
            ['project members', `/projects/${projectId}/members`],
            ['project activity', `/projects/${projectId}/activity`],
            ['project access review', `/projects/${projectId}/access-review`],
            ['project settings', `/projects/${projectId}/settings`],
            ['profile', '/profile'],
            ['admin', '/admin'],
            ['admin users', '/admin/users'],
            ['secret expiry', '/secrets/expiry'],
            ['audit', '/audit'],
            ['sharing', '/sharing'],
            ['compliance', '/compliance'],
        ];

        const failures: string[] = [];
        for (const [name, path] of routes) {
            await page.goto(path);
            await page.waitForLoadState('networkidle', { timeout: 15_000 });
            if (page.url().includes('/login')) {
                failures.push(`${name} (${path}): bounced back to /login`);
                continue;
            }
            const m = await measure(page);
            await shot(page, name.replace(/\s+/g, '-'));
            if (m.scrollWidth > m.clientWidth) {
                failures.push(
                    `${name} (${path}): scrollWidth ${m.scrollWidth} > clientWidth ${m.clientWidth}` +
                        (m.offenders.length ? `\n      ${m.offenders.join('\n      ')}` : '')
                );
            }
        }
        expect(failures, `pages that scroll sideways at ${PHONE.width}px:\n  ${failures.join('\n  ')}`).toEqual([]);
    } finally {
        await context.close();
    }
});
