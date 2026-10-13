// web/e2e/real/demo-permission-aware.spec.ts -- DEMO-UI-1 (DEMO-WALK-3 findings 6/36, 14, 24-27):
// what a least-privilege user is OFFERED and what a refusal SAYS, against a REAL keyorix-server.
//
// The persona is the one scripts/e2e/web-real-smoke.sh seeds: system_viewer globally plus
// project_viewer on web-e2e-project (the demo's "alice"). Before this change she saw Edit /
// Rotate / Share / Suspend / Delete / Transfer / New Secret / Members controls and an Audit nav
// entry, every one of which ended in a 403 and, for several, in axios's own "Request failed
// with status code 403". The admin runs the same screens as the positive control: without it
// "the button is absent" would also pass on a page that rendered nothing.
//
// Run via scripts/e2e/web-real-smoke.sh (it boots the backend, seeds, and exports the env vars
// read below), never directly.
import { test, expect, Page } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;
const LOWPRIV_USERNAME = process.env.KEYORIX_E2E_LOWPRIV_USERNAME;
const LOWPRIV_PASSWORD = process.env.KEYORIX_E2E_LOWPRIV_PASSWORD;
const PROJECT_NAME = process.env.KEYORIX_E2E_PROJECT_NAME;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !LOWPRIV_USERNAME || !LOWPRIV_PASSWORD || !PROJECT_NAME) {
    throw new Error(
        'KEYORIX_E2E_{ADMIN,LOWPRIV}_{USERNAME,PASSWORD} and KEYORIX_E2E_PROJECT_NAME are not all ' +
            'set -- run scripts/e2e/web-real-smoke.sh, which bootstraps the accounts, seeds the ' +
            'project and exports them.'
    );
}

async function login(page: Page, username: string, password: string) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(username);
    await page.getByTestId('password-input').fill(password);
    await page.getByTestId('login-button').click();
    await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
}

async function settle(page: Page) {
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    await page.waitForTimeout(500);
}

// The seeded project's id, from the API as the signed-in session.
async function projectId(page: Page): Promise<number> {
    const id = await page.evaluate(async (name) => {
        const res = await fetch('/api/v1/projects', { credentials: 'include' });
        if (!res.ok) return null;
        const body = await res.json();
        const hit = (body.data?.projects ?? []).find((p: { name?: string }) => p.name === name);
        return hit?.id ?? null;
    }, PROJECT_NAME as string);
    expect(id, `the signed-in user must see project ${PROJECT_NAME}`).not.toBeNull();
    return id as number;
}

const RAW_AXIOS = /Request failed with status code \d+/;

test.describe('least-privilege user (alice)', () => {
    test.beforeEach(async ({ page }) => {
        await login(page, LOWPRIV_USERNAME as string, LOWPRIV_PASSWORD as string);
    });

    test('the nav offers no Audit Logs, Billing or Access Control', async ({ page }) => {
        await page.goto('/dashboard');
        await settle(page);
        const nav = page.locator('nav').first();
        await expect(nav.getByRole('link', { name: 'Projects' })).toBeVisible();
        await expect(nav.getByRole('link', { name: 'Audit Logs' })).toHaveCount(0);
        await expect(nav.getByRole('link', { name: 'Billing' })).toHaveCount(0);
        await expect(nav.getByRole('button', { name: 'Access Control' })).toHaveCount(0);
    });

    test('dashboard tiles she cannot see say so instead of showing zeros', async ({ page }) => {
        await page.goto('/dashboard');
        await settle(page);
        const main = page.locator('main');
        for (const label of ['Active Users', 'Audit Events (30d)', 'Failed Auth (24h)']) {
            const card = main
                .getByText(label, { exact: true })
                .locator('xpath=ancestor::*[contains(@class,"rounded")][1]');
            await expect(card, label).toContainText('Not visible to you');
        }
        await expect(main).not.toContainText('No anomaly or expiry alerts');
        // The "Audit (30d)" side panel lists no zero counts for numbers she cannot see (#3155).
        await expect(page.getByTestId('audit-panel-not-visible')).toContainText('Not visible to you');
        await expect(main.getByText('Total events', { exact: true })).toHaveCount(0);
        // The tile she can read keeps its real number.
        await expect(page.getByTestId('stat-card-total-secrets-value')).toHaveText('5');
    });

    test('the secrets list opens on the environment that has secrets and offers no write actions', async ({ page }) => {
        const pid = await projectId(page);
        // No ?env= on purpose: the default must be an environment with secrets, not an empty production.
        await page.goto(`/projects/${pid}/secrets`);
        await settle(page);
        const main = page.locator('main');
        await expect(main, 'landed on an empty environment').not.toContainText(/No secrets in /);
        await expect(main.getByText('e2e-api-key').or(main.getByText('e2e-plain-text'))).toBeVisible();

        await expect(page.getByRole('button', { name: /new secret/i })).toHaveCount(0);
        const row = page.getByRole('row').filter({ hasText: /e2e-/ }).first();
        await expect(row.getByTitle('View')).toBeVisible();
        for (const title of ['Edit', 'Rotate', 'Share', 'Delete']) {
            await expect(row.getByTitle(title), title).toHaveCount(0);
        }
    });

    test('the global secrets page offers no New Secret', async ({ page }) => {
        await page.goto('/secrets');
        await settle(page);
        await expect(page.locator('main').getByRole('heading', { name: 'Secrets' })).toBeVisible();
        await expect(page.getByTestId('create-secret-button')).toHaveCount(0);
    });

    test('an open secret has no Edit / Rotate / Share / Suspend / Delete / Transfer', async ({ page }) => {
        const pid = await projectId(page);
        await page.goto(`/projects/${pid}/secrets`);
        await settle(page);
        await page.getByRole('row').filter({ hasText: /e2e-/ }).first().getByTitle('View').click();
        const actions = page.getByTestId('secret-actions');
        // The detail view itself is up (header rendered); the action bar is attached but empty.
        await expect(page.getByTestId('secret-header')).toBeVisible();
        await expect(actions).toBeAttached();
        for (const name of [/^edit$/i, /^rotate$/i, /^share$/i, /^suspend$/i, /^resume$/i, /^delete$/i, /^copy$/i]) {
            await expect(actions.getByRole('button', { name }), String(name)).toHaveCount(0);
        }
        await expect(page.getByText('Transfer ownership')).toHaveCount(0);
    });

    // #3142. The dependency graph is readable (secrets.read) but declaring/removing an edge is
    // secrets.write, so the Add form and Remove buttons are not offered. The graph itself stays.
    test('an open secret shows the dependency graph without the Add form or Remove buttons', async ({ page }) => {
        const pid = await projectId(page);
        await page.goto(`/projects/${pid}/secrets`);
        await settle(page);
        await page.getByRole('row').filter({ hasText: /e2e-/ }).first().getByTitle('View').click();
        await expect(page.getByTestId('secret-header')).toBeVisible();
        await expect(page.getByRole('heading', { name: 'Dependencies', exact: true })).toBeVisible();
        await expect(page.getByTestId('add-dependency-form')).toHaveCount(0);
        await expect(page.getByText('Add a dependency')).toHaveCount(0);
        await expect(page.getByRole('button', { name: /^Remove$/ })).toHaveCount(0);
    });

    // #3142. Check Drift / Rotation Plan are GET /projects/{id}/drift and /rotation-plan, gated on
    // secrets.read in the project (server/http/router.go), which project_viewer holds: the server
    // answers 200, so the buttons stay offered and must not end in a refusal.
    test('Check Drift and Rotation Plan stay offered and the server answers them', async ({ page }) => {
        const pid = await projectId(page);
        const statuses: Record<string, number> = {};
        page.on('response', (r) => {
            const p = new URL(r.url()).pathname;
            if (p === `/api/v1/projects/${pid}/drift` || p === `/api/v1/projects/${pid}/rotation-plan`) {
                statuses[p] = r.status();
            }
        });
        await page.goto(`/projects/${pid}/secrets`);
        await settle(page);
        const main = page.locator('main');
        await main.getByRole('button', { name: 'Check Drift' }).click();
        await expect.poll(() => statuses[`/api/v1/projects/${pid}/drift`]).toBe(200);
        await page.keyboard.press('Escape');
        await main.getByRole('button', { name: 'Rotation Plan' }).click();
        await expect.poll(() => statuses[`/api/v1/projects/${pid}/rotation-plan`]).toBe(200);
    });

    test('the Members tab lists members without Add / Invite / role / remove controls', async ({ page }) => {
        const pid = await projectId(page);
        const failed: string[] = [];
        page.on('response', (r) => {
            if (r.status() === 403) failed.push(new URL(r.url()).pathname);
        });
        await page.goto(`/projects/${pid}/members`);
        await settle(page);
        const main = page.locator('main');
        await expect(main.getByRole('heading', { name: 'Human members' })).toBeVisible();
        await expect(main.getByRole('button', { name: /invite by email/i })).toHaveCount(0);
        await expect(main.getByRole('button', { name: /^Add$/ })).toHaveCount(0);
        // The one removal she keeps is leaving the project herself (the row confirms "Remove yourself").
        const removes = main.getByTitle('Remove from project');
        expect(await removes.count()).toBeLessThanOrEqual(1);
        if ((await removes.count()) === 1) {
            await expect(main.locator('li').filter({ has: page.getByTitle('Remove from project') })).toContainText(
                LOWPRIV_USERNAME as string
            );
        }
        await expect(main.locator('select')).toHaveCount(0);
        // The admin-only lookups are not even requested, so they cannot 403 into the console.
        expect(
            failed.filter((p) => p === '/api/v1/users'),
            '403s from the user directory'
        ).toEqual([]);
    });

    test('opening Audit by URL shows the server reason, never axios text', async ({ page }) => {
        await page.goto('/audit');
        await settle(page);
        const main = page.locator('main');
        await expect(main).toContainText(/Failed to load audit log|do not have permission|not permitted|forbidden/i);
        const text = await main.innerText();
        expect(text).not.toMatch(RAW_AXIOS);
    });
});

test.describe('admin keeps every control (positive control)', () => {
    test.beforeEach(async ({ page }) => {
        await login(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    });

    test('nav, New Secret and row actions are present', async ({ page }) => {
        await page.goto('/secrets');
        await settle(page);
        await expect(page.locator('nav').first().getByRole('link', { name: 'Audit Logs' })).toBeVisible();
        await expect(page.getByTestId('create-secret-button').first()).toBeVisible();
        const row = page.getByRole('row').filter({ hasText: /e2e-/ }).first();
        for (const title of ['View', 'Edit', 'Rotate', 'Share', 'Delete']) {
            await expect(row.getByTitle(title), title).toBeVisible();
        }
    });

    test('an open secret offers the dependency Add form (positive control, #3142)', async ({ page }) => {
        await page.goto('/secrets');
        await settle(page);
        await page.getByRole('row').filter({ hasText: /e2e-/ }).first().getByTitle('View').click();
        await expect(page.getByTestId('add-dependency-form')).toBeVisible();
    });

    test('Billing is not offered on a community build and nothing 403s while the shell loads', async ({ page }) => {
        const refused: string[] = [];
        page.on('response', (r) => {
            if (r.status() === 403) refused.push(new URL(r.url()).pathname);
        });
        await page.goto('/dashboard');
        await settle(page);
        await expect(page.locator('nav').first().getByRole('link', { name: 'Billing' })).toHaveCount(0);
        expect(refused, 'the app shell requested something this user is refused').toEqual([]);
    });
});
