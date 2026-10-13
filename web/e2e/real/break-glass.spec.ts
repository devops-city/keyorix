// e2e-server: break_glass=true
// web/e2e/real/break-glass.spec.ts — the project's Break-glass tab against a REAL keyorix-server (#3148).
//
// The first line above is read by scripts/e2e/web-real-smoke.sh: break-glass is OFF by default
// (secure default), so the group that runs this spec boots with `break_glass.enabled: true`.
//
//   1. alice (project_viewer member) requests emergency access with a justification and a TTL,
//      and sees her own activation as Active with a live countdown.
//   2. the global admin (roles.read / roles.assign) opens the same tab: the all-activations
//      view lists alice's request with who, justification and status.
//   3. the admin revokes it through the confirm dialog (no browser alert/confirm): the row
//      turns Revoked and loses its Revoke action.
//   4. alice reloads: her activation reads Revoked, no countdown, no Revoke control.
//   5. an outsider (not a member) sees only the project-level "Failed to load project."
//      refusal (the project itself is a 403 for them, so the tab never mounts) and
//      alice's justification never reaches that browser.
//
// Login budget (see web-real-smoke.sh): 1 API login (admin) + 3 UI logins (alice, admin,
// outsider) + 1 seeding login = 5 of 10.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Browser, BrowserContext, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';
import { compliantPassword, personalInfoCandidates } from './support/password';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

interface Persona {
    username: string;
    password: string;
    id: number;
    displayName: string;
}

const stamp = Date.now();
const projectName = `e2e-breakglass-${stamp}`;
const justification = `prod database down, paging oncall ${stamp}`;

let projectId: number;
let alice: Persona;
let outsider: Persona;
let adminToken: string;
let alicePage: Page;
let adminPage: Page;
let outsiderPage: Page;
const contexts: BrowserContext[] = [];

async function bearer(
    token: string,
    method: 'GET' | 'POST',
    path: string,
    data?: unknown
): Promise<{ status: number; body: any }> {
    const ctx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const res = await ctx.fetch(path, {
            method,
            headers: { Authorization: `Bearer ${token}` },
            ...(data === undefined ? {} : { data }),
        });
        let body: any = null;
        try {
            body = await res.json();
        } catch {
            body = null;
        }
        return { status: res.status(), body };
    } finally {
        await ctx.dispose();
    }
}

async function mustBearer(token: string, method: 'GET' | 'POST', path: string, data?: unknown) {
    const res = await bearer(token, method, path, data);
    if (res.status >= 300) throw new Error(`setup ${method} ${path} failed: ${res.status} ${JSON.stringify(res.body)}`);
    return res.body;
}

async function createUser(prefix: string, label: string): Promise<Persona> {
    const username = `${prefix}${stamp}`;
    const email = `${username}@example.invalid`;
    const displayName = `${label} ${stamp}`;
    const password = compliantPassword(personalInfoCandidates({ username, email, displayName }));
    const body = await mustBearer(adminToken, 'POST', '/api/v1/users', {
        username,
        email,
        display_name: displayName,
        password,
    });
    return { username, password, id: body.data.id as number, displayName };
}

async function newPersonaPage(browser: Browser, who: { username: string; password: string }): Promise<Page> {
    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 1400 } });
    contexts.push(ctx);
    const page = await ctx.newPage();
    await realLogin(page, who.username, who.password);
    return page;
}

// openTab opens the project's Break-glass tab and waits for the list the page asked for.
async function openTab(page: Page): Promise<number> {
    const answered = page.waitForResponse(
        (r) =>
            new URL(r.url()).pathname === `/api/v1/projects/${projectId}/break-glass` && r.request().method() === 'GET'
    );
    await page.goto(`/projects/${projectId}/break-glass`);
    return (await answered).status();
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const project = await mustBearer(adminToken, 'POST', '/api/v1/projects', {
        name: projectName,
        description: 'break-glass e2e fixture',
    });
    projectId = project.data.id;

    alice = await createUser('bgalice', 'Break Glass Alice');
    outsider = await createUser('bgoutsider', 'Break Glass Outsider');
    await mustBearer(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, {
        user_id: alice.id,
        role: 'project_viewer',
    });

    alicePage = await newPersonaPage(browser, alice);
    adminPage = await newPersonaPage(browser, {
        username: ADMIN_USERNAME as string,
        password: ADMIN_PASSWORD as string,
    });
    outsiderPage = await newPersonaPage(browser, outsider);
});

test.afterAll(async () => {
    for (const ctx of contexts) await ctx.close();
});

test('alice requests emergency access and sees her own activation count down', async () => {
    expect(await openTab(alicePage)).toBe(200);
    await expect(alicePage.getByRole('heading', { name: 'Your activations' })).toBeVisible();
    // A member's view has no admin columns and no Revoke.
    await expect(alicePage.getByRole('columnheader', { name: 'Who' })).toHaveCount(0);

    // The picker is built from the limits the server sends (e2e config: default 4h, max 24h).
    await expect(alicePage.getByRole('option', { name: 'Server default (4 hours)' })).toBeAttached();
    await expect(alicePage.getByRole('option', { name: '24 hours' })).toBeAttached();

    await alicePage.getByLabel('Justification').fill(justification);
    await alicePage.getByLabel('How long').selectOption('1h');
    await alicePage.getByRole('button', { name: 'Request emergency access' }).click();

    await expect(alicePage.getByText('Emergency access is active')).toBeVisible({ timeout: 15_000 });
    const row = alicePage.getByRole('row', { name: new RegExp(justification) });
    await expect(row).toBeVisible();
    await expect(row.getByText('Active', { exact: true })).toBeVisible();
    await expect(row.getByTestId(/^bg-countdown-/)).toHaveText(/^(\d+h \d\dm|\d+m) \d\ds$/);
    await expect(row.getByRole('button', { name: 'Revoke' })).toHaveCount(0);

    // The countdown is live: it ticks down on its own.
    const first = await row.getByTestId(/^bg-countdown-/).innerText();
    await expect.poll(async () => row.getByTestId(/^bg-countdown-/).innerText(), { timeout: 10_000 }).not.toBe(first);
});

test('the admin sees alice’s activation in the all-activations view', async () => {
    expect(await openTab(adminPage)).toBe(200);
    await expect(adminPage.getByRole('heading', { name: 'All activations on this project' })).toBeVisible();
    const row = adminPage.getByRole('row', { name: new RegExp(justification) });
    await expect(row).toBeVisible();
    await expect(row.getByText(alice.displayName)).toBeVisible();
    await expect(row.getByText('Active', { exact: true })).toBeVisible();
    await expect(row.getByRole('button', { name: 'Revoke' })).toBeVisible();
});

test('the admin revokes it through the confirm dialog', async () => {
    let browserDialog = false;
    adminPage.on('dialog', async (d) => {
        browserDialog = true;
        await d.dismiss();
    });
    await openTab(adminPage);
    const row = adminPage.getByRole('row', { name: new RegExp(justification) });
    await row.getByRole('button', { name: 'Revoke' }).click();

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'Revoke emergency access?', level: 3 })).toBeVisible();
    await expect(dialog).toContainText(alice.displayName);
    const revoked = adminPage.waitForResponse(
        (r) => /\/break-glass\/\d+\/revoke$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST'
    );
    await dialog.getByRole('button', { name: 'Revoke' }).click();
    expect((await revoked).status()).toBe(200);

    await expect(row.getByText('Revoked', { exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(row.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
    expect(browserDialog, 'revoke must use the in-page dialog, never alert()/confirm()').toBe(false);
});

test('alice sees her activation as revoked', async () => {
    expect(await openTab(alicePage)).toBe(200);
    const row = alicePage.getByRole('row', { name: new RegExp(justification) });
    await expect(row.getByText('Revoked', { exact: true })).toBeVisible();
    await expect(row.getByTestId(/^bg-countdown-/)).toHaveCount(0);
    await expect(row.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
});

test('an outsider sees only the project-level refusal, never the break-glass tab', async () => {
    // The server refuses the list outright (not a member, no roles.read).
    expect(
        (
            await bearer(
                await apiLogin(outsider.username, outsider.password),
                'GET',
                `/api/v1/projects/${projectId}/break-glass`
            )
        ).status
    ).toBe(403);

    await outsiderPage.goto(`/projects/${projectId}/break-glass`);
    await outsiderPage.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    const main = outsiderPage.locator('main');
    // The project itself is refused to them (GET /projects/{id} needs secrets.read there), so
    // the page shows the project-level refusal and the break-glass tab never mounts: exactly
    // that, not the tab's own "Not allowed", and none of alice's data, form or tab navigation.
    await expect(main.getByText(/Failed to load project\./)).toBeVisible({ timeout: 15_000 });
    await expect(main.getByText('Not allowed')).toHaveCount(0);
    await expect(main.getByRole('link', { name: 'Break-glass' })).toHaveCount(0);
    await expect(main.getByRole('heading', { name: /activations/i })).toHaveCount(0);
    await expect(main).not.toContainText(justification);
    await expect(outsiderPage.getByLabel('Justification')).toHaveCount(0);
});
