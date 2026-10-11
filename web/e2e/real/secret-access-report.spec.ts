// web/e2e/real/secret-access-report.spec.ts — the secret detail's "Who can access" panel against a
// REAL keyorix-server (#3020).
//
// GET /secrets/{id}/access leaves out what the caller may not read through its own routes
// (per-secret ACL holders need secrets.manage, the gate of GET /secrets/{id}/acl; the member
// roster and role grants need users.read at the project) and then flags the report `degraded`.
// No built-in project role holds secrets.manage, so a project member always gets a shortened
// list. The panel must say so, with the server's reasons, instead of presenting the short list
// as everyone who can read the secret. A caller who may see everything (the global admin) gets a
// complete report and no warning, plus each user's effective level and the grants behind it.
//
//   1. viewer (project_viewer, plus a write share from the owner) opens the secret: the panel
//      lists them and shows "This list is incomplete" with the secret_acls reason; the API
//      answers degraded with the same reason.
//   2. the global admin opens the same secret: no warning; the viewer is listed with both
//      grants (role:read + direct_share:write); the API answers degraded=false.
//
// Login budget (see web-real-smoke.sh): 2 API logins (admin, owner) + 2 UI logins (viewer,
// admin) + 1 seeding login = 5 of 10.
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
}

const stamp = Date.now();
const projectName = `e2e-access-${stamp}`;
const secretName = `access-${stamp}`;

let projectId: number;
let envName: string;
let secretId: number;
let viewer: Persona;
let adminToken: string;
let viewerPage: Page;
let adminPage: Page;
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
    return { username, password, id: body.data.id as number };
}

async function newPersonaPage(browser: Browser, who: { username: string; password: string }): Promise<Page> {
    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 2600 } });
    contexts.push(ctx);
    const page = await ctx.newPage();
    await realLogin(page, who.username, who.password);
    return page;
}

// openAccessPanel opens the secret's detail view and returns its "Who can access" panel.
async function openAccessPanel(page: Page) {
    await page.goto(`/projects/${projectId}/secrets?env=${envName}`);
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await expect(row).toBeVisible({ timeout: 15_000 });
    const answered = page.waitForResponse(
        (r) => new URL(r.url()).pathname === `/api/v1/secrets/${secretId}/access` && r.request().method() === 'GET'
    );
    await row.getByTitle('View').click();
    expect((await answered).status()).toBe(200);
    const heading = page.getByRole('heading', { name: 'Who can access' });
    await expect(heading).toBeVisible({ timeout: 15_000 });
    return heading.locator('..');
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const project = await mustBearer(adminToken, 'POST', '/api/v1/projects', {
        name: projectName,
        description: 'secret-access-report e2e fixture',
    });
    projectId = project.data.id;
    const envs = await mustBearer(adminToken, 'GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;
    envName = envs.data.environments[0].name as string;

    const owner = await createUser('accessowner', 'Access Owner');
    viewer = await createUser('accessviewer', 'Access Viewer');
    await mustBearer(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, {
        user_id: owner.id,
        role: 'project_admin',
    });
    await mustBearer(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, {
        user_id: viewer.id,
        role: 'project_viewer',
    });

    const ownerToken = await apiLogin(owner.username, owner.password);
    secretId = (
        await mustBearer(ownerToken, 'POST', '/api/v1/secrets', {
            name: secretName,
            value: `value-${stamp}`,
            type: 'text',
            project_id: projectId,
            environment_id: envId,
        })
    ).data.id as number;
    await mustBearer(ownerToken, 'POST', `/api/v1/secrets/${secretId}/share`, {
        recipient_id: viewer.id,
        is_group: false,
        permission: 'write',
    });

    viewerPage = await newPersonaPage(browser, viewer);
    adminPage = await newPersonaPage(browser, {
        username: ADMIN_USERNAME as string,
        password: ADMIN_PASSWORD as string,
    });
});

test.afterEach(async () => {
    const testInfo = test.info();
    if (testInfo.status === testInfo.expectedStatus) return;
    for (const [name, page] of [
        ['viewer', viewerPage],
        ['admin', adminPage],
    ] as const) {
        await page?.screenshot({ path: testInfo.outputPath(`${name}.png`), fullPage: true }).catch(() => undefined);
    }
});

test.afterAll(async () => {
    for (const ctx of contexts) await ctx.close().catch(() => undefined);
});

test('a project member sees that the access list is incomplete, and why', async () => {
    const panel = await openAccessPanel(viewerPage);
    await expect(panel).toContainText(viewer.username);
    await expect(panel.getByText('This list is incomplete')).toBeVisible();
    await expect(panel).toContainText(/secret_acls: .*secrets\.manage/);

    // The panel shows what the server said, as the viewer's own session.
    const report = await viewerPage.evaluate(async (id) => {
        const res = await fetch(`/api/v1/secrets/${id}/access`, { credentials: 'include' });
        return (await res.json()).data;
    }, secretId);
    expect(report.degraded).toBe(true);
    expect(report.degraded_reasons.some((r: string) => r.startsWith('secret_acls'))).toBe(true);
});

test('the global admin gets the complete list with no warning, and each grant', async () => {
    const panel = await openAccessPanel(adminPage);
    await expect(panel.getByText('This list is incomplete')).toHaveCount(0);
    await expect(panel).toContainText(viewer.username);
    await expect(panel).toContainText('role:read + direct_share:write');

    const res = await bearer(adminToken, 'GET', `/api/v1/secrets/${secretId}/access`);
    expect(res.status).toBe(200);
    expect(res.body.data.degraded, JSON.stringify(res.body.data.degraded_reasons)).toBe(false);
    const row = res.body.data.accessors.find((a: any) => a.user_id === viewer.id);
    expect(row.permission).toBe('write');
    expect(row.grants).toEqual(expect.arrayContaining(['role:read', 'direct_share:write']));
});
