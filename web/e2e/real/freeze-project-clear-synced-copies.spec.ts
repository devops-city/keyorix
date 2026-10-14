// web/e2e/real/freeze-project-clear-synced-copies.spec.ts — the project-wide freeze takes the
// same "also clear synced Kubernetes copies" choice as the single-secret suspend, against a
// REAL keyorix-server.
//
//   1. Cancel: nothing is sent and the secrets stay active.
//   2. Checked: the POST carries clear_synced_copies:true, every secret is suspended with the
//      stored choice, a reader sees it on the 409 SecretSuspended refusal, the page keeps the
//      rotate note. Resume all removes it.
//   3. Unchecked: the POST body has no such member, no note, the refusal has no details.
//
// Login budget (see web-real-smoke.sh): 1 API login + 1 UI login = 2 of 10.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

const stamp = Date.now();
const names = [`freeze-a-${stamp}`, `freeze-b-${stamp}`];

let adminToken: string;
let projectId: number;
let page: Page;
const ids: Record<string, number> = {};

async function bearer(method: 'GET' | 'POST', path: string, data?: unknown) {
    const ctx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const res = await ctx.fetch(path, {
            method,
            headers: { Authorization: `Bearer ${adminToken}` },
            ...(data === undefined ? {} : { data }),
        });
        return { status: res.status(), body: await res.json().catch(() => ({})) };
    } finally {
        await ctx.dispose();
    }
}

async function mustBearer(method: 'GET' | 'POST', path: string, data?: unknown) {
    const r = await bearer(method, path, data);
    if (r.status >= 300) throw new Error(`setup ${method} ${path} failed: ${r.status} ${JSON.stringify(r.body)}`);
    return r.body;
}

async function stored(name: string) {
    const body = await mustBearer('GET', `/api/v1/secrets/${ids[name]}`);
    return { status: body.data.status as string, clear: Boolean(body.data.clear_synced_copies) };
}

async function refusal(name: string) {
    const r = await bearer('GET', `/api/v1/secrets/${ids[name]}?include_value=true`);
    return { status: r.status, error: r.body.error as string, details: r.body.details };
}

async function openSettings() {
    await page.goto(`/projects/${projectId}/settings`);
    await expect(page.getByRole('button', { name: 'Freeze all secrets', exact: true })).toBeVisible({
        timeout: 15_000,
    });
}

const freezeDialog = () => page.getByRole('dialog', { name: /^Freeze all secrets in this project/ });
const checkbox = () => freezeDialog().getByLabel(/Also clear copies synced to Kubernetes clusters/i);
const freezeCall = () =>
    page.waitForRequest(
        (r) =>
            r.method() === 'POST' && new URL(r.url()).pathname === `/api/v1/projects/${projectId}/secrets/suspend-all`
    );

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    projectId = (
        await mustBearer('POST', '/api/v1/projects', {
            name: `e2e-freeze-${stamp}`,
            description: 'freeze-project-clear-synced-copies e2e fixture',
        })
    ).data.id;
    const envs = await mustBearer('GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;
    for (const name of names) {
        ids[name] = (
            await mustBearer('POST', '/api/v1/secrets', {
                name,
                value: `value-${name}`,
                type: 'text',
                project_id: projectId,
                environment_id: envId,
            })
        ).data.id as number;
    }

    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 2600 } });
    page = await ctx.newPage();
    await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
});

test.afterEach(async () => {
    const testInfo = test.info();
    if (testInfo.status === testInfo.expectedStatus) return;
    await page?.screenshot({ path: testInfo.outputPath('page.png'), fullPage: true }).catch(() => undefined);
});

test.afterAll(async () => {
    await page
        ?.context()
        .close()
        .catch(() => undefined);
});

test('the dialog offers the option unchecked, with a rotation note', async () => {
    await openSettings();
    await page.getByRole('button', { name: 'Freeze all secrets', exact: true }).click();
    await expect(freezeDialog()).toBeVisible();
    await expect(checkbox()).not.toBeChecked();
    await expect(freezeDialog().getByText(/Rotate the secrets if they may be compromised/i)).toBeVisible();
});

test('cancel sends nothing and leaves the secrets active', async () => {
    await openSettings();
    await page.getByRole('button', { name: 'Freeze all secrets', exact: true }).click();
    let posted = false;
    page.on('request', (r) => {
        if (r.method() === 'POST' && r.url().includes('/suspend-all')) posted = true;
    });
    await freezeDialog().getByRole('button', { name: 'Cancel' }).click();
    await expect(freezeDialog()).toHaveCount(0);
    expect(posted).toBe(false);
    for (const name of names) expect((await stored(name)).status).toBe('active');
});

test('checked: the request, every stored choice and the reader all see it; resume all removes it', async () => {
    await openSettings();
    await page.getByRole('button', { name: 'Freeze all secrets', exact: true }).click();
    await checkbox().check();

    const request = freezeCall();
    await freezeDialog().getByRole('button', { name: 'Freeze all secrets', exact: true }).click();
    expect((await request).postDataJSON()).toMatchObject({ clear_synced_copies: true });

    await expect(page.getByText(/Froze \d+ secret\(s\)/)).toBeVisible({ timeout: 10_000 });
    await expect(
        page.getByText(/Copies synced to Kubernetes clusters will be cleared on their next sync/)
    ).toBeVisible();
    await expect(page.getByText(/Rotate these secrets/)).toBeVisible();

    for (const name of names) {
        expect(await stored(name)).toEqual({ status: 'suspended', clear: true });
        const refused = await refusal(name);
        expect(refused.status).toBe(409);
        expect(refused.error).toBe('SecretSuspended');
        expect(refused.details).toEqual({ clear_synced_copies: true });
    }

    await page.getByRole('button', { name: 'Resume all', exact: true }).click();
    await expect(page.getByText(/Resumed \d+ secret\(s\)/)).toBeVisible({ timeout: 10_000 });
    for (const name of names) {
        expect(await stored(name)).toEqual({ status: 'active', clear: false });
        expect((await refusal(name)).status).toBe(200);
    }
});

test('unchecked: no clearing request, no note, no details on the refusal', async () => {
    await openSettings();
    await page.getByRole('button', { name: 'Freeze all secrets', exact: true }).click();

    const request = freezeCall();
    await freezeDialog().getByRole('button', { name: 'Freeze all secrets', exact: true }).click();
    const body = (await request).postDataJSON() ?? {};
    expect(body).not.toHaveProperty('clear_synced_copies');

    await expect(page.getByText(/Froze \d+ secret\(s\)/)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/Copies synced to Kubernetes clusters will be cleared/)).toHaveCount(0);

    for (const name of names) {
        expect(await stored(name)).toEqual({ status: 'suspended', clear: false });
        const refused = await refusal(name);
        expect(refused.status).toBe(409);
        expect(refused.error).toBe('SecretSuspended');
        expect(refused.details).toBeUndefined();
    }
});
