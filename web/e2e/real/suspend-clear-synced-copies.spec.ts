// web/e2e/real/suspend-clear-synced-copies.spec.ts — SUSPEND-PURGE-1 against a REAL keyorix-server.
//
// The suspend dialog offers "Also clear copies synced to Kubernetes clusters" with a
// note recommending rotation. The choice is per suspension:
//
//   1. Checked: the POST carries clear_synced_copies:true, the secret is suspended, the
//      page keeps the rotate prompt, the server stores the choice and a reader sees it on
//      the 409 SecretSuspended refusal (details.clear_synced_copies). Resume removes it.
//   2. Unchecked: the POST has no such member, no note appears, the refusal has no details.
//   3. Cancel: nothing is sent and the secret stays active.
//
// Login budget (see web-real-smoke.sh): 1 API login + 1 UI login = 2 of 10.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

const stamp = Date.now();
const flaggedName = `purge-flagged-${stamp}`;
const plainName = `purge-plain-${stamp}`;
const cancelName = `purge-cancel-${stamp}`;

let adminToken: string;
let projectId: number;
let envName: string;
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

// storedChoice is what the server says about the secret right now.
async function stored(name: string) {
    const body = await mustBearer('GET', `/api/v1/secrets/${ids[name]}`);
    return { status: body.data.status as string, clear: Boolean(body.data.clear_synced_copies) };
}

// refusal reads the value the way a workload would and returns the 409 envelope's details.
async function refusal(name: string) {
    const r = await bearer('GET', `/api/v1/secrets/${ids[name]}?include_value=true`);
    return { status: r.status, error: r.body.error as string, details: r.body.details };
}

async function openDetail(name: string) {
    await page.goto(`/projects/${projectId}/secrets?env=${envName}`);
    const row = page.getByRole('row', { name });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await row.getByTitle('View').click();
    await expect(page.getByTestId('secret-header')).toBeVisible({ timeout: 10_000 });
}

// The secret's detail view is itself a modal, so "a dialog" is not specific enough: the
// suspend dialog is the one titled "Suspend <name>".
const suspendDialog = () => page.getByRole('dialog', { name: /^Suspend / });

const suspendCall = (name: string) =>
    page.waitForRequest(
        (r) => r.method() === 'POST' && new URL(r.url()).pathname === `/api/v1/secrets/${ids[name]}/suspend`
    );

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    projectId = (
        await mustBearer('POST', '/api/v1/projects', {
            name: `e2e-purge-${stamp}`,
            description: 'suspend-clear-synced-copies e2e fixture',
        })
    ).data.id;
    const envs = await mustBearer('GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;
    envName = envs.data.environments[0].name as string;
    for (const name of [flaggedName, plainName, cancelName]) {
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
    await openDetail(flaggedName);
    await page.getByRole('button', { name: 'Suspend', exact: true }).click();
    const dialog = suspendDialog();
    await expect(dialog).toBeVisible();
    await expect(dialog.getByLabel(/Also clear copies synced to Kubernetes clusters/i)).not.toBeChecked();
    await expect(dialog.getByText(/Rotate the secret if it may be compromised/i)).toBeVisible();
});

test('cancel sends nothing and leaves the secret active', async () => {
    await openDetail(cancelName);
    await page.getByRole('button', { name: 'Suspend', exact: true }).click();
    let posted = false;
    page.on('request', (r) => {
        if (r.method() === 'POST' && r.url().includes('/suspend')) posted = true;
    });
    await suspendDialog().getByRole('button', { name: 'Cancel' }).click();
    await expect(suspendDialog()).toHaveCount(0);
    expect(posted).toBe(false);
    expect((await stored(cancelName)).status).toBe('active');
});

test('checked: the request, the stored choice and the reader all see it; resume removes it', async () => {
    await openDetail(flaggedName);
    await page.getByRole('button', { name: 'Suspend', exact: true }).click();
    const dialog = suspendDialog();
    await dialog.getByLabel(/Also clear copies synced to Kubernetes clusters/i).check();

    const request = suspendCall(flaggedName);
    await dialog.getByRole('button', { name: 'Suspend secret', exact: true }).click();
    expect((await request).postDataJSON()).toMatchObject({ clear_synced_copies: true });

    await expect(page.getByTestId('suspended-badge')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/Synced Kubernetes copies will be cleared/i)).toBeVisible();

    expect(await stored(flaggedName)).toEqual({ status: 'suspended', clear: true });
    const refused = await refusal(flaggedName);
    expect(refused.status).toBe(409);
    expect(refused.error).toBe('SecretSuspended');
    expect(refused.details).toEqual({ clear_synced_copies: true });

    await page.getByRole('button', { name: 'Resume', exact: true }).click();
    await expect(page.getByTestId('suspended-badge')).toHaveCount(0, { timeout: 10_000 });
    await expect(page.getByText(/Synced Kubernetes copies will be cleared/i)).toHaveCount(0);
    expect(await stored(flaggedName)).toEqual({ status: 'active', clear: false });
    expect((await refusal(flaggedName)).status).toBe(200);
});

test('unchecked: no clearing request, no note, no details on the refusal', async () => {
    await openDetail(plainName);
    await page.getByRole('button', { name: 'Suspend', exact: true }).click();

    const request = suspendCall(plainName);
    await suspendDialog().getByRole('button', { name: 'Suspend secret', exact: true }).click();
    const body = (await request).postDataJSON() ?? {};
    expect(body).not.toHaveProperty('clear_synced_copies');

    await expect(page.getByTestId('suspended-badge')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/Synced Kubernetes copies will be cleared/i)).toHaveCount(0);

    expect(await stored(plainName)).toEqual({ status: 'suspended', clear: false });
    const refused = await refusal(plainName);
    expect(refused.status).toBe(409);
    expect(refused.error).toBe('SecretSuspended');
    expect(refused.details).toBeUndefined();
});
