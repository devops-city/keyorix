// e2e-server: insecure_audit_skip_reads=true
//
// web/e2e/real/audit-reads-skipped-banner.spec.ts — ADR-112 Amendment 4 against a
// REAL keyorix-server booted with storage.database.insecure_audit_skip_reads: true
// (the directive on line 1; web-real-smoke.sh gives this spec its own server).
//
//   1. GET /api/v1/system/info reports security.audit_reads_skipped: true.
//   2. The web UI shows the persistent "Secret reads are not audited" banner on every
//      page, with no way to dismiss it.
//   3. Revealing a secret's value in the UI works and leaves no secret.read audit
//      event, while the secret's creation is still audited.
//
// Login budget (see web-real-smoke.sh): 1 API login + 1 UI login = 2 of 10.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

const stamp = Date.now();
const secretName = `skip-reads-${stamp}`;
const secretValue = `value-${stamp}`;

let adminToken: string;
let projectId: number;
let envName: string;
let secretId: number;
let page: Page;

async function bearer(method: 'GET' | 'POST', path: string, data?: unknown) {
    const ctx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const res = await ctx.fetch(path, {
            method,
            headers: { Authorization: `Bearer ${adminToken}` },
            ...(data === undefined ? {} : { data }),
        });
        if (res.status() >= 300) throw new Error(`${method} ${path} failed: ${res.status()} ${await res.text()}`);
        return await res.json();
    } finally {
        await ctx.dispose();
    }
}

async function auditCount(action: string): Promise<number> {
    const body = await bearer('GET', `/api/v1/audit/search?action=${action}&resource_id=${secretId}`);
    return body.data.total as number;
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    projectId = (
        await bearer('POST', '/api/v1/projects', {
            name: `e2e-skip-reads-${stamp}`,
            description: 'audit-reads-skipped-banner e2e fixture',
        })
    ).data.id;
    const envs = await bearer('GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;
    envName = envs.data.environments[0].name as string;
    secretId = (
        await bearer('POST', '/api/v1/secrets', {
            name: secretName,
            value: secretValue,
            type: 'text',
            project_id: projectId,
            environment_id: envId,
        })
    ).data.id as number;

    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 2000 } });
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

test('system info reports that reads are not audited', async () => {
    const info = await bearer('GET', '/api/v1/system/info');
    expect(info.data.security.audit_reads_skipped).toBe(true);
});

test('the banner is shown on every page and cannot be dismissed', async () => {
    const banner = page.getByTestId('audit-reads-skipped-banner');
    for (const path of ['/dashboard', `/projects/${projectId}/secrets?env=${envName}`, '/settings']) {
        await page.goto(path);
        await expect(banner).toBeVisible({ timeout: 15_000 });
        await expect(banner).toContainText('Secret reads are not audited.');
        await expect(banner).toContainText('storage.database.insecure_audit_skip_reads');
        await expect(banner.getByRole('button')).toHaveCount(0);
    }
});

test('revealing a secret works and writes no secret.read, while its creation is audited', async () => {
    await page.goto(`/projects/${projectId}/secrets?env=${envName}`);
    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await row.getByTitle('View').click();
    const answered = page.waitForResponse(
        (r) =>
            new URL(r.url()).pathname === `/api/v1/secrets/${secretId}` &&
            new URL(r.url()).searchParams.get('include_value') === 'true'
    );
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    expect((await answered).status()).toBe(200);
    await expect(page.getByText(secretValue)).toBeVisible({ timeout: 10_000 });

    expect(await auditCount('secret.created')).toBe(1);
    expect(await auditCount('secret.read')).toBe(0);
});
