// web/e2e/real/secret-read-refusal.spec.ts — ERRMAP-1 against a REAL keyorix-server.
//
// A secret whose own state refuses a value read used to answer 500, so Reveal showed
// "Failed to get secret value" and the copy button just turned red. The server now
// answers 409 (expired, suspended, max reads exhausted) or 403 (outside the access
// schedule) with a stable code and a fixed message, and the UI shows that message:
//
//   1. Reveal on a suspended secret: GET ...?include_value=true answers 409
//      SecretSuspended, and the detail view shows the server's reason.
//   2. Reveal outside the access schedule: 403 SecretAccessOutsideSchedule, the reason
//      is shown, and no generic "you do not have permission" error appears.
//   3. The list's copy button on the suspended secret: its tooltip carries the reason.
//
// Login budget (see web-real-smoke.sh): 1 API login + 1 UI login = 2 of 10.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

const SUSPENDED_MESSAGE = 'secret is suspended; its value cannot be read until it is resumed';
const SCHEDULE_MESSAGE = 'secret access is not permitted outside the configured time window';

const stamp = Date.now();
const suspendedName = `refused-suspended-${stamp}`;
const scheduledName = `refused-scheduled-${stamp}`;

let projectId: number;
let envName: string;
let suspendedId: number;
let scheduledId: number;
let page: Page;

async function mustBearer(token: string, method: 'GET' | 'POST' | 'PUT', path: string, data?: unknown) {
    const ctx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const res = await ctx.fetch(path, {
            method,
            headers: { Authorization: `Bearer ${token}` },
            ...(data === undefined ? {} : { data }),
        });
        if (res.status() >= 300) throw new Error(`setup ${method} ${path} failed: ${res.status()} ${await res.text()}`);
        return await res.json();
    } finally {
        await ctx.dispose();
    }
}

// ISO weekdays other than today and tomorrow (UTC): a schedule closed for the whole run.
function notTodayOrTomorrow(): string {
    const iso = (d: number) => (d === 0 ? 7 : d);
    const now = new Date();
    const skip = new Set([iso(now.getUTCDay()), iso(new Date(now.getTime() + 86_400_000).getUTCDay())]);
    return [1, 2, 3, 4, 5, 6, 7].filter((d) => !skip.has(d)).join(',');
}

async function openSecret(name: string) {
    await page.goto(`/projects/${projectId}/secrets?env=${envName}`);
    const row = page.getByRole('row', { name });
    await expect(row).toBeVisible({ timeout: 15_000 });
    return row;
}

// reveal opens the secret's detail view, clicks Reveal and returns the value read's status.
async function reveal(name: string, id: number): Promise<number> {
    const row = await openSecret(name);
    await row.getByTitle('View').click();
    const answered = page.waitForResponse(
        (r) =>
            new URL(r.url()).pathname === `/api/v1/secrets/${id}` &&
            new URL(r.url()).searchParams.get('include_value') === 'true'
    );
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    return (await answered).status();
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    const adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    projectId = (
        await mustBearer(adminToken, 'POST', '/api/v1/projects', {
            name: `e2e-refusal-${stamp}`,
            description: 'secret-read-refusal e2e fixture',
        })
    ).data.id;
    const envs = await mustBearer(adminToken, 'GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;
    envName = envs.data.environments[0].name as string;

    const create = async (name: string) =>
        (
            await mustBearer(adminToken, 'POST', '/api/v1/secrets', {
                name,
                value: `value-${name}`,
                type: 'text',
                project_id: projectId,
                environment_id: envId,
            })
        ).data.id as number;
    suspendedId = await create(suspendedName);
    scheduledId = await create(scheduledName);
    await mustBearer(adminToken, 'POST', `/api/v1/secrets/${suspendedId}/suspend`, { reason: 'e2e' });
    await mustBearer(adminToken, 'PUT', `/api/v1/secrets/${scheduledId}/schedule`, {
        allowed_days: notTodayOrTomorrow(),
        start_hour: 0,
        end_hour: 24,
        timezone: 'UTC',
    });

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

test('revealing a suspended secret says it is suspended (409), not a server error', async () => {
    expect(await reveal(suspendedName, suspendedId)).toBe(409);
    await expect(page.getByText(SUSPENDED_MESSAGE)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Failed to get secret value')).toHaveCount(0);
    await expect(page.getByText('Page failed to load')).toHaveCount(0);
    await expect(page.locator('body')).not.toContainText(`value-${suspendedName}`);
});

test('revealing outside the access schedule says so (403), not "no permission"', async () => {
    expect(await reveal(scheduledName, scheduledId)).toBe(403);
    await expect(page.getByText(SCHEDULE_MESSAGE)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/do not have permission/i)).toHaveCount(0);
    await expect(page.locator('body')).not.toContainText(`value-${scheduledName}`);
});

test("the list's copy button gives the refusal reason", async () => {
    const row = await openSecret(suspendedName);
    const answered = page.waitForResponse((r) => new URL(r.url()).pathname === `/api/v1/secrets/${suspendedId}`);
    await row.getByTitle('Copy value').click();
    expect((await answered).status()).toBe(409);
    await expect(row.getByTitle(SUSPENDED_MESSAGE)).toBeVisible({ timeout: 5_000 });
});
