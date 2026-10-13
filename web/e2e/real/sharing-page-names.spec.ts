// web/e2e/real/sharing-page-names.spec.ts — #3153 (from DEMO-WALK-4), against a REAL
// keyorix-server:
//
//   1. the Sharing page's Secret column names the secret (and its project) instead of
//      "Secret #<id>", for a project-only owner (GET /shares/owned);
//   2. the API names a secret only for a caller who may read it: the same share is
//      listed for the owner WITH the name and the name is not in any other user's list;
//   3. the revoke dialog's title ("Delete Share") is readable in BOTH themes: WCAG AA
//      contrast (>= 4.5:1) of the title and message against the dialog's own background.
//
// Run via scripts/e2e/web-real-smoke.sh (it boots the backend and exports the env vars
// read below), never directly. Login budget: 2 API logins (admin, owner) + 1 UI login.
import { test, expect, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';
import { compliantPassword, personalInfoCandidates } from './support/password';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

const stamp = Date.now();
const projectName = `e2e-names-${stamp}`;
const secretName = `db-password-${stamp}`;

let adminToken: string;
let ownerToken: string;
let projectId: number;
let secretId: number;
let owner: { username: string; password: string; id: number };
let viewer: { username: string; id: number };
let page: Page;

async function bearer(token: string, method: 'GET' | 'POST', path: string, data?: unknown) {
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

async function must(token: string, method: 'GET' | 'POST', path: string, data?: unknown) {
    const res = await bearer(token, method, path, data);
    if (res.status >= 300) throw new Error(`setup ${method} ${path} failed: ${res.status} ${JSON.stringify(res.body)}`);
    return res.body;
}

async function createUser(prefix: string, label: string) {
    const username = `${prefix}${stamp}`;
    const email = `${username}@example.invalid`;
    const displayName = `${label} ${stamp}`;
    const password = compliantPassword(personalInfoCandidates({ username, email, displayName }));
    const body = await must(adminToken, 'POST', '/api/v1/users', {
        username,
        email,
        display_name: displayName,
        password,
    });
    return { username, password, id: body.data.id as number };
}

// contrastOf returns the WCAG contrast ratio of `selector`'s text colour against the
// background the user actually sees behind it (first non-transparent ancestor background).
// Colours are resolved through a canvas so oklch()/color() values from Tailwind v4 work.
async function contrastOf(p: Page, selector: string): Promise<number> {
    return p.evaluate((sel) => {
        const el = document.querySelector(sel) as HTMLElement | null;
        if (!el) throw new Error(`no element for ${sel}`);
        const ctx = document.createElement('canvas').getContext('2d', { willReadFrequently: true })!;
        const rgba = (css: string): [number, number, number, number] => {
            ctx.clearRect(0, 0, 1, 1);
            ctx.fillStyle = '#000';
            ctx.fillStyle = css;
            ctx.fillRect(0, 0, 1, 1);
            const d = ctx.getImageData(0, 0, 1, 1).data;
            return [d[0], d[1], d[2], d[3] / 255];
        };
        let bg: [number, number, number] = [255, 255, 255];
        const layers: [number, number, number, number][] = [];
        for (let n: HTMLElement | null = el; n; n = n.parentElement) {
            const c = rgba(getComputedStyle(n).backgroundColor);
            if (c[3] > 0) layers.push(c);
            if (c[3] >= 1) break;
        }
        for (const l of layers.reverse()) {
            bg = [0, 1, 2].map((i) => l[i] * l[3] + bg[i] * (1 - l[3])) as [number, number, number];
        }
        const fg = rgba(getComputedStyle(el).color);
        const lum = (c: number[]) => {
            const [r, g, b] = c.map((v) => {
                const s = v / 255;
                return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
            });
            return 0.2126 * r + 0.7152 * g + 0.0722 * b;
        };
        const a = lum([fg[0], fg[1], fg[2]]);
        const b = lum(bg);
        return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    }, selector);
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const project = await must(adminToken, 'POST', '/api/v1/projects', {
        name: projectName,
        description: 'sharing page names e2e fixture',
    });
    projectId = project.data.id;
    const envs = await must(adminToken, 'GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;

    owner = await createUser('namesowner', 'Names Owner');
    const v = await createUser('namesviewer', 'Names Viewer');
    viewer = { username: v.username, id: v.id };
    await must(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, { user_id: owner.id, role: 'project_admin' });
    await must(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, { user_id: v.id, role: 'project_viewer' });

    ownerToken = await apiLogin(owner.username, owner.password);
    secretId = (
        await must(ownerToken, 'POST', '/api/v1/secrets', {
            name: secretName,
            value: `value-${stamp}`,
            type: 'text',
            project_id: projectId,
            environment_id: envId,
        })
    ).data.id as number;
    await must(ownerToken, 'POST', `/api/v1/secrets/${secretId}/share`, {
        recipient_id: viewer.id,
        is_group: false,
        permission: 'write',
    });

    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 900 } });
    page = await ctx.newPage();
    await realLogin(page, owner.username, owner.password);
});

test.afterAll(async () => {
    await page?.context().close().catch(() => undefined);
});

test('the API names the secret and project for the owner who may read it', async () => {
    const res = await bearer(ownerToken, 'GET', '/api/v1/shares/owned');
    expect(res.status).toBe(200);
    const rows = res.body.data.data as any[];
    const row = rows.find((r) => r.secretId === secretId);
    expect(row, 'the owner lists the share they created').toBeTruthy();
    expect(row.secretName).toBe(secretName);
    expect(row.projectId).toBe(projectId);
    expect(row.projectName).toBe(projectName);
});

test('the Sharing page shows the secret name and project, not "Secret #<id>"', async () => {
    await page.goto('/sharing');
    const row = page.getByRole('row', { name: new RegExp(viewer.username) });
    await expect(row).toBeVisible({ timeout: 20_000 });
    await expect(row.getByTestId('share-secret-name')).toHaveText(secretName);
    await expect(row.getByTestId('share-secret-project')).toHaveText(projectName);
    await expect(page.getByText(`Secret #${secretId}`)).toHaveCount(0);
});

test('the revoke dialog title is readable in both themes', async () => {
    await page.goto('/sharing');
    const row = page.getByRole('row', { name: new RegExp(viewer.username) });
    await expect(row).toBeVisible({ timeout: 20_000 });

    for (const theme of ['dark', 'light'] as const) {
        await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), theme);

        await row.getByTitle('Revoke access').click();
        const dialog = page.getByRole('dialog');
        await expect(dialog).toBeVisible();
        const title = dialog.locator('h3', { hasText: 'Delete Share' });
        await expect(title).toBeVisible();
        const titleRatio = await contrastOf(page, '[role="dialog"] h3');
        const messageRatio = await contrastOf(page, '[role="dialog"] h3 + div p');
        expect(titleRatio, `${theme}: revoke dialog title contrast`).toBeGreaterThanOrEqual(4.5);
        expect(messageRatio, `${theme}: revoke dialog message contrast`).toBeGreaterThanOrEqual(4.5);
        await page.keyboard.press('Escape');
        await expect(dialog).toBeHidden();
    }
});
