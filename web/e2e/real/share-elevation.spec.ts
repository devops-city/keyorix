// web/e2e/real/share-elevation.spec.ts — E2E-SHARE-1: share → elevated access → revoke, driven
// through the real UI against a REAL keyorix-server (#3001, decision #2941).
//
// The rule under test: a share may ELEVATE a project member's access on that one secret
// (effective = max(role, active share)); revoking the share removes exactly the elevation;
// the owner must be a live project member to share (a global admin with no project role is
// refused), and the refusal says what to do rather than a bare 403.
//
//   1. owner (project_admin of the project and NOTHING else: no global role) finds the
//      viewer in the Share dialog's recipient search (project members only; a non-member
//      is not offered) and shares secret A at `write` → the dialog shows "Shared!" and
//      closes, and the share is listed for A.
//   2. the viewer edits A in the UI (the value really changes) while B, which was NOT
//      shared, stays read-only: its row offers no Edit/Rotate and the API answers 403.
//      The same write share does NOT allow Suspend: refused with the server's reason (#3001).
//      The secret's detail page offers Edit/Rotate on A exactly like the row (and edits from
//      it), and neither on B; Share, Copy, Suspend and Delete stay role-only (SHARE-DETAIL-1).
//   3. owner revokes the share → it is gone from A's share list, A's row stops offering
//      Edit/Rotate and the API refuses the viewer's update again, the value unchanged.
//   4. a global admin who OWNS a secret but holds no role in its project tries to share →
//      the dialog shows the explanatory message and the API answers 403 with the same text.
//
// SHARE-2: the owner used to need the global system_auditor role, because the dialog's
// recipient search was GET /api/v1/users (global users.read). It now searches
// GET /api/v1/projects/{id}/share-recipients, so the owner is project-only.
//
// SHARE-3: the Sharing Management page loads GET /api/v1/shares (global secrets.read). For the
// project-only owner that is refused, so the page loads the owner-scoped
// GET /api/v1/shares/owned instead and labels it "Shares you created". Step 3 revokes from
// that page. The global admin's page is unchanged (no label, GET /shares answers 200).
//
// Login budget: server/http/handlers/auth.go allows 10 login attempts per IP per 15 min and
// web-real-smoke.sh gives every spec file its own fresh server. This file uses 3 API logins
// (admin, owner-setup, viewer-checks) + 3 UI logins (owner, viewer, admin) + 1 seeding
// login = 7. Each persona logs in ONCE and keeps its browser context for the whole serial
// run, so adding a test here does not add logins.
//
// require_mfa is switched off for this harness by web-real-smoke.sh (see its comment on
// the sed), so there is no MFA step; MFA login is covered by mfa-login.spec.ts.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Browser, BrowserContext, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';
import { compliantPassword, personalInfoCandidates } from './support/password';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

// The fixed server-side wording (internal/core/share_authz.go ShareRefusalMessage). Asserted on
// a stable fragment of each sentence rather than the whole string, so a copy tweak that keeps
// the advice does not break the spec, but dropping the advice does.
const OWNER_NOT_MEMBER_MESSAGE = /not a member of this secret's project/i;
const OWNER_NOT_MEMBER_ADVICE = /Ask a project admin to give you a role in the project/i;

interface Persona {
    username: string;
    password: string;
    id: number;
}

const stamp = Date.now();
const projectName = `e2e-share-${stamp}`;
const secretAName = `share-a-${stamp}`;
const secretBName = `share-b-${stamp}`;
const secretCName = `share-c-${stamp}`;
const valueA0 = `value-a-original-${stamp}`;
const valueA1 = `value-a-by-viewer-${stamp}`;
const valueA2 = `value-a-after-revoke-${stamp}`;
const valueA3 = `value-a-from-detail-${stamp}`;
const valueB0 = `value-b-original-${stamp}`;
const valueB1 = `value-b-by-viewer-${stamp}`;

let projectId: number;
let envName: string;
let owner: Persona;
let viewer: Persona;
let secretA: number;
let secretB: number;
let secretC: number;
let outsider: Persona;
let adminToken: string;
let ownerToken: string;
let viewerToken: string;
let ownerPage: Page;
let viewerPage: Page;
let adminPage: Page;
const contexts: BrowserContext[] = [];

// bearer runs one API call with a fresh cookie-free context (see helpers.ts apiLogin for why a
// context must not be reused across a login and a mutation).
async function bearer(
    token: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
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

async function mustBearer(token: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, data?: unknown) {
    const res = await bearer(token, method, path, data);
    if (res.status >= 300) throw new Error(`setup ${method} ${path} failed: ${res.status} ${JSON.stringify(res.body)}`);
    return res.body;
}

// createUser mirrors helpers.ts createDedicatedUser but lets the caller pick a global role,
// which that helper does not take. `role` is the same field web-real-smoke.sh's seeding uses.
async function createUser(prefix: string, label: string, role?: string): Promise<Persona> {
    const username = `${prefix}${stamp}`;
    const email = `${username}@example.invalid`;
    const displayName = `${label} ${stamp}`;
    const password = compliantPassword(personalInfoCandidates({ username, email, displayName }));
    const body = await mustBearer(adminToken, 'POST', '/api/v1/users', {
        username,
        email,
        display_name: displayName,
        password,
        ...(role ? { role } : {}),
    });
    return { username, password, id: body.data.id as number };
}

async function newPersonaPage(browser: Browser, who: { username: string; password: string }): Promise<Page> {
    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 1600 } });
    contexts.push(ctx);
    const page = await ctx.newPage();
    await realLogin(page, who.username, who.password);
    return page;
}

async function settle(page: Page) {
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
}

async function openProjectSecrets(page: Page) {
    // The tab opens on "Production" by default; the fixture secrets live in the first environment.
    await page.goto(`/projects/${projectId}/secrets?env=${envName}`);
    await settle(page);
}

function secretRow(page: Page, name: string) {
    return page.getByRole('row', { name: new RegExp(name) });
}

// openShareDialog + fillShare drive the Share dialog for `recipient` at `permission`.
async function openShareDialog(page: Page, secretName: string) {
    await openProjectSecrets(page);
    await expect(secretRow(page, secretName)).toBeVisible({ timeout: 15_000 });
    await secretRow(page, secretName).getByTitle('Share').click();
    await expect(page.getByRole('dialog')).toContainText(`Share "${secretName}"`);
}

async function fillShare(page: Page, recipient: Persona, permission: 'read' | 'write') {
    const dialog = page.getByRole('dialog');
    await dialog.locator('#recipient-input').fill(recipient.username);
    await dialog.getByRole('button', { name: new RegExp(`@${recipient.username}`) }).click();
    await dialog.locator('#permission-select').selectOption(permission);
    const answered = page.waitForResponse(
        (r) => /\/api\/v1\/secrets\/\d+\/share$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST'
    );
    await dialog.getByRole('button', { name: 'Share', exact: true }).click();
    return (await answered).status();
}

// editSecretValue drives the Edit dialog and returns once the request has been answered.
async function editSecretValue(page: Page, secretName: string, newValue: string) {
    await openProjectSecrets(page);
    await expect(secretRow(page, secretName)).toBeVisible({ timeout: 15_000 });
    await secretRow(page, secretName).getByTitle('Edit').click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText(`Edit Secret: ${secretName}`);
    await dialog.locator('#edit-secret-value').fill(newValue);
    const answered = page.waitForResponse(
        (r) => /\/api\/v1\/secrets\/\d+$/.test(new URL(r.url()).pathname) && r.request().method() === 'PUT'
    );
    await dialog.getByRole('button', { name: 'Save Changes' }).click();
    return (await answered).status();
}

// expectNoUpdateControls: the row is listed (the viewer reads it) but offers neither Edit nor Rotate.
async function expectNoUpdateControls(page: Page, secretName: string) {
    await openProjectSecrets(page);
    const row = secretRow(page, secretName);
    await expect(row).toBeVisible({ timeout: 15_000 });
    await expect(row.getByTitle('Edit')).toHaveCount(0);
    await expect(row.getByTitle('Rotate')).toHaveCount(0);
}

// readValue asks the API, as the page's own session, for a secret's plaintext.
async function readValue(page: Page, id: number): Promise<string | null> {
    return page.evaluate(async (secretId) => {
        const res = await fetch(`/api/v1/secrets/${secretId}?include_value=true`, { credentials: 'include' });
        if (!res.ok) return null;
        const body = await res.json();
        return (body.data?.value ?? body.data?.secret?.value ?? null) as string | null;
    }, id);
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);

    // The bootstrap admin creates the project but is NOT a member of it: creating a project
    // grants the creator no role in it (web-real-smoke.sh adds the self-membership explicitly
    // for its own fixture project). That is exactly the "global admin, no project role" persona.
    const project = await mustBearer(adminToken, 'POST', '/api/v1/projects', {
        name: projectName,
        description: 'share-elevation e2e fixture',
    });
    projectId = project.data.id;
    const envs = await mustBearer(adminToken, 'GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;
    envName = envs.data.environments[0].name as string;

    // owner: project_admin in the project and nothing else (SHARE-2 dropped the global
    // system_auditor workaround). viewer: project_viewer only. outsider: no role in the
    // project, so the owner's recipient search must not offer them (no login: costs nothing).
    owner = await createUser('shareowner', 'Share Owner');
    viewer = await createUser('shareviewer', 'Share Viewer');
    outsider = await createUser('shareoutsider', 'Share Outsider');
    await mustBearer(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, {
        user_id: owner.id,
        role: 'project_admin',
    });
    await mustBearer(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, {
        user_id: viewer.id,
        role: 'project_viewer',
    });

    ownerToken = await apiLogin(owner.username, owner.password);
    const mk = async (token: string, name: string, value: string) =>
        (
            await mustBearer(token, 'POST', '/api/v1/secrets', {
                name,
                value,
                type: 'text',
                project_id: projectId,
                environment_id: envId,
            })
        ).data.id as number;
    secretA = await mk(ownerToken, secretAName, valueA0);
    secretB = await mk(ownerToken, secretBName, valueB0);
    // C is owned by the admin, who holds no role in the project.
    secretC = await mk(adminToken, secretCName, `value-c-${stamp}`);

    viewerToken = await apiLogin(viewer.username, viewer.password);

    ownerPage = await newPersonaPage(browser, owner);
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
        ['owner', ownerPage],
        ['viewer', viewerPage],
        ['admin', adminPage],
    ] as const) {
        await page?.screenshot({ path: testInfo.outputPath(`${name}.png`), fullPage: true }).catch(() => undefined);
    }
});

test.afterAll(async () => {
    for (const ctx of contexts) await ctx.close().catch(() => undefined);
});

test('fixture sanity: the viewer starts read-only on both secrets', async () => {
    // Before any share, the viewer's project_viewer role must not allow a write. Without this a
    // later "viewer can edit A" would be vacuous if the role were already permissive.
    for (const id of [secretA, secretB]) {
        const res = await bearer(viewerToken, 'PUT', `/api/v1/secrets/${id}`, { value: `probe-${stamp}` });
        expect(res.status, `a plain project_viewer must not be able to update secret ${id}`).toBe(403);
    }
    // And can read, so the Edit dialog's absence of a value is not a read failure.
    const read = await bearer(viewerToken, 'GET', `/api/v1/secrets/${secretA}`);
    expect(read.status).toBe(200);
});

test('the project-only owner finds only project members as recipients', async () => {
    // The owner holds no global role, so GET /api/v1/users is closed to them…
    const globalList = await bearer(ownerToken, 'GET', '/api/v1/users?search=share');
    expect(globalList.status, 'GET /users stays a global users.read route').toBe(403);

    // …and the dialog searches the secret's project instead (SHARE-2).
    await openShareDialog(ownerPage, secretAName);
    const dialog = ownerPage.getByRole('dialog');
    const searched = ownerPage.waitForResponse((r) =>
        new URL(r.url()).pathname.endsWith(`/api/v1/projects/${projectId}/share-recipients`)
    );
    await dialog.locator('#recipient-input').fill(viewer.username);
    expect((await searched).status(), 'the project-scoped search is open to a project-only admin').toBe(200);
    await expect(dialog.getByRole('button', { name: new RegExp(`@${viewer.username}`) })).toBeVisible();

    // A user with no role in the project is not offered (UI and API agree).
    await dialog.locator('#recipient-input').fill(outsider.username);
    await expect(dialog).toContainText('No project members found', { timeout: 10_000 });
    const api = await bearer(ownerToken, 'GET', `/api/v1/projects/${projectId}/share-recipients?q=share`);
    expect(api.status).toBe(200);
    const names = (api.body.data.recipients as Array<{ username: string }>).map((r) => r.username);
    expect(names).toContain(viewer.username);
    expect(names).not.toContain(outsider.username);
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
});

test('owner shares secret A with the project_viewer at write', async () => {
    await openShareDialog(ownerPage, secretAName);
    const shareStatus = await fillShare(ownerPage, viewer, 'write');
    expect(shareStatus, 'POST /secrets/A/share at write').toBeLessThan(300);
    // SHARE-2: the dialog shows its confirmation, then closes itself (the page used to close
    // it at once, so "Shared!" never rendered).
    await expect(ownerPage.getByRole('dialog')).toContainText('Shared!');
    await expect(ownerPage.getByRole('dialog')).toBeHidden({ timeout: 10_000 });
    await expect(secretRow(ownerPage, secretAName)).toContainText('1 shares', { timeout: 10_000 });
    await expect(secretRow(ownerPage, secretBName)).not.toContainText('shares');

    // A's own share list (secret-scoped, open to the owner) names the viewer at write.
    const shares = await bearer(ownerToken, 'GET', `/api/v1/secrets/${secretA}/shares`);
    expect(shares.status).toBe(200);
    const list = shares.body.data.shares as Array<{ recipient_id: number; permission: string }>;
    expect(list.filter((sh) => sh.recipient_id === viewer.id).map((sh) => sh.permission)).toEqual(['write']);
    // Secret B was not shared.
    const sharesB = await bearer(ownerToken, 'GET', `/api/v1/secrets/${secretB}/shares`);
    expect(sharesB.body.data.shares ?? []).toHaveLength(0);
});

test('the viewer can update the shared secret A in the UI, and B stays read-only', async () => {
    // ── A: the share elevates project_viewer to write on this one secret ──
    const statusA = await editSecretValue(viewerPage, secretAName, valueA1);
    expect(statusA, 'PUT /secrets/A as the elevated viewer').toBe(200);
    await expect(viewerPage.getByRole('dialog')).toBeHidden({ timeout: 10_000 });
    await expect(viewerPage.getByText('Failed to update secret')).toHaveCount(0);
    expect(await readValue(viewerPage, secretA), 'the new value is really stored').toBe(valueA1);
    // The row offers exactly what the write share allows: Rotate yes; Share and Delete no.
    await openProjectSecrets(viewerPage);
    const rowA = secretRow(viewerPage, secretAName);
    await expect(rowA.getByTitle('Rotate')).toBeVisible();
    await expect(rowA.getByTitle('Share')).toHaveCount(0);
    await expect(rowA.getByTitle('Delete')).toHaveCount(0);

    // ── B: nothing shared, so the viewer's role alone decides ──
    // The permission-aware UI (#3047) does not offer Edit or Rotate on a row the viewer cannot
    // update, so the refusal is not reachable through the dialog any more; the server still
    // refuses and says why.
    await expectNoUpdateControls(viewerPage, secretBName);
    const viaApi = await bearer(viewerToken, 'PUT', `/api/v1/secrets/${secretB}`, { value: valueB1 });
    expect(viaApi.status, 'PUT /secrets/B as the un-elevated viewer').toBe(403);
    expect(typeof viaApi.body?.message, 'the refusal carries a reason').toBe('string');
    // The owner still sees B's original value.
    expect(await readValue(ownerPage, secretB)).toBe(valueB0);

    // The elevation is not a role: delete on A is still refused (a share satisfies only
    // secrets.read / secrets.write).
    const del = await bearer(viewerToken, 'DELETE', `/api/v1/secrets/${secretA}`);
    expect(del.status, 'a write share must not allow delete').toBe(403);
});

test("the viewer's detail page offers Edit and Rotate on A, like the row, and edits from it (SHARE-DETAIL-1)", async () => {
    await openProjectSecrets(viewerPage);
    await secretRow(viewerPage, secretAName).getByTitle('View').click();
    const actions = viewerPage.getByTestId('secret-actions');
    await expect(actions).toBeVisible({ timeout: 15_000 });
    // Exactly what the write share allows; Share, Copy, Suspend and Delete stay role-only.
    await expect(actions.getByRole('button', { name: 'Edit', exact: true })).toBeVisible();
    await expect(actions.getByRole('button', { name: 'Rotate', exact: true })).toBeVisible();
    for (const name of ['Share', 'Copy', 'Suspend', 'Delete']) {
        await expect(actions.getByRole('button', { name, exact: true }), name).toHaveCount(0);
    }
    // Edit from the detail page: the value really changes.
    await actions.getByRole('button', { name: 'Edit', exact: true }).click();
    const dialog = viewerPage.getByRole('dialog');
    await expect(dialog).toContainText(`Edit Secret: ${secretAName}`);
    await dialog.locator('#edit-secret-value').fill(valueA3);
    const answered = viewerPage.waitForResponse(
        (r) => /\/api\/v1\/secrets\/\d+$/.test(new URL(r.url()).pathname) && r.request().method() === 'PUT'
    );
    await dialog.getByRole('button', { name: 'Save Changes' }).click();
    expect((await answered).status(), 'PUT /secrets/A from the detail page').toBe(200);
    await expect(viewerPage.getByText('Failed to update secret')).toHaveCount(0);
    expect(await readValue(viewerPage, secretA), 'the detail-page edit is really stored').toBe(valueA3);

    // B was not shared: its detail page offers no Edit or Rotate.
    await openProjectSecrets(viewerPage);
    await secretRow(viewerPage, secretBName).getByTitle('View').click();
    await expect(viewerPage.getByTestId('secret-header')).toContainText(secretBName, { timeout: 15_000 });
    await expect(viewerPage.getByTestId('secret-actions').getByRole('button', { name: 'Edit', exact: true })).toHaveCount(0);
    await expect(viewerPage.getByTestId('secret-actions').getByRole('button', { name: 'Rotate', exact: true })).toHaveCount(0);

    // Put A back to the value the later steps expect (still through the elevation).
    const back = await bearer(viewerToken, 'PUT', `/api/v1/secrets/${secretA}`, { value: valueA1 });
    expect(back.status, 'restore A to its step-2 value').toBe(200);
});

test("a write-share recipient's Suspend is refused with the server's reason (#3001 allowlist)", async () => {
    // The write share is still in place (revoked in the next test). It elevates update and
    // rotate only; suspending would deny every other reader the secret, so the server refuses
    // it and says why instead of a bare 403. The detail view's Suspend button posts to this
    // same route (but window.confirm()s first and shows no error), so assert at the API.
    const res = await bearer(viewerToken, 'POST', `/api/v1/secrets/${secretA}/suspend`, { reason: 'e2e deny service' });
    expect(res.status, 'POST /secrets/A/suspend as a write-share recipient').toBe(403);
    expect(typeof res.body?.message, 'the refusal carries a reason').toBe('string');
    expect(res.body.message).toMatch(/only lets you update its value and metadata or rotate it/i);
    expect(res.body.message).toMatch(/ask a project admin/i);

    // Nothing happened: a suspended secret blocks value reads, and the owner still reads A.
    expect(await readValue(ownerPage, secretA), 'A is still active and readable').toBe(valueA1);
    // And the elevation itself still works (the refusal is per action, not a revoked share).
    const update = await bearer(viewerToken, 'PUT', `/api/v1/secrets/${secretA}`, { value: valueA1 });
    expect(update.status, 'update stays elevated').toBe(200);
});

test('owner revokes the share from Sharing Management: it leaves the list and the viewer is refused again', async () => {
    // SHARE-3: the project-only owner opens Sharing Management. GET /api/v1/shares (global
    // secrets.read) is refused, so the page loads the owner-scoped GET /api/v1/shares/owned.
    const globalList = ownerPage.waitForResponse(
        (r) => new URL(r.url()).pathname === '/api/v1/shares' && r.request().method() === 'GET'
    );
    const ownedList = ownerPage.waitForResponse(
        (r) => new URL(r.url()).pathname === '/api/v1/shares/owned' && r.request().method() === 'GET'
    );
    await ownerPage.goto('/sharing');
    expect((await globalList).status(), 'GET /shares stays a global secrets.read route').toBe(403);
    expect((await ownedList).status(), 'the owner-scoped list is open to a project-only owner').toBe(200);
    await expect(ownerPage.getByRole('heading', { name: 'Shares you created' })).toBeVisible({ timeout: 15_000 });
    await expect(ownerPage.getByText('Failed to load shares')).toHaveCount(0);

    // The row for the share to the viewer, on secret A, created by the owner.
    const row = ownerPage.getByRole('row', { name: new RegExp(`Secret #${secretA}\\b.*${viewer.username}`) });
    await expect(row).toBeVisible();
    await expect(row).toContainText(owner.username);
    // The API agrees: only the owner's shares, and this one is among them.
    const owned = await bearer(ownerToken, 'GET', '/api/v1/shares/owned');
    expect(owned.status).toBe(200);
    const ownedRows = owned.body.data.data as Array<{
        id: number;
        secretId: number;
        recipientId: number;
        createdBy: string;
    }>;
    expect(new Set(ownedRows.map((sh) => sh.createdBy))).toEqual(new Set([owner.username]));
    expect(ownedRows.filter((sh) => sh.secretId === secretA && sh.recipientId === viewer.id)).toHaveLength(1);

    // Revoke in the UI: the row's trash button, then the confirmation.
    await row.getByTitle('Revoke access').click();
    const deleted = ownerPage.waitForResponse(
        (r) => /\/api\/v1\/shares\/\d+$/.test(new URL(r.url()).pathname) && r.request().method() === 'DELETE'
    );
    await ownerPage.getByRole('dialog').getByRole('button', { name: 'Revoke' }).click();
    expect((await deleted).status(), 'DELETE /shares/{id} as the project-only owner').toBeLessThan(300);
    await expect(row).toHaveCount(0, { timeout: 10_000 });
    await expect(ownerPage.getByText('Failed to revoke share')).toHaveCount(0);

    // Gone from A's share list (the server's answer, not a cache).
    const shares = await bearer(ownerToken, 'GET', `/api/v1/secrets/${secretA}/shares`);
    expect(shares.status).toBe(200);
    expect(JSON.stringify(shares.body)).not.toContain(`"recipient_id":${viewer.id}`);
    await openProjectSecrets(ownerPage);
    await expect(secretRow(ownerPage, secretAName)).not.toContainText('shares', { timeout: 10_000 });

    // The elevation is gone in the UI (the row no longer offers Edit or Rotate, #3047) and at
    // the API (403 with a reason), value unchanged.
    await expectNoUpdateControls(viewerPage, secretAName);
    const viaApi = await bearer(viewerToken, 'PUT', `/api/v1/secrets/${secretA}`, { value: valueA2 });
    expect(viaApi.status, 'PUT /secrets/A after the share was revoked').toBe(403);
    expect(typeof viaApi.body?.message === 'string' && viaApi.body.message.length > 0, 'a reason is given').toBe(true);
    expect(
        await readValue(ownerPage, secretA),
        "the viewer's last accepted value survives; the refused one never landed"
    ).toBe(valueA1);

    // Revoke removed exactly the elevation: the viewer still READS A (project_viewer).
    const read = await bearer(viewerToken, 'GET', `/api/v1/secrets/${secretA}`);
    expect(read.status).toBe(200);
});

test('a global admin who owns a secret but is not a project member is told why the share is refused', async () => {
    await openShareDialog(adminPage, secretCName);
    await fillShare(adminPage, viewer, 'read');
    const dialog = adminPage.getByRole('dialog');
    // Not the axios fallback and not a bare 403: the dialog says what is wrong and what to do.
    await expect(dialog).toContainText(OWNER_NOT_MEMBER_MESSAGE, { timeout: 10_000 });
    await expect(dialog).toContainText(OWNER_NOT_MEMBER_ADVICE);
    await expect(dialog).not.toContainText('Request failed with status code');
    await expect(dialog).not.toContainText('Shared!');

    // The same answer at the API, and nothing was created.
    const res = await bearer(adminToken, 'POST', `/api/v1/secrets/${secretC}/share`, {
        recipient_id: viewer.id,
        is_group: false,
        permission: 'read',
    });
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).toMatch(OWNER_NOT_MEMBER_MESSAGE);
    const shares = await bearer(adminToken, 'GET', `/api/v1/secrets/${secretC}/shares`);
    expect(JSON.stringify(shares.body)).not.toContain(viewer.username);
});

test('the global admin still gets the unchanged Sharing Management list', async () => {
    // SHARE-3: global secrets.read keeps GET /api/v1/shares; the page does not switch to the
    // owner-scoped list or label it.
    const globalList = adminPage.waitForResponse(
        (r) => new URL(r.url()).pathname === '/api/v1/shares' && r.request().method() === 'GET'
    );
    await adminPage.goto('/sharing');
    expect((await globalList).status()).toBe(200);
    await expect(adminPage.getByRole('heading', { name: 'Sharing Management' })).toBeVisible({ timeout: 15_000 });
    await expect(adminPage.getByText('Failed to load shares')).toHaveCount(0);
    await expect(adminPage.getByRole('heading', { name: 'Shares you created' })).toHaveCount(0);
});
