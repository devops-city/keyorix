// web/e2e/demo/03-share-expiry-revoke.spec.ts -- DEMO-E2E-1 journey 3 of 8: share a secret with an
// expiry, watch it work, revoke it, and see that a share also ends by itself. Scenario 12 of the demo
// catalogue ("share with expiry + revoke"), through the real UI against a real server.
//
// WHAT IT GUARDS:
//   1. the Share dialog's "Access expires" choice reaches the server (the 201 carries an expires_at about
//      an hour out) and the Sharing page shows a countdown badge for it;
//   2. a WRITE share lifts a project_viewer to editing that one secret (the Edit control appears for the
//      recipient, and their PUT is accepted);
//   3. Revoke on the Sharing page takes the elevation away at once: no Edit control, PUT refused (403);
//   4. a share created with a short expiry stops working BY ITSELF once it passes (PUT refused with no
//      one revoking anything) -- polled, not slept on;
//   5. the audit log names both the share and its revocation.
//
// The recipient is the least-privilege user web-real-smoke.sh seeds (system_viewer + project_viewer on
// the seeded project). The secret is created here, so the harness's own share on e2e-json-blob is untouched.
//
// LOGIN BUDGET: harness 1 + admin API 1 + recipient API 1 + admin UI 1 + recipient UI 1 = 5 of 10.
import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import {
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    LOWPRIV_PASSWORD,
    LOWPRIV_USERNAME,
    type SeedProject,
    apiLogin,
    bearer,
    mustBearer,
    newPersonaPage,
    seedProject,
} from './support';

const stamp = Date.now();
const secretName = `demo-share-${stamp}`;

let adminToken: string;
let recipientToken: string;
let recipientId: number;
let project: SeedProject;
let secretId: number;
let adminPage: Page;
let recipientPage: Page;
const contexts: BrowserContext[] = [];

function secretRow(page: Page) {
    return page.getByRole('row', { name: new RegExp(secretName) });
}

async function openSecrets(page: Page) {
    await page.goto(`/projects/${project.id}/secrets?env=development`);
    await expect(secretRow(page)).toBeVisible({ timeout: 15_000 });
}

// recipientWrites asks the API, as the recipient, to change the secret. 200 = allowed, 403 = refused.
async function recipientWrites(value: string): Promise<number> {
    return (await bearer(recipientToken, 'PUT', `/api/v1/secrets/${secretId}`, { value })).status;
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }: { browser: Browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    project = await seedProject(adminToken);
    const users = (await mustBearer(adminToken, 'GET', '/api/v1/users?page_size=100')).data;
    recipientId = (users.users ?? users.data).find((u: { username: string }) => u.username === LOWPRIV_USERNAME).id;
    secretId = (
        await mustBearer(adminToken, 'POST', '/api/v1/secrets', {
            name: secretName,
            value: `initial-${stamp}`,
            type: 'text',
            project_id: project.id,
            environment_id: project.environments['development'],
        })
    ).data.id as number;
    recipientToken = await apiLogin(LOWPRIV_USERNAME, LOWPRIV_PASSWORD);

    adminPage = await newPersonaPage(
        browser,
        { username: ADMIN_USERNAME as string, password: ADMIN_PASSWORD as string },
        contexts
    );
    recipientPage = await newPersonaPage(browser, { username: LOWPRIV_USERNAME, password: LOWPRIV_PASSWORD }, contexts);
});

test.afterAll(async () => {
    for (const ctx of contexts) await ctx.close();
});

// expectReadOnlyRow: the row's own actions have rendered (View is always offered to a reader), and
// Edit is not among them. Checking View first stops "Edit absent" passing before the actions exist.
async function expectReadOnlyRow(page: Page) {
    await expect(secretRow(page).getByTitle('View')).toBeVisible();
    await expect(secretRow(page).getByTitle('Edit')).toHaveCount(0);
}

test('before any share the recipient can read the project but not edit the secret', async () => {
    await openSecrets(recipientPage);
    await expectReadOnlyRow(recipientPage);
    expect(await recipientWrites('nope-before-share')).toBe(403);
});

test('the owner shares it at write with a 1-hour expiry; the Sharing page shows the countdown', async () => {
    await openSecrets(adminPage);
    await secretRow(adminPage).getByTitle('Share').click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText(`Share "${secretName}"`);
    await dialog.locator('#recipient-input').fill(LOWPRIV_USERNAME);
    await dialog.getByRole('button', { name: `@${LOWPRIV_USERNAME}` }).click();
    await dialog.locator('#permission-select').selectOption('write');
    await dialog.locator('#access-expires-select').selectOption('1h');
    const answered = adminPage.waitForResponse(
        (r) => /\/api\/v1\/secrets\/\d+\/share$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST'
    );
    await dialog.getByRole('button', { name: 'Share', exact: true }).click();
    const response = await answered;
    expect(response.status()).toBe(201);
    const expiresAt = new Date((await response.json()).data.expires_at).getTime();
    expect(expiresAt - Date.now(), 'the share must expire about an hour from now').toBeGreaterThan(50 * 60_000);
    expect(expiresAt - Date.now()).toBeLessThan(61 * 60_000);
    await expect(dialog).toBeHidden({ timeout: 10_000 });

    await adminPage.goto('/sharing');
    const shareRow = adminPage
        .getByRole('row')
        .filter({ has: adminPage.getByTestId('share-secret-name').filter({ hasText: secretName }) });
    await expect(shareRow).toBeVisible({ timeout: 15_000 });
    // "in 59m" (the preset is resolved at submit, so it has already ticked under the hour) or "in 1h".
    await expect(shareRow.getByTitle(/^\d{4}-\d\d-\d\dT/)).toHaveText(/^in (5\d|60)m$|^in 1h$/);
});

test('the recipient can now edit that one secret', async () => {
    await openSecrets(recipientPage);
    await expect(secretRow(recipientPage).getByTitle('Edit')).toBeVisible();
    expect(await recipientWrites(`edited-by-recipient-${stamp}`)).toBe(200);
});

test('the owner revokes it on the Sharing page and the elevation ends at once', async () => {
    await adminPage.goto('/sharing');
    const shareRow = adminPage
        .getByRole('row')
        .filter({ has: adminPage.getByTestId('share-secret-name').filter({ hasText: secretName }) });
    await expect(shareRow).toBeVisible({ timeout: 15_000 });
    await shareRow.getByTitle('Revoke access').click();
    await expect(adminPage.getByText(/Are you sure you want to revoke access/)).toBeVisible();
    const revoked = adminPage.waitForResponse(
        (r) => /\/api\/v1\/shares\/\d+$/.test(new URL(r.url()).pathname) && r.request().method() === 'DELETE'
    );
    await adminPage.getByRole('button', { name: 'Revoke', exact: true }).click();
    expect((await revoked).status()).toBe(204);
    await expect(shareRow).toHaveCount(0, { timeout: 15_000 });

    await openSecrets(recipientPage);
    await expectReadOnlyRow(recipientPage);
    expect(await recipientWrites('nope-after-revoke')).toBe(403);
});

test('a share with a short expiry stops working by itself', async () => {
    // 20 s is long enough that the "works while live" check below cannot lose a race on a slow runner,
    // short enough to wait out. The wait is a poll on the observable effect, not a sleep.
    const expiresAt = new Date(Date.now() + 20_000).toISOString();
    await mustBearer(adminToken, 'POST', `/api/v1/secrets/${secretId}/share`, {
        recipient_id: recipientId,
        is_group: false,
        permission: 'write',
        expires_at: expiresAt,
    });
    expect(await recipientWrites('while-live'), 'the share works while it is live').toBe(200);
    await expect
        .poll(() => recipientWrites('after-expiry'), {
            message: 'once expires_at passes the write must be refused with nobody revoking anything',
            timeout: 60_000,
            intervals: [2_000],
        })
        .toBe(403);
});

test('the audit log names the share and its revocation', async () => {
    await expect(async () => {
        await adminPage.goto('/audit');
        await adminPage.getByPlaceholder('Filter by actor…').fill(ADMIN_USERNAME as string);
        await expect(
            adminPage.getByRole('row', { name: new RegExp(`Shared secret ${secretId} \\("${secretName}"\\)`) }).first()
        ).toBeVisible({ timeout: 5_000 });
        await expect(
            adminPage
                .getByRole('row', { name: new RegExp(`Revoked share of secret ${secretId} \\("${secretName}"\\)`) })
                .first()
        ).toBeVisible({ timeout: 5_000 });
    }).toPass({ timeout: 60_000 });
});
