// web/e2e/demo/04-machine-identity-token.spec.ts -- DEMO-E2E-1 journey 4 of 8: a machine identity for a
// CI runner, its one-time token, a read with that token, and revoking the token. The demo's "CI without
// a person" act, through the real UI against a real server.
//
// WHAT IT GUARDS:
//   1. the project's Members tab creates a machine identity and lists it as active;
//   2. issuing a token shows the raw token ONCE, in a dialog, and the list keeps only its prefix;
//   3. the token authenticates a read of a secret (HTTP 200, the right value) -- after a role is granted;
//   4. the read is audited AS THE MACHINE IDENTITY (actor = its name, flagged "machine"), and the
//      creation and the token issue are in the log too;
//   5. revoking the token in the UI ends it: the same token is refused (401) from then on.
//
// A machine identity has no role when it is created, and the console has no control for granting one
// (POST /api/v1/projects/{id}/machine-identities/{id}/roles is API/CLI only), so that one step is done
// through the API as setup, with the project_viewer role. Nothing else in this journey is shortcut.
//
// LOGIN BUDGET: harness 1 + admin API 1 + admin UI 1 = 3 of 10.
import { test, expect } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME, apiLogin, bearer, mustBearer, realLogin, seedProject } from './support';

test('create a machine identity, issue its token, read with it, see it audited, revoke it', async ({ page }) => {
    test.setTimeout(90_000);
    const stamp = Date.now();
    const identityName = `demo-ci-${stamp}`;
    const tokenName = `ci-token-${stamp}`;
    const secretName = `demo-ci-secret-${stamp}`;
    const secretValue = `ci-readable-${stamp}`;

    const adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const project = await seedProject(adminToken);
    const secretId = (
        await mustBearer(adminToken, 'POST', '/api/v1/secrets', {
            name: secretName,
            value: secretValue,
            type: 'text',
            project_id: project.id,
            environment_id: project.environments['development'],
        })
    ).data.id as number;
    const roles = (await mustBearer(adminToken, 'GET', '/api/v1/roles')).data.roles as { id: number; name: string }[];
    const viewerRoleId = roles.find((r) => r.name === 'project_viewer')?.id as number;

    await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);

    // 1. Create the identity on the project's Members tab.
    await page.goto(`/projects/${project.id}/members`);
    const nameInput = page.getByPlaceholder('Machine identity name…');
    await nameInput.fill(identityName);
    const created = page.waitForResponse(
        (r) =>
            new URL(r.url()).pathname === `/api/v1/projects/${project.id}/machine-identities` &&
            r.request().method() === 'POST'
    );
    // The input, the type select and the Add button are siblings in one row.
    await nameInput.locator('..').getByRole('button', { name: 'Add' }).click();
    const createdResponse = await created;
    expect(createdResponse.status()).toBe(201);
    const machineId = (await createdResponse.json()).data.machine_identity.id as number;

    const identityRow = page.getByRole('listitem').filter({ hasText: identityName });
    await expect(identityRow).toBeVisible();
    await expect(identityRow.getByText('active', { exact: true })).toBeVisible();

    // The identity cannot read anything until it holds a role (setup through the API, see the header).
    await mustBearer(adminToken, 'POST', `/api/v1/projects/${project.id}/machine-identities/${machineId}/roles`, {
        role_id: viewerRoleId,
    });

    // 2. Issue a token: shown once, in a dialog.
    await page.getByRole('button', { name: `Toggle tokens for ${identityName}` }).click();
    await page.getByPlaceholder('Token name…').fill(tokenName);
    const issued = page.waitForResponse(
        (r) => /\/machine-identities\/\d+\/tokens$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST'
    );
    await page.getByRole('button', { name: 'Issue token' }).click();
    expect((await issued).status()).toBe(201);
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Machine token issued');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('shown once and cannot be retrieved again')).toBeVisible();
    const token = ((await dialog.locator('code').innerText()) ?? '').trim();
    expect(token, 'the dialog must show a machine token').toMatch(/^kx_machine_/);
    await dialog.getByRole('button', { name: 'Done' }).click();
    await expect(dialog).toBeHidden();

    // The list keeps only the prefix and the name, never the token.
    const tokenItem = identityRow.locator('li').filter({ hasText: tokenName });
    await expect(tokenItem).toBeVisible();
    await expect(tokenItem).toContainText(token.slice(0, 'kx_machine_'.length + 4));
    await expect(page.locator('body')).not.toContainText(token);

    // 3. The token reads the secret.
    const read = await bearer(token, 'GET', `/api/v1/secrets/${secretId}?include_value=true`);
    expect(read.status).toBe(200);
    expect(read.body.data.value).toBe(secretValue);

    // 4. The audit log shows the read AS the machine identity, and the lifecycle around it.
    await expect(async () => {
        await page.goto('/audit');
        const readRow = page
            .getByRole('row')
            .filter({ hasText: `Machine identity ${identityName} read secret ${secretName}` });
        await expect(readRow).toBeVisible({ timeout: 5_000 });
        await expect(readRow.getByText('machine', { exact: true })).toBeVisible();
        await expect(
            page.getByRole('row').filter({ hasText: `created machine identity "${identityName}"` })
        ).toBeVisible({ timeout: 5_000 });
        await expect(
            page.getByRole('row').filter({ hasText: `issued token for machine identity "${identityName}"` })
        ).toBeVisible({ timeout: 5_000 });
    }).toPass({ timeout: 60_000 });

    // 5. Revoke the token in the UI (a browser confirm()), and the server refuses it from then on.
    page.once('dialog', (d) => d.accept());
    await page.goto(`/projects/${project.id}/members`);
    await page.getByRole('button', { name: `Toggle tokens for ${identityName}` }).click();
    const revoked = page.waitForResponse(
        (r) =>
            /\/machine-identities\/\d+\/tokens\/\d+$/.test(new URL(r.url()).pathname) &&
            r.request().method() === 'DELETE'
    );
    const revokedRow = page
        .getByRole('listitem')
        .filter({ hasText: identityName })
        .locator('li')
        .filter({ hasText: tokenName });
    await revokedRow.getByTitle('Revoke token').click();
    expect((await revoked).status()).toBe(200);
    await expect(revokedRow.getByText('revoked')).toBeVisible();

    const after = await bearer(token, 'GET', `/api/v1/secrets/${secretId}?include_value=true`);
    expect(after.status, 'a revoked machine token must be refused').toBe(401);
});
