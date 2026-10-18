// web/e2e/demo/02-secret-lifecycle.spec.ts -- DEMO-E2E-1 journey 2 of 8: a secret's life in the console:
// create, rotate, read the version history, roll back. The demo's "secrets" act, through the real UI
// against a real server.
//
// WHAT IT GUARDS (docs/demo.md "secret lifecycle"):
//   1. a created secret is listed, and its value is not in the page until someone clicks Reveal;
//   2. Rotate works without ever fetching the value (no /versions request before Reveal);
//   3. Reveal shows the ROTATED value, never the original;
//   4. Version History lists v1 and v2, v2 marked current;
//   5. Roll back to v1 re-instates the original value as a NEW version (v3) and hides the value again;
//   6. the server agrees: the API returns three versions and the original value as the current one.
//
// It uses the project and "development" environment web-real-smoke.sh seeds, so it does not spend time
// re-driving project/environment creation (real/secrets-crud.spec.ts owns that).
//
// LOGIN BUDGET: harness 1 + seeding 0 + this spec's API login 1 + UI login 1 = 3 of 10.
import { test, expect } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME, apiLogin, bearer, realLogin, seedProject } from './support';

test('create, rotate, history and rollback of a secret through the console', async ({ page }) => {
    test.setTimeout(90_000);
    // The secret detail modal has no internal scroll container and many panels (see
    // real/secrets-crud.spec.ts): a tall viewport keeps every control reachable.
    await page.setViewportSize({ width: 1280, height: 2600 });

    const stamp = Date.now();
    const secretName = `demo-secret-${stamp}`;
    const originalValue = `original-value-${stamp}`;
    const rotatedValue = `rotated-value-${stamp}`;

    const adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const project = await seedProject(adminToken);
    await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);

    // 1. Create it in the development environment.
    await page.goto(`/projects/${project.id}/secrets?env=development`);
    await page.getByRole('button', { name: 'New Secret' }).first().click();
    await expect(page.getByRole('dialog')).toContainText('development', { ignoreCase: true });
    await page.locator('#create-secret-name').fill(secretName);
    await page.locator('#create-secret-value').fill(originalValue);
    await page.getByRole('button', { name: 'Create Secret' }).click();
    await expect(page.getByRole('dialog')).toBeHidden({ timeout: 10_000 });

    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await expect(row).toBeVisible();
    await expect(page.locator('body')).not.toContainText(originalValue);

    // 2. Open it: hidden until Reveal. Count requests for the version data (what Reveal fetches).
    await row.getByTitle('View').click();
    await expect(page.getByRole('heading', { name: 'Secret Value' })).toBeVisible();
    await expect(page.getByText('Secret value is hidden for security')).toBeVisible();
    await expect(page.locator('body')).not.toContainText(originalValue);
    expect(page.url(), 'the secret value must never appear in the page URL').not.toContain(originalValue);

    let versionsRequests = 0;
    page.on('request', (req) => {
        if (/\/secrets\/\d+\/versions/.test(req.url())) versionsRequests++;
    });

    // 3. Rotate without revealing.
    await page.getByRole('button', { name: 'Rotate', exact: true }).click();
    await page.getByLabel('New value').fill(rotatedValue);
    await page.getByRole('button', { name: 'Rotate secret' }).click();
    await expect(page.getByText(`Rotate ${secretName}`)).not.toBeVisible({ timeout: 10_000 });
    expect(versionsRequests, 'rotating a secret never requires fetching its value').toBe(0);

    // 4. Reveal: the rotated value, not the original; history has v1 and v2 (current).
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    await expect(page.getByText(rotatedValue, { exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('body')).not.toContainText(originalValue);
    await expect(page.getByText('Version History', { exact: true })).toBeVisible();
    await expect(page.getByText('v1', { exact: true })).toBeVisible();
    const v2Row = page.getByText('v2', { exact: true }).locator('..');
    await expect(v2Row.getByText('current', { exact: true })).toBeVisible();

    // 5. Roll back to v1: the value is hidden again, and the original is back as v3.
    await page.getByRole('button', { name: 'Roll back', exact: true }).click();
    await expect(page.getByText('Rolling back…')).toHaveCount(0, { timeout: 10_000 });
    await expect(page.getByText('Secret value is hidden for security')).toBeVisible();
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    await expect(page.getByText(originalValue, { exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('v3', { exact: true })).toBeVisible();

    // 6. The server agrees with the screen.
    const id = (await bearer(adminToken, 'GET', `/api/v1/secrets?project_id=${project.id}`)).body.data.secrets.find(
        (s: { name: string }) => s.name === secretName
    ).id as number;
    const versions = (await bearer(adminToken, 'GET', `/api/v1/secrets/${id}/versions`)).body.data.versions as {
        VersionNumber: number;
    }[];
    expect(versions.map((v) => v.VersionNumber).sort((a, b) => a - b)).toEqual([1, 2, 3]);
    const current = await bearer(adminToken, 'GET', `/api/v1/secrets/${id}?include_value=true`);
    expect(current.body.data.value ?? current.body.data.secret?.value).toBe(originalValue);
});
