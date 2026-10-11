// web/e2e/real/secrets-table-layout.spec.ts — #2977: the first-minute display
// defects of the secrets screens, driven through the real UI against a real
// backend (scripts/e2e/web-real-smoke.sh):
//
//   1. project Secrets table: every header sits over its own column (the
//      Classification header was missing, so ENVIRONMENT sat over the
//      classification badge, SHARING over the environment, MODIFIED over
//      "Private");
//   2. secret detail header says "Rotated …" (not "Never rotated") right after a
//      rotation done in that view;
//   3. the detail header's action buttons stay inside the modal at 1366 px
//      (they overflowed and "Suspend" was cut off).
//
// With KEYORIX_E2E_SHOT_DIR set the spec also writes screenshots there, so a
// before/after pair can be compared by running it on both sides of the fix.
import { test, expect, Page, Locator } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

async function shot(target: Page | Locator, name: string) {
    const dir = process.env.KEYORIX_E2E_SHOT_DIR;
    if (dir) await target.screenshot({ path: `${dir}/${name}.png` });
}

async function realLogin(page: Page) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });
}

test('secrets table headers, rotation label and action bar at 1366 px', async ({ page }) => {
    await page.setViewportSize({ width: 1366, height: 900 });

    const unique = Date.now();
    const projectName = `e2e-layout-${unique}`;
    const envName = `e2elayout${unique}`;
    const secretName = `e2e-layout-secret-${unique}`;

    await realLogin(page);

    // ── Project, environment, secret (same UI path as secrets-crud.spec.ts) ──
    await page.goto('/projects');
    await page.getByRole('button', { name: 'New Project' }).click();
    await page.locator('#create-project-name').fill(projectName);
    await page.getByRole('button', { name: 'Create Project' }).click();
    await page.waitForURL(/\/projects\/\d+(\/secrets)?$/, { timeout: 15_000 });
    const projectUrl = page.url().replace(/\/secrets$/, '');

    await page.goto(`${projectUrl}/settings`);
    await page.getByPlaceholder('New environment name…').fill(envName);
    await page.getByRole('button', { name: 'Add' }).click();
    await expect(page.getByText(envName, { exact: false })).toBeVisible({ timeout: 10_000 });

    await page.goto(`${projectUrl}/secrets`);
    await page.getByRole('button', { name: new RegExp(`^${envName}$`, 'i') }).click();
    await expect(page).toHaveURL(new RegExp(`env=${envName}`), { timeout: 10_000 });
    await page.getByRole('button', { name: 'New Secret' }).first().click();
    await page.locator('#create-secret-name').fill(secretName);
    await page.locator('#create-secret-value').fill(`layout-value-${unique}`);
    await page.getByRole('button', { name: 'Create Secret' }).click();
    await expect(page.getByRole('dialog')).toBeHidden({ timeout: 10_000 });

    // ── 1. every header sits over its own column ─────────────────────────────
    const table = page.locator('table').first();
    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await expect(row).toBeVisible();
    await shot(table, 'secrets-table');

    const headers = (await table.locator('thead th').allTextContents()).map((h) => h.trim());
    const cells = await row.locator('td').allTextContents();
    expect(cells.length, `header/cell count mismatch: ${JSON.stringify(headers)} vs ${JSON.stringify(cells)}`).toBe(
        headers.length
    );
    const cellUnder = (header: string) => cells[headers.indexOf(header)] ?? '';
    expect(headers).toContain('Classification');
    expect(cellUnder('Classification')).toMatch(/Unclassified|Public|Internal|Confidential|Restricted/);
    expect(cellUnder('Environment').toLowerCase()).toContain(envName.toLowerCase());
    expect(cellUnder('Sharing')).toMatch(/Private|share/i);

    // ── 2./3. detail header ─────────────────────────────────────────────────
    await row.getByTitle('View').click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByTestId('secret-actions')).toBeVisible();
    await expect(dialog.getByText('Never rotated', { exact: true })).toBeVisible();

    const dialogBox = (await dialog.boundingBox())!;
    for (const button of await dialog.getByTestId('secret-actions').getByRole('button').all()) {
        const box = (await button.boundingBox())!;
        const label = (await button.textContent())?.trim();
        expect(box.x, `${label} starts left of the modal`).toBeGreaterThanOrEqual(dialogBox.x - 1);
        expect(box.x + box.width, `${label} overflows the modal's right edge`).toBeLessThanOrEqual(
            dialogBox.x + dialogBox.width + 1
        );
    }
    await shot(page, 'detail-before-rotate');

    await dialog.getByRole('button', { name: 'Rotate', exact: true }).click();
    await page.getByLabel('New value').fill(`layout-rotated-${unique}`);
    await page.getByRole('button', { name: 'Rotate secret' }).click();
    await expect(page.getByText(`Rotate ${secretName}`)).not.toBeVisible({ timeout: 10_000 });

    await expect(dialog.getByText('Never rotated', { exact: true })).toHaveCount(0);
    await expect(dialog.getByTestId('secret-meta').getByText(/^Rotated /)).toBeVisible();
    await shot(page, 'detail-after-rotate');
});
