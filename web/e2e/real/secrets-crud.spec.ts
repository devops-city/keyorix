// web/e2e/real/secrets-crud.spec.ts — SESSION-WEB-E2E item 2: the secrets
// lifecycle through the real Profile → Projects → Secrets UI (no mocked
// routes, real backend via scripts/e2e/web-real-smoke.sh): create a project
// and environment, create a secret, confirm its value is never visible
// before an explicit reveal (and never appears in the page URL), update it
// (rotate), reveal the current value, walk Version History, roll back, then
// delete and restore it from the project's recycle bin.
//
// WEB-FIX1 (#2450): Reveal used to crash the whole page unconditionally (see
// the second test below) -- GET .../versions never returns a value field,
// but the old Reveal handler atob()-decoded it anyway. Fixed in
// web/src/features/secrets/SecretDetailView.tsx (now fetches the plaintext
// from GET /secrets/{id}?include_value=true via the new useSecretValue
// hook). That fix is what makes Version History and rollback reachable
// through this test at all -- both are gated behind the same showValue
// state Reveal controls -- so this file now exercises the full lifecycle
// the item originally asked for, not just the create/update/delete/restore
// subset the bug allowed.
import { test, expect, Page } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

async function realLogin(page: Page) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });
}

// createProjectEnvAndSecret drives the UI through project creation, an
// explicit custom environment, and a secret in it -- shared setup for both
// tests below. Returns the project's base URL and the created secret's name.
async function createProjectEnvAndSecret(
    page: Page,
    opts: { projectName: string; envName: string; secretName: string; value: string }
): Promise<string> {
    await page.goto('/projects');
    await page.getByRole('button', { name: 'New Project' }).click();
    await page.locator('#create-project-name').fill(opts.projectName);
    await page.getByRole('button', { name: 'Create Project' }).click();
    await page.waitForURL(/\/projects\/\d+(\/secrets)?$/, { timeout: 15_000 });
    const projectUrl = page.url().replace(/\/secrets$/, '');

    await page.goto(`${projectUrl}/settings`);
    await page.getByPlaceholder('New environment name…').fill(opts.envName);
    await page.getByRole('button', { name: 'Add' }).click();
    await expect(page.getByText(opts.envName, { exact: false })).toBeVisible({ timeout: 10_000 });

    await page.goto(`${projectUrl}/secrets`);
    await page.getByRole('button', { name: new RegExp(`^${opts.envName}$`, 'i') }).click();
    await expect(page).toHaveURL(new RegExp(`env=${opts.envName}`), { timeout: 10_000 });

    // Two "New Secret" buttons render at once for a freshly-created, empty
    // environment: one in the toolbar, one in the empty-state panel
    // (web/src/pages/projects/ProjectSecretsTab.tsx) -- .first() is the
    // toolbar one, deliberately, so this still works once the environment is
    // no longer empty (the empty-state button disappears, the toolbar one
    // doesn't).
    await page.getByRole('button', { name: 'New Secret' }).first().click();
    // The create-secret modal's own context badge confirms it really is
    // scoped to the environment just switched to, not whatever was active
    // before. Scoped to the dialog as a whole, not the "Environment:" label
    // span itself -- that label and the env name are two separate sibling
    // spans, not one text node.
    await expect(page.getByRole('dialog')).toContainText(opts.envName, { ignoreCase: true });
    await page.locator('#create-secret-name').fill(opts.secretName);
    await page.locator('#create-secret-value').fill(opts.value);
    await page.getByRole('button', { name: 'Create Secret' }).click();
    await expect(page.getByRole('dialog')).toBeHidden({ timeout: 10_000 });

    return projectUrl;
}

test('secrets lifecycle: project/env creation, reveal gating, update, delete, restore', async ({ page }) => {
    // Auto-accept every window.confirm() this flow triggers (suspend) --
    // this is Playwright's own browser context under full test automation,
    // not an interactive session, so there is no "blocks all further
    // events" hazard the way there is for the claude-in-chrome extension;
    // page.on('dialog', ...) is the standard way Playwright tests handle
    // confirm()/alert().
    page.on('dialog', (d) => d.accept());

    // The secret detail modal (web/src/features/secrets/SecretDetailView.tsx)
    // has no internal scroll container -- same real, no-scroll-on-tall-content
    // gap as the "New User" modal (see access-control.spec.ts's own comment
    // on this), and this view has many panels (header, value, accessors,
    // recent access, description, tags, audit trail, risk score,
    // dependencies, metadata, sharing, permissions) so it overflows a
    // standard viewport even more readily. Folded into SESSION-WEB-E2E's J36
    // UI-polish report; worked around here with a taller viewport.
    await page.setViewportSize({ width: 1280, height: 2600 });

    const unique = Date.now();
    const projectName = `e2e-secrets-${unique}`;
    const envName = `e2eenv${unique}`;
    const secretName = `e2e-secret-${unique}`;
    const originalValue = `original-value-${unique}-${Math.random().toString(36).slice(2)}`;
    const rotatedValue = `rotated-value-${unique}-${Math.random().toString(36).slice(2)}`;

    await realLogin(page);
    const projectUrl = await createProjectEnvAndSecret(page, {
        projectName,
        envName,
        secretName,
        value: originalValue,
    });

    // The value must never appear in the plain row/list view.
    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await expect(row).toBeVisible();
    await expect(page.locator('body')).not.toContainText(originalValue);

    // ── Open the detail view: value must be hidden, no reveal clicked here ──
    await row.getByTitle('View').click();
    await expect(page.getByRole('heading', { name: 'Secret Value' })).toBeVisible();
    await expect(page.getByText('Secret value is hidden for security')).toBeVisible();
    await expect(page.locator('body')).not.toContainText(originalValue);
    expect(page.url(), 'the secret value must never appear in the page URL').not.toContain(originalValue);

    // No request for the version data (which is what Reveal would normally
    // fetch) has been made -- confirms the value was never even requested,
    // not just hidden client-side.
    let versionsRequests = 0;
    page.on('request', (req) => {
        if (/\/secrets\/\d+\/versions/.test(req.url())) versionsRequests++;
    });

    // ── Update (rotate), without ever revealing ─────────────────────────────
    // Deliberately NOT clicking Reveal first -- Rotate is reachable directly
    // from the detail header regardless of reveal state.
    await page.getByRole('button', { name: 'Rotate', exact: true }).click();
    await page.getByLabel('New value').fill(rotatedValue);
    await page.getByRole('button', { name: 'Rotate secret' }).click();
    await expect(page.getByText(`Rotate ${secretName}`)).not.toBeVisible({ timeout: 10_000 });
    expect(versionsRequests, 'rotating a secret never requires fetching its value').toBe(0);

    // ── Reveal: shows the CURRENT (rotated) value, not the original ────────
    // WEB-FIX1 (#2450): this is the exact action that used to crash the
    // whole page, unconditionally, for every secret.
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    await expect(page.getByText(rotatedValue, { exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('body')).not.toContainText(originalValue);

    // ── Version History: both versions listed, current one marked ──────────
    // exact: true throughout -- envName embeds a raw timestamp (e2eenv1790...),
    // which can coincidentally contain "v1"/"v2"/"v3" as a substring, and a
    // non-exact getByText matches that too (confirmed live: a bare
    // getByText('v1') strict-mode-violated against the environment-name text).
    await expect(page.getByText('Version History', { exact: true })).toBeVisible();
    await expect(page.getByText('v1', { exact: true })).toBeVisible();
    const v2Row = page.getByText('v2', { exact: true }).locator('..');
    await expect(v2Row.getByText('current', { exact: true })).toBeVisible();

    // ── Roll back to v1: re-instates the ORIGINAL value as a new version ───
    await page.getByRole('button', { name: 'Roll back', exact: true }).click();
    await expect(page.getByText('Rolling back…')).toHaveCount(0, { timeout: 10_000 });
    // Rollback force-hides the value (SecretDetailView's onSuccess handler) --
    // re-reveal to confirm the original content actually came back.
    await expect(page.getByText('Secret value is hidden for security')).toBeVisible();
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    await expect(page.getByText(originalValue, { exact: true })).toBeVisible({ timeout: 10_000 });
    // Three versions now: v1 (original), v2 (rotated), v3 (rollback's copy of v1).
    await expect(page.getByText('v3', { exact: true })).toBeVisible();

    // ── Delete, then restore from the project's recycle bin ─────────────────
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('Delete Secret')).toBeVisible();
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('Delete Secret')).not.toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole('row', { name: new RegExp(secretName) })).toHaveCount(0);

    await page.goto(`${projectUrl}/settings`);
    // #2788: getByText('Recycle bin') is a case-insensitive SUBSTRING match, so it also hit the
    // "Recycle bin is empty." placeholder. ProjectSettingsTab renders that placeholder for as
    // long as the deleted-secrets query is still loading (`data: deletedSecrets = []`), i.e.
    // right after page.goto, and a strict-mode violation (two matches) throws immediately
    // instead of being retried. Target the heading by role; the recycleRow wait below is what
    // actually covers the query finishing.
    await expect(page.getByRole('heading', { name: 'Recycle bin', exact: true })).toBeVisible();
    const recycleRow = page.locator('li', { hasText: secretName });
    await expect(recycleRow).toBeVisible({ timeout: 10_000 });
    await recycleRow.getByRole('button', { name: 'Restore' }).click();
    await expect(recycleRow).toHaveCount(0, { timeout: 10_000 });

    await page.goto(`${projectUrl}/secrets?env=${envName}`);
    await expect(page.getByRole('row', { name: new RegExp(secretName) })).toBeVisible({ timeout: 10_000 });

    // DEMO-UI-2: the restore event names the secret (it used to say only "secret 12 restored").
    await page.goto('/audit');
    await expect(page.getByText(new RegExp(`secret \\d+ \\("${secretName}"\\) restored`)).first()).toBeVisible({
        timeout: 15_000,
    });
});

test('revealing a secret value shows the plaintext without crashing the page (regression test for #2450)', async ({
    page,
}) => {
    // https://github.com/keyorixhq/keyorix/issues/2450 -- FIXED by WEB-FIX1.
    // Root cause: the versions endpoint Reveal used to read from (GET
    // /secrets/{id}/versions) can never return a value field at all
    // (internal/storage/models.SecretVersion's EncryptedValue is tagged
    // `json:"-"`), but the old Reveal handler called atob() on that
    // always-undefined field unconditionally. atob(undefined) coerces to the
    // literal string "undefined", which is not valid base64, so it threw and
    // the nearest route error boundary replaced the whole page with "Page
    // failed to load." Fixed in web/src/features/secrets/SecretDetailView.tsx
    // (now fetches the plaintext via the new useSecretValue hook, GET
    // /secrets/{id}?include_value=true -- the endpoint that actually returns
    // a value). This test is deliberately narrow and standalone (one secret,
    // one reveal) as a focused regression check, separate from the first
    // test's broader lifecycle coverage (which also now exercises reveal,
    // Version History, and rollback as part of the full flow).
    await page.setViewportSize({ width: 1280, height: 2600 });

    const unique = Date.now();
    const projectName = `e2e-reveal-crash-${unique}`;
    const envName = `e2eenv${unique}`;
    const secretName = `e2e-secret-${unique}`;
    const value = `value-${unique}`;

    await realLogin(page);
    await createProjectEnvAndSecret(page, { projectName, envName, secretName, value });

    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await row.getByTitle('View').click();

    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    await expect(page.locator('body')).toContainText(value, { timeout: 10_000 });
    // The page must still be the real secret detail view, not a crashed
    // RouteErrorBoundary fallback.
    await expect(page.getByText('Page failed to load')).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Secret Value' })).toBeVisible();
});

// DEMO-UI-2: the History and Recent access panels must follow the secret's own
// mutations without a reload. Before, History kept showing only "Created" after
// a rotation and Recent access never learned about a Reveal until a manual refresh.
test('secret detail History and Recent access update after rotate and reveal, without a reload', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 2600 });

    const unique = Date.now();
    const secretName = `e2e-secret-${unique}`;
    const envName = `e2eenv${unique}`;

    await realLogin(page);
    await createProjectEnvAndSecret(page, {
        projectName: `e2e-history-${unique}`,
        envName,
        secretName,
        value: `value-${unique}`,
    });

    await page
        .getByRole('row', { name: new RegExp(secretName) })
        .getByTitle('View')
        .click();

    const history = page.locator('div', { has: page.getByRole('heading', { name: 'History', exact: true }) }).last();
    await expect(history.getByText('Created', { exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(history.getByText('Rotated', { exact: true })).toHaveCount(0);

    await page.getByRole('button', { name: 'Rotate', exact: true }).click();
    await page.getByLabel('New value').fill(`rotated-${unique}`);
    await page.getByRole('button', { name: 'Rotate secret' }).click();
    await expect(page.getByText(`Rotate ${secretName}`)).not.toBeVisible({ timeout: 10_000 });
    // No reload, no navigation: the rotation shows up in History by itself.
    await expect(history.getByText('Rotated', { exact: true })).toBeVisible({ timeout: 10_000 });

    // Reveal is a read: it lands in Recent access and History without a refresh.
    const recent = page
        .locator('div', { has: page.getByRole('heading', { name: 'Recent access', exact: true }) })
        .last();
    await expect(recent.getByText(/^Rotated/)).toBeVisible({ timeout: 10_000 });
    // Opening the view may already log reads; what matters is that Reveal adds one without a refresh.
    const readsBefore = await recent.getByText(/^Read/).count();
    const historyReadsBefore = await history.getByText('Read', { exact: true }).count();
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    await expect(page.getByText(`rotated-${unique}`, { exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(recent.getByText(/^Read/)).toHaveCount(readsBefore + 1, { timeout: 10_000 });
    await expect(history.getByText('Read', { exact: true })).toHaveCount(historyReadsBefore + 1, { timeout: 10_000 });
});
