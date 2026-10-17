// e2e-server: break_glass=true
//
// web/e2e/demo/08-break-glass-audit.spec.ts -- DEMO-E2E-1 journey 8 of 8: "it is 3 a.m. and production is
// down". The demo's break-glass act (scenario 7 of the catalogue): a read-only member takes emergency
// access with a justification, and the activation -- and its end -- are visible in the audit log, loudly.
//
// The first line of this file is read by scripts/e2e/web-real-smoke.sh: break-glass is off by default (the
// secure default), so the group that runs this file boots with `break_glass.enabled: true`.
//
// WHAT IT GUARDS:
//   1. a project_viewer asks for emergency access on the project's Break-glass tab, with a justification
//      and a 1-hour TTL, and sees it active;
//   2. the audit log shows "Break-glass activated" BY THAT PERSON, and its description carries the
//      granted role and the justification they typed;
//   3. an admin revokes it in the console, and the audit log then shows "Break-glass revoked" too.
//
// real/break-glass.spec.ts owns the tab's own behaviour (countdown, the member vs admin views, outsiders
// refused). This journey is about the audit trail an incident reviewer reads afterwards.
//
// LOGIN BUDGET: harness 1 + admin API 1 + member UI 1 + admin UI 1 = 4 of 10.
import { test, expect, BrowserContext, Page } from '@playwright/test';
import {
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    addProjectMember,
    apiLogin,
    createUser,
    newPersonaPage,
    seedProject,
} from './support';

const contexts: BrowserContext[] = [];

test.afterAll(async () => {
    for (const ctx of contexts) await ctx.close();
});

// auditRow finds a row of the audit log by its event label and a fragment of its description.
function auditRow(page: Page, label: string, description: string) {
    return page
        .getByRole('row')
        .filter({ has: page.getByText(label, { exact: true }) })
        .filter({ hasText: description });
}

test('a break-glass activation and its revocation are visible in the audit log', async ({ browser }) => {
    test.setTimeout(120_000);
    const stamp = Date.now();
    const justification = `prod database down, paging oncall ${stamp}`;

    const adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const project = await seedProject(adminToken);
    const member = await createUser(adminToken, 'bgmember', 'Break Glass Member');
    await addProjectMember(adminToken, project.id, member.id, 'project_viewer');

    const memberPage = await newPersonaPage(browser, member, contexts);
    const adminPage = await newPersonaPage(
        browser,
        { username: ADMIN_USERNAME as string, password: ADMIN_PASSWORD as string },
        contexts
    );

    // 1. The member takes emergency access.
    await memberPage.goto(`/projects/${project.id}/break-glass`);
    await memberPage.getByLabel('Justification').fill(justification);
    await memberPage.getByLabel('How long').selectOption('1h');
    await memberPage.getByRole('button', { name: 'Request emergency access' }).click();
    await expect(memberPage.getByText('Emergency access is active')).toBeVisible({ timeout: 15_000 });
    const activation = memberPage.getByRole('row', { name: new RegExp(justification) });
    await expect(activation.getByText('Active', { exact: true })).toBeVisible();

    // 2. The activation is in the audit log: who, what role, and the justification they gave.
    await expect(async () => {
        await adminPage.goto('/audit');
        await adminPage.getByPlaceholder('Filter by actor…').fill(member.username);
        const row = auditRow(adminPage, 'Break-glass activated', justification);
        await expect(row).toBeVisible({ timeout: 5_000 });
        await expect(row).toContainText(`user ${member.id} self-granted "project_developer"`);
        await expect(row).toContainText(member.username);
    }).toPass({ timeout: 60_000 });

    // 3. An admin revokes it in the console; the revocation is audited as well.
    await adminPage.goto(`/projects/${project.id}/break-glass`);
    const adminRow = adminPage.getByRole('row', { name: new RegExp(justification) });
    await expect(adminRow).toBeVisible({ timeout: 15_000 });
    await adminRow.getByRole('button', { name: 'Revoke' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'Revoke emergency access?', level: 3 })).toBeVisible();
    const revoked = adminPage.waitForResponse(
        (r) => /\/break-glass\/\d+\/revoke$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST'
    );
    await dialog.getByRole('button', { name: 'Revoke' }).click();
    expect((await revoked).status()).toBe(200);
    await expect(adminRow.getByText('Revoked', { exact: true })).toBeVisible({ timeout: 15_000 });

    await expect(async () => {
        await adminPage.goto('/audit');
        await expect(
            adminPage
                .getByRole('row')
                .filter({ has: adminPage.getByText('Break-glass revoked', { exact: true }) })
                .first()
        ).toBeVisible({ timeout: 5_000 });
    }).toPass({ timeout: 60_000 });
});
