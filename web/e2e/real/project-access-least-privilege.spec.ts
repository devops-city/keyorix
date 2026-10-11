// web/e2e/real/project-access-least-privilege.spec.ts — PROJ-ACCESS-1: the
// least-privilege persona's view of the app, against a REAL keyorix-server, after
// #2780 and #2781.
//
// WEB-SWEEP-1's ui-route-walk.spec.ts already proves every route is SURVIVABLE for
// this persona — a refusal, never a blank page or a stuck spinner. That is a
// deliberately weak bar, and it had to be: at the time, this persona got a 403 on
// GET /api/v1/projects from every page, and the dashboard reported TOTAL SECRETS 0
// while they could read five, so nothing stronger could have been asserted without
// encoding the bug as expected behaviour. That spec says so in its own header and
// explicitly leaves the dashboard counts out.
//
// This file asserts what is now true: the persona sees their project and their real
// secret count. It is the demo-visible end of #2780, checked the way a user
// experiences it rather than at the API — the server-side tests
// (server/http/project_listing_least_privilege_2780_test.go,
// server/http/dashboard_readable_count_2780_test.go) already cover the endpoints, so
// what this adds is that the UI actually renders those answers.
//
// The persona is scripts/e2e/web-real-smoke.sh's seed_demo_data one: system_viewer
// globally plus project_viewer on the seeded project, which holds 5 secrets (one per
// type the UI offers). The install's own default project has none and the persona is
// not a member of it.
//
// Run via scripts/e2e/web-real-smoke.sh (it boots the backend, seeds, and exports
// the env vars read below), never directly.
import { test, expect, Page } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;
const LOWPRIV_USERNAME = process.env.KEYORIX_E2E_LOWPRIV_USERNAME;
const LOWPRIV_PASSWORD = process.env.KEYORIX_E2E_LOWPRIV_PASSWORD;
const PROJECT_NAME = process.env.KEYORIX_E2E_PROJECT_NAME;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !LOWPRIV_USERNAME || !LOWPRIV_PASSWORD || !PROJECT_NAME) {
    throw new Error(
        'KEYORIX_E2E_{ADMIN,LOWPRIV}_{USERNAME,PASSWORD} and KEYORIX_E2E_PROJECT_NAME are not all ' +
            'set -- run scripts/e2e/web-real-smoke.sh, which bootstraps the accounts, seeds the ' +
            'project and exports them.'
    );
}

async function login(page: Page, username: string, password: string) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(username);
    await page.getByTestId('password-input').fill(password);
    await page.getByTestId('login-button').click();
    await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
}

// settle waits for the page's own queries to land. networkidle alone is not enough:
// React Query renders one tick after a request resolves, so a value read at the
// instant the network goes quiet can still be the placeholder.
async function settle(page: Page) {
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    await page.waitForTimeout(500);
}

// readableSecretCount asks the API, as this same session, how many secrets this
// caller can actually read. The dashboard tile is then compared against THAT rather
// than against a hard-coded 5.
//
// Why: a literal 5 would couple this spec to seed_demo_data's current secret count
// and would pass if both the tile and the seed drifted together. The property the
// tile claims is "the number of secrets you can read", and the endpoint that serves
// that list is the only honest reference for it. The absolute count is asserted too,
// separately and as a fixture sanity check, so a suite where the seeding silently
// failed cannot report a vacuous 0 == 0 pass.
async function readableSecretCount(page: Page): Promise<number> {
    const body = await page.evaluate(async () => {
        const res = await fetch('/api/v1/secrets?page_size=100', { credentials: 'include' });
        return res.ok ? await res.json() : null;
    });
    expect(body, 'GET /api/v1/secrets must answer this session').not.toBeNull();
    return body.data?.total ?? 0;
}

test.describe('least-privilege persona (#2780, #2781)', () => {
    test('the dashboard reports the real readable secret count, not zero', async ({ page }) => {
        await login(page, LOWPRIV_USERNAME, LOWPRIV_PASSWORD);
        await page.goto('/dashboard');
        await settle(page);

        const apiTotal = await readableSecretCount(page);
        expect(apiTotal, 'fixture sanity: seed_demo_data gives this persona five readable secrets').toBe(5);

        const tile = page.getByTestId('stat-card-total-secrets-value');
        await expect(tile).toBeVisible();
        const shown = Number((await tile.innerText()).replace(/[^\d]/g, ''));

        expect(
            shown,
            'TOTAL SECRETS must be the count of what this user can read. Showing 0 to someone ' +
                'reading five is #2780 — and the panel below then says "Create your first secret ' +
                'to get started", which is both wrong and an invitation to an action that fails.'
        ).toBe(apiTotal);

        // The copy that made the wrong number worse. Asserting its absence pins the
        // user-visible consequence, not just the number.
        await expect(
            page.locator('main'),
            'the empty-state prompt must not be shown to a user who already has secrets'
        ).not.toContainText('Create your first secret');
    });

    test('the project switcher and the projects page show the project they belong to', async ({ page }) => {
        await login(page, LOWPRIV_USERNAME, LOWPRIV_PASSWORD);

        // The switcher lives in the layout, so it is on every page — which is why
        // #2780's 403 hit all 36 routes rather than just /projects.
        //
        // Asserted on the switcher's LIST, not its trigger label. The label reads
        // "Select project" whenever the URL carries no /projects/:id, for an admin
        // as much as for this persona (ProjectSwitcher derives currentProject from
        // the path), so a label assertion would not distinguish "no project
        // selected" from "no projects to select" — and it is the second that #2780
        // caused. Opening the dropdown asks the question that actually changed.
        await page.goto('/dashboard');
        await settle(page);
        await page.getByTestId('project-switcher-trigger').click();
        await settle(page);
        await expect(
            page.getByTestId('project-switcher-list'),
            'the switcher offered an EMPTY list while GET /api/v1/projects 403d from every page (#2780)'
        ).toContainText(PROJECT_NAME);
        await page.keyboard.press('Escape');

        await page.goto('/projects');
        await settle(page);
        const main = page.locator('main');
        await expect(main, 'the project this persona is a member of must be listed').toContainText(PROJECT_NAME);
        // The 403 the page used to get was rendered as a backend-is-down message;
        // whatever the copy, neither that nor an empty list is acceptable now.
        await expect(main).not.toContainText('Check that the backend is running');

        // The negative half, asked for in review: the install's OWN default project
        // (seed_demo_data creates its fixture project alongside it, and this persona
        // is a member of only the fixture one) must NOT appear. Without this, the
        // assertion above would pass just as well against an unfiltered list — the
        // exact failure mode #2780's fix had to avoid, and the one a "project A never
        // reveals B" test exists for at every other layer.
        const listed = await main.innerText();
        const names = await page.evaluate(async () => {
            const res = await fetch('/api/v1/projects', { credentials: 'include' });
            if (!res.ok) return null;
            const body = await res.json();
            return (body.data?.projects ?? []).map((p: { name?: string }) => p.name ?? '');
        });
        expect(names, 'GET /api/v1/projects must answer this session').not.toBeNull();
        expect(names, 'exactly the one project this persona is a member of').toEqual([PROJECT_NAME]);
        expect(
            listed.includes('default'),
            'the install default project is not one this persona is a member of, so the page must not show it'
        ).toBe(false);
    });

    test('the read-only persona is not offered New Secret, and the server refuses the create (#3067)', async ({
        page,
    }) => {
        // #2780 originally asserted that this persona SEES "New Secret" with a populated
        // dialog. That predates #3047 (permission-aware UI), which hides write controls
        // from a caller without secrets.write. The persona holds project_viewer
        // (secrets.read + users.read, internal/core/auth_bootstrap.go) plus
        // system_viewer, so it must NOT be able to create: the button is hidden
        // correctly, and the old expectation was stale. What survives of the #2780
        // property is asserted below: the Project and Environment listings the dialog
        // is built from still answer this persona.
        await login(page, LOWPRIV_USERNAME, LOWPRIV_PASSWORD);
        await page.goto('/secrets');
        await settle(page);

        // The list rendered (so a missing button is not just a page that never loaded).
        await expect(page.locator('main')).toContainText('e2e-api-key');
        await expect(
            page.getByRole('button', { name: /new secret/i }),
            'a project_viewer holds no secrets.write, so the UI must not offer New Secret'
        ).toHaveCount(0);

        // The server, not the hidden button, is the authority: the same create the
        // dialog would send must be refused for this session.
        const result = await page.evaluate(async () => {
            const csrf = /(?:^|; )csrf_token=([^;]*)/.exec(document.cookie)?.[1] ?? '';
            const get = async (path: string) => {
                const res = await fetch(path, { credentials: 'include' });
                return res.ok ? await res.json() : null;
            };
            const projects = (await get('/api/v1/projects'))?.data?.projects ?? [];
            const envs = (await get('/api/v1/environments'))?.data?.environments ?? [];
            const res = await fetch('/api/v1/secrets', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf) },
                body: JSON.stringify({
                    name: 'e2e-lowpriv-must-not-create',
                    value: 'x',
                    type: 'text',
                    project_id: projects[0]?.id,
                    environment_id: envs[0]?.id,
                }),
            });
            return { projects: projects.length, envs: envs.length, status: res.status };
        });
        expect(result.projects, 'the Project listing (#2780) still answers this persona').toBeGreaterThanOrEqual(1);
        expect(result.envs, 'the Environment listing (#2780) still answers this persona').toBeGreaterThanOrEqual(1);
        expect(result.status, 'POST /api/v1/secrets by a project_viewer must be refused').toBe(403);
    });

    test('the New Secret dialog has a project and an environment to choose', async ({ page }) => {
        // Driven as the admin, who may create: the dialog itself is still covered.
        await login(page, ADMIN_USERNAME, ADMIN_PASSWORD);
        await page.goto('/secrets');
        await settle(page);

        // Both selects were empty for the least-privilege persona (the Project list came
        // from the 403ing /api/v1/projects, the Environment list from
        // /api/v1/environments, which was gated the same way), so the dialog rejected
        // every submit with a validation message the user could not satisfy (#2780).
        const newSecret = page.getByRole('button', { name: /new secret/i }).first();
        await expect(newSecret).toBeVisible();
        await newSecret.click();
        await settle(page);

        const selects = page.locator('[role="dialog"] select, dialog select, main select');
        const count = await selects.count();
        expect(count, 'the dialog renders its Project and Environment selects').toBeGreaterThanOrEqual(2);

        let populated = 0;
        for (let i = 0; i < count; i++) {
            // Options minus the placeholder row. A select with only a placeholder is
            // the dead end this asserts against.
            if ((await selects.nth(i).locator('option').count()) > 1) populated++;
        }
        expect(
            populated,
            'at least the Project and Environment selects must have something to select — an empty ' +
                'required select is a dialog the user cannot submit (#2780)'
        ).toBeGreaterThanOrEqual(2);
    });

    test("the admin's own dashboard and project list are unchanged", async ({ page }) => {
        // The no-loss half. #2780's fix narrows a listing for scoped callers; it must
        // not narrow anything for an admin, and the dashboard's deployment-wide total
        // for an audit.read holder is deliberately untouched.
        await login(page, ADMIN_USERNAME, ADMIN_PASSWORD);
        await page.goto('/dashboard');
        await settle(page);

        const tile = page.getByTestId('stat-card-total-secrets-value');
        await expect(tile).toBeVisible();
        const shown = Number((await tile.innerText()).replace(/[^\d]/g, ''));
        expect(shown, "an admin's deployment-wide secret count must still be served").toBeGreaterThanOrEqual(5);

        await page.goto('/projects');
        await settle(page);
        await expect(page.locator('main')).toContainText(PROJECT_NAME);
    });

    test('Admin → Users → the persona lists the project they are a member of (#2781)', async ({ page }) => {
        // The admin screen that said "Not a member of any project" for every user on
        // the install, while that project's own Members tab listed them. Checked
        // through the UI as an auditor would: ask the user-detail page who this user
        // is a member of, and compare it with what the project says.
        await login(page, ADMIN_USERNAME, ADMIN_PASSWORD);

        const userID = await page.evaluate(async (username) => {
            const res = await fetch('/api/v1/users?page_size=100', { credentials: 'include' });
            if (!res.ok) return null;
            const body = await res.json();
            const rows = body.data?.users ?? [];
            const match = rows.find((u: { username?: string }) => u.username === username);
            return match ? match.id : null;
        }, LOWPRIV_USERNAME);
        expect(userID, 'the least-privilege user must be findable in the admin user list').not.toBeNull();

        await page.goto(`/admin/users/${userID}`);
        await settle(page);

        const main = page.locator('main');
        await expect(
            main,
            'Project assignments read "Not a member of any project." for EVERY user on a UI-driven ' +
                'install, because it answered from the ADR-022 journal that nothing writes (#2781)'
        ).not.toContainText('Not a member of any project');
        await expect(main, 'the project this user holds a project_viewer grant in must be named').toContainText(
            PROJECT_NAME
        );
    });
});
