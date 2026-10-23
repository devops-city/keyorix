// web/e2e/real/group-role-scope.spec.ts — GROUP-ROLE-SCOPE-1 (#3546),
// DEMO-WALK-4 against a real server. The group "Manage Roles" modal used to
// post {role_id} with no project_id, and the server stored the grant at the
// global scope, so every member became a project_developer of EVERY project.
//
// The admin opens Manage Roles on a fresh group and:
//   1. checks project_developer with "All projects (global)": the modal refuses
//      it before sending anything;
//   2. the server refuses the same request made directly (400, no grant);
//   3. picks the project and checks it again: the grant lands.
import { test, expect, request as apiRequestFactory } from '@playwright/test';
import { randomInt } from 'node:crypto';
import { ADMIN_PASSWORD, ADMIN_USERNAME, BACKEND_URL, apiLogin, realLogin } from './helpers';

test('a project role is granted to a group only with a project', async ({ page }) => {
    const stamp = randomInt(1_000_000);
    const token = await apiLogin(ADMIN_USERNAME!, ADMIN_PASSWORD!);
    const api = await apiRequestFactory.newContext({
        baseURL: BACKEND_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}` },
    });
    try {
        const project = await api.post('/api/v1/projects', { data: { name: `grs-${stamp}`, description: 'e2e' } });
        expect(project.ok(), await project.text()).toBeTruthy();
        const projectBody = await project.json();
        const projectId: number = projectBody.data?.id ?? projectBody.data?.project?.id;
        const projectName: string = projectBody.data?.name ?? `grs-${stamp}`;

        const group = await api.post('/api/v1/groups', { data: { name: `grs-group-${stamp}`, description: 'e2e' } });
        expect(group.ok(), await group.text()).toBeTruthy();
        const groupId: number = (await group.json()).data.id;

        const roles = await api.get('/api/v1/roles');
        const roleList = (await roles.json()).data;
        const devRole = (Array.isArray(roleList) ? roleList : roleList.roles).find(
            (r: { name: string }) => r.name === 'project_developer'
        );
        expect(devRole, 'the built-in project_developer role exists').toBeTruthy();

        // 2. The server refuses the DEMO-WALK-4 request itself and writes nothing.
        const refused = await api.post(`/api/v1/groups/${groupId}/roles`, { data: { role_id: devRole.id } });
        expect(refused.status()).toBe(400);
        expect(await refused.text()).toContain('role project_developer is project-scoped');
        const before = await (await api.get(`/api/v1/groups/${groupId}/roles`)).json();
        expect(before.data.roles ?? []).toHaveLength(0);

        // 1. The modal refuses it client-side, with a message saying what to do.
        await realLogin(page, ADMIN_USERNAME!, ADMIN_PASSWORD!);
        await page.goto('/admin/groups');
        const row = page.getByRole('row', { name: new RegExp(`grs-group-${stamp}`) });
        await row.getByTitle('Manage roles').click();
        const dialog = page.getByRole('dialog');
        await dialog.getByRole('checkbox', { name: /project_developer/ }).click();
        await expect(dialog.getByRole('alert')).toContainText('project_developer is a project role');

        // 3. With the project chosen, the grant lands.
        await dialog.getByLabel('Project', { exact: true }).selectOption(String(projectId));
        await dialog.getByRole('checkbox', { name: /project_developer/ }).click();
        await expect(dialog.getByRole('checkbox', { name: /project_developer/ })).toBeChecked({ timeout: 15_000 });
        await expect(dialog.getByRole('alert')).toHaveCount(0);
        const after = await (await api.get(`/api/v1/groups/${groupId}/roles`)).json();
        expect((after.data.roles ?? []).map((r: { name: string }) => r.name)).toEqual(['project_developer']);
        test.info().annotations.push({ type: 'project', description: projectName });
    } finally {
        await api.dispose();
    }
});
