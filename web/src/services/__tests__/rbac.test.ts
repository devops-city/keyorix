import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the shared axios instance before importing the service under test.
vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { rbacApi } from '../rbac';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
    mocked.post.mockResolvedValue({ data: { data: {} } });
});

describe('rbacApi.assignRoleToGroup', () => {
    it('omits expires_at for a permanent grant', async () => {
        await rbacApi.assignRoleToGroup(7, 3);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/groups/7/roles', { role_id: 3 });
    });

    it('sends expires_at for a time-bound (JIT) grant', async () => {
        const iso = '2026-07-01T00:00:00.000Z';
        await rbacApi.assignRoleToGroup(7, 3, iso);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/groups/7/roles', {
            role_id: 3,
            expires_at: iso,
        });
    });

    // #3546: a project role needs its project; the scope travels with the grant.
    it('sends project_id and environment_id for a scoped grant', async () => {
        await rbacApi.assignRoleToGroup(7, 3, undefined, { projectId: 2, environmentId: 5 });
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/groups/7/roles', {
            role_id: 3,
            project_id: 2,
            environment_id: 5,
        });
    });

    it('never sends an environment without its project', async () => {
        await rbacApi.assignRoleToGroup(7, 3, undefined, { environmentId: 5 });
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/groups/7/roles', { role_id: 3 });
    });
});

describe('rbacApi.getGroupSharedSecrets', () => {
    it('extracts id/name/type from the server secretNodeWire rows', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secrets: [
                        { id: 1, name: 'alpha', type: 'password' },
                        { id: 2, name: 'beta', type: 'token' },
                    ],
                },
            },
        });
        const out = await rbacApi.getGroupSharedSecrets(7);
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/groups/7/shared-secrets');
        expect(out).toEqual([
            { id: 1, name: 'alpha', type: 'password' },
            { id: 2, name: 'beta', type: 'token' },
        ]);
    });

    it('returns an empty array when there are no shared secrets', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });
        expect(await rbacApi.getGroupSharedSecrets(7)).toEqual([]);
    });

    it('normalizes lowercase id/name/type and defaults a sparse row', async () => {
        mocked.get.mockResolvedValue({
            data: { data: { secrets: [{ id: 3, name: 'gamma', type: 'ssh_key' }, {}] } },
        });
        const out = await rbacApi.getGroupSharedSecrets(7);
        expect(out).toEqual([
            { id: 3, name: 'gamma', type: 'ssh_key' },
            { id: 0, name: '', type: '' },
        ]);
    });

    it('returns [] when the secrets field is not an array', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: 'not-an-array' } } });
        expect(await rbacApi.getGroupSharedSecrets(7)).toEqual([]);
    });

    it('returns [] when data.data itself is absent', async () => {
        mocked.get.mockResolvedValue({ data: {} });
        expect(await rbacApi.getGroupSharedSecrets(7)).toEqual([]);
    });
});

// ── getRoles ──────────────────────────────────────────────────────────────────

describe('rbacApi.getRoles', () => {
    it('passes bypasses_permission_checks through from the server', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: [
                    { id: 1, name: 'super_admin', description: '', bypasses_permission_checks: true, permissions: [] },
                ],
            },
        });
        const roles = await rbacApi.getRoles();
        expect(roles[0].bypasses_permission_checks).toBe(true);
    });

    it('normalizes lowercase field names', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: [{ id: 1, name: 'admin', description: 'Admins', permissions: [] }],
            },
        });
        const roles = await rbacApi.getRoles();
        expect(roles[0]).toMatchObject({ id: 1, name: 'admin' });
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/roles');
    });

    it('handles {roles: [...]} wrapper shape', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: {
                    roles: [{ id: 3, name: 'editor', description: '', permissions: [] }],
                },
            },
        });
        const roles = await rbacApi.getRoles();
        expect(roles[0]).toMatchObject({ id: 3, name: 'editor' });
    });

    it('normalizes string permissions to the full Permission shape', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: [
                    {
                        id: 1,
                        name: 'admin',
                        description: '',
                        permissions: ['secrets.read'],
                    },
                ],
            },
        });
        const roles = await rbacApi.getRoles();
        expect(roles[0].permissions[0]).toMatchObject({ name: 'secrets.read', resource: 'secrets', action: 'read' });
    });

    it('defaults the resource/action split when a string permission has no dot', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: [{ id: 1, name: 'admin', permissions: ['adminonly'] }] },
        });
        const roles = await rbacApi.getRoles();
        expect(roles[0].permissions[0]).toMatchObject({ name: 'adminonly', resource: 'adminonly', action: '' });
    });

    it('normalizes object permissions with full snake_case fields', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: [
                    {
                        id: 1,
                        name: 'admin',
                        permissions: [
                            { id: 5, name: 'secrets.read', description: 'read', resource: 'secrets', action: 'read' },
                        ],
                    },
                ],
            },
        });
        const roles = await rbacApi.getRoles();
        expect(roles[0].permissions[0]).toEqual({
            id: 5,
            name: 'secrets.read',
            description: 'read',
            resource: 'secrets',
            action: 'read',
        });
    });

    it('defaults every role field, including object permissions, on a sparse role', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: [{ permissions: [{}] }] },
        });
        const roles = await rbacApi.getRoles();
        expect(roles[0]).toEqual({
            id: 0,
            name: '',
            description: '',
            bypasses_permission_checks: false,
            permissions: [{ id: 0, name: '', description: '', resource: '', action: '' }],
        });
    });

    it('returns [] when data.data is neither an array nor a {roles} wrapper', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: {} } });
        await expect(rbacApi.getRoles()).resolves.toEqual([]);
    });

    it('defaults permissions to [] when neither permissions nor Permissions is present', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: [{ id: 1, name: 'no-perms-field' }] },
        });
        const roles = await rbacApi.getRoles();
        expect(roles[0].permissions).toEqual([]);
    });
});

// ── getRole ───────────────────────────────────────────────────────────────────

describe('rbacApi.getRole', () => {
    it('fetches and normalizes a single role', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: { id: 5, name: 'ops', description: '', permissions: [] } },
        });
        const role = await rbacApi.getRole(5);
        expect(role).toMatchObject({ id: 5, name: 'ops' });
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/roles/5');
    });
});

// ── createRole ────────────────────────────────────────────────────────────────

describe('rbacApi.createRole', () => {
    it('posts the role body and returns the created role', async () => {
        mocked.post.mockResolvedValueOnce({ data: { data: { id: 10, name: 'dev' } } });
        const role = await rbacApi.createRole({ name: 'dev', description: 'Developers' });
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/roles', {
            name: 'dev',
            description: 'Developers',
            permissions: [],
        });
        expect(role).toMatchObject({ id: 10, name: 'dev' });
    });

    it('passes explicit permissions array', async () => {
        mocked.post.mockResolvedValueOnce({ data: { data: {} } });
        await rbacApi.createRole({ name: 'dev', description: '', permissions: ['secrets.read'] });
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/roles', {
            name: 'dev',
            description: '',
            permissions: ['secrets.read'],
        });
    });
});

// ── updateRole ────────────────────────────────────────────────────────────────

describe('rbacApi.updateRole', () => {
    it('sends PUT with updated fields', async () => {
        mocked.put.mockResolvedValueOnce({ data: { data: { id: 1, name: 'admin-v2' } } });
        await rbacApi.updateRole(1, { name: 'admin-v2', description: 'Updated' });
        expect(mocked.put).toHaveBeenCalledWith('/api/v1/roles/1', {
            name: 'admin-v2',
            description: 'Updated',
            permissions: [],
        });
    });
});

// ── deleteRole ────────────────────────────────────────────────────────────────

describe('rbacApi.deleteRole', () => {
    it('sends DELETE to the role endpoint', async () => {
        mocked.delete.mockResolvedValueOnce({});
        await rbacApi.deleteRole(3);
        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/roles/3');
    });
});

// ── getPermissions ────────────────────────────────────────────────────────────

describe('rbacApi.getPermissions', () => {
    it('returns flat permissions array without resource filter', async () => {
        const perms = [{ id: 1, name: 'secrets.read' }];
        mocked.get.mockResolvedValueOnce({ data: { data: perms } });
        await expect(rbacApi.getPermissions()).resolves.toEqual(perms);
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/permissions', { params: undefined });
    });

    it('passes resource filter as query param', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: [] } });
        await rbacApi.getPermissions('secrets');
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/permissions', { params: { resource: 'secrets' } });
    });

    it('unwraps {permissions: [...]} wrapper shape', async () => {
        const perms = [{ id: 2, name: 'admin.write' }];
        mocked.get.mockResolvedValueOnce({ data: { data: { permissions: perms } } });
        await expect(rbacApi.getPermissions()).resolves.toEqual(perms);
    });

    it('returns [] when data.data is neither an array nor a {permissions} wrapper', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: {} } });
        await expect(rbacApi.getPermissions()).resolves.toEqual([]);
    });
});

// ── getRolePermissions ────────────────────────────────────────────────────────

describe('rbacApi.getRolePermissions', () => {
    it('fetches the role-permissions view and unwraps data.data', async () => {
        const payload = { role_id: 2, role_name: 'admin', permissions: [{ id: 1, name: 'secrets.read' }] };
        mocked.get.mockResolvedValueOnce({ data: { data: payload } });

        const result = await rbacApi.getRolePermissions(2);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/roles/2/permissions');
        expect(result).toEqual(payload);
    });
});

// ── getGroupRoles ─────────────────────────────────────────────────────────────

describe('rbacApi.getGroupRoles', () => {
    it('fetches the group-roles view and unwraps data.data', async () => {
        const payload = { roles: [{ id: 1, name: 'project_admin' }] };
        mocked.get.mockResolvedValueOnce({ data: { data: payload } });

        const result = await rbacApi.getGroupRoles(7);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/groups/7/roles');
        expect(result).toEqual(payload);
    });
});

// ── assignPermissionToRole / removePermissionFromRole ─────────────────────────

describe('rbacApi permission assignment', () => {
    it('assignPermissionToRole posts permission_id', async () => {
        mocked.post.mockResolvedValueOnce({ data: { data: {} } });
        await rbacApi.assignPermissionToRole(2, 5);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/roles/2/permissions', { permission_id: 5 });
    });

    it('removePermissionFromRole sends DELETE', async () => {
        mocked.delete.mockResolvedValueOnce({});
        await rbacApi.removePermissionFromRole(2, 5);
        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/roles/2/permissions/5');
    });
});

// ── group management ──────────────────────────────────────────────────────────

describe('rbacApi group management', () => {
    it('createGroup posts and returns the group', async () => {
        mocked.post.mockResolvedValueOnce({ data: { data: { id: 1, name: 'ops-team' } } });
        const group = await rbacApi.createGroup({ name: 'ops-team', description: 'Ops' });
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/groups', { name: 'ops-team', description: 'Ops' });
        expect(group).toMatchObject({ id: 1, name: 'ops-team' });
    });

    it('updateGroup sends PUT', async () => {
        mocked.put.mockResolvedValueOnce({ data: { data: { id: 1, name: 'ops-team-v2' } } });
        await rbacApi.updateGroup(1, { name: 'ops-team-v2', description: '' });
        expect(mocked.put).toHaveBeenCalledWith('/api/v1/groups/1', { name: 'ops-team-v2', description: '' });
    });

    it('deleteGroup sends DELETE', async () => {
        mocked.delete.mockResolvedValueOnce({});
        await rbacApi.deleteGroup(1);
        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/groups/1');
    });
});

// ── removeRoleFromGroup ───────────────────────────────────────────────────────

describe('rbacApi.removeRoleFromGroup', () => {
    it('sends DELETE to the group-role endpoint', async () => {
        mocked.delete.mockResolvedValueOnce({});
        await rbacApi.removeRoleFromGroup(7, 3);
        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/groups/7/roles/3', { params: {} });
    });

    it('removes the grant at the given scope', async () => {
        await rbacApi.removeRoleFromGroup(7, 3, { projectId: 2 });
        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/groups/7/roles/3', { params: { project_id: 2 } });
    });
});
