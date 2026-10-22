import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import {
    useRoles,
    useRole,
    usePermissions,
    useRolePermissions,
    useCreateRole,
    useUpdateRole,
    useDeleteRole,
    useAssignPermissionToRole,
    useRemovePermissionFromRole,
    useGroupRoles,
    useGroupSharedSecrets,
    useAssignRoleToGroup,
    useRemoveRoleFromGroup,
    useGroups,
    useCreateGroup,
    useUpdateGroup,
    useDeleteGroup,
} from '../useRbac';

const { rbacApiMock, groupsApiMock } = vi.hoisted(() => ({
    rbacApiMock: {
        getRoles: vi.fn(),
        getRole: vi.fn(),
        createRole: vi.fn(),
        updateRole: vi.fn(),
        deleteRole: vi.fn(),
        getPermissions: vi.fn(),
        getRolePermissions: vi.fn(),
        assignPermissionToRole: vi.fn(),
        removePermissionFromRole: vi.fn(),
        getGroupRoles: vi.fn(),
        getGroupSharedSecrets: vi.fn(),
        assignRoleToGroup: vi.fn(),
        removeRoleFromGroup: vi.fn(),
        createGroup: vi.fn(),
        updateGroup: vi.fn(),
        deleteGroup: vi.fn(),
    },
    groupsApiMock: {
        list: vi.fn(),
        get: vi.fn(),
        search: vi.fn(),
    },
}));

vi.mock('../../../services/rbac', () => ({ rbacApi: rbacApiMock }));
vi.mock('../../../services/groups', () => ({ groupsApi: groupsApiMock }));

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return function Wrapper({ children }: { children: React.ReactNode }) {
        return React.createElement(QueryClientProvider, { client: queryClient }, children);
    };
}

// Wrapper variant that exposes the QueryClient it was built with, so a test
// can spy on invalidateQueries.
function createSpyableWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
    const Wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { Wrapper, invalidateSpy };
}

beforeEach(() => {
    vi.clearAllMocks();
});

// ── useRoles ──────────────────────────────────────────────────────────────

describe('useRoles', () => {
    it('starts loading and transitions to success, using the ["rbac","roles"] key', async () => {
        const roles = [
            { id: 1, name: 'admin', description: 'Admin role', permissions: [], created_at: '', updated_at: '' },
        ];
        rbacApiMock.getRoles.mockResolvedValueOnce(roles);

        const { result } = renderHook(() => useRoles(), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.data).toEqual(roles);
        expect(rbacApiMock.getRoles).toHaveBeenCalledTimes(1);
    });

    it('serves a second mount from cache without a fresh call (shared ["rbac","roles"] key)', async () => {
        rbacApiMock.getRoles.mockResolvedValue([]);
        const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
        const wrapper = ({ children }: { children: React.ReactNode }) =>
            React.createElement(QueryClientProvider, { client: queryClient }, children);

        const first = renderHook(() => useRoles(), { wrapper });
        await waitFor(() => expect(first.result.current.isLoading).toBe(false));

        const second = renderHook(() => useRoles(), { wrapper });
        await waitFor(() => expect(second.result.current.isLoading).toBe(false));

        expect(rbacApiMock.getRoles).toHaveBeenCalledTimes(1);
    });
});

// ── useRole ───────────────────────────────────────────────────────────────

describe('useRole', () => {
    it('fetches a single role by id when id is non-null', async () => {
        const role = { id: 5, name: 'editor', description: '', permissions: [], created_at: '', updated_at: '' };
        rbacApiMock.getRole.mockResolvedValueOnce(role);

        const { result } = renderHook(() => useRole(5), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(rbacApiMock.getRole).toHaveBeenCalledWith(5);
        expect(result.current.data).toEqual(role);
    });

    it('stays disabled and never calls the service when id is null', async () => {
        const { result } = renderHook(() => useRole(null), { wrapper: createWrapper() });

        expect(result.current.isPending).toBe(true);
        expect(result.current.fetchStatus).toBe('idle');
        expect(rbacApiMock.getRole).not.toHaveBeenCalled();
    });
});

// ── usePermissions ────────────────────────────────────────────────────────

describe('usePermissions', () => {
    it('fetches permissions and keys the query by the resource filter', async () => {
        const permissions = [{ id: 1, name: 'secrets.read', description: '', resource: 'secrets', action: 'read' }];
        rbacApiMock.getPermissions.mockResolvedValueOnce(permissions);

        const { result } = renderHook(() => usePermissions('secrets'), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(rbacApiMock.getPermissions).toHaveBeenCalledWith('secrets');
        expect(result.current.data).toEqual(permissions);
    });

    it('fetches all permissions when no resource filter is given', async () => {
        rbacApiMock.getPermissions.mockResolvedValueOnce([]);

        const { result } = renderHook(() => usePermissions(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(rbacApiMock.getPermissions).toHaveBeenCalledWith(undefined);
    });
});

// ── useRolePermissions ────────────────────────────────────────────────────

describe('useRolePermissions', () => {
    it('fetches permissions for a role when roleId is non-null', async () => {
        const payload = { role_id: 3, role_name: 'viewer', permissions: [] };
        rbacApiMock.getRolePermissions.mockResolvedValueOnce(payload);

        const { result } = renderHook(() => useRolePermissions(3), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(rbacApiMock.getRolePermissions).toHaveBeenCalledWith(3);
        expect(result.current.data).toEqual(payload);
    });

    it('stays disabled and never calls the service when roleId is null', () => {
        const { result } = renderHook(() => useRolePermissions(null), { wrapper: createWrapper() });

        expect(result.current.fetchStatus).toBe('idle');
        expect(rbacApiMock.getRolePermissions).not.toHaveBeenCalled();
    });
});

// ── useCreateRole ─────────────────────────────────────────────────────────

describe('useCreateRole', () => {
    const body = { name: 'new-role', description: 'desc' };

    it('calls rbacApi.createRole with the body and resolves with the created role', async () => {
        const created = { id: 9, ...body, created_at: '', updated_at: '' };
        rbacApiMock.createRole.mockResolvedValueOnce(created);

        const { result } = renderHook(() => useCreateRole(), { wrapper: createWrapper() });

        let mutationResult: unknown;
        await act(async () => {
            mutationResult = await result.current.mutateAsync(body);
        });

        expect(rbacApiMock.createRole).toHaveBeenCalledWith(body);
        expect(mutationResult).toEqual(created);
    });

    it('invalidates the ["rbac","roles"] query cache on success', async () => {
        rbacApiMock.createRole.mockResolvedValueOnce({ id: 1, ...body, created_at: '', updated_at: '' });
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useCreateRole(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync(body);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'roles'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.createRole.mockRejectedValueOnce(new Error('create failed'));

        const { result } = renderHook(() => useCreateRole(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync(body)).rejects.toThrow('create failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useUpdateRole ─────────────────────────────────────────────────────────

describe('useUpdateRole', () => {
    const body = { name: 'renamed', description: 'desc' };

    it('calls rbacApi.updateRole with id and body', async () => {
        rbacApiMock.updateRole.mockResolvedValueOnce({ id: 4, ...body, created_at: '', updated_at: '' });

        const { result } = renderHook(() => useUpdateRole(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ id: 4, body });
        });

        expect(rbacApiMock.updateRole).toHaveBeenCalledWith(4, body);
    });

    it('invalidates the ["rbac","roles"] query cache on success', async () => {
        rbacApiMock.updateRole.mockResolvedValueOnce({ id: 4, ...body, created_at: '', updated_at: '' });
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useUpdateRole(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync({ id: 4, body });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'roles'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.updateRole.mockRejectedValueOnce(new Error('update failed'));

        const { result } = renderHook(() => useUpdateRole(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync({ id: 4, body })).rejects.toThrow('update failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useDeleteRole ─────────────────────────────────────────────────────────

describe('useDeleteRole', () => {
    it('calls rbacApi.deleteRole with the id', async () => {
        rbacApiMock.deleteRole.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useDeleteRole(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync(7);
        });

        expect(rbacApiMock.deleteRole).toHaveBeenCalledWith(7);
    });

    it('invalidates the ["rbac","roles"] query cache on success', async () => {
        rbacApiMock.deleteRole.mockResolvedValueOnce(undefined);
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useDeleteRole(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync(7);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'roles'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.deleteRole.mockRejectedValueOnce(new Error('delete failed'));

        const { result } = renderHook(() => useDeleteRole(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync(7)).rejects.toThrow('delete failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useAssignPermissionToRole ─────────────────────────────────────────────

describe('useAssignPermissionToRole', () => {
    it('calls rbacApi.assignPermissionToRole with roleId and permissionId', async () => {
        rbacApiMock.assignPermissionToRole.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useAssignPermissionToRole(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ roleId: 1, permissionId: 2 });
        });

        expect(rbacApiMock.assignPermissionToRole).toHaveBeenCalledWith(1, 2);
    });

    it('invalidates the ["rbac","roles"] query cache on success', async () => {
        rbacApiMock.assignPermissionToRole.mockResolvedValueOnce(undefined);
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useAssignPermissionToRole(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync({ roleId: 1, permissionId: 2 });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'roles'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.assignPermissionToRole.mockRejectedValueOnce(new Error('assign failed'));

        const { result } = renderHook(() => useAssignPermissionToRole(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync({ roleId: 1, permissionId: 2 })).rejects.toThrow('assign failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useRemovePermissionFromRole ───────────────────────────────────────────

describe('useRemovePermissionFromRole', () => {
    it('calls rbacApi.removePermissionFromRole with roleId and permissionId', async () => {
        rbacApiMock.removePermissionFromRole.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useRemovePermissionFromRole(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ roleId: 1, permissionId: 2 });
        });

        expect(rbacApiMock.removePermissionFromRole).toHaveBeenCalledWith(1, 2);
    });

    it('invalidates the ["rbac","roles"] query cache on success', async () => {
        rbacApiMock.removePermissionFromRole.mockResolvedValueOnce(undefined);
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useRemovePermissionFromRole(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync({ roleId: 1, permissionId: 2 });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'roles'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.removePermissionFromRole.mockRejectedValueOnce(new Error('remove failed'));

        const { result } = renderHook(() => useRemovePermissionFromRole(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync({ roleId: 1, permissionId: 2 })).rejects.toThrow('remove failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useGroupRoles ─────────────────────────────────────────────────────────

describe('useGroupRoles', () => {
    it('fetches roles for a group when groupId is non-null', async () => {
        const payload = { group_id: 8, roles: [] };
        rbacApiMock.getGroupRoles.mockResolvedValueOnce(payload);

        const { result } = renderHook(() => useGroupRoles(8), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(rbacApiMock.getGroupRoles).toHaveBeenCalledWith(8);
        expect(result.current.data).toEqual(payload);
    });

    it('stays disabled and never calls the service when groupId is null', () => {
        const { result } = renderHook(() => useGroupRoles(null), { wrapper: createWrapper() });

        expect(result.current.fetchStatus).toBe('idle');
        expect(rbacApiMock.getGroupRoles).not.toHaveBeenCalled();
    });
});

// ── useGroupSharedSecrets ─────────────────────────────────────────────────

describe('useGroupSharedSecrets', () => {
    it('fetches shared secrets for a group when groupId is non-null', async () => {
        const secrets = [{ id: 1, name: 'db-password', type: 'static' }];
        rbacApiMock.getGroupSharedSecrets.mockResolvedValueOnce(secrets);

        const { result } = renderHook(() => useGroupSharedSecrets(11), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(rbacApiMock.getGroupSharedSecrets).toHaveBeenCalledWith(11);
        expect(result.current.data).toEqual(secrets);
    });

    it('stays disabled and never calls the service when groupId is null', () => {
        const { result } = renderHook(() => useGroupSharedSecrets(null), { wrapper: createWrapper() });

        expect(result.current.fetchStatus).toBe('idle');
        expect(rbacApiMock.getGroupSharedSecrets).not.toHaveBeenCalled();
    });
});

// ── useAssignRoleToGroup ──────────────────────────────────────────────────

describe('useAssignRoleToGroup', () => {
    it('calls rbacApi.assignRoleToGroup with groupId, roleId and expiresAt when provided', async () => {
        rbacApiMock.assignRoleToGroup.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useAssignRoleToGroup(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ groupId: 1, roleId: 2, expiresAt: '2026-12-31T00:00:00Z' });
        });

        expect(rbacApiMock.assignRoleToGroup).toHaveBeenCalledWith(1, 2, '2026-12-31T00:00:00Z', undefined);
    });

    it('omits expiresAt for a permanent grant', async () => {
        rbacApiMock.assignRoleToGroup.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useAssignRoleToGroup(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ groupId: 1, roleId: 2 });
        });

        expect(rbacApiMock.assignRoleToGroup).toHaveBeenCalledWith(1, 2, undefined, undefined);
    });

    it('invalidates ["rbac","group-roles",groupId] scoped to the mutated group on success', async () => {
        rbacApiMock.assignRoleToGroup.mockResolvedValueOnce(undefined);
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useAssignRoleToGroup(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync({ groupId: 42, roleId: 2 });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'group-roles', 42] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.assignRoleToGroup.mockRejectedValueOnce(new Error('assign-to-group failed'));

        const { result } = renderHook(() => useAssignRoleToGroup(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync({ groupId: 1, roleId: 2 })).rejects.toThrow('assign-to-group failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useRemoveRoleFromGroup ────────────────────────────────────────────────

describe('useRemoveRoleFromGroup', () => {
    it('calls rbacApi.removeRoleFromGroup with groupId and roleId', async () => {
        rbacApiMock.removeRoleFromGroup.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useRemoveRoleFromGroup(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ groupId: 1, roleId: 2 });
        });

        expect(rbacApiMock.removeRoleFromGroup).toHaveBeenCalledWith(1, 2, undefined);
    });

    it('invalidates ["rbac","group-roles",groupId] scoped to the mutated group on success', async () => {
        rbacApiMock.removeRoleFromGroup.mockResolvedValueOnce(undefined);
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useRemoveRoleFromGroup(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync({ groupId: 42, roleId: 2 });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'group-roles', 42] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.removeRoleFromGroup.mockRejectedValueOnce(new Error('remove-from-group failed'));

        const { result } = renderHook(() => useRemoveRoleFromGroup(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync({ groupId: 1, roleId: 2 })).rejects.toThrow('remove-from-group failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useGroups ─────────────────────────────────────────────────────────────

describe('useGroups', () => {
    it('fetches groups via groupsApi.list, keyed by the params object', async () => {
        const page = { items: [{ id: 1, name: 'eng', description: '', created_at: '', updated_at: '' }], total: 1 };
        groupsApiMock.list.mockResolvedValueOnce(page);

        const params = { page: 1, pageSize: 20, search: 'eng' };
        const { result } = renderHook(() => useGroups(params), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(groupsApiMock.list).toHaveBeenCalledWith(params);
        expect(result.current.data).toEqual(page);
    });

    it('calls groupsApi.list with undefined params when none are given', async () => {
        groupsApiMock.list.mockResolvedValueOnce({ items: [], total: 0 });

        const { result } = renderHook(() => useGroups(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(groupsApiMock.list).toHaveBeenCalledWith(undefined);
    });
});

// ── useCreateGroup ────────────────────────────────────────────────────────
// Note: useGroups reads through groupsApi.list, but the group CRUD mutations
// below go through rbacApi (createGroup/updateGroup/deleteGroup) rather than
// groupsApi. That split is real in the source (src/features/admin/useRbac.ts)
// — documented here, not treated as a bug to fix (scope of this PR is tests only).

describe('useCreateGroup', () => {
    const body = { name: 'new-group', description: 'desc' };

    it('calls rbacApi.createGroup with the body', async () => {
        const created = { id: 3, ...body, created_at: '', updated_at: '' };
        rbacApiMock.createGroup.mockResolvedValueOnce(created);

        const { result } = renderHook(() => useCreateGroup(), { wrapper: createWrapper() });

        let mutationResult: unknown;
        await act(async () => {
            mutationResult = await result.current.mutateAsync(body);
        });

        expect(rbacApiMock.createGroup).toHaveBeenCalledWith(body);
        expect(mutationResult).toEqual(created);
    });

    it('invalidates the ["rbac","groups"] query cache on success', async () => {
        rbacApiMock.createGroup.mockResolvedValueOnce({ id: 3, ...body, created_at: '', updated_at: '' });
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useCreateGroup(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync(body);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'groups'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.createGroup.mockRejectedValueOnce(new Error('create-group failed'));

        const { result } = renderHook(() => useCreateGroup(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync(body)).rejects.toThrow('create-group failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useUpdateGroup ────────────────────────────────────────────────────────

describe('useUpdateGroup', () => {
    const body = { name: 'renamed-group', description: 'desc' };

    it('calls rbacApi.updateGroup with id and body', async () => {
        rbacApiMock.updateGroup.mockResolvedValueOnce({ id: 6, ...body, created_at: '', updated_at: '' });

        const { result } = renderHook(() => useUpdateGroup(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ id: 6, body });
        });

        expect(rbacApiMock.updateGroup).toHaveBeenCalledWith(6, body);
    });

    it('invalidates the ["rbac","groups"] query cache on success', async () => {
        rbacApiMock.updateGroup.mockResolvedValueOnce({ id: 6, ...body, created_at: '', updated_at: '' });
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useUpdateGroup(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync({ id: 6, body });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'groups'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.updateGroup.mockRejectedValueOnce(new Error('update-group failed'));

        const { result } = renderHook(() => useUpdateGroup(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync({ id: 6, body })).rejects.toThrow('update-group failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useDeleteGroup ────────────────────────────────────────────────────────

describe('useDeleteGroup', () => {
    it('calls rbacApi.deleteGroup with the id', async () => {
        rbacApiMock.deleteGroup.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useDeleteGroup(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync(9);
        });

        expect(rbacApiMock.deleteGroup).toHaveBeenCalledWith(9);
    });

    it('invalidates the ["rbac","groups"] query cache on success', async () => {
        rbacApiMock.deleteGroup.mockResolvedValueOnce(undefined);
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useDeleteGroup(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync(9);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rbac', 'groups'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        rbacApiMock.deleteGroup.mockRejectedValueOnce(new Error('delete-group failed'));

        const { result } = renderHook(() => useDeleteGroup(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync(9)).rejects.toThrow('delete-group failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});
