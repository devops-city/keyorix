import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { rbacApi, type RoleGrantScope } from '../../services/rbac';
import { groupsApi } from '../../services/groups';

// ── Role hooks ──────────────────────────────────────────────────────────────

export const useRoles = () =>
    useQuery({
        queryKey: ['rbac', 'roles'],
        queryFn: () => rbacApi.getRoles(),
        staleTime: 5 * 60 * 1000,
    });

export const useRole = (id: number | null) =>
    useQuery({
        queryKey: ['rbac', 'role', id],
        queryFn: () => rbacApi.getRole(id!),
        enabled: id !== null,
        staleTime: 5 * 60 * 1000,
    });

export const usePermissions = (resource?: string) =>
    useQuery({
        queryKey: ['rbac', 'permissions', resource],
        queryFn: () => rbacApi.getPermissions(resource),
        staleTime: 10 * 60 * 1000,
    });

export const useRolePermissions = (roleId: number | null) =>
    useQuery({
        queryKey: ['rbac', 'role-permissions', roleId],
        queryFn: () => rbacApi.getRolePermissions(roleId!),
        enabled: roleId !== null,
        staleTime: 5 * 60 * 1000,
    });

export const useCreateRole = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (body: { name: string; description: string }) => rbacApi.createRole(body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rbac', 'roles'] }),
    });
};

export const useUpdateRole = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, body }: { id: number; body: { name: string; description: string } }) =>
            rbacApi.updateRole(id, body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rbac', 'roles'] }),
    });
};

export const useDeleteRole = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => rbacApi.deleteRole(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rbac', 'roles'] }),
    });
};

export const useAssignPermissionToRole = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ roleId, permissionId }: { roleId: number; permissionId: number }) =>
            rbacApi.assignPermissionToRole(roleId, permissionId),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rbac', 'roles'] }),
    });
};

export const useRemovePermissionFromRole = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ roleId, permissionId }: { roleId: number; permissionId: number }) =>
            rbacApi.removePermissionFromRole(roleId, permissionId),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rbac', 'roles'] }),
    });
};

// ── Group role hooks ────────────────────────────────────────────────────────

export const useGroupRoles = (groupId: number | null) =>
    useQuery({
        queryKey: ['rbac', 'group-roles', groupId],
        queryFn: () => rbacApi.getGroupRoles(groupId!),
        enabled: groupId !== null,
        staleTime: 5 * 60 * 1000,
    });

export const useGroupSharedSecrets = (groupId: number | null) =>
    useQuery({
        queryKey: ['rbac', 'group-shared-secrets', groupId],
        queryFn: () => rbacApi.getGroupSharedSecrets(groupId!),
        enabled: groupId !== null,
        staleTime: 5 * 60 * 1000,
    });

export const useAssignRoleToGroup = () => {
    const queryClient = useQueryClient();
    return useMutation({
        // expiresAt (ISO), when set, makes the grant time-bound (just-in-time access).
        mutationFn: ({
            groupId,
            roleId,
            expiresAt,
            scope,
        }: {
            groupId: number;
            roleId: number;
            expiresAt?: string;
            scope?: RoleGrantScope;
        }) => rbacApi.assignRoleToGroup(groupId, roleId, expiresAt, scope),
        onSuccess: (_data, { groupId }) =>
            queryClient.invalidateQueries({ queryKey: ['rbac', 'group-roles', groupId] }),
    });
};

export const useRemoveRoleFromGroup = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ groupId, roleId, scope }: { groupId: number; roleId: number; scope?: RoleGrantScope }) =>
            rbacApi.removeRoleFromGroup(groupId, roleId, scope),
        onSuccess: (_data, { groupId }) =>
            queryClient.invalidateQueries({ queryKey: ['rbac', 'group-roles', groupId] }),
    });
};

// ── Group CRUD hooks ────────────────────────────────────────────────────────

export const useGroups = (params?: { page?: number; pageSize?: number; search?: string }) =>
    useQuery({
        queryKey: ['rbac', 'groups', params],
        queryFn: () => groupsApi.list(params),
        staleTime: 5 * 60 * 1000,
    });

export const useCreateGroup = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (body: { name: string; description: string }) => rbacApi.createGroup(body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rbac', 'groups'] }),
    });
};

export const useUpdateGroup = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, body }: { id: number; body: { name: string; description: string } }) =>
            rbacApi.updateGroup(id, body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rbac', 'groups'] }),
    });
};

export const useDeleteGroup = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => rbacApi.deleteGroup(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rbac', 'groups'] }),
    });
};
