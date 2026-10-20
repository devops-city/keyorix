import React, { useState } from 'react';
import { PlusIcon, PencilSquareIcon, TrashIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';
import { Button, Modal, Input, Spinner } from '../../components/ui';
import {
    useRoles,
    usePermissions,
    useCreateRole,
    useUpdateRole,
    useDeleteRole,
    useAssignPermissionToRole,
    useRemovePermissionFromRole,
} from '../../features/admin';
import type { Role, RoleWithPermissions, Permission } from '../../types/rbac';
import { BUILT_IN_ROLES } from '../../types/rbac';

type Tab = 'roles' | 'permissions';

interface RoleFormData {
    name: string;
    description: string;
}

const isBuiltIn = (name: string): boolean => (BUILT_IN_ROLES as readonly string[]).includes(name);

const groupByResource = (perms: Permission[]): Record<string, Permission[]> =>
    perms.reduce<Record<string, Permission[]>>((acc, p) => {
        const existing = acc[p.resource];
        if (existing !== undefined) {
            existing.push(p);
        } else {
            acc[p.resource] = [p];
        }
        return acc;
    }, {});

interface RoleCardProps {
    role: RoleWithPermissions;
    onEdit: (role: Role) => void;
    onDelete: (role: Role) => void;
    onManage: (role: RoleWithPermissions) => void;
}

const RoleCard: React.FC<RoleCardProps> = ({ role, onEdit, onDelete, onManage }) => {
    const builtIn = isBuiltIn(role.name);
    return (
        <div
            className="rounded-xl border flex flex-col"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div
                className="px-5 py-4 border-b flex items-start justify-between gap-2"
                style={{ borderColor: 'var(--border)' }}
            >
                <div className="min-w-0">
                    <h3 className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
                        {role.name}
                    </h3>
                    {role.description && (
                        <p
                            className="mt-0.5 text-xs leading-relaxed line-clamp-2"
                            style={{ color: 'var(--text-muted)' }}
                        >
                            {role.description}
                        </p>
                    )}
                </div>
                {builtIn && (
                    <span
                        className="text-[10px] font-semibold px-1.5 py-0.5 rounded-sm uppercase tracking-wide shrink-0"
                        style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }}
                    >
                        Built-in
                    </span>
                )}
            </div>
            <div className="px-5 py-3 flex-1">
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    {role.permissions.length} permission{role.permissions.length !== 1 ? 's' : ''}
                </p>
            </div>
            <div className="px-5 py-3 border-t flex items-center gap-2" style={{ borderColor: 'var(--border)' }}>
                <Button size="sm" variant="outline" onClick={() => onManage(role)} className="flex-1">
                    <ShieldCheckIcon className="size-4" />
                    Permissions
                </Button>
                <button
                    type="button"
                    onClick={() => onEdit(role)}
                    className="p-1.5 rounded-md transition-colors"
                    style={{ color: 'var(--text-muted)' }}
                    title="Edit role"
                    onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-primary)')}
                    onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                >
                    <PencilSquareIcon className="h-4 w-4" />
                </button>
                <button
                    type="button"
                    onClick={builtIn ? undefined : () => onDelete(role)}
                    disabled={builtIn}
                    className="p-1.5 rounded-md transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                    style={{ color: 'var(--text-muted)' }}
                    title={builtIn ? 'Built-in roles cannot be deleted' : 'Delete role'}
                    onMouseEnter={(e) => {
                        if (!builtIn) (e.currentTarget as HTMLElement).style.color = '#ef4444';
                    }}
                    onMouseLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.color = 'var(--text-muted)';
                    }}
                >
                    <TrashIcon className="h-4 w-4" />
                </button>
            </div>
        </div>
    );
};

export const RolesPoliciesPage: React.FC = () => {
    const [tab, setTab] = useState<Tab>('roles');
    const [formData, setFormData] = useState<RoleFormData>({ name: '', description: '' });
    const [createOpen, setCreateOpen] = useState(false);
    const [editRole, setEditRole] = useState<Role | null>(null);
    const [deleteRole, setDeleteRole] = useState<Role | null>(null);
    const [manageRoleId, setManageRoleId] = useState<number | null>(null);

    const { data: roles, isLoading: rolesLoading, error: rolesError } = useRoles();
    const { data: permissions, isLoading: permsLoading } = usePermissions();
    const createMutation = useCreateRole();
    const updateMutation = useUpdateRole();
    const deleteMutation = useDeleteRole();
    const assignMutation = useAssignPermissionToRole();
    const removeMutation = useRemovePermissionFromRole();

    const manageRole = roles?.find((r) => r.id === manageRoleId) ?? null;
    const permsByResource = groupByResource(permissions ?? []);
    const isMutatingPerm = assignMutation.isPending || removeMutation.isPending;

    const openCreate = () => {
        setFormData({ name: '', description: '' });
        createMutation.reset();
        setCreateOpen(true);
    };

    const openEdit = (role: Role) => {
        setFormData({ name: role.name, description: role.description });
        updateMutation.reset();
        setEditRole(role);
    };

    const openDelete = (role: Role) => {
        deleteMutation.reset();
        setDeleteRole(role);
    };

    const handleCreate = () => {
        if (!formData.name.trim()) return;
        createMutation.mutate(formData, { onSuccess: () => setCreateOpen(false) });
    };

    const handleUpdate = () => {
        if (!editRole || !formData.name.trim()) return;
        updateMutation.mutate({ id: editRole.id, body: formData }, { onSuccess: () => setEditRole(null) });
    };

    const handleDelete = () => {
        if (!deleteRole) return;
        deleteMutation.mutate(deleteRole.id, {
            onSuccess: () => {
                deleteMutation.reset();
                setDeleteRole(null);
            },
        });
    };

    const handleTogglePerm = (perm: Permission) => {
        if (!manageRole) return;
        const assigned = manageRole.permissions.some((p) => p.id === perm.id);
        if (assigned) {
            removeMutation.mutate({ roleId: manageRole.id, permissionId: perm.id });
        } else {
            assignMutation.mutate({ roleId: manageRole.id, permissionId: perm.id });
        }
    };

    return (
        <div className="max-w-5xl mx-auto px-6 py-8">
            <div className="mb-6">
                <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                    Roles & Policies
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Manage roles and their associated permissions.
                </p>
            </div>

            {/* Tab bar */}
            <div className="flex gap-1 mb-6 border-b" style={{ borderColor: 'var(--border)' }}>
                {(['roles', 'permissions'] as const).map((t) => (
                    <button
                        key={t}
                        type="button"
                        onClick={() => setTab(t)}
                        className="px-4 py-2 text-sm font-medium -mb-px border-b-2 transition-colors"
                        style={{
                            borderColor: tab === t ? 'var(--accent)' : 'transparent',
                            color: tab === t ? 'var(--accent-text)' : 'var(--text-muted)',
                        }}
                    >
                        {t === 'roles' ? 'Roles' : 'Permissions'}
                    </button>
                ))}
            </div>

            {/* Roles tab */}
            {tab === 'roles' && (
                <div>
                    <div className="flex justify-end mb-4">
                        <Button size="sm" onClick={openCreate}>
                            <PlusIcon className="size-4" />
                            New Role
                        </Button>
                    </div>

                    {rolesLoading && (
                        <div className="flex justify-center py-12">
                            <Spinner />
                        </div>
                    )}
                    {rolesError !== null && (
                        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                            Failed to load roles. Please try again.
                        </p>
                    )}
                    {!rolesLoading && !rolesError && (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            {(roles ?? []).map((role) => (
                                <RoleCard
                                    key={role.id}
                                    role={role}
                                    onEdit={openEdit}
                                    onDelete={openDelete}
                                    onManage={(r) => setManageRoleId(r.id)}
                                />
                            ))}
                            {roles?.length === 0 && (
                                <p
                                    className="col-span-full text-sm py-8 text-center"
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    No roles found.
                                </p>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Permissions tab */}
            {tab === 'permissions' && (
                <div>
                    <p className="text-xs mb-5" style={{ color: 'var(--text-muted)' }}>
                        System-defined permissions. Read-only.
                    </p>
                    {permsLoading && (
                        <div className="flex justify-center py-12">
                            <Spinner />
                        </div>
                    )}
                    {!permsLoading &&
                        Object.entries(permsByResource).map(([resource, perms]) => (
                            <div key={resource} className="mb-6">
                                <h3
                                    className="text-xs font-semibold uppercase tracking-wider mb-2"
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    {resource}
                                </h3>
                                <div
                                    className="rounded-xl border overflow-hidden"
                                    style={{ borderColor: 'var(--border)' }}
                                >
                                    <table className="w-full text-sm">
                                        <thead>
                                            <tr style={{ backgroundColor: 'var(--bg-subtle)' }}>
                                                <th
                                                    className="px-4 py-2 text-left text-xs font-medium"
                                                    style={{ color: 'var(--text-muted)' }}
                                                >
                                                    Action
                                                </th>
                                                <th
                                                    className="px-4 py-2 text-left text-xs font-medium"
                                                    style={{ color: 'var(--text-muted)' }}
                                                >
                                                    Name
                                                </th>
                                                <th
                                                    className="px-4 py-2 text-left text-xs font-medium"
                                                    style={{ color: 'var(--text-muted)' }}
                                                >
                                                    Description
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {perms.map((perm, i) => (
                                                <tr
                                                    key={perm.id}
                                                    style={{ borderTop: i > 0 ? '1px solid var(--border)' : undefined }}
                                                >
                                                    <td
                                                        className="px-4 py-2.5 font-mono text-xs"
                                                        style={{ color: 'var(--text-secondary)' }}
                                                    >
                                                        {perm.action}
                                                    </td>
                                                    <td
                                                        className="px-4 py-2.5"
                                                        style={{ color: 'var(--text-primary)' }}
                                                    >
                                                        {perm.name}
                                                    </td>
                                                    <td className="px-4 py-2.5" style={{ color: 'var(--text-muted)' }}>
                                                        {perm.description}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        ))}
                    {!permsLoading && Object.keys(permsByResource).length === 0 && (
                        <p className="text-sm py-8 text-center" style={{ color: 'var(--text-muted)' }}>
                            No permissions found.
                        </p>
                    )}
                </div>
            )}

            {/* Create Role */}
            <Modal isOpen={createOpen} onClose={() => setCreateOpen(false)} title="New Role">
                <div className="space-y-4">
                    <Input
                        label="Name"
                        value={formData.name}
                        onChange={(e) => setFormData((d) => ({ ...d, name: e.target.value }))}
                        placeholder="e.g. developer"
                    />
                    <div>
                        <label
                            htmlFor="create-role-description"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Description
                        </label>
                        <textarea
                            id="create-role-description"
                            value={formData.description}
                            onChange={(e) => setFormData((d) => ({ ...d, description: e.target.value }))}
                            rows={3}
                            className="w-full px-3 py-2 rounded-md border text-sm resize-none"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                borderColor: 'var(--border-strong)',
                                color: 'var(--text-primary)',
                            }}
                            placeholder="What this role is for"
                        />
                    </div>
                    {createMutation.isError && (
                        <p className="text-sm text-red-600">Failed to create role. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={() => setCreateOpen(false)}>
                            Cancel
                        </Button>
                        <Button
                            loading={createMutation.isPending}
                            disabled={!formData.name.trim()}
                            onClick={handleCreate}
                        >
                            Create
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* Edit Role */}
            <Modal isOpen={editRole !== null} onClose={() => setEditRole(null)} title="Edit Role">
                <div className="space-y-4">
                    <Input
                        label="Name"
                        value={formData.name}
                        onChange={(e) => setFormData((d) => ({ ...d, name: e.target.value }))}
                    />
                    <div>
                        <label
                            htmlFor="edit-role-description"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Description
                        </label>
                        <textarea
                            id="edit-role-description"
                            value={formData.description}
                            onChange={(e) => setFormData((d) => ({ ...d, description: e.target.value }))}
                            rows={3}
                            className="w-full px-3 py-2 rounded-md border text-sm resize-none"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                borderColor: 'var(--border-strong)',
                                color: 'var(--text-primary)',
                            }}
                        />
                    </div>
                    {updateMutation.isError && (
                        <p className="text-sm text-red-600">Failed to update role. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={() => setEditRole(null)}>
                            Cancel
                        </Button>
                        <Button
                            loading={updateMutation.isPending}
                            disabled={!formData.name.trim()}
                            onClick={handleUpdate}
                        >
                            Save
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* Manage Permissions */}
            <Modal
                isOpen={manageRoleId !== null}
                onClose={() => setManageRoleId(null)}
                title={manageRole ? `Permissions — ${manageRole.name}` : 'Permissions'}
                size="lg"
            >
                {!manageRole || permsLoading ? (
                    <div className="flex justify-center py-8">
                        <Spinner />
                    </div>
                ) : (
                    <div className="max-h-[55vh] overflow-y-auto space-y-5 pr-1">
                        {Object.entries(permsByResource).map(([resource, perms]) => (
                            <div key={resource}>
                                <h4
                                    className="text-xs font-semibold uppercase tracking-wider mb-2"
                                    style={{ color: 'var(--text-secondary)' }}
                                >
                                    {resource}
                                </h4>
                                <div className="space-y-1">
                                    {perms.map((perm) => {
                                        const assigned = manageRole.permissions.some((p) => p.id === perm.id);
                                        return (
                                            <label
                                                key={perm.id}
                                                className="flex items-center gap-3 rounded-md px-3 py-2 cursor-pointer"
                                                style={{ backgroundColor: 'var(--bg-subtle)' }}
                                            >
                                                <input
                                                    type="checkbox"
                                                    checked={assigned}
                                                    disabled={isMutatingPerm}
                                                    onChange={() => handleTogglePerm(perm)}
                                                    className="h-4 w-4 rounded-sm accent-blue-600"
                                                />
                                                <div className="min-w-0">
                                                    <span
                                                        className="text-sm font-medium"
                                                        style={{ color: 'var(--text-primary)' }}
                                                    >
                                                        {perm.name}
                                                    </span>
                                                    {perm.description && (
                                                        <span
                                                            className="text-xs ml-2"
                                                            style={{ color: 'var(--text-muted)' }}
                                                        >
                                                            {perm.description}
                                                        </span>
                                                    )}
                                                </div>
                                            </label>
                                        );
                                    })}
                                </div>
                            </div>
                        ))}
                        {Object.keys(permsByResource).length === 0 && (
                            <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>
                                No permissions available.
                            </p>
                        )}
                    </div>
                )}
                <div className="flex justify-end pt-4 mt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                    <Button variant="secondary" onClick={() => setManageRoleId(null)}>
                        Close
                    </Button>
                </div>
            </Modal>

            {/* Delete Role */}
            <Modal
                isOpen={deleteRole !== null}
                onClose={() => {
                    setDeleteRole(null);
                    deleteMutation.reset();
                }}
                title="Delete Role"
                size="sm"
            >
                <div className="space-y-4">
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Delete role <strong style={{ color: 'var(--text-primary)' }}>{deleteRole?.name}</strong>? This
                        action cannot be undone.
                    </p>
                    {deleteMutation.isError && (
                        <p className="text-sm text-red-600">Failed to delete role. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button
                            variant="secondary"
                            onClick={() => {
                                setDeleteRole(null);
                                deleteMutation.reset();
                            }}
                        >
                            Cancel
                        </Button>
                        <Button variant="destructive" loading={deleteMutation.isPending} onClick={handleDelete}>
                            Delete
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
