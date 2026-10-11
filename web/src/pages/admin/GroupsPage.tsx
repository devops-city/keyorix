import { formatDateTime } from '../../utils/datetime';
import React, { useState } from 'react';
import { PlusIcon, PencilSquareIcon, TrashIcon, UsersIcon, KeyIcon } from '@heroicons/react/24/outline';
import { Button, Modal, Input, Spinner, Select } from '../../components/ui';
import {
    useGroups,
    useGroupRoles,
    useGroupSharedSecrets,
    useRoles,
    useCreateGroup,
    useUpdateGroup,
    useDeleteGroup,
    useAssignRoleToGroup,
    useRemoveRoleFromGroup,
} from '../../features/admin';
import type { Group, Role } from '../../types/rbac';
import { EXPIRY_OPTIONS, expiresAtFromPreset, formatRemaining } from '../../lib/expiry';

interface GroupFormData {
    name: string;
    description: string;
}

interface GroupRowProps {
    group: Group;
    onEdit: (group: Group) => void;
    onDelete: (group: Group) => void;
    onManageRoles: (group: Group) => void;
    onViewSecrets: (group: Group) => void;
}

const GroupRow: React.FC<GroupRowProps> = ({ group, onEdit, onDelete, onManageRoles, onViewSecrets }) => {
    const { data: groupRoles } = useGroupRoles(group.id);
    const roles = groupRoles?.roles ?? [];

    return (
        <tr style={{ borderTop: '1px solid var(--border)' }}>
            <td className="px-4 py-3">
                <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                    {group.name}
                </span>
            </td>
            <td className="px-4 py-3">
                <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                    {group.description || '—'}
                </span>
            </td>
            <td className="px-4 py-3 text-center">
                <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
                    {group.member_count ?? '—'}
                </span>
            </td>
            <td className="px-4 py-3">
                {roles.length === 0 ? (
                    <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        None
                    </span>
                ) : (
                    <div className="flex flex-wrap gap-1">
                        {roles.map((r) => (
                            <span
                                key={r.id}
                                className="text-xs px-2 py-0.5 rounded-full font-medium"
                                style={{
                                    backgroundColor: 'var(--accent-subtle)',
                                    color: 'var(--accent-text)',
                                }}
                            >
                                {r.name}
                            </span>
                        ))}
                    </div>
                )}
            </td>
            <td className="px-4 py-3">
                <div className="flex items-center gap-1 justify-end">
                    <button
                        type="button"
                        onClick={() => onManageRoles(group)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Manage roles"
                        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-primary)')}
                        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                    >
                        <UsersIcon className="h-4 w-4" />
                    </button>
                    <button
                        type="button"
                        onClick={() => onViewSecrets(group)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Shared secrets"
                        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-primary)')}
                        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                    >
                        <KeyIcon className="h-4 w-4" />
                    </button>
                    <button
                        type="button"
                        onClick={() => onEdit(group)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Edit group"
                        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-primary)')}
                        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                    >
                        <PencilSquareIcon className="h-4 w-4" />
                    </button>
                    <button
                        type="button"
                        onClick={() => onDelete(group)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Delete group"
                        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = '#ef4444')}
                        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                    >
                        <TrashIcon className="h-4 w-4" />
                    </button>
                </div>
            </td>
        </tr>
    );
};

export const GroupsPage: React.FC = () => {
    const [formData, setFormData] = useState<GroupFormData>({ name: '', description: '' });
    const [createOpen, setCreateOpen] = useState(false);
    const [editGroup, setEditGroup] = useState<Group | null>(null);
    const [deleteGroup, setDeleteGroup] = useState<Group | null>(null);
    const [manageGroupId, setManageGroupId] = useState<number | null>(null);
    const [secretsGroup, setSecretsGroup] = useState<Group | null>(null);
    const { data: sharedSecrets, isLoading: sharedSecretsLoading } = useGroupSharedSecrets(secretsGroup?.id ?? null);
    // Duration preset applied to the NEXT role granted in the Manage Roles modal.
    const [roleTtl, setRoleTtl] = useState('never');

    const { data: groupsData, isLoading: groupsLoading, error: groupsError } = useGroups();
    const { data: allRoles, isLoading: rolesLoading } = useRoles();
    const { data: groupRolesData } = useGroupRoles(manageGroupId);
    const createMutation = useCreateGroup();
    const updateMutation = useUpdateGroup();

    // Surface the server's actual validation message (e.g. the identifier-charset
    // rule) instead of a generic "please try again", which hides why the save failed.
    const errMsg = (e: unknown, fallback: string): string => {
        const r = e as { response?: { data?: { message?: string } } };
        return r?.response?.data?.message?.trim() || fallback;
    };
    const deleteMutation = useDeleteGroup();
    const assignMutation = useAssignRoleToGroup();
    const removeMutation = useRemoveRoleFromGroup();

    const groups = (groupsData?.groups ?? []) as Group[];
    const assignedRoleIds = new Set((groupRolesData?.roles ?? []).map((r) => r.id));
    // Per-grant expiry (ISO) by role id, for the time-bound badge on assigned roles.
    const roleExpiryById = new Map(
        (groupRolesData?.roles ?? []).filter((r) => r.expires_at).map((r) => [r.id, r.expires_at as string])
    );
    const isMutatingRole = assignMutation.isPending || removeMutation.isPending;

    const openCreate = () => {
        setFormData({ name: '', description: '' });
        createMutation.reset();
        setCreateOpen(true);
    };

    const openEdit = (group: Group) => {
        setFormData({ name: group.name, description: group.description });
        updateMutation.reset();
        setEditGroup(group);
    };

    const openDelete = (group: Group) => {
        deleteMutation.reset();
        setDeleteGroup(group);
    };

    const handleCreate = () => {
        const body = { name: formData.name.trim(), description: formData.description.trim() };
        if (!body.name) return;
        createMutation.mutate(body, { onSuccess: () => setCreateOpen(false) });
    };

    const handleUpdate = () => {
        if (!editGroup) return;
        const body = { name: formData.name.trim(), description: formData.description.trim() };
        if (!body.name) return;
        updateMutation.mutate({ id: editGroup.id, body }, { onSuccess: () => setEditGroup(null) });
    };

    const handleDelete = () => {
        if (!deleteGroup) return;
        deleteMutation.mutate(deleteGroup.id, {
            onSuccess: () => {
                deleteMutation.reset();
                setDeleteGroup(null);
            },
        });
    };

    const handleToggleRole = (role: Role) => {
        if (manageGroupId === null) return;
        if (assignedRoleIds.has(role.id)) {
            removeMutation.mutate({ groupId: manageGroupId, roleId: role.id });
        } else {
            // A non-permanent preset makes this a time-bound (JIT) grant.
            const expiresAt = expiresAtFromPreset(roleTtl);
            assignMutation.mutate({ groupId: manageGroupId, roleId: role.id, ...(expiresAt ? { expiresAt } : {}) });
        }
    };

    return (
        <div className="max-w-5xl mx-auto px-6 py-8">
            <div className="mb-6 flex items-start justify-between">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                        Groups
                    </h1>
                    <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Organise users into groups and assign roles at the group level.
                    </p>
                </div>
                <Button size="sm" onClick={openCreate}>
                    <PlusIcon className="size-4" />
                    New Group
                </Button>
            </div>

            {/* Table */}
            <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                <table className="w-full text-sm">
                    <thead>
                        <tr style={{ backgroundColor: 'var(--bg-subtle)' }}>
                            <th
                                className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Name
                            </th>
                            <th
                                className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Description
                            </th>
                            <th
                                className="px-4 py-3 text-center text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Members
                            </th>
                            <th
                                className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Roles
                            </th>
                            <th
                                className="px-4 py-3 text-right text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Actions
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {groupsLoading && (
                            <tr>
                                <td colSpan={5} className="px-4 py-12 text-center">
                                    <Spinner className="mx-auto" />
                                </td>
                            </tr>
                        )}
                        {groupsError !== null && (
                            <tr>
                                <td
                                    colSpan={5}
                                    className="px-4 py-8 text-center text-sm"
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    Failed to load groups. Please try again.
                                </td>
                            </tr>
                        )}
                        {!groupsLoading && !groupsError && groups.length === 0 && (
                            <tr>
                                <td
                                    colSpan={5}
                                    className="px-4 py-8 text-center text-sm"
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    No groups yet. Create one to get started.
                                </td>
                            </tr>
                        )}
                        {!groupsLoading &&
                            !groupsError &&
                            groups.map((group) => (
                                <GroupRow
                                    key={group.id}
                                    group={group}
                                    onEdit={openEdit}
                                    onDelete={openDelete}
                                    onManageRoles={(g) => {
                                        setRoleTtl('never');
                                        setManageGroupId(g.id);
                                    }}
                                    onViewSecrets={(g) => setSecretsGroup(g)}
                                />
                            ))}
                    </tbody>
                </table>
            </div>

            {/* Create Group */}
            <Modal isOpen={createOpen} onClose={() => setCreateOpen(false)} title="New Group">
                <div className="space-y-4">
                    <Input
                        label="Name"
                        value={formData.name}
                        onChange={(e) => setFormData((d) => ({ ...d, name: e.target.value }))}
                        placeholder="e.g. platform-team"
                    />
                    <div>
                        <label
                            htmlFor="create-group-description"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Description
                        </label>
                        <textarea
                            id="create-group-description"
                            value={formData.description}
                            onChange={(e) => setFormData((d) => ({ ...d, description: e.target.value }))}
                            rows={3}
                            className="w-full px-3 py-2 rounded-md border text-sm resize-none"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                borderColor: 'var(--border-strong)',
                                color: 'var(--text-primary)',
                            }}
                            placeholder="What this group is for"
                        />
                    </div>
                    {createMutation.isError && (
                        <p className="text-sm text-red-600">
                            {errMsg(createMutation.error, 'Failed to create group. Please try again.')}
                        </p>
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

            {/* Edit Group */}
            <Modal isOpen={editGroup !== null} onClose={() => setEditGroup(null)} title="Edit Group">
                <div className="space-y-4">
                    <Input
                        label="Name"
                        value={formData.name}
                        onChange={(e) => setFormData((d) => ({ ...d, name: e.target.value }))}
                    />
                    <div>
                        <label
                            htmlFor="edit-group-description"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Description
                        </label>
                        <textarea
                            id="edit-group-description"
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
                        <p className="text-sm text-red-600">
                            {errMsg(updateMutation.error, 'Failed to update group. Please try again.')}
                        </p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={() => setEditGroup(null)}>
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

            {/* Manage Roles */}
            <Modal
                isOpen={manageGroupId !== null}
                onClose={() => setManageGroupId(null)}
                title="Manage Roles"
                size="sm"
            >
                <div className="mb-3">
                    <Select
                        label="Grant duration"
                        options={EXPIRY_OPTIONS}
                        value={roleTtl}
                        onChange={(e) => setRoleTtl(e.target.value)}
                        helperText="Applied to the next role you check. Time-bound grants expire automatically."
                        fullWidth
                    />
                </div>
                {rolesLoading ? (
                    <div className="flex justify-center py-8">
                        <Spinner />
                    </div>
                ) : (
                    <div className="space-y-1 max-h-[55vh] overflow-y-auto pr-1">
                        {(allRoles ?? []).map((role) => {
                            const assigned = assignedRoleIds.has(role.id);
                            return (
                                <label
                                    key={role.id}
                                    className="flex items-center gap-3 rounded-md px-3 py-2.5 cursor-pointer"
                                    style={{ backgroundColor: 'var(--bg-subtle)' }}
                                >
                                    <input
                                        type="checkbox"
                                        checked={assigned}
                                        disabled={isMutatingRole}
                                        onChange={() => handleToggleRole(role)}
                                        className="h-4 w-4 rounded-sm accent-blue-600"
                                    />
                                    <div className="min-w-0">
                                        <span
                                            className="text-sm font-medium flex items-center gap-2"
                                            style={{ color: 'var(--text-primary)' }}
                                        >
                                            {role.name}
                                            {assigned && roleExpiryById.has(role.id) && (
                                                <span
                                                    className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
                                                    style={{
                                                        backgroundColor: 'var(--warning-subtle, #fef9c3)',
                                                        color: 'var(--warning, #a16207)',
                                                    }}
                                                    title={formatDateTime(roleExpiryById.get(role.id) as string)}
                                                >
                                                    {formatRemaining(roleExpiryById.get(role.id) as string)}
                                                </span>
                                            )}
                                        </span>
                                        {role.description && (
                                            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                                {role.description}
                                            </span>
                                        )}
                                    </div>
                                </label>
                            );
                        })}
                        {(allRoles ?? []).length === 0 && (
                            <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>
                                No roles available.
                            </p>
                        )}
                    </div>
                )}
                <div className="flex justify-end pt-4 mt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                    <Button variant="secondary" onClick={() => setManageGroupId(null)}>
                        Close
                    </Button>
                </div>
            </Modal>

            {/* Delete Group */}
            <Modal
                isOpen={deleteGroup !== null}
                onClose={() => {
                    setDeleteGroup(null);
                    deleteMutation.reset();
                }}
                title="Delete Group"
                size="sm"
            >
                <div className="space-y-4">
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Delete group <strong style={{ color: 'var(--text-primary)' }}>{deleteGroup?.name}</strong>? This
                        action cannot be undone.
                    </p>
                    {deleteMutation.isError && (
                        <p className="text-sm text-red-600">Failed to delete group. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button
                            variant="secondary"
                            onClick={() => {
                                setDeleteGroup(null);
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

            {/* Shared secrets — what this group can reach via shares (server #392) */}
            <Modal
                isOpen={secretsGroup !== null}
                onClose={() => setSecretsGroup(null)}
                title={secretsGroup ? `Secrets shared with ${secretsGroup.name}` : 'Shared secrets'}
                size="sm"
            >
                {sharedSecretsLoading ? (
                    <div className="flex justify-center py-8">
                        <Spinner />
                    </div>
                ) : (
                    (() => {
                        const secretsList = sharedSecrets ?? [];
                        if (secretsList.length === 0) {
                            return (
                                <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>
                                    No secrets are shared with this group.
                                </p>
                            );
                        }
                        return (
                            <ul className="space-y-1 max-h-[55vh] overflow-y-auto pr-1">
                                {secretsList.map((s) => (
                                    <li
                                        key={s.id}
                                        className="flex items-center justify-between rounded-md px-3 py-2.5"
                                        style={{ backgroundColor: 'var(--bg-subtle)' }}
                                    >
                                        <span
                                            className="text-sm font-medium truncate"
                                            style={{ color: 'var(--text-primary)' }}
                                        >
                                            {s.name}
                                        </span>
                                        {s.type && (
                                            <span
                                                className="text-xs ml-3 shrink-0"
                                                style={{ color: 'var(--text-muted)' }}
                                            >
                                                {s.type}
                                            </span>
                                        )}
                                    </li>
                                ))}
                            </ul>
                        );
                    })()
                )}
                <div className="flex justify-end pt-4 mt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                    <Button variant="secondary" onClick={() => setSecretsGroup(null)}>
                        Close
                    </Button>
                </div>
            </Modal>
        </div>
    );
};
