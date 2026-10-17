import { useCan } from '../../features/auth/useCan';
import { apiErrorMessage } from '../../services/client';
import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    UserCircleIcon,
    TrashIcon,
    PlusIcon,
    EnvelopeIcon,
    ChevronDownIcon,
    ChevronRightIcon,
} from '@heroicons/react/24/outline';
import { usersApi } from '../../services/users';
import { PROJECT_ROLES, ProjectMember } from '../../services/projects';
import { useAuthStore } from '../../store/authStore';
import { useConfirm } from '../../components/ui/useConfirm';
import {
    useProject,
    useProjectMembers,
    useAddProjectMember,
    useUpdateProjectMemberRole,
    useRemoveProjectMember,
} from '../../features/projects/api';
import { InviteToProjectModal } from '../../features/invitations/InviteToProjectModal';
import { PendingOnboardingSection } from '../../features/invitations/PendingOnboardingSection';
import { PendingAccessRequestsSection } from '../../features/invitations/PendingAccessRequestsSection';
import { ProjectInvitationsSection } from '../../features/invitations/ProjectInvitationsSection';
import { MachineIdentitiesSection } from '../../features/machine-identities';

interface ProjectMembersTabProps {
    projectId: number;
}

// "project_developer" → "Developer"
const roleLabel = (role: string) => role.replace(/^project_/, '').replace(/^\w/, (c) => c.toUpperCase());

// ─── Role permission definitions ─────────────────────────────────────────────
// Static capability matrix for each project role. Covers the capabilities that
// project members care about; org-level permissions (admin console, user
// management) are separate and controlled by system roles.

interface Capability {
    name: string;
    description: string;
    granted: boolean;
}

const ROLE_CAPABILITIES: Record<string, Capability[]> = {
    project_admin: [
        { name: 'Read secrets', description: 'View secret values in this project', granted: true },
        { name: 'Write secrets', description: 'Create and update secrets', granted: true },
        { name: 'Delete secrets', description: 'Permanently remove secrets', granted: true },
        { name: 'Rotate secrets', description: 'Trigger and configure rotation', granted: true },
        { name: 'Manage members', description: 'Add, remove, and change member roles', granted: true },
        { name: 'Manage machine identities', description: 'Issue and revoke CI/CD tokens', granted: true },
        { name: 'View audit log', description: 'Read project audit events', granted: true },
        { name: 'Export / share secrets', description: 'Share secrets with other projects', granted: true },
    ],
    project_developer: [
        { name: 'Read secrets', description: 'View secret values in this project', granted: true },
        { name: 'Write secrets', description: 'Create and update secrets', granted: true },
        { name: 'Delete secrets', description: 'Permanently remove secrets', granted: false },
        { name: 'Rotate secrets', description: 'Trigger and configure rotation', granted: true },
        { name: 'Manage members', description: 'Add, remove, and change member roles', granted: false },
        { name: 'Manage machine identities', description: 'Issue and revoke CI/CD tokens', granted: false },
        { name: 'View audit log', description: 'Read project audit events', granted: true },
        { name: 'Export / share secrets', description: 'Share secrets with other projects', granted: false },
    ],
    project_viewer: [
        { name: 'Read secrets', description: 'View secret values in this project', granted: true },
        { name: 'Write secrets', description: 'Create and update secrets', granted: false },
        { name: 'Delete secrets', description: 'Permanently remove secrets', granted: false },
        { name: 'Rotate secrets', description: 'Trigger and configure rotation', granted: false },
        { name: 'Manage members', description: 'Add, remove, and change member roles', granted: false },
        { name: 'Manage machine identities', description: 'Issue and revoke CI/CD tokens', granted: false },
        { name: 'View audit log', description: 'Read project audit events', granted: false },
        { name: 'Export / share secrets', description: 'Share secrets with other projects', granted: false },
    ],
    project_auditor: [
        { name: 'Read secrets', description: 'View secret values in this project', granted: false },
        { name: 'Write secrets', description: 'Create and update secrets', granted: false },
        { name: 'Delete secrets', description: 'Permanently remove secrets', granted: false },
        { name: 'Rotate secrets', description: 'Trigger and configure rotation', granted: false },
        { name: 'Manage members', description: 'Add, remove, and change member roles', granted: false },
        { name: 'Manage machine identities', description: 'Issue and revoke CI/CD tokens', granted: false },
        { name: 'View audit log', description: 'Read project audit events', granted: true },
        { name: 'Export / share secrets', description: 'Share secrets with other projects', granted: false },
    ],
};

const ROLE_DESCRIPTIONS: Record<string, string> = {
    project_admin: 'Full project control — read, write, delete secrets; manage members and machine identities.',
    project_developer: 'Read and write secrets; trigger rotation; view audit log. Cannot delete or manage access.',
    project_viewer: 'Read-only access to secrets. Cannot modify anything.',
    project_auditor: 'Audit log access only. Cannot view or modify secrets.',
};

// ─── EffectivePermissionsPanel ────────────────────────────────────────────────

interface EffectivePermissionsPanelProps {
    role: string;
}

const EffectivePermissionsPanel: React.FC<EffectivePermissionsPanelProps> = ({ role }) => {
    const caps = ROLE_CAPABILITIES[role] ?? [];
    const granted = caps.filter((c) => c.granted);
    const denied = caps.filter((c) => !c.granted);

    return (
        <div className="px-4 py-4" style={{ backgroundColor: 'var(--bg-app)' }}>
            <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
                <span className="font-semibold" style={{ color: 'var(--text-secondary)' }}>
                    {roleLabel(role)} role
                </span>
                {' — '}
                {ROLE_DESCRIPTIONS[role] ?? ''}
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {granted.map((c) => (
                    <div key={c.name} className="flex items-start gap-2">
                        <span className="mt-0.5 text-emerald-500 text-xs shrink-0">✓</span>
                        <div>
                            <span className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>
                                {c.name}
                            </span>
                            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                {' '}
                                — {c.description}
                            </span>
                        </div>
                    </div>
                ))}
                {denied.map((c) => (
                    <div key={c.name} className="flex items-start gap-2 opacity-40">
                        <span className="mt-0.5 text-xs shrink-0" style={{ color: 'var(--text-muted)' }}>
                            ✕
                        </span>
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {c.name}
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
};

// ─── RoleLegend ──────────────────────────────────────────────────────────────

const RoleLegend: React.FC = () => {
    const [open, setOpen] = useState(false);
    return (
        <div
            className="rounded-lg border mb-4 overflow-hidden"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <button
                type="button"
                onClick={() => setOpen((o) => !o)}
                className="w-full px-4 py-3 flex items-center justify-between text-left"
            >
                <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
                    Role permissions reference
                </span>
                {open ? (
                    <ChevronDownIcon className="h-4 w-4" style={{ color: 'var(--text-muted)' }} />
                ) : (
                    <ChevronRightIcon className="h-4 w-4" style={{ color: 'var(--text-muted)' }} />
                )}
            </button>
            {open && (
                <div
                    className="border-t px-4 py-4 grid grid-cols-1 sm:grid-cols-2 gap-4"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-app)' }}
                >
                    {PROJECT_ROLES.map((role) => {
                        const caps = ROLE_CAPABILITIES[role] ?? [];
                        const grantedNames = caps.filter((c) => c.granted).map((c) => c.name);
                        return (
                            <div key={role}>
                                <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>
                                    {roleLabel(role)}
                                </p>
                                <p className="text-xs leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                                    {grantedNames.join(' · ') || 'No project-level permissions'}
                                </p>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
};

// ─── Main tab component ───────────────────────────────────────────────────────

/**
 * ADR-021 Members tab. Project-scoped membership: shows the users who hold a
 * role in *this* project, with controls to add members, change their project
 * role, and remove them. Expandable rows show effective permissions per role.
 * System-level user provisioning stays on the admin User Management page.
 */
export const ProjectMembersTab: React.FC<ProjectMembersTabProps> = ({ projectId }) => {
    const { data: members = [], isLoading, isError } = useProjectMembers(projectId);
    const { data: project } = useProject(projectId);
    const { user } = useAuthStore();
    const can = useCan();
    const { data: usersResp } = useQuery({
        queryKey: ['users-list-members'],
        queryFn: () => usersApi.list({ pageSize: 200 }),
        staleTime: 60_000,
        // The user directory is an admin read; asking as a plain member only produces a 403.
        enabled: can.manageMembers,
    });

    const addMember = useAddProjectMember(projectId);
    const updateRole = useUpdateProjectMemberRole(projectId);
    const removeMember = useRemoveProjectMember(projectId);
    const { requestConfirm, confirmDialog } = useConfirm();

    const [newUserId, setNewUserId] = useState('');
    const [newRole, setNewRole] = useState<string>(PROJECT_ROLES[2]); // project_viewer
    const [error, setError] = useState('');
    const [inviteOpen, setInviteOpen] = useState(false);
    const [expandedMemberId, setExpandedMemberId] = useState<number | null>(null);

    const allUsers = useMemo(() => usersResp?.data ?? [], [usersResp]);

    const memberIds = useMemo(() => new Set(members.map((m) => m.userId)), [members]);
    const candidates = useMemo(() => allUsers.filter((u: any) => !memberIds.has(u.id)), [allUsers, memberIds]);

    // "project_admin" is the closest analog to an "owner" role this project
    // model has — there is no dedicated owner flag. Removing the last one
    // would leave the project with nobody able to manage members or secrets.
    const adminCount = useMemo(() => members.filter((m) => m.roleName === 'project_admin').length, [members]);

    const handleRemoveMember = async (member: ProjectMember) => {
        const isLastAdmin = member.roleName === 'project_admin' && adminCount <= 1;
        if (isLastAdmin) {
            setError('Cannot remove the last admin from this project. Promote another member to Admin first.');
            return;
        }

        const isSelf = member.userId === user?.id;
        const confirmed = await requestConfirm({
            title: isSelf ? 'Leave project' : 'Remove member',
            message: isSelf
                ? 'Remove yourself from this project? You will lose access immediately.'
                : `Remove ${member.displayName || member.username || 'this member'} from this project?`,
            confirmText: 'Remove',
        });
        if (!confirmed) return;

        setError('');
        removeMember.mutate(member.userId);
    };

    const handleAdd = () => {
        if (!newUserId) return;
        setError('');
        addMember.mutate(
            { userId: Number(newUserId), role: newRole },
            {
                onSuccess: () => setNewUserId(''),
                onError: (err: unknown) => setError(apiErrorMessage(err, 'Failed to add member.')),
            }
        );
    };

    const selectStyle: React.CSSProperties = {
        backgroundColor: 'var(--bg-app)',
        border: '1px solid var(--border)',
        color: 'var(--text-primary)',
    };

    return (
        <div>
            <div className="mb-4 flex items-start justify-between gap-3">
                <div>
                    <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                        Members
                    </h2>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                        Users with a role in this project. Click a member to see their effective permissions. Add
                        existing users and assign a project role; create new user accounts from Access Control → Users.
                    </p>
                </div>
                {can.manageMembers && (
                    <button
                        type="button"
                        onClick={() => setInviteOpen(true)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm font-medium shrink-0"
                        style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                    >
                        <EnvelopeIcon className="h-4 w-4" />
                        Invite by email
                    </button>
                )}
            </div>

            {error && (
                <div
                    className="rounded-lg px-3 py-2 text-sm mb-3"
                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                >
                    {error}
                </div>
            )}

            {/* Add member */}
            {can.manageMembers && (
                <div
                    className="rounded-lg border p-3 mb-4 flex flex-wrap items-center gap-2"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                >
                    <select
                        value={newUserId}
                        onChange={(e) => setNewUserId(e.target.value)}
                        className="flex-1 min-w-[12rem] rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={selectStyle}
                    >
                        <option value="">Select a user to add…</option>
                        {candidates.map((u: any) => (
                            <option key={u.id} value={u.id}>
                                {u.displayName ?? u.username}
                                {u.email ? ` (${u.email})` : ''}
                            </option>
                        ))}
                    </select>
                    <select
                        value={newRole}
                        onChange={(e) => setNewRole(e.target.value)}
                        className="rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={selectStyle}
                    >
                        {PROJECT_ROLES.map((r) => (
                            <option key={r} value={r}>
                                {roleLabel(r)}
                            </option>
                        ))}
                    </select>
                    <button
                        type="button"
                        onClick={handleAdd}
                        disabled={!newUserId || addMember.isPending}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50"
                        style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                    >
                        <PlusIcon className="h-4 w-4" />
                        Add
                    </button>
                </div>
            )}

            {/* Role permissions reference (collapsible) */}
            <RoleLegend />

            {/* Human members (the human half of the ADR-023 Humans vs Machine
                Identities segmentation; machine identities are listed below). */}
            <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
                Human members
            </h3>
            <div
                className="rounded-lg border overflow-hidden"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                {(() => {
                    if (isLoading) {
                        return (
                            <div className="p-6 space-y-3">
                                {[1, 2, 3].map((i) => (
                                    <div key={i} className="flex items-center gap-3 animate-pulse">
                                        <div
                                            className="h-8 w-8 rounded-full"
                                            style={{ backgroundColor: 'var(--bg-muted)' }}
                                        />
                                        <div className="flex-1">
                                            <div
                                                className="h-3 w-32 rounded-sm mb-1.5"
                                                style={{ backgroundColor: 'var(--bg-muted)' }}
                                            />
                                            <div
                                                className="h-2.5 w-48 rounded-sm"
                                                style={{ backgroundColor: 'var(--bg-muted)' }}
                                            />
                                        </div>
                                    </div>
                                ))}
                            </div>
                        );
                    }
                    if (isError) {
                        return (
                            <div className="p-10 text-center">
                                <UserCircleIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--error)' }} />
                                <p className="text-sm font-medium" style={{ color: 'var(--error)' }}>
                                    Failed to load members.
                                </p>
                                <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                                    Try refreshing the page.
                                </p>
                            </div>
                        );
                    }
                    if (members.length === 0) {
                        return (
                            <div className="p-10 text-center">
                                <UserCircleIcon
                                    className="h-10 w-10 mx-auto mb-3"
                                    style={{ color: 'var(--text-muted)' }}
                                />
                                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                    No members yet. Add a user above to grant project access.
                                </p>
                            </div>
                        );
                    }
                    const toggleMember = (userId: number) =>
                        setExpandedMemberId((prev) => (prev === userId ? null : userId));
                    return (
                        <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                            {members.map((m) => {
                                const isExpanded = expandedMemberId === m.userId;
                                return (
                                    <React.Fragment key={m.userId}>
                                        <li
                                            className="relative hover:bg-subtle transition-colors duration-75"
                                            style={{ borderColor: 'var(--border)' }}
                                        >
                                            <button
                                                type="button"
                                                className="absolute inset-0 cursor-pointer"
                                                onClick={() => toggleMember(m.userId)}
                                                aria-label={`${isExpanded ? 'Collapse' : 'Expand'} ${m.displayName || m.username || ''}`}
                                            />
                                            <div className="relative flex items-center gap-3 px-4 py-3 pointer-events-none">
                                                {/* Expand chevron */}
                                                <span className="text-base-muted text-xs select-none">
                                                    {isExpanded ? '▾' : '▸'}
                                                </span>
                                                <div
                                                    className="h-8 w-8 rounded-full flex items-center justify-center shrink-0 text-xs font-semibold"
                                                    style={{
                                                        backgroundColor: 'var(--accent-subtle)',
                                                        color: 'var(--accent-text)',
                                                    }}
                                                >
                                                    {(m.displayName || m.username || '?').charAt(0).toUpperCase()}
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <p
                                                        className="text-sm font-medium truncate"
                                                        style={{ color: 'var(--text-primary)' }}
                                                    >
                                                        {m.displayName || m.username}
                                                    </p>
                                                    <p
                                                        className="text-xs truncate"
                                                        style={{ color: 'var(--text-muted)' }}
                                                    >
                                                        {m.email}
                                                    </p>
                                                </div>
                                                {!can.manageMembers && (
                                                    <span
                                                        className="text-xs shrink-0"
                                                        style={{ color: 'var(--text-muted)' }}
                                                    >
                                                        {roleLabel(m.roleName)}
                                                    </span>
                                                )}
                                                {can.manageMembers && (
                                                    <select
                                                        value={m.roleName}
                                                        onChange={(e) => {
                                                            e.stopPropagation();
                                                            updateRole.mutate({
                                                                userId: m.userId,
                                                                role: e.target.value,
                                                            });
                                                        }}
                                                        onClick={(e) => e.stopPropagation()}
                                                        disabled={updateRole.isPending}
                                                        className="rounded-lg px-2 py-1 text-xs outline-hidden shrink-0 pointer-events-auto"
                                                        style={selectStyle}
                                                    >
                                                        {/* Include the current role even if it's outside the standard set (e.g. a custom or system role). */}
                                                        {!PROJECT_ROLES.includes(m.roleName as any) && (
                                                            <option value={m.roleName}>{roleLabel(m.roleName)}</option>
                                                        )}
                                                        {PROJECT_ROLES.map((r) => (
                                                            <option key={r} value={r}>
                                                                {roleLabel(r)}
                                                            </option>
                                                        ))}
                                                    </select>
                                                )}
                                                {(can.manageMembers || m.userId === user?.id) && (
                                                    <button
                                                        type="button"
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            handleRemoveMember(m);
                                                        }}
                                                        disabled={removeMember.isPending}
                                                        className="p-1.5 rounded-sm transition-colors hover:bg-red-50 disabled:opacity-50 shrink-0 pointer-events-auto"
                                                        style={{ color: 'var(--error)' }}
                                                        title="Remove from project"
                                                    >
                                                        <TrashIcon className="h-4 w-4" />
                                                    </button>
                                                )}
                                            </div>
                                        </li>
                                        {isExpanded && (
                                            <li className="border-t" style={{ borderColor: 'var(--border)' }}>
                                                <EffectivePermissionsPanel role={m.roleName} />
                                            </li>
                                        )}
                                    </React.Fragment>
                                );
                            })}
                        </ul>
                    );
                })()}
            </div>

            {/* ADR-023: machine identities — the non-human half of the Members
                segmentation. Read-only for ordinary members; admins manage. */}
            <MachineIdentitiesSection projectId={projectId} />

            {/* ADR-022: memberships stuck mid-onboarding (invited by email but not
                yet stepped through to active — no role, not in the list above). */}
            {can.manageMembers && <PendingOnboardingSection projectId={projectId} users={allUsers} />}

            {/* ADR-024: pending access requests + invitations (admin-only; the
                queries 403 for non-admins and the sections render nothing). */}
            {can.manageMembers && <PendingAccessRequestsSection projectId={projectId} users={allUsers} />}
            {can.manageMembers && <ProjectInvitationsSection projectId={projectId} />}

            <InviteToProjectModal
                isOpen={inviteOpen}
                onClose={() => setInviteOpen(false)}
                projectId={projectId}
                projectName={project?.name ?? 'project'}
            />
            {confirmDialog}
        </div>
    );
};
