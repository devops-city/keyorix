import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '../../../test/test-utils';
import { ProjectMembersTab } from '../ProjectMembersTab';
import { answerConfirm, queryConfirm } from '../../../test/confirm';
import type { ProjectMember } from '../../../services/projects';
import { AxiosError } from 'axios';

const {
    addMemberMutate,
    updateRoleMutate,
    removeMemberMutate,
    useProjectMembersMock,
    useProjectMock,
    usersApiListMock,
} = vi.hoisted(() => ({
    addMemberMutate: vi.fn(),
    updateRoleMutate: vi.fn(),
    removeMemberMutate: vi.fn(),
    useProjectMembersMock: vi.fn(),
    useProjectMock: vi.fn(),
    usersApiListMock: vi.fn(),
}));

vi.mock('../../../features/projects/api', () => ({
    useProject: (...args: any[]) => useProjectMock(...args),
    useProjectMembers: (...args: any[]) => useProjectMembersMock(...args),
    useAddProjectMember: () => ({ mutate: addMemberMutate, isPending: false }),
    useUpdateProjectMemberRole: () => ({ mutate: updateRoleMutate, isPending: false }),
    useRemoveProjectMember: () => ({ mutate: removeMemberMutate, isPending: false }),
}));

vi.mock('../../../services/users', () => ({
    usersApi: { list: (...args: any[]) => usersApiListMock(...args) },
}));

vi.mock('../../../store/authStore', () => ({
    useAuthStore: () => ({ user: { id: 1 } }),
}));

// Every real entry in PROJECT_ROLES currently has a matching ROLE_CAPABILITIES
// entry with at least one granted capability, so RoleLegend's `?? []` and
// `|| 'No project-level permissions'` fallbacks are otherwise unreachable.
// Append one extra role name absent from the capability map to exercise them.
vi.mock('../../../services/projects', async (importOriginal) => {
    const actual = (await importOriginal()) as object;
    return { ...actual, PROJECT_ROLES: [...(actual as any).PROJECT_ROLES, 'mystery_role'] };
});

// The invite flow is owned by features/invitations and covered by its own
// tests (Phase 1). Here we only verify this tab opens/closes it and passes
// the right project context — not the modal's internal form behavior.
vi.mock('../../../features/invitations/InviteToProjectModal', () => ({
    InviteToProjectModal: ({ isOpen, onClose, projectId, projectName }: any) =>
        isOpen ? (
            <div data-testid="invite-modal">
                <span>
                    Invite modal for {projectName} (project {projectId})
                </span>
                <button type="button" onClick={onClose}>
                    Close invite modal
                </button>
            </div>
        ) : null,
}));

vi.mock('../../../features/invitations/PendingOnboardingSection', () => ({
    PendingOnboardingSection: ({ projectId, users }: any) => (
        <div data-testid="pending-onboarding">
            onboarding for project {projectId}, {users?.length ?? 0} users
        </div>
    ),
}));

vi.mock('../../../features/invitations/PendingAccessRequestsSection', () => ({
    PendingAccessRequestsSection: ({ projectId, users }: any) => (
        <div data-testid="pending-access-requests">
            access requests for project {projectId}, {users?.length ?? 0} users
        </div>
    ),
}));

vi.mock('../../../features/invitations/ProjectInvitationsSection', () => ({
    ProjectInvitationsSection: ({ projectId }: any) => (
        <div data-testid="project-invitations">invitations for project {projectId}</div>
    ),
}));

vi.mock('../../../features/machine-identities', () => ({
    MachineIdentitiesSection: ({ projectId }: any) => (
        <div data-testid="machine-identities">machine identities for project {projectId}</div>
    ),
}));

const makeMember = (overrides: Partial<ProjectMember> = {}): ProjectMember => ({
    userId: 1,
    username: 'alice',
    displayName: 'Alice Anderson',
    email: 'alice@example.com',
    roleId: 10,
    roleName: 'project_developer',
    ...overrides,
});

const otherUser = {
    id: 5,
    username: 'bob',
    displayName: 'Bob Baker',
    email: 'bob@example.com',
    role: 'user',
    roles: [],
    permissions: [],
    preferences: {},
    lastLogin: '',
};

function mockMembers(members: ProjectMember[], overrides: Partial<{ isLoading: boolean }> = {}) {
    useProjectMembersMock.mockReturnValue({ data: members, isLoading: overrides.isLoading ?? false });
}

beforeEach(() => {
    addMemberMutate.mockReset();
    updateRoleMutate.mockReset();
    removeMemberMutate.mockReset();
    useProjectMembersMock.mockReset();
    useProjectMock.mockReset();
    usersApiListMock.mockReset();

    useProjectMock.mockReturnValue({ data: { id: 1, name: 'Payments API' } });
    usersApiListMock.mockResolvedValue({ data: [otherUser], total: 1, page: 1, pageSize: 200, totalPages: 1 });
    mockMembers([]);
});

// What the signed-in user may do. Tests that exercise a control assume the user can; the
// permission-aware cases flip fields on this object (see useCan.ts).
const canState = vi.hoisted(() => ({
    value: { admin: true, writeSecrets: true, deleteSecrets: true, readAudit: true, manageMembers: true },
}));
vi.mock('../../../features/auth/useCan', () => ({ useCan: () => canState.value }));
beforeEach(() => {
    canState.value = { admin: true, writeSecrets: true, deleteSecrets: true, readAudit: true, manageMembers: true };
});

describe('ProjectMembersTab', () => {
    describe('members list states', () => {
        it('shows skeleton placeholders while loading', () => {
            mockMembers([], { isLoading: true });
            const { container } = render(<ProjectMembersTab projectId={1} />);

            expect(container.querySelectorAll('.animate-pulse')).toHaveLength(3);
        });

        it('shows an empty state when there are no members', () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            expect(screen.getByText(/No members yet\. Add a user above/i)).toBeInTheDocument();
        });

        it('renders each member with their display name, email and role', () => {
            mockMembers([
                makeMember(),
                makeMember({
                    userId: 2,
                    username: 'carol',
                    displayName: '',
                    email: 'carol@example.com',
                    roleName: 'project_viewer',
                }),
            ]);
            render(<ProjectMembersTab projectId={1} />);

            expect(screen.getByText('Alice Anderson')).toBeInTheDocument();
            expect(screen.getByText('alice@example.com')).toBeInTheDocument();
            // Falls back to username when displayName is empty.
            expect(screen.getByText('carol')).toBeInTheDocument();

            // Scope each role select to its own row — the "Add member" role
            // select above the list also defaults to "Viewer" and would
            // otherwise collide with carol's row select.
            const aliceRow = screen.getByText('Alice Anderson').closest('li')!;
            expect(within(aliceRow).getByDisplayValue('Developer')).toBeInTheDocument();
            const carolRow = screen.getByText('carol').closest('li')!;
            expect(within(carolRow).getByDisplayValue('Viewer')).toBeInTheDocument();
        });

        // Fixed: the members query's isError is now surfaced as a distinct
        // error state, instead of falling through to the same "No members
        // yet" copy a genuinely empty project shows.
        it('shows a distinct error state when the members query fails, not the empty-members copy', () => {
            useProjectMembersMock.mockReturnValue({ data: undefined, isLoading: false, isError: true });
            render(<ProjectMembersTab projectId={1} />);

            expect(screen.getByText(/Failed to load members/i)).toBeInTheDocument();
            expect(screen.queryByText(/No members yet/i)).not.toBeInTheDocument();
        });
    });

    describe('effective permissions panel', () => {
        it('expands a member row to show granted and denied capabilities for their role', () => {
            mockMembers([makeMember({ roleName: 'project_viewer' })]);
            render(<ProjectMembersTab projectId={1} />);

            expect(screen.queryByText('Read secrets')).not.toBeInTheDocument();
            fireEvent.click(screen.getByRole('button', { name: /Expand Alice Anderson/i }));

            expect(screen.getByText('Viewer role', { exact: false })).toBeInTheDocument();
            expect(screen.getByText('Read secrets')).toBeInTheDocument();
            expect(screen.getByText('Manage members')).toBeInTheDocument();

            // Collapses again on a second click.
            fireEvent.click(screen.getByRole('button', { name: /Collapse Alice Anderson/i }));
            expect(screen.queryByText('Read secrets')).not.toBeInTheDocument();
        });

        it('falls back to no capabilities/description for a role outside the known set', () => {
            mockMembers([makeMember({ roleName: 'legacy_owner' })]);
            render(<ProjectMembersTab projectId={1} />);

            fireEvent.click(screen.getByRole('button', { name: /Expand Alice Anderson/i }));

            // The role heading renders with an empty description, and there are no
            // granted/denied capability rows since ROLE_CAPABILITIES has no entry for it.
            expect(screen.getByText('Legacy_owner role', { exact: false })).toBeInTheDocument();
            expect(screen.queryByText('Read secrets')).not.toBeInTheDocument();
        });
    });

    describe('role change', () => {
        it('calls updateRole.mutate with the new role when the select changes', () => {
            mockMembers([makeMember()]);
            render(<ProjectMembersTab projectId={1} />);

            fireEvent.change(screen.getByDisplayValue('Developer'), { target: { value: 'project_admin' } });

            expect(updateRoleMutate).toHaveBeenCalledWith({ userId: 1, role: 'project_admin' });
        });

        it('includes the current role as an extra option when it is outside the standard set', () => {
            mockMembers([makeMember({ roleName: 'legacy_owner' })]);
            render(<ProjectMembersTab projectId={1} />);

            expect(screen.getByDisplayValue('Legacy_owner')).toBeInTheDocument();
        });

        it('stops a click on the role select from bubbling up and toggling the row', () => {
            mockMembers([makeMember()]);
            render(<ProjectMembersTab projectId={1} />);

            fireEvent.click(screen.getByDisplayValue('Developer'));

            expect(screen.getByRole('button', { name: /Expand Alice Anderson/i })).toBeInTheDocument();
            expect(screen.queryByText('Read secrets')).not.toBeInTheDocument();
        });
    });

    describe('remove member', () => {
        // Removal goes through the in-app confirmation dialog (#3153) and
        // proceeds only when confirmed. The mocked current user is id 1,
        // matching makeMember()'s default userId, so this exercises the
        // self-removal wording specifically.
        it('confirms before removing, with a self-removal warning when the current user removes themselves', async () => {
            const confirmSpy = vi.spyOn(window, 'confirm');
            mockMembers([makeMember(), makeMember({ userId: 2, roleName: 'project_admin' })]);
            render(<ProjectMembersTab projectId={1} />);

            const removeButtons = screen.getAllByTitle('Remove from project');
            fireEvent.click(removeButtons[0]); // Alice — userId 1, the mocked "current user"
            expect(removeMemberMutate).not.toHaveBeenCalled();
            await answerConfirm('Remove yourself from this project? You will lose access immediately.', 'accept');

            await waitFor(() => expect(removeMemberMutate).toHaveBeenCalledWith(1));
            expect(confirmSpy).not.toHaveBeenCalled(); // in-app dialog, not window.confirm
            confirmSpy.mockRestore();
        });

        it('confirms with the member name (not self-removal wording) when removing someone else', async () => {
            mockMembers([makeMember(), makeMember({ userId: 2, displayName: 'Carol', roleName: 'project_developer' })]);
            render(<ProjectMembersTab projectId={1} />);

            const removeButtons = screen.getAllByTitle('Remove from project');
            fireEvent.click(removeButtons[1]); // Carol, userId 2 — not the mocked current user
            await answerConfirm('Remove Carol from this project?', 'accept');

            await waitFor(() => expect(removeMemberMutate).toHaveBeenCalledWith(2));
        });

        it('does not remove the member when the confirmation is cancelled', async () => {
            mockMembers([makeMember()]);
            render(<ProjectMembersTab projectId={1} />);

            fireEvent.click(screen.getByTitle('Remove from project'));
            await answerConfirm(/^Remove yourself from this project\?/, 'cancel');

            await waitFor(() => expect(queryConfirm(/^Remove yourself/)).toBeNull());
            expect(removeMemberMutate).not.toHaveBeenCalled();
        });

        // Fixed: removing the last project_admin (the closest analog to an
        // "owner" this project model has) is now hard-blocked, before ever
        // prompting for confirmation.
        it('blocks removing the last admin, without ever prompting for confirmation', () => {
            mockMembers([makeMember({ roleName: 'project_admin' })]);
            render(<ProjectMembersTab projectId={1} />);

            fireEvent.click(screen.getByTitle('Remove from project'));

            expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
            expect(removeMemberMutate).not.toHaveBeenCalled();
            expect(screen.getByText(/cannot remove the last admin/i)).toBeInTheDocument();
        });

        it('falls back through displayName to username, then to a generic label/initial', async () => {
            mockMembers([
                makeMember({ userId: 3, displayName: '', username: 'dave', roleName: 'project_developer' }),
                makeMember({ userId: 4, displayName: '', username: '', roleName: 'project_developer' }),
            ]);
            render(<ProjectMembersTab projectId={1} />);

            // displayName empty -> falls back to username for the avatar initial and aria-label.
            expect(screen.getByRole('button', { name: /Expand dave/i })).toBeInTheDocument();
            // Both empty -> avatar initial falls back to '?' and aria-label's name segment is
            // empty (the accessible name computation trims the resulting trailing space).
            expect(screen.getByText('?')).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /^Expand$/i })).toBeInTheDocument();

            const removeButtons = screen.getAllByTitle('Remove from project');
            fireEvent.click(removeButtons[0]); // dave: displayName empty, username set
            await answerConfirm('Remove dave from this project?', 'cancel');
            await waitFor(() => expect(queryConfirm(/^Remove dave/)).toBeNull());

            fireEvent.click(removeButtons[1]); // both empty -> generic "this member"
            await answerConfirm('Remove this member from this project?', 'cancel');
        });

        it('allows removing an admin when another admin remains', async () => {
            mockMembers([
                makeMember({ roleName: 'project_admin' }),
                makeMember({ userId: 2, displayName: 'Carol', roleName: 'project_admin' }),
            ]);
            render(<ProjectMembersTab projectId={1} />);

            const removeButtons = screen.getAllByTitle('Remove from project');
            fireEvent.click(removeButtons[1]); // Carol — not the last admin
            await answerConfirm('Remove Carol from this project?', 'accept');

            await waitFor(() => expect(removeMemberMutate).toHaveBeenCalledWith(2));
        });
    });

    describe('add member', () => {
        it('excludes existing members from the candidate dropdown', async () => {
            mockMembers([makeMember({ userId: 5 })]); // same id as otherUser
            render(<ProjectMembersTab projectId={1} />);

            await waitFor(() => expect(usersApiListMock).toHaveBeenCalled());
            expect(screen.queryByRole('option', { name: /Bob Baker/i })).not.toBeInTheDocument();
        });

        it('adds a candidate user with the selected role', async () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            const userSelect = await screen.findByDisplayValue('Select a user to add…');
            // Wait for the candidate option to actually be in the DOM before
            // selecting it — the users list resolves asynchronously.
            await screen.findByRole('option', { name: /Bob Baker/i });
            fireEvent.change(userSelect, { target: { value: '5' } });

            const roleSelect = screen.getByDisplayValue('Viewer');
            fireEvent.change(roleSelect, { target: { value: 'project_admin' } });

            fireEvent.click(screen.getByRole('button', { name: /^Add$/i }));

            expect(addMemberMutate).toHaveBeenCalledWith(
                { userId: 5, role: 'project_admin' },
                expect.objectContaining({ onSuccess: expect.any(Function), onError: expect.any(Function) })
            );
        });

        it('does nothing when Add is clicked with no user selected', () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            expect(screen.getByRole('button', { name: /^Add$/i })).toBeDisabled();
        });

        it('falls back to username and omits the email parenthetical for a candidate with neither', async () => {
            // displayName uses `??`, which only falls through on null/undefined (not '').
            usersApiListMock.mockResolvedValue({
                data: [{ ...otherUser, id: 6, username: 'eve', displayName: undefined, email: '' }],
                total: 1,
                page: 1,
                pageSize: 200,
                totalPages: 1,
            });
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            expect(await screen.findByRole('option', { name: /^eve$/i })).toBeInTheDocument();
        });

        it('clears the selected user on a successful add', async () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            const userSelect = (await screen.findByDisplayValue('Select a user to add…')) as HTMLSelectElement;
            await screen.findByRole('option', { name: /Bob Baker/i });
            fireEvent.change(userSelect, { target: { value: '5' } });
            fireEvent.click(screen.getByRole('button', { name: /^Add$/i }));

            const onSuccess = addMemberMutate.mock.calls[0][1].onSuccess;
            onSuccess();

            await waitFor(() => expect(userSelect.value).toBe(''));
        });

        it('surfaces the API error message from a failed add', async () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            const userSelect = await screen.findByDisplayValue('Select a user to add…');
            await screen.findByRole('option', { name: /Bob Baker/i });
            fireEvent.change(userSelect, { target: { value: '5' } });
            fireEvent.click(screen.getByRole('button', { name: /^Add$/i }));

            const onError = addMemberMutate.mock.calls[0][1].onError;
            const refusal = new AxiosError('Request failed with status code 409');
            refusal.response = { data: { error: 'user already a member' } } as AxiosError['response'];
            onError(refusal);

            expect(await screen.findByText('user already a member')).toBeInTheDocument();
        });

        it('falls back to a generic message when the add error has no server message', async () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            const userSelect = await screen.findByDisplayValue('Select a user to add…');
            await screen.findByRole('option', { name: /Bob Baker/i });
            fireEvent.change(userSelect, { target: { value: '5' } });
            fireEvent.click(screen.getByRole('button', { name: /^Add$/i }));

            const onError = addMemberMutate.mock.calls[0][1].onError;
            onError({});

            expect(await screen.findByText('Failed to add member.')).toBeInTheDocument();
        });
    });

    describe('role permissions reference (legend)', () => {
        it('is collapsed by default and expands to list each role', () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            expect(screen.queryByText('No project-level permissions')).not.toBeInTheDocument();
            const legendRoot = screen.getByText('Role permissions reference').closest('div')!;
            fireEvent.click(screen.getByText('Role permissions reference'));

            // Scope to the legend panel — the "Add member" role select above it
            // also renders an <option>Admin</option> / <option>Auditor</option>.
            expect(within(legendRoot).getByText('Admin')).toBeInTheDocument();
            expect(within(legendRoot).getByText('Auditor')).toBeInTheDocument();
        });

        it('falls back to a generic label and "no permissions" copy for a role missing from the capability map', () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            const legendRoot = screen.getByText('Role permissions reference').closest('div')!;
            fireEvent.click(screen.getByText('Role permissions reference'));

            expect(within(legendRoot).getByText('Mystery_role')).toBeInTheDocument();
            expect(within(legendRoot).getByText('No project-level permissions')).toBeInTheDocument();
        });
    });

    describe('invite modal wiring', () => {
        it('is closed by default and opens when "Invite by email" is clicked', () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            expect(screen.queryByTestId('invite-modal')).not.toBeInTheDocument();
            fireEvent.click(screen.getByRole('button', { name: /Invite by email/i }));

            const modal = screen.getByTestId('invite-modal');
            expect(within(modal).getByText(/Invite modal for Payments API \(project 1\)/i)).toBeInTheDocument();
        });

        it('closes when the modal requests it', () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            fireEvent.click(screen.getByRole('button', { name: /Invite by email/i }));
            fireEvent.click(screen.getByRole('button', { name: /Close invite modal/i }));

            expect(screen.queryByTestId('invite-modal')).not.toBeInTheDocument();
        });

        it('falls back to a generic project name when the project has not loaded yet', () => {
            useProjectMock.mockReturnValue({ data: undefined });
            mockMembers([]);
            render(<ProjectMembersTab projectId={1} />);

            fireEvent.click(screen.getByRole('button', { name: /Invite by email/i }));
            expect(screen.getByText(/Invite modal for project \(project 1\)/i)).toBeInTheDocument();
        });
    });

    describe('membership-related child sections', () => {
        it('wires projectId (and users where applicable) into each child section', async () => {
            mockMembers([]);
            render(<ProjectMembersTab projectId={7} />);

            await waitFor(() => expect(usersApiListMock).toHaveBeenCalled());

            expect(screen.getByTestId('machine-identities')).toHaveTextContent('machine identities for project 7');
            expect(await screen.findByTestId('pending-onboarding')).toHaveTextContent(
                'onboarding for project 7, 1 users'
            );
            expect(screen.getByTestId('pending-access-requests')).toHaveTextContent(
                'access requests for project 7, 1 users'
            );
            expect(screen.getByTestId('project-invitations')).toHaveTextContent('invitations for project 7');
        });
    });
});

describe('ProjectMembersTab permission-aware controls (DEMO-UI-1)', () => {
    it('a member without roles.assign sees the roster but no Add / Invite / role / remove controls', async () => {
        canState.value = {
            ...canState.value,
            admin: false,
            writeSecrets: false,
            deleteSecrets: false,
            manageMembers: false,
            readAudit: false,
        };
        mockMembers([makeMember({ userId: 2, roleName: 'project_viewer' })]);
        render(<ProjectMembersTab projectId={1} />);

        expect(screen.getByText('Human members')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /invite by email/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /^Add$/i })).not.toBeInTheDocument();
        expect(screen.queryByTitle('Remove from project')).not.toBeInTheDocument();
        expect(screen.queryByDisplayValue('Select a user to add…')).not.toBeInTheDocument();
        // The user directory is an admin read: asking for it as a plain member is just a 403.
        expect(usersApiListMock).not.toHaveBeenCalled();
        // The admin-only child sections are not mounted for them either.
        expect(screen.queryByTestId('pending-onboarding')).not.toBeInTheDocument();
        expect(screen.queryByTestId('project-invitations')).not.toBeInTheDocument();
    });
});
