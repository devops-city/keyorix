import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within, act } from '../../../test/test-utils';
import { GroupsPage } from '../GroupsPage';

const mocks = vi.hoisted(() => ({
    createMutate: vi.fn(),
    createReset: vi.fn(),
    updateMutate: vi.fn(),
    updateReset: vi.fn(),
    deleteMutate: vi.fn(),
    deleteReset: vi.fn(),
    assignMutate: vi.fn(),
    removeMutate: vi.fn(),
}));

const state = vi.hoisted(() => ({
    groups: { data: undefined as any, isLoading: false, error: null as unknown },
    roles: { data: undefined as any, isLoading: false },
    // group id -> role grants assigned to that group (drives both the row badges
    // and the Manage Roles modal's checked state).
    groupRolesByGroupId: {} as Record<number, any[]>,
    // group ids for which the per-row roles query hasn't resolved yet (data undefined).
    groupRolesUndefinedIds: new Set<number>(),
    sharedSecrets: { data: undefined as any, isLoading: false },
    createMutation: { isPending: false, isError: false },
    updateMutation: { isPending: false, isError: false },
    deleteMutation: { isPending: false, isError: false },
    assignMutation: { isPending: false },
    removeMutation: { isPending: false },
}));

vi.mock('../../../features/admin', () => ({
    useGroups: () => state.groups,
    useRoles: () => state.roles,
    useGroupRoles: (groupId: number | null) => {
        if (groupId === null || state.groupRolesUndefinedIds.has(groupId)) return { data: undefined };
        return { data: { group_id: groupId, roles: state.groupRolesByGroupId[groupId] ?? [] } };
    },
    useGroupSharedSecrets: (groupId: number | null) =>
        groupId === null ? { data: undefined, isLoading: false } : state.sharedSecrets,
    useCreateGroup: () => ({ mutate: mocks.createMutate, reset: mocks.createReset, ...state.createMutation }),
    useUpdateGroup: () => ({ mutate: mocks.updateMutate, reset: mocks.updateReset, ...state.updateMutation }),
    useDeleteGroup: () => ({ mutate: mocks.deleteMutate, reset: mocks.deleteReset, ...state.deleteMutation }),
    useAssignRoleToGroup: () => ({ mutate: mocks.assignMutate, ...state.assignMutation }),
    useRemoveRoleFromGroup: () => ({ mutate: mocks.removeMutate, ...state.removeMutation }),
}));

vi.mock('../../../features/projects/api', () => ({
    useProjects: () => ({ data: [{ id: 2, name: 'payments' }] }),
    useProjectEnvironments: (projectId: number) => ({
        data: projectId === 2 ? [{ id: 5, name: 'prod', projectId: 2 }] : undefined,
    }),
}));

const platformGroup = {
    id: 1,
    name: 'platform-team',
    description: 'Platform infra folks',
    member_count: 5,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
};

const securityGroup = {
    id: 2,
    name: 'security',
    description: '',
    created_at: '2026-01-02T00:00:00Z',
    updated_at: '2026-01-02T00:00:00Z',
};

const adminRole = { id: 10, name: 'admin', description: 'Full access', created_at: '', updated_at: '' };
const viewerRole = { id: 11, name: 'viewer', description: '', created_at: '', updated_at: '' };

function resetState() {
    state.groups = { data: undefined, isLoading: false, error: null };
    state.roles = { data: undefined, isLoading: false };
    state.groupRolesByGroupId = {};
    state.groupRolesUndefinedIds = new Set();
    state.sharedSecrets = { data: undefined, isLoading: false };
    state.createMutation = { isPending: false, isError: false };
    state.updateMutation = { isPending: false, isError: false };
    state.deleteMutation = { isPending: false, isError: false };
    state.assignMutation = { isPending: false };
    state.removeMutation = { isPending: false };
}

beforeEach(() => {
    vi.clearAllMocks();
    resetState();
});

describe('GroupsPage — groups list', () => {
    it('shows a loading spinner while groups are loading', () => {
        state.groups.isLoading = true;
        render(<GroupsPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an error state when groups fail to load', () => {
        state.groups.error = new Error('boom');
        render(<GroupsPage />);
        expect(screen.getByText('Failed to load groups. Please try again.')).toBeInTheDocument();
    });

    it('shows an empty state when there are no groups', () => {
        state.groups.data = { groups: [] };
        render(<GroupsPage />);
        expect(screen.getByText('No groups yet. Create one to get started.')).toBeInTheDocument();
    });

    it('renders group rows with name, description, member count, and assigned roles', () => {
        state.groups.data = { groups: [platformGroup, securityGroup] };
        state.groupRolesByGroupId[1] = [adminRole];
        render(<GroupsPage />);

        const rows = screen.getAllByRole('row');
        const platformRow = within(rows[1]!);
        expect(platformRow.getByText('platform-team')).toBeInTheDocument();
        expect(platformRow.getByText('Platform infra folks')).toBeInTheDocument();
        expect(platformRow.getByText('5')).toBeInTheDocument();
        expect(platformRow.getByText('admin')).toBeInTheDocument();

        const securityRow = within(rows[2]!);
        expect(securityRow.getByText('security')).toBeInTheDocument();
        // No description and no member_count -> em-dash placeholders; no roles -> "None".
        expect(securityRow.getAllByText('—').length).toBeGreaterThanOrEqual(2);
        expect(securityRow.getByText('None')).toBeInTheDocument();
    });

    it('shows "None" when the per-row roles query has not resolved yet', () => {
        state.groups.data = { groups: [platformGroup] };
        state.groupRolesUndefinedIds.add(1);
        render(<GroupsPage />);
        const row = within(screen.getAllByRole('row')[1]!);
        expect(row.getByText('None')).toBeInTheDocument();
    });

    it('swaps the row action buttons to their hover colors on mouse enter and back on leave', () => {
        state.groups.data = { groups: [platformGroup] };
        render(<GroupsPage />);

        const manageRolesButton = screen.getByTitle('Manage roles');
        fireEvent.mouseEnter(manageRolesButton);
        expect(manageRolesButton.style.color).toBe('var(--text-primary)');
        fireEvent.mouseLeave(manageRolesButton);
        expect(manageRolesButton.style.color).toBe('var(--text-muted)');

        const sharedSecretsButton = screen.getByTitle('Shared secrets');
        fireEvent.mouseEnter(sharedSecretsButton);
        expect(sharedSecretsButton.style.color).toBe('var(--text-primary)');
        fireEvent.mouseLeave(sharedSecretsButton);
        expect(sharedSecretsButton.style.color).toBe('var(--text-muted)');

        const editButton = screen.getByTitle('Edit group');
        fireEvent.mouseEnter(editButton);
        expect(editButton.style.color).toBe('var(--text-primary)');
        fireEvent.mouseLeave(editButton);
        expect(editButton.style.color).toBe('var(--text-muted)');

        const deleteButton = screen.getByTitle('Delete group');
        fireEvent.mouseEnter(deleteButton);
        expect(deleteButton.style.color).toBe('rgb(239, 68, 68)');
        fireEvent.mouseLeave(deleteButton);
        expect(deleteButton.style.color).toBe('var(--text-muted)');
    });
});

describe('GroupsPage — create group', () => {
    beforeEach(() => {
        state.groups.data = { groups: [platformGroup] };
    });

    it('disables Create until a name is entered, then submits the payload', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new group/i }));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByRole('button', { name: 'Create' })).toBeDisabled();

        fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'new-team' } });
        fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'a new team' } });
        expect(within(dialog).getByRole('button', { name: 'Create' })).toBeEnabled();

        fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
        expect(mocks.createMutate).toHaveBeenCalledWith(
            { name: 'new-team', description: 'a new team' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('closes the modal on successful create', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new group/i }));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'new-team' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create' }));

        const onSuccess = mocks.createMutate.mock.calls[0]![1].onSuccess;
        act(() => onSuccess());
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('shows an error message when create fails', () => {
        state.createMutation.isError = true;
        render(<GroupsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new group/i }));
        expect(screen.getByText('Failed to create group. Please try again.')).toBeInTheDocument();
    });

    it('discards the draft and resets mutation state when Cancel is clicked', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new group/i }));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'draft-name' } });
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        expect(mocks.createReset).toHaveBeenCalled();

        fireEvent.click(screen.getByRole('button', { name: /new group/i }));
        expect(screen.getByLabelText('Name')).toHaveValue('');
        // Opening the modal always resets the mutation state too.
        expect(mocks.createReset).toHaveBeenCalledTimes(2);
    });

    it('closes the create modal via the dialog close button without submitting', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new group/i }));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'draft-name' } });

        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(mocks.createMutate).not.toHaveBeenCalled();
    });
});

describe('GroupsPage — edit group', () => {
    beforeEach(() => {
        state.groups.data = { groups: [platformGroup] };
    });

    it('prefills the form from the selected group and submits an update', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Edit group'));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByLabelText('Name')).toHaveValue('platform-team');
        expect(within(dialog).getByLabelText('Description')).toHaveValue('Platform infra folks');

        fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'platform-team-renamed' } });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));

        expect(mocks.updateMutate).toHaveBeenCalledWith(
            { id: 1, body: { name: 'platform-team-renamed', description: 'Platform infra folks' } },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('closes the modal on successful update', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Edit group'));
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));

        const onSuccess = mocks.updateMutate.mock.calls[0]![1].onSuccess;
        act(() => onSuccess());
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('shows an error message when update fails', () => {
        state.updateMutation.isError = true;
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Edit group'));
        expect(screen.getByText('Failed to update group. Please try again.')).toBeInTheDocument();
    });

    it('lets the description be edited and closes on Cancel without submitting', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Edit group'));

        const dialog = screen.getByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'updated description' } });
        expect(within(dialog).getByLabelText('Description')).toHaveValue('updated description');

        fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(mocks.updateMutate).not.toHaveBeenCalled();
    });

    it('closes the edit modal via the dialog close button', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Edit group'));
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
});

describe('GroupsPage — delete group', () => {
    beforeEach(() => {
        state.groups.data = { groups: [platformGroup] };
    });

    it('shows a confirmation naming the group and calls delete on confirm', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Delete group'));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByText('platform-team')).toBeInTheDocument();

        fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
        expect(mocks.deleteMutate).toHaveBeenCalledWith(
            1,
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('resets the mutation state and closes the modal on successful delete', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Delete group'));
        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        const onSuccess = mocks.deleteMutate.mock.calls[0]![1].onSuccess;
        act(() => onSuccess());
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(mocks.deleteReset).toHaveBeenCalled();
    });

    it('shows an error message when delete fails', () => {
        state.deleteMutation.isError = true;
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Delete group'));
        expect(screen.getByText('Failed to delete group. Please try again.')).toBeInTheDocument();
    });

    it('cancels deletion and resets mutation state without deleting', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Delete group'));
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        expect(mocks.deleteMutate).not.toHaveBeenCalled();
        expect(mocks.deleteReset).toHaveBeenCalled();
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('closes the delete modal via the dialog close button and resets mutation state', () => {
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Delete group'));
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));

        expect(mocks.deleteMutate).not.toHaveBeenCalled();
        expect(mocks.deleteReset).toHaveBeenCalled();
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
});

describe('GroupsPage — manage roles', () => {
    beforeEach(() => {
        state.groups.data = { groups: [platformGroup] };
    });

    it('shows a loading spinner while roles are loading', () => {
        state.roles.isLoading = true;
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows "No roles available" when there are none', () => {
        state.roles.data = [];
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));
        expect(screen.getByText('No roles available.')).toBeInTheDocument();
    });

    it('reflects assigned roles as checked and shows an expiry badge for time-bound grants', () => {
        state.roles.data = [adminRole, viewerRole];
        state.groupRolesByGroupId[1] = [{ ...adminRole, expires_at: '2099-01-01T00:00:00Z' }];
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByRole('checkbox', { name: /admin/i })).toBeChecked();
        expect(within(dialog).getByRole('checkbox', { name: /viewer/i })).not.toBeChecked();
        expect(within(dialog).getByText(/expires in/)).toBeInTheDocument();
    });

    it('assigns a permanent grant when the duration preset is "Never" and the box is checked', () => {
        state.roles.data = [adminRole, viewerRole];
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('checkbox', { name: /viewer/i }));

        expect(mocks.assignMutate).toHaveBeenCalledWith({ groupId: 1, roleId: 11, scope: {} });
    });

    it('assigns a time-bound grant with a resolved expiresAt when a duration preset is selected', () => {
        state.roles.data = [adminRole, viewerRole];
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        const dialog = screen.getByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText('Grant duration'), { target: { value: '1h' } });

        const before = Date.now();
        fireEvent.click(within(dialog).getByRole('checkbox', { name: /viewer/i }));

        expect(mocks.assignMutate).toHaveBeenCalledTimes(1);
        const call = mocks.assignMutate.mock.calls[0]![0];
        expect(call).toMatchObject({ groupId: 1, roleId: 11 });
        const expiresMs = Date.parse(call.expiresAt);
        expect(expiresMs).toBeGreaterThan(before);
        expect(expiresMs).toBeLessThanOrEqual(before + 60 * 60 * 1000 + 5000);
    });

    it('removes a role grant when an assigned checkbox is unchecked', () => {
        state.roles.data = [adminRole];
        state.groupRolesByGroupId[1] = [adminRole];
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('checkbox', { name: /admin/i }));

        expect(mocks.removeMutate).toHaveBeenCalledWith({ groupId: 1, roleId: 10, scope: {} });
    });

    // #3546: a project role granted with no project applied in EVERY project.
    it('refuses a project role at the global scope and sends nothing', () => {
        const devRole = { id: 12, name: 'project_developer', description: '', created_at: '', updated_at: '' };
        state.roles.data = [devRole];
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('checkbox', { name: /project_developer/i }));

        expect(mocks.assignMutate).not.toHaveBeenCalled();
        expect(within(dialog).getByRole('alert')).toHaveTextContent(
            'project_developer is a project role: choose a project above'
        );
    });

    it('grants a project role at the chosen project and environment', () => {
        const devRole = { id: 12, name: 'project_developer', description: '', created_at: '', updated_at: '' };
        state.roles.data = [devRole];
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        const dialog = screen.getByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText('Project'), { target: { value: '2' } });
        fireEvent.change(within(dialog).getByLabelText('Environment (optional)'), { target: { value: '5' } });
        fireEvent.click(within(dialog).getByRole('checkbox', { name: /project_developer/i }));

        expect(mocks.assignMutate).toHaveBeenCalledWith({
            groupId: 1,
            roleId: 12,
            scope: { projectId: 2, environmentId: 5 },
        });
    });

    it("shows the server's refusal message in the modal", () => {
        state.roles.data = [viewerRole];
        state.assignMutation = {
            isPending: false,
            error: {
                response: { data: { message: 'role project_developer is project-scoped; specify a project_id' } },
            },
        } as any;
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        expect(within(screen.getByRole('dialog')).getByRole('alert')).toHaveTextContent(
            'role project_developer is project-scoped; specify a project_id'
        );
    });

    it('disables role checkboxes while a role mutation is pending', () => {
        state.roles.data = [adminRole];
        state.assignMutation.isPending = true;
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByRole('checkbox', { name: /admin/i })).toBeDisabled();
    });

    it('closes the manage roles modal from its own footer Close button', () => {
        state.roles.data = [adminRole];
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        const dialog = screen.getByRole('dialog');
        // The modal has two elements named "Close": the header's icon-only Dialog.Close
        // (sr-only text) and the explicit footer Button — the footer one is the second match.
        const closeButtons = within(dialog).getAllByRole('button', { name: 'Close' });
        fireEvent.click(closeButtons[1]!);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('closes the manage roles modal via the dialog close (X) button', () => {
        state.roles.data = [adminRole];
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Manage roles'));

        const dialog = screen.getByRole('dialog');
        const closeButtons = within(dialog).getAllByRole('button', { name: 'Close' });
        fireEvent.click(closeButtons[0]!);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
});

describe('GroupsPage — shared secrets', () => {
    beforeEach(() => {
        state.groups.data = { groups: [platformGroup] };
    });

    it('shows a loading spinner while shared secrets load', () => {
        state.sharedSecrets = { data: undefined, isLoading: true };
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Shared secrets'));
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an empty state when no secrets are shared', () => {
        state.sharedSecrets = { data: [], isLoading: false };
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Shared secrets'));
        expect(screen.getByText('No secrets are shared with this group.')).toBeInTheDocument();
    });

    it('lists the secrets shared with the group', () => {
        state.sharedSecrets = {
            data: [
                { id: 1, name: 'db-password', type: 'password' },
                { id: 2, name: 'api-key', type: 'api_key' },
            ],
            isLoading: false,
        };
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Shared secrets'));

        const dialog = screen.getByRole('dialog');
        expect(dialog).toHaveTextContent('Secrets shared with platform-team');
        expect(within(dialog).getByText('db-password')).toBeInTheDocument();
        expect(within(dialog).getByText('password')).toBeInTheDocument();
        expect(within(dialog).getByText('api-key')).toBeInTheDocument();
    });

    it('closes the shared secrets modal from its own footer Close button', () => {
        state.sharedSecrets = { data: [], isLoading: false };
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Shared secrets'));

        const dialog = screen.getByRole('dialog');
        // The modal has two elements named "Close": the header's icon-only Dialog.Close
        // (sr-only text) and the explicit footer Button — the footer one is the second match.
        const closeButtons = within(dialog).getAllByRole('button', { name: 'Close' });
        fireEvent.click(closeButtons[1]!);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('closes the shared secrets modal via the dialog close (X) button', () => {
        state.sharedSecrets = { data: [], isLoading: false };
        render(<GroupsPage />);
        fireEvent.click(screen.getByTitle('Shared secrets'));

        const dialog = screen.getByRole('dialog');
        const closeButtons = within(dialog).getAllByRole('button', { name: 'Close' });
        fireEvent.click(closeButtons[0]!);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
});
