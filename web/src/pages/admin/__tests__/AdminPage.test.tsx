import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within, act } from '../../../test/test-utils';
import { AdminPage } from '../AdminPage';
import { ProjectAssignmentsPicker } from '../../../features/admin';
import { useUIStore } from '../../../store/uiStore';

const navigateMock = vi.fn();
vi.mock('react-router', async () => {
    const actual = await vi.importActual<typeof import('react-router')>('react-router');
    return { ...actual, useNavigate: () => navigateMock };
});

const useAdminUserList = vi.fn();
const createMutate = vi.fn();
const updateMutate = vi.fn();
const updateMutateAsync = vi.fn();
const deleteMutate = vi.fn();
const deleteMutateAsync = vi.fn();
const restoreMutate = vi.fn();
const updateRolesMutate = vi.fn();
const impersonateMutate = vi.fn();
const useAdminRoles = vi.fn();
const useUserRoles = vi.fn();
const useAdminCreateUser = vi.fn();
const useAdminUpdateUser = vi.fn();
const useAdminDeleteUser = vi.fn();
const useAdminRestoreUser = vi.fn();
const useUpdateUserRoles = vi.fn();
const useImpersonateUser = vi.fn();

vi.mock('../../../features/admin', () => ({
    useAdminUserList: (...args: any[]) => useAdminUserList(...args),
    useAdminCreateUser: (...args: any[]) => useAdminCreateUser(...args),
    useAdminUpdateUser: (...args: any[]) => useAdminUpdateUser(...args),
    useAdminDeleteUser: (...args: any[]) => useAdminDeleteUser(...args),
    useAdminRestoreUser: (...args: any[]) => useAdminRestoreUser(...args),
    useAdminRoles: (...args: any[]) => useAdminRoles(...args),
    useUserRoles: (...args: any[]) => useUserRoles(...args),
    useUpdateUserRoles: (...args: any[]) => useUpdateUserRoles(...args),
    useImpersonateUser: (...args: any[]) => useImpersonateUser(...args),
    AccountStateBadge: ({ state }: { state?: string }) => <span data-testid="state-badge">{state}</span>,
    StaleAccountsSection: () => null,
    PATHygieneSection: () => null,
    MachineTokenHygieneSection: () => null,
    DeploymentHygieneSection: () => null,
    OrgNameConformanceSection: () => null,
    OrgInventoryExport: () => null,
    ProjectAssignmentsPicker: vi.fn(() => null),
    MaintenanceSection: () => null,
}));

vi.mock('../../../features/invitations/GlobalInviteUserModal', () => ({
    GlobalInviteUserModal: ({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) =>
        isOpen ? (
            <div data-testid="invite-modal">
                <button type="button" onClick={onClose}>
                    Close Invite
                </button>
            </div>
        ) : null,
}));

const activeUser = {
    id: 1,
    username: 'alice',
    email: 'alice@example.com',
    display_name: 'Alice A',
    active: true,
    account_state: 'active',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    last_login_at: '2026-02-01T00:00:00Z',
    deleted_at: null,
};

const inactiveUser = {
    id: 2,
    username: 'bob',
    email: 'bob@example.com',
    display_name: 'Bob B',
    active: false,
    account_state: 'suspended',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    last_login_at: null,
    deleted_at: null,
};

const deletedUser = {
    ...activeUser,
    id: 3,
    username: 'carol',
    deleted_at: '2026-02-15T00:00:00Z',
};

const userWithProjects = {
    ...activeUser,
    id: 4,
    username: 'dave',
    project_count: 5,
    active_project_count: 3,
};

function mockUserList(
    users: any[],
    overrides: Partial<{ isLoading: boolean; isError: boolean; total: number; totalPages: number }> = {}
) {
    useAdminUserList.mockReturnValue({
        data: { users, total: overrides.total ?? users.length, total_pages: overrides.totalPages ?? 1 },
        isLoading: overrides.isLoading ?? false,
        isError: overrides.isError ?? false,
    });
}

const initialTheme = useUIStore.getState().theme;

beforeEach(() => {
    vi.clearAllMocks();
    useAdminRoles.mockReturnValue({ data: [{ id: 1, name: 'admin', description: 'Full access' }] });
    useUserRoles.mockReturnValue({ data: [], isLoading: false });
    useAdminCreateUser.mockReturnValue({ mutate: createMutate, isPending: false });
    useAdminUpdateUser.mockReturnValue({ mutate: updateMutate, mutateAsync: updateMutateAsync, isPending: false });
    useAdminDeleteUser.mockReturnValue({ mutate: deleteMutate, mutateAsync: deleteMutateAsync, isPending: false });
    useAdminRestoreUser.mockReturnValue({ mutate: restoreMutate, isPending: false });
    useUpdateUserRoles.mockReturnValue({ mutate: updateRolesMutate, isPending: false });
    useImpersonateUser.mockReturnValue({ mutate: impersonateMutate, isPending: false });
    vi.mocked(ProjectAssignmentsPicker).mockImplementation(() => null);
    mockUserList([activeUser, inactiveUser]);
});

afterEach(() => {
    useUIStore.setState({ theme: initialTheme });
});

describe('AdminPage — loading/empty/populated', () => {
    it('shows a loading state', () => {
        mockUserList([], { isLoading: true });
        render(<AdminPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an empty state with no users', () => {
        mockUserList([]);
        render(<AdminPage />);
        expect(screen.getByText('No users yet.')).toBeInTheDocument();
    });

    it('renders each user row', () => {
        render(<AdminPage />);
        expect(screen.getByText('Alice A')).toBeInTheDocument();
        expect(screen.getByText('bob@example.com')).toBeInTheDocument();
        expect(screen.getByText('2 users')).toBeInTheDocument();
    });

    it('shows an error state when the list fails to load', () => {
        mockUserList([], { isError: true });
        render(<AdminPage />);
        expect(screen.getByText('Failed to load users')).toBeInTheDocument();
        expect(screen.getByText('Check that the server is running and you have admin access.')).toBeInTheDocument();
    });

    it('shows a search-specific empty message when a search yields no results', async () => {
        mockUserList([]);
        render(<AdminPage />);
        fireEvent.change(screen.getByPlaceholderText(/search by username or email/i), {
            target: { value: 'nobody' },
        });
        fireEvent.click(screen.getByRole('button', { name: 'Search' }));

        expect(await screen.findByText('No users match your search.')).toBeInTheDocument();
    });

    it('shows active/total project counts when the API supplies them', () => {
        mockUserList([userWithProjects]);
        render(<AdminPage />);
        expect(screen.getByText('3 active · 5 total')).toBeInTheDocument();
    });

    it('defaults active project count to 0 when the API omits it', () => {
        mockUserList([{ ...userWithProjects, active_project_count: undefined }]);
        render(<AdminPage />);
        expect(screen.getByText('0 active · 5 total')).toBeInTheDocument();
    });

    it('falls back to an empty user list when the API response is missing fields', () => {
        useAdminUserList.mockReturnValue({ data: undefined, isLoading: false, isError: false });
        render(<AdminPage />);
        expect(screen.getByText('No users found')).toBeInTheDocument();
        expect(screen.getByText('No users yet.')).toBeInTheDocument();
    });

    it('falls back to the username when a user has no display name', () => {
        mockUserList([{ ...activeUser, display_name: '' }]);
        render(<AdminPage />);
        expect(screen.getByRole('button', { name: 'alice' })).toBeInTheDocument();
    });
});

describe('AdminPage — search', () => {
    it('submits the search box value and resets to page 1', async () => {
        render(<AdminPage />);
        fireEvent.change(screen.getByPlaceholderText(/search by username or email/i), {
            target: { value: 'alice' },
        });
        fireEvent.click(screen.getByRole('button', { name: 'Search' }));

        await waitFor(() =>
            expect(useAdminUserList).toHaveBeenLastCalledWith(expect.objectContaining({ search: 'alice', page: 1 }))
        );
    });
});

describe('AdminPage — pagination', () => {
    it('advances to the next page', async () => {
        mockUserList([activeUser], { totalPages: 3 });
        render(<AdminPage />);

        fireEvent.click(screen.getByLabelText('Next page'));

        await waitFor(() => expect(useAdminUserList).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2 })));
    });

    it('goes back to the previous page', async () => {
        mockUserList([activeUser], { totalPages: 3 });
        render(<AdminPage />);

        fireEvent.click(screen.getByLabelText('Next page'));
        await waitFor(() => expect(useAdminUserList).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2 })));

        fireEvent.click(screen.getByLabelText('Previous page'));
        await waitFor(() => expect(useAdminUserList).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1 })));
    });
});

describe('AdminPage — user detail navigation', () => {
    it('navigates to the user detail page when the name is clicked', () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Alice A' }));
        expect(navigateMock).toHaveBeenCalledWith('/admin/users/1');
    });
});

describe('AdminPage — bulk actions', () => {
    it('shows Activate for a selected inactive user and Deactivate for a selected active user', () => {
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1); // skip header row
        fireEvent.click(within(rows[0]!).getByRole('checkbox')); // alice (active)
        fireEvent.click(within(rows[1]!).getByRole('checkbox')); // bob (inactive)

        expect(screen.getByText('2 selected')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Activate' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Deactivate' })).toBeInTheDocument();
    });

    it('bulk-deletes every selected user', async () => {
        deleteMutateAsync.mockResolvedValue(undefined);
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));
        fireEvent.click(within(rows[1]!).getByRole('checkbox'));

        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        await waitFor(() => expect(deleteMutateAsync).toHaveBeenCalledTimes(2));
        expect(deleteMutateAsync).toHaveBeenCalledWith(1);
        expect(deleteMutateAsync).toHaveBeenCalledWith(2);
    });

    it('reports a page error when a bulk delete fails', async () => {
        deleteMutateAsync.mockRejectedValue({ response: { data: { error: 'Bulk delete blew up' } } });
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));

        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        expect(await screen.findByText('Bulk delete blew up')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
        expect(screen.queryByText('Bulk delete blew up')).not.toBeInTheDocument();
    });

    it('falls back to err.message when the bulk delete error has no response error field', async () => {
        deleteMutateAsync.mockRejectedValue({ message: 'Network Error' });
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));

        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        expect(await screen.findByText('Network Error')).toBeInTheDocument();
    });

    it('falls back to a generic message when the bulk delete error has neither a response nor a message', async () => {
        deleteMutateAsync.mockRejectedValue({});
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));

        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        expect(await screen.findByText('Bulk delete failed')).toBeInTheDocument();
    });

    it('deselects a single user by clicking its row checkbox a second time', () => {
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        const checkbox = within(rows[0]!).getByRole('checkbox');

        fireEvent.click(checkbox);
        expect(screen.getByText('1 selected')).toBeInTheDocument();

        fireEvent.click(checkbox);
        expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
    });

    it('selects and deselects every user via the header checkbox', () => {
        render(<AdminPage />);
        const headerRow = screen.getAllByRole('row')[0]!;
        const headerCheckbox = within(headerRow).getByRole('checkbox');

        fireEvent.click(headerCheckbox);
        expect(screen.getByText('2 selected')).toBeInTheDocument();

        fireEvent.click(headerCheckbox);
        expect(screen.queryByText('2 selected')).not.toBeInTheDocument();
    });

    it('clears the selection via the Clear button', () => {
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));
        expect(screen.getByText('1 selected')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
        expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
    });

    it('bulk-activates every selected inactive user', async () => {
        updateMutateAsync.mockResolvedValue(undefined);
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[1]!).getByRole('checkbox')); // bob (inactive)

        fireEvent.click(screen.getByRole('button', { name: 'Activate' }));

        await waitFor(() =>
            expect(updateMutateAsync).toHaveBeenCalledWith({
                id: 2,
                body: { email: 'bob@example.com', display_name: 'Bob B', active: true },
            })
        );
    });

    it('bulk-deactivates every selected active user', async () => {
        updateMutateAsync.mockResolvedValue(undefined);
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox')); // alice (active)

        fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));

        await waitFor(() =>
            expect(updateMutateAsync).toHaveBeenCalledWith({
                id: 1,
                body: { email: 'alice@example.com', display_name: 'Alice A', active: false },
            })
        );
    });

    it('reports a page error when a bulk activate/deactivate fails', async () => {
        updateMutateAsync.mockRejectedValue({ response: { data: { error: 'Bulk update blew up' } } });
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));

        fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));

        expect(await screen.findByText('Bulk update blew up')).toBeInTheDocument();
    });

    it('falls back to err.message when the bulk activate/deactivate error has no response error field', async () => {
        updateMutateAsync.mockRejectedValue({ message: 'Network Error' });
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));

        fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));

        expect(await screen.findByText('Network Error')).toBeInTheDocument();
    });

    it('falls back to a generic message when the bulk activate/deactivate error has neither a response nor a message', async () => {
        updateMutateAsync.mockRejectedValue({});
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));

        fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));

        expect(await screen.findByText('Bulk action failed')).toBeInTheDocument();
    });
});

describe('AdminPage — create user', () => {
    it('validates required fields before submitting', async () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));

        expect(await screen.findByText('Username is required')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('creates a user with a password', async () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'longpassword' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));

        await waitFor(() =>
            expect(createMutate).toHaveBeenCalledWith(
                {
                    username: 'newu',
                    email: 'new@example.com',
                    display_name: 'New User',
                    password: 'longpassword',
                },
                expect.anything()
            )
        );
    });

    it('sends deliver_setup_link (no password) in setup-link mode', async () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.click(screen.getByLabelText('Send a setup link'));
        fireEvent.click(screen.getByRole('button', { name: 'Create & Send Link' }));

        await waitFor(() =>
            expect(createMutate).toHaveBeenCalledWith(
                {
                    username: 'newu',
                    email: 'new@example.com',
                    display_name: 'New User',
                    deliver_setup_link: true,
                },
                expect.anything()
            )
        );
    });

    it('sends generate_one_time_password (no password) in one-time-password mode', async () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.click(screen.getByLabelText('Generate a one-time password'));
        fireEvent.click(screen.getByRole('button', { name: 'Create & Generate Password' }));

        await waitFor(() =>
            expect(createMutate).toHaveBeenCalledWith(
                {
                    username: 'newu',
                    email: 'new@example.com',
                    display_name: 'New User',
                    generate_one_time_password: true,
                },
                expect.anything()
            )
        );
    });

    it('validates each required field in turn', async () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));
        expect(await screen.findByText('Email is required')).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'not-an-email' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));
        expect(await screen.findByText('Please enter a valid email address')).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));
        expect(await screen.findByText('Display name is required')).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));
        expect(await screen.findByText('Password must be at least 8 characters')).toBeInTheDocument();

        expect(createMutate).not.toHaveBeenCalled();
    });

    it('generates a random password and reveals it', () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        const passwordInput = screen.getByLabelText('Password') as HTMLInputElement;
        expect(passwordInput.type).toBe('password');
        expect(passwordInput.value).toBe('');

        fireEvent.click(screen.getByRole('button', { name: '↻ Generate' }));

        expect(passwordInput.value.length).toBeGreaterThan(0);
        expect(passwordInput.type).toBe('text');

        fireEvent.click(screen.getByRole('button', { name: 'Hide' }));
        expect(passwordInput.type).toBe('password');
    });

    it('sends the chosen system role when one is selected', async () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'longpassword' } });
        fireEvent.change(screen.getByLabelText(/system role/i), { target: { value: 'system_admin' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));

        await waitFor(() =>
            expect(createMutate).toHaveBeenCalledWith(
                expect.objectContaining({ role: 'system_admin' }),
                expect.anything()
            )
        );
    });

    it('includes project assignments chosen in the picker', async () => {
        vi.mocked(ProjectAssignmentsPicker).mockImplementation(({ onChange }) => (
            <button
                type="button"
                onClick={() => onChange([{ project_id: 7, role: 'project_developer', project_name: 'Demo' }])}
            >
                Add assignment
            </button>
        ));
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'longpassword' } });
        fireEvent.click(screen.getByRole('button', { name: 'Add assignment' }));
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));

        await waitFor(() =>
            expect(createMutate).toHaveBeenCalledWith(
                expect.objectContaining({ project_assignments: [{ project_id: 7, role: 'project_developer' }] }),
                expect.anything()
            )
        );
    });

    it('closes the modal once a classic password create succeeds', async () => {
        createMutate.mockImplementation((_body, opts) => opts.onSuccess({}));
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'longpassword' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));

        await waitFor(() => expect(screen.queryByLabelText('Username')).not.toBeInTheDocument());
    });

    it('shows a Creating… label and disables the buttons while pending', () => {
        useAdminCreateUser.mockReturnValue({ mutate: createMutate, isPending: true });
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        const createButton = screen.getByRole('button', { name: 'Creating…' });
        expect(createButton).toBeDisabled();
    });

    it('shows a create error from the API', async () => {
        createMutate.mockImplementation((_body, opts) =>
            opts.onError({ response: { data: { error: 'Username already taken' } } })
        );
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'longpassword' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));

        expect(await screen.findByText('Username already taken')).toBeInTheDocument();
    });

    it('falls back to the error message, then a generic message, when the API gives no error field', async () => {
        createMutate.mockImplementationOnce((_body, opts) => opts.onError({ message: 'Network Error' }));
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'longpassword' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));
        expect(await screen.findByText('Network Error')).toBeInTheDocument();

        createMutate.mockImplementationOnce((_body, opts) => opts.onError({}));
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));
        expect(await screen.findByText('Failed to create user')).toBeInTheDocument();
    });

    it('shows the setup link result, copies it, and closes on Done', async () => {
        vi.useFakeTimers();
        createMutate.mockImplementation((_body, opts) =>
            opts.onSuccess({
                setup_link: {
                    email: 'new@example.com',
                    channel: 'out_of_band',
                    delivered: false,
                    link_for_admin: 'https://app.example.com/setup/abc123',
                },
            })
        );
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.click(screen.getByLabelText('Send a setup link'));
        fireEvent.click(screen.getByRole('button', { name: 'Create & Send Link' }));

        expect(screen.getByText('https://app.example.com/setup/abc123')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
        await act(async () => {
            await vi.advanceTimersByTimeAsync(0);
        });
        expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });
        expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Done' }));
        expect(screen.queryByText('https://app.example.com/setup/abc123')).not.toBeInTheDocument();
        vi.useRealTimers();
    });

    it('shows the delivered-by-email setup message when no admin link is returned', async () => {
        createMutate.mockImplementation((_body, opts) =>
            opts.onSuccess({
                setup_link: { email: 'new@example.com', channel: 'smtp', delivered: true },
            })
        );
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.click(screen.getByLabelText('Send a setup link'));
        fireEvent.click(screen.getByRole('button', { name: 'Create & Send Link' }));

        expect(await screen.findByText(/a setup link was sent to/i)).toBeInTheDocument();
        expect(screen.getByText(/via smtp/i)).toBeInTheDocument();
    });

    it('omits the delivery channel when the API does not report one', async () => {
        createMutate.mockImplementation((_body, opts) =>
            opts.onSuccess({
                setup_link: { email: 'new@example.com', channel: '', delivered: true },
            })
        );
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.click(screen.getByLabelText('Send a setup link'));
        fireEvent.click(screen.getByRole('button', { name: 'Create & Send Link' }));

        expect(await screen.findByText(/a setup link was sent to/i)).toBeInTheDocument();
        expect(screen.queryByText(/ via /i)).not.toBeInTheDocument();
    });

    it('tells the admin when the generated one-time password expires', async () => {
        createMutate.mockImplementation((_body, opts) =>
            opts.onSuccess({
                one_time_password: {
                    email: 'new@example.com',
                    one_time_password: 'Sup3rSecret!',
                    expires_at: '2026-10-13T12:00:00Z',
                },
            })
        );
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.click(screen.getByLabelText('Generate a one-time password'));
        fireEvent.click(screen.getByRole('button', { name: 'Create & Generate Password' }));

        expect(await screen.findByTestId('otp-expires-at')).toHaveTextContent('Expires 2026-10-13T12:00:00Z');
    });

    it('shows the generated one-time password result and copies it', async () => {
        vi.useFakeTimers();
        createMutate.mockImplementation((_body, opts) =>
            opts.onSuccess({ one_time_password: { email: 'new@example.com', one_time_password: 'Sup3rSecret!' } })
        );
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.click(screen.getByLabelText('Generate a one-time password'));
        fireEvent.click(screen.getByRole('button', { name: 'Create & Generate Password' }));

        expect(screen.getByText('Sup3rSecret!')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
        await act(async () => {
            await vi.advanceTimersByTimeAsync(0);
        });
        expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });
        expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Done' }));
        expect(screen.queryByText('Sup3rSecret!')).not.toBeInTheDocument();
        vi.useRealTimers();
    });
});

function aliceRow() {
    return screen.getAllByRole('row')[1]!; // header row is index 0; alice is the first data row
}

describe('AdminPage — edit user', () => {
    it('opens pre-filled and saves the changes', async () => {
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Edit user'));

        const emailInput = screen.getByLabelText('Email') as HTMLInputElement;
        expect(emailInput.value).toBe('alice@example.com');

        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'Alice Updated' } });
        fireEvent.click(screen.getByLabelText('Active'));
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        await waitFor(() =>
            expect(updateMutate).toHaveBeenCalledWith(
                {
                    id: 1,
                    body: { email: 'alice@example.com', display_name: 'Alice Updated', active: false },
                },
                expect.anything()
            )
        );
    });

    it('requires an email before saving', async () => {
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Edit user'));

        fireEvent.change(screen.getByLabelText('Email'), { target: { value: '   ' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(await screen.findByText('Email is required')).toBeInTheDocument();
        expect(updateMutate).not.toHaveBeenCalled();
    });

    it('shows an error from the API when saving fails', async () => {
        updateMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { error: 'Email already in use' } } })
        );
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Edit user'));
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(await screen.findByText('Email already in use')).toBeInTheDocument();
    });

    it('falls back to err.message when the update error has no response error field', async () => {
        updateMutate.mockImplementation((_vars, opts) => opts.onError({ message: 'Network Error' }));
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Edit user'));
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(await screen.findByText('Network Error')).toBeInTheDocument();
    });

    it('falls back to a generic message when the update error has neither a response nor a message', async () => {
        updateMutate.mockImplementation((_vars, opts) => opts.onError({}));
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Edit user'));
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(await screen.findByText('Failed to update user')).toBeInTheDocument();
    });

    it('shows a Saving… label and disables the buttons while pending', () => {
        useAdminUpdateUser.mockReturnValue({ mutate: updateMutate, mutateAsync: updateMutateAsync, isPending: true });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Edit user'));

        const saveButton = screen.getByRole('button', { name: 'Saving…' });
        expect(saveButton).toBeDisabled();
    });
});

describe('AdminPage — delete user', () => {
    it('confirms and deletes a single user', async () => {
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Delete user'));
        expect(screen.getByText(/soft-deleted and can be restored/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Delete User' }));

        await waitFor(() => expect(deleteMutate).toHaveBeenCalledWith(1, expect.anything()));
    });

    it('shows a page error from the API when deleting fails', async () => {
        deleteMutate.mockImplementation((_id, opts) =>
            opts.onError({ response: { data: { error: 'Cannot delete the last admin' } } })
        );
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Delete user'));
        fireEvent.click(screen.getByRole('button', { name: 'Delete User' }));

        expect(await screen.findByText('Cannot delete the last admin')).toBeInTheDocument();
    });

    it('falls back to err.message when the delete error has no response error field', async () => {
        deleteMutate.mockImplementation((_id, opts) => opts.onError({ message: 'Network Error' }));
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Delete user'));
        fireEvent.click(screen.getByRole('button', { name: 'Delete User' }));

        expect(await screen.findByText('Network Error')).toBeInTheDocument();
    });

    it('falls back to a generic message when the delete error has neither a response nor a message', async () => {
        deleteMutate.mockImplementation((_id, opts) => opts.onError({}));
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Delete user'));
        fireEvent.click(screen.getByRole('button', { name: 'Delete User' }));

        expect(await screen.findByText('Failed to delete user')).toBeInTheDocument();
    });

    it('shows a Deleting… label and disables the buttons while pending', () => {
        useAdminDeleteUser.mockReturnValue({ mutate: deleteMutate, mutateAsync: deleteMutateAsync, isPending: true });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Delete user'));

        const deleteButton = screen.getByRole('button', { name: 'Deleting…' });
        expect(deleteButton).toBeDisabled();
    });
});

describe('AdminPage — restore user', () => {
    it('shows a restore action for a deleted user and restores it', async () => {
        mockUserList([deletedUser]);
        render(<AdminPage />);

        fireEvent.click(screen.getByTitle('Restore user'));
        fireEvent.click(screen.getByRole('button', { name: 'Restore User' }));

        await waitFor(() => expect(restoreMutate).toHaveBeenCalledWith(3, expect.anything()));
    });

    it('shows a page error from the API when restoring fails', async () => {
        restoreMutate.mockImplementation((_id, opts) =>
            opts.onError({ response: { data: { error: 'Restore window has expired' } } })
        );
        mockUserList([deletedUser]);
        render(<AdminPage />);

        fireEvent.click(screen.getByTitle('Restore user'));
        fireEvent.click(screen.getByRole('button', { name: 'Restore User' }));

        expect(await screen.findByText('Restore window has expired')).toBeInTheDocument();
    });

    it('falls back to err.message when the restore error has no response error field', async () => {
        restoreMutate.mockImplementation((_id, opts) => opts.onError({ message: 'Network Error' }));
        mockUserList([deletedUser]);
        render(<AdminPage />);

        fireEvent.click(screen.getByTitle('Restore user'));
        fireEvent.click(screen.getByRole('button', { name: 'Restore User' }));

        expect(await screen.findByText('Network Error')).toBeInTheDocument();
    });

    it('falls back to a generic message when the restore error has neither a response nor a message', async () => {
        restoreMutate.mockImplementation((_id, opts) => opts.onError({}));
        mockUserList([deletedUser]);
        render(<AdminPage />);

        fireEvent.click(screen.getByTitle('Restore user'));
        fireEvent.click(screen.getByRole('button', { name: 'Restore User' }));

        expect(await screen.findByText('Failed to restore user')).toBeInTheDocument();
    });

    it('shows a Restoring… label and disables the buttons while pending', () => {
        useAdminRestoreUser.mockReturnValue({ mutate: restoreMutate, isPending: true });
        mockUserList([deletedUser]);
        render(<AdminPage />);
        fireEvent.click(screen.getByTitle('Restore user'));

        const restoreButton = screen.getByRole('button', { name: 'Restoring…' });
        expect(restoreButton).toBeDisabled();
    });
});

describe('AdminPage — roles', () => {
    it('requires at least one role before saving', async () => {
        useUserRoles.mockReturnValue({ data: [{ id: 1 }], isLoading: false });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        // Uncheck the only pre-selected role.
        fireEvent.click(await screen.findByRole('checkbox', { name: /admin/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Save Roles' }));

        expect(await screen.findByText('User must have at least one role')).toBeInTheDocument();
        expect(updateRolesMutate).not.toHaveBeenCalled();
    });

    it('saves the selected roles', async () => {
        useUserRoles.mockReturnValue({ data: [], isLoading: false });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        fireEvent.click(await screen.findByRole('checkbox', { name: /admin/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Save Roles' }));

        await waitFor(() =>
            expect(updateRolesMutate).toHaveBeenCalledWith({ userId: 1, roleIds: [1] }, expect.anything())
        );
    });

    it('closes the modal once the save succeeds', async () => {
        useUserRoles.mockReturnValue({ data: [], isLoading: false });
        updateRolesMutate.mockImplementation((_vars, opts) => opts.onSuccess());
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        fireEvent.click(await screen.findByRole('checkbox', { name: /admin/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Save Roles' }));

        await waitFor(() => expect(screen.queryByText('Manage Roles')).not.toBeInTheDocument());
    });

    it('shows an error from the API when saving roles fails', async () => {
        useUserRoles.mockReturnValue({ data: [], isLoading: false });
        updateRolesMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { error: 'Role update rejected' } } })
        );
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        fireEvent.click(await screen.findByRole('checkbox', { name: /admin/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Save Roles' }));

        expect(await screen.findByText('Role update rejected')).toBeInTheDocument();
    });

    it('falls back to err.message when the role-save error has no response error field', async () => {
        useUserRoles.mockReturnValue({ data: [], isLoading: false });
        updateRolesMutate.mockImplementation((_vars, opts) => opts.onError({ message: 'Network Error' }));
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        fireEvent.click(await screen.findByRole('checkbox', { name: /admin/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Save Roles' }));

        expect(await screen.findByText('Network Error')).toBeInTheDocument();
    });

    it('falls back to a generic message when the role-save error has neither a response nor a message', async () => {
        useUserRoles.mockReturnValue({ data: [], isLoading: false });
        updateRolesMutate.mockImplementation((_vars, opts) => opts.onError({}));
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        fireEvent.click(await screen.findByRole('checkbox', { name: /admin/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Save Roles' }));

        expect(await screen.findByText('Failed to update roles')).toBeInTheDocument();
    });

    it('renders a role with no description', async () => {
        useAdminRoles.mockReturnValue({ data: [{ id: 2, name: 'viewer' }] });
        useUserRoles.mockReturnValue({ data: [], isLoading: false });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        expect(await screen.findByText('viewer')).toBeInTheDocument();
    });

    it('shows a loading spinner while the user’s current roles are loading', async () => {
        useUserRoles.mockReturnValue({ data: undefined, isLoading: true });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        const dialog = await screen.findByRole('dialog');
        expect(within(dialog).getByText('Manage Roles')).toBeInTheDocument();
        expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument();
    });

    it('renders an empty role list when the roles catalog is unavailable', async () => {
        useAdminRoles.mockReturnValue({ data: undefined });
        useUserRoles.mockReturnValue({ data: [], isLoading: false });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        const dialog = await screen.findByRole('dialog');
        expect(within(dialog).getByText('Manage Roles')).toBeInTheDocument();
        expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument();
    });

    it('shows a Saving… label and disables the buttons while pending', async () => {
        useUpdateUserRoles.mockReturnValue({ mutate: updateRolesMutate, isPending: true });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        const saveButton = await screen.findByRole('button', { name: 'Saving…' });
        expect(saveButton).toBeDisabled();
    });
});

describe('AdminPage — impersonate', () => {
    it('impersonates a user and navigates to the dashboard on success', async () => {
        impersonateMutate.mockImplementation((_vars, opts) => opts?.onSuccess?.());
        render(<AdminPage />);

        fireEvent.click(within(aliceRow()).getByTitle('Impersonate user'));

        expect(impersonateMutate).toHaveBeenCalledWith(
            { id: 1, username: 'alice', display_name: 'Alice A' },
            expect.anything()
        );
        expect(navigateMock).toHaveBeenCalledWith('/dashboard');
    });
});

describe('AdminPage — inactive filter banner', () => {
    it('shows the banner when ?filter=inactive is present and links to audit', () => {
        window.history.pushState({}, '', '/admin?filter=inactive');
        render(<AdminPage />);

        expect(screen.getByText(/showing inactive users only/i)).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /view login history/i }));
        expect(navigateMock).toHaveBeenCalledWith(expect.stringContaining('filter=logins'));

        window.history.pushState({}, '', '/');
    });

    it('renders the banner in its light-theme colors', () => {
        useUIStore.setState({ theme: 'light' });
        window.history.pushState({}, '', '/admin?filter=inactive');
        render(<AdminPage />);

        expect(screen.getByText(/showing inactive users only/i)).toBeInTheDocument();

        window.history.pushState({}, '', '/');
    });
});

describe('AdminPage — theme resolution', () => {
    it('resolves a light theme without touching matchMedia', () => {
        useUIStore.setState({ theme: 'light' });
        render(<AdminPage />);
        expect(screen.getByText('User Management')).toBeInTheDocument();
    });

    it('resolves a system theme via matchMedia', () => {
        useUIStore.setState({ theme: 'system' });
        render(<AdminPage />);
        expect(window.matchMedia).toHaveBeenCalledWith('(prefers-color-scheme: dark)');
    });
});

describe('AdminPage — invite user', () => {
    it('opens and closes the global invite modal', () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /invite user/i }));

        expect(screen.getByTestId('invite-modal')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close Invite' }));
        expect(screen.queryByTestId('invite-modal')).not.toBeInTheDocument();
    });
});

describe('AdminPage — search bar extras', () => {
    it('clears the search box and resets to page 1', async () => {
        render(<AdminPage />);
        fireEvent.change(screen.getByPlaceholderText(/search by username or email/i), {
            target: { value: 'alice' },
        });
        fireEvent.click(screen.getByRole('button', { name: 'Search' }));
        await waitFor(() =>
            expect(useAdminUserList).toHaveBeenLastCalledWith(expect.objectContaining({ search: 'alice' }))
        );

        fireEvent.click(screen.getByRole('button', { name: 'Clear' }));

        await waitFor(() =>
            expect(useAdminUserList).toHaveBeenLastCalledWith(expect.objectContaining({ search: '', page: 1 }))
        );
    });

    it('toggles showing deleted users and resets page and selection', async () => {
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));
        expect(screen.getByText('1 selected')).toBeInTheDocument();

        fireEvent.click(screen.getByLabelText('Show deleted users'));

        await waitFor(() =>
            expect(useAdminUserList).toHaveBeenLastCalledWith(
                expect.objectContaining({ includeDeleted: true, page: 1 })
            )
        );
        expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
    });
});
