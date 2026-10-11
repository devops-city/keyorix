import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, within, waitFor, act } from '../../../test/test-utils';
import { UserDetailPage } from '../UserDetailPage';

let userData: Record<string, unknown> | null;
let rolesData: Array<{ id: number; name: string }>;
let permsData: Array<{ id?: number; name: string; description?: string; resource: string; action: string }>;
let membershipsData: Array<{ project_id: number; project_name?: string; role?: string; state: string }>;
let detailState: { isLoading: boolean; isError: boolean };
let resendIsPending: boolean;
let authUserId: number | null;
let routeId: string | undefined;

const mockNavigate = vi.fn();
const suspendMutate = vi.fn();
const reactivateMutate = vi.fn();
const unlockMutate = vi.fn();
const requireResetMutate = vi.fn();
const revokeSessionsMutate = vi.fn();
const resendMutate = vi.fn();
const migrateMutate = vi.fn();

vi.mock('react-router', async (orig) => ({
    ...(await orig<typeof import('react-router')>()),
    useParams: () => ({ id: routeId }),
    useNavigate: () => mockNavigate,
}));

vi.mock('../../../features/admin', () => ({
    useUserDetail: () => ({ data: userData, isLoading: detailState.isLoading, isError: detailState.isError }),
    useUserRoles: () => ({ data: rolesData }),
    useUserPermissions: () => ({ data: permsData }),
    useUserMemberships: () => ({ data: membershipsData }),
    useSuspendUser: () => ({ mutate: suspendMutate, isPending: false }),
    useReactivateUser: () => ({ mutate: reactivateMutate, isPending: false }),
    useUnlockUser: () => ({ mutate: unlockMutate, isPending: false }),
    useRequirePasswordReset: () => ({ mutate: requireResetMutate, isPending: false }),
    useRevokeSessions: () => ({ mutate: revokeSessionsMutate, isPending: false }),
    useResendSetupLink: () => ({ mutate: resendMutate, isPending: resendIsPending }),
    useMigrateUserToMachine: () => ({ mutate: migrateMutate, isPending: false }),
    AccountStateBadge: ({ state }: { state: string }) => <span>state:{state}</span>,
}));

vi.mock('../../../features/projects/api', () => ({
    useProjects: () => ({ data: [{ id: 7, name: 'platform' }] }),
}));

vi.mock('../../../features/auth', () => ({
    useAuth: () => ({ user: authUserId === null ? null : { id: authUserId } }),
}));

const baseUser = {
    id: 5,
    username: 'bob',
    email: 'bob@x.com',
    display_name: 'Bob',
    active: true,
    account_state: 'active',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    last_login_at: null,
    deleted_at: null,
};

beforeEach(() => {
    mockNavigate.mockReset();
    suspendMutate.mockReset();
    reactivateMutate.mockReset();
    unlockMutate.mockReset();
    requireResetMutate.mockReset();
    revokeSessionsMutate.mockReset();
    resendMutate.mockReset();
    migrateMutate.mockReset();
    userData = { ...baseUser };
    rolesData = [];
    permsData = [];
    membershipsData = [];
    detailState = { isLoading: false, isError: false };
    resendIsPending = false;
    authUserId = 99; // viewing someone else by default
    routeId = '5';
});

describe('UserDetailPage — login lockout', () => {
    it('shows a Locked out badge and Unlock action when the account is locked', () => {
        userData = { ...baseUser, login_locked_until: '2099-01-01T00:00:00Z' };
        render(<UserDetailPage />);
        expect(screen.getByText('Locked out')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Unlock login' })).toBeInTheDocument();
    });

    it('does not show the Unlock action when not locked', () => {
        render(<UserDetailPage />);
        expect(screen.queryByText('Locked out')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Unlock login' })).not.toBeInTheDocument();
    });

    it('confirms and calls unlock for the viewed user', () => {
        userData = { ...baseUser, login_locked_until: '2099-01-01T00:00:00Z' };
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Unlock login' }));
        // Confirm modal.
        expect(screen.getByText('Clear login lockout')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
        expect(unlockMutate).toHaveBeenCalledWith(5, expect.anything());
    });
});

describe('UserDetailPage — effective permissions', () => {
    it('lists the effective permissions when present', () => {
        permsData = [
            { id: 2, name: 'secrets.write', description: 'Write secrets', resource: 'secrets', action: 'write' },
            { id: 1, name: 'secrets.read', description: 'Read secrets', resource: 'secrets', action: 'read' },
        ];
        render(<UserDetailPage />);
        expect(screen.getByText('Effective permissions')).toBeInTheDocument();
        expect(screen.getByText('secrets.read')).toBeInTheDocument();
        expect(screen.getByText('secrets.write')).toBeInTheDocument();
    });

    it('shows an empty state when the user has no permissions', () => {
        render(<UserDetailPage />);
        expect(screen.getByText('Effective permissions')).toBeInTheDocument();
        expect(screen.getByText('No permissions.')).toBeInTheDocument();
    });

    it('renders a permission without an id or description using its name as the key and no title', () => {
        permsData = [{ name: 'secrets.list', resource: 'secrets', action: 'list' }];
        render(<UserDetailPage />);
        const chip = screen.getByText('secrets.list');
        expect(chip).toBeInTheDocument();
        expect(chip).not.toHaveAttribute('title');
    });
});

describe('UserDetailPage — convert to machine identity', () => {
    it('opens the modal and migrates with the chosen project, type, and keep-user', () => {
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Convert to machine identity' }));

        // Pick a project (required), keep the default type 'service', keep the user.
        fireEvent.change(screen.getByLabelText('Project'), { target: { value: '7' } });
        fireEvent.click(screen.getByLabelText(/Keep the source user active/i));
        fireEvent.click(screen.getByRole('button', { name: 'Convert' }));

        expect(migrateMutate).toHaveBeenCalledTimes(1);
        const [vars] = migrateMutate.mock.calls[0];
        expect(vars).toMatchObject({
            projectId: 7,
            userId: 5,
            body: { username: 'bob', identity_type: 'service', keep_user: true },
        });
    });

    it('keeps Convert disabled until a project is selected', () => {
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Convert to machine identity' }));
        expect(screen.getByRole('button', { name: 'Convert' })).toBeDisabled();
    });

    it('submits a custom identity type and name, defaulting keep-user to false', () => {
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Convert to machine identity' }));

        fireEvent.change(screen.getByLabelText('Project'), { target: { value: '7' } });
        fireEvent.change(screen.getByLabelText('Identity type'), { target: { value: 'ci' } });
        fireEvent.change(screen.getByLabelText('Name (optional)'), { target: { value: 'ci-runner' } });
        fireEvent.click(screen.getByRole('button', { name: 'Convert' }));

        const [vars] = migrateMutate.mock.calls[0];
        expect(vars).toMatchObject({
            projectId: 7,
            userId: 5,
            body: { username: 'bob', identity_type: 'ci', name: 'ci-runner', keep_user: false },
        });
    });

    it('shows a success note naming the created identity on migrate success', () => {
        migrateMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({ machine_identity: { name: 'ci-runner' } });
        });
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Convert to machine identity' }));
        fireEvent.change(screen.getByLabelText('Project'), { target: { value: '7' } });
        fireEvent.click(screen.getByRole('button', { name: 'Convert' }));

        expect(screen.getByText('Created machine identity “ci-runner”; source user suspended.')).toBeInTheDocument();
    });

    it('falls back to the username and omits the suspended note when keeping the source user', () => {
        migrateMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({});
        });
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Convert to machine identity' }));
        fireEvent.change(screen.getByLabelText('Project'), { target: { value: '7' } });
        fireEvent.click(screen.getByLabelText(/Keep the source user active/i));
        fireEvent.click(screen.getByRole('button', { name: 'Convert' }));

        expect(screen.getByText('Created machine identity “bob”.')).toBeInTheDocument();
    });

    it('shows an error alert when migration fails', () => {
        migrateMutate.mockImplementation((_vars, opts) => {
            opts.onError({ response: { data: { error: 'Project quota exceeded' } } });
        });
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Convert to machine identity' }));
        fireEvent.change(screen.getByLabelText('Project'), { target: { value: '7' } });
        fireEvent.click(screen.getByRole('button', { name: 'Convert' }));

        expect(screen.getByText('Project quota exceeded')).toBeInTheDocument();
    });

    it('closes the convert modal on Cancel without migrating', () => {
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Convert to machine identity' }));
        expect(screen.getByText('Create a project machine identity for', { exact: false })).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(migrateMutate).not.toHaveBeenCalled();
        expect(screen.queryByText('Create a project machine identity for', { exact: false })).not.toBeInTheDocument();
    });
});

describe('UserDetailPage — loading and error states', () => {
    it('shows the loading indicator while the user is being fetched', () => {
        detailState = { isLoading: true, isError: false };
        render(<UserDetailPage />);
        expect(screen.getByText(/loading/i)).toBeInTheDocument();
        expect(screen.queryByText('Account actions')).not.toBeInTheDocument();
    });

    it('shows an error message when the user fails to load', () => {
        detailState = { isLoading: false, isError: true };
        render(<UserDetailPage />);
        expect(screen.getByText('Failed to load user')).toBeInTheDocument();
        expect(screen.getByText('The user could not be found or you lack access.')).toBeInTheDocument();
    });

    it('shows an error message when there is no detail data even without an explicit error flag', () => {
        userData = null;
        render(<UserDetailPage />);
        expect(screen.getByText('Failed to load user')).toBeInTheDocument();
    });
});

describe('UserDetailPage — date formatting', () => {
    // Note: formatDate's catch branch (returning the raw ISO string) is defensive only —
    // in V8/Chromium (this app's target runtime, per the Chromium-only e2e config),
    // Date.prototype.toLocaleString never throws for an invalid date; it returns the
    // string "Invalid Date" instead. That branch is not exercised here as it isn't
    // reachable via this environment's Intl implementation.
    it('renders a dash, never "Invalid Date", for an unparseable created_at', () => {
        userData = { ...baseUser, created_at: 'not-a-real-date' };
        render(<UserDetailPage />);
        expect(screen.queryByText('Invalid Date')).not.toBeInTheDocument();
    });

    it('shows "Never" when the user has no last login', () => {
        render(<UserDetailPage />);
        expect(screen.getByText('Never')).toBeInTheDocument();
    });

    it('formats the last login date when the user has logged in', () => {
        userData = { ...baseUser, last_login_at: '2026-03-15T10:30:00Z' };
        render(<UserDetailPage />);
        expect(screen.queryByText('Never')).not.toBeInTheDocument();
        // formatDate renders locale-formatted text; just assert it isn't the raw ISO or "Never".
        expect(screen.queryByText('2026-03-15T10:30:00Z')).not.toBeInTheDocument();
    });

    it('shows an em dash for a missing created_at', () => {
        userData = { ...baseUser, created_at: undefined };
        render(<UserDetailPage />);
        expect(screen.getByText('—')).toBeInTheDocument();
    });
});

describe('UserDetailPage — header display name fallback', () => {
    it('falls back to the username for the avatar initial and heading when display_name is missing', () => {
        userData = { ...baseUser, display_name: undefined, username: 'zoe' };
        render(<UserDetailPage />);
        expect(screen.getByText('Z')).toBeInTheDocument(); // avatar initial from "zoe"
        expect(screen.getByRole('heading', { name: 'zoe' })).toBeInTheDocument();
    });
});

describe('UserDetailPage — lifecycle action visibility', () => {
    it('hides lifecycle actions and shows a note when viewing your own account', () => {
        authUserId = 5; // same id as the viewed user
        render(<UserDetailPage />);
        expect(screen.getByText('Lifecycle actions are unavailable on your own account.')).toBeInTheDocument();
        expect(screen.queryByText('Account actions')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Suspend' })).not.toBeInTheDocument();
    });

    it('shows account actions when there is no authenticated user (never self)', () => {
        authUserId = null;
        render(<UserDetailPage />);
        expect(screen.getByText('Account actions')).toBeInTheDocument();
        expect(screen.queryByText('Lifecycle actions are unavailable on your own account.')).not.toBeInTheDocument();
    });

    it('hides lifecycle actions entirely for a deleted user (not self)', () => {
        userData = { ...baseUser, deleted_at: '2026-02-01T00:00:00Z' };
        render(<UserDetailPage />);
        expect(screen.queryByText('Account actions')).not.toBeInTheDocument();
        expect(screen.queryByText('Lifecycle actions are unavailable on your own account.')).not.toBeInTheDocument();
    });

    it('shows Reactivate instead of Suspend for a suspended user, and hides state-specific actions', () => {
        userData = { ...baseUser, account_state: 'suspended' };
        render(<UserDetailPage />);
        expect(screen.getByRole('button', { name: 'Reactivate' })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Suspend' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Force password reset' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Force log out' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Convert to machine identity' })).not.toBeInTheDocument();
    });

    it('treats a missing account_state as active', () => {
        userData = { ...baseUser, account_state: undefined };
        render(<UserDetailPage />);
        expect(screen.getByText('state:active')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Force password reset' })).toBeInTheDocument();
    });

    it('shows the Resend setup link action, disabled with "Resending…" while pending', () => {
        userData = { ...baseUser, account_state: 'pending_first_login' };
        resendIsPending = true;
        render(<UserDetailPage />);
        expect(screen.getByRole('button', { name: 'Resending…' })).toBeDisabled();
    });
});

describe('UserDetailPage — account action confirm flows', () => {
    it('confirms and calls suspend, then shows a success note that can be dismissed', () => {
        suspendMutate.mockImplementation((_id, opts) => opts.onSuccess());
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Suspend' }));
        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByText('Suspend user')).toBeInTheDocument();
        fireEvent.click(within(dialog).getByRole('button', { name: 'Suspend' }));

        expect(suspendMutate).toHaveBeenCalledWith(5, expect.anything());
        expect(screen.getByText('Suspend applied.')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(screen.queryByText('Suspend applied.')).not.toBeInTheDocument();
    });

    it('cancels the confirm modal without calling the mutation', () => {
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Suspend' }));
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(suspendMutate).not.toHaveBeenCalled();
        expect(screen.queryByText('Suspend user')).not.toBeInTheDocument();
    });

    it('confirms and calls reactivate for a suspended user', () => {
        userData = { ...baseUser, account_state: 'suspended' };
        reactivateMutate.mockImplementation((_id, opts) => opts.onSuccess());
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Reactivate' }));
        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Reactivate' }));
        expect(reactivateMutate).toHaveBeenCalledWith(5, expect.anything());
        expect(screen.getByText('Reactivate applied.')).toBeInTheDocument();
    });

    it('confirms and calls the password reset mutation, surfacing the error message fallback on failure', () => {
        requireResetMutate.mockImplementation((_id, opts) => opts.onError(new Error('Network down')));
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Force password reset' }));
        expect(screen.getByRole('dialog')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Force reset' }));

        expect(requireResetMutate).toHaveBeenCalledWith(5, expect.anything());
        expect(screen.getByText('Network down')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(screen.queryByText('Network down')).not.toBeInTheDocument();
    });

    it('confirms and calls the revoke-sessions mutation, falling back to a generic error message', () => {
        revokeSessionsMutate.mockImplementation((_id, opts) => opts.onError({}));
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Force log out' }));
        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Force log out' }));

        expect(revokeSessionsMutate).toHaveBeenCalledWith(5, expect.anything());
        expect(screen.getByText('Action failed.')).toBeInTheDocument();
    });
});

describe('UserDetailPage — resend setup link', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    // Note: copyLink() also guards on `!resentLink?.link_for_admin` before copying, but
    // ResentLinkPanel applies that exact same check before it ever renders the Copy button
    // (see ResentLinkPanel in UserDetailPage.tsx) — so that guard's early-return branch can
    // never actually be reached by clicking through the UI. It isn't exercised here for the
    // same reason formatDate's catch branch isn't (see the "date formatting" describe above).

    it('shows the single-use link panel and lets the admin copy it', async () => {
        resendMutate.mockImplementation((_id, opts) => opts.onSuccess({ link_for_admin: 'https://x/setup/abc' }));
        userData = { ...baseUser, account_state: 'pending_first_login' };
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Resend setup link' }));

        expect(screen.getByText('https://x/setup/abc')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Copy' }));

        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('https://x/setup/abc');
        await waitFor(() => expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument());
    });

    it('shows a generic success note when no link is returned', () => {
        resendMutate.mockImplementation((_id, opts) => opts.onSuccess({}));
        userData = { ...baseUser, account_state: 'pending_first_login' };
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Resend setup link' }));
        expect(screen.getByText('Setup link re-sent to bob@x.com.')).toBeInTheDocument();
    });

    it('surfaces an error when resending the setup link fails', () => {
        resendMutate.mockImplementation((_id, opts) =>
            opts.onError({ response: { data: { error: 'Mailer unavailable' } } })
        );
        userData = { ...baseUser, account_state: 'pending_first_login' };
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Resend setup link' }));
        expect(screen.getByText('Mailer unavailable')).toBeInTheDocument();
    });

    it('does not crash when copying to clipboard fails, and leaves the link visible', async () => {
        resendMutate.mockImplementation((_id, opts) => opts.onSuccess({ link_for_admin: 'https://x/setup/abc' }));
        (navigator.clipboard.writeText as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('denied'));
        userData = { ...baseUser, account_state: 'pending_first_login' };
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Resend setup link' }));
        fireEvent.click(screen.getByRole('button', { name: 'Copy' }));

        await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalled());
        expect(screen.getByText('https://x/setup/abc')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Copied' })).not.toBeInTheDocument();
    });

    it('reverts the Copy button label back to "Copy" after the timeout elapses', async () => {
        resendMutate.mockImplementation((_id, opts) => opts.onSuccess({ link_for_admin: 'https://x/setup/abc' }));
        userData = { ...baseUser, account_state: 'pending_first_login' };
        vi.useFakeTimers();
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Resend setup link' }));
        fireEvent.click(screen.getByRole('button', { name: 'Copy' }));

        await act(async () => {
            await vi.advanceTimersByTimeAsync(0);
        });
        expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });
        expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    });
});

describe('UserDetailPage — roles and project assignments with data', () => {
    it('renders role chips when roles are assigned', () => {
        rolesData = [
            { id: 1, name: 'admin' },
            { id: 2, name: 'billing' },
        ];
        render(<UserDetailPage />);
        expect(screen.getByText('admin')).toBeInTheDocument();
        expect(screen.getByText('billing')).toBeInTheDocument();
    });

    it('renders a project assignments table row for each membership', () => {
        membershipsData = [{ project_id: 7, project_name: 'platform', role: 'editor', state: 'active' }];
        render(<UserDetailPage />);
        expect(screen.getByText('platform')).toBeInTheDocument();
        expect(screen.getByText('editor')).toBeInTheDocument();
        expect(screen.getByText('active')).toBeInTheDocument();
    });

    it('falls back to project id and an em dash when name/role are missing', () => {
        membershipsData = [{ project_id: 42, state: 'invited' }];
        render(<UserDetailPage />);
        expect(screen.getByText('#42')).toBeInTheDocument();
        expect(screen.getByText('—')).toBeInTheDocument();
    });
});

describe('UserDetailPage — navigation', () => {
    it('navigates back to the users list', () => {
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: /back to users/i }));
        expect(mockNavigate).toHaveBeenCalledWith('/admin/users');
    });
});

// The route always supplies a numeric :id for this page (see App.tsx), so `userId` is
// never actually null in production. These guards exist purely as a defensive fallback;
// exercised here only to keep the mutate calls from firing on a malformed/missing id.
describe('UserDetailPage — missing route id (defensive guards)', () => {
    beforeEach(() => {
        routeId = undefined;
        userData = { ...baseUser, account_state: 'pending_first_login' };
    });

    it('does not call suspend when the route has no numeric id', () => {
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Suspend' }));
        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Suspend' }));
        expect(suspendMutate).not.toHaveBeenCalled();
    });

    it('does not call resend when the route has no numeric id', () => {
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Resend setup link' }));
        expect(resendMutate).not.toHaveBeenCalled();
    });

    it('does not call migrate when the route has no numeric id', () => {
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Convert to machine identity' }));
        fireEvent.change(screen.getByLabelText('Project'), { target: { value: '7' } });
        fireEvent.click(screen.getByRole('button', { name: 'Convert' }));
        expect(migrateMutate).not.toHaveBeenCalled();
    });
});
