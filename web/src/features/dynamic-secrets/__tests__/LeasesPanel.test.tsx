import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '../../../test/test-utils';
import { LeasesPanel } from '../LeasesPanel';
import { answerConfirm } from '../../../test/confirm';
import { DEFAULT_SENSITIVE_IDLE_MS } from '../../../hooks/useAutoClearOnIdle';

let leasesData: any[] = [];
let leasesLoading = false;

const issueMutate = vi.fn();
const revokeMutate = vi.fn();
const revokeAllMutate = vi.fn();

vi.mock('../api', () => ({
    useDynamicLeases: () => ({ data: leasesData, isLoading: leasesLoading }),
    useIssueLease: () => ({ mutate: issueMutate, isPending: false }),
    useRevokeLease: () => ({ mutate: revokeMutate, isPending: false }),
    useRevokeAllLeases: () => ({ mutate: revokeAllMutate, isPending: false }),
}));

beforeEach(() => {
    leasesData = [];
    leasesLoading = false;
    issueMutate.mockReset();
    revokeMutate.mockReset();
    revokeAllMutate.mockReset();
    // Revoke (single and all) is confirmation-gated (G27); default to confirmed
    // so existing revoke-flow tests below don't have to opt in individually.
    vi.spyOn(window, 'confirm').mockReturnValue(true);
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('LeasesPanel cloud credentials', () => {
    it('shows an issued cloud credential as labelled fields, not username/password', () => {
        issueMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({
                leaseId: 'lease-1',
                username: '',
                password: '',
                fields: {
                    access_key_id: 'AKIAEXAMPLE',
                    secret_access_key: 'sekret',
                    session_token: 'tok',
                    expiration: '2026-06-15T12:00:00Z',
                },
                expiresAt: '2026-06-15T12:00:00Z',
            })
        );

        render(<LeasesPanel configId={5} canManage />);

        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
        expect(issueMutate).toHaveBeenCalledTimes(1);

        // The cloud credential fields are rendered (humanized labels), expiration excluded.
        expect(screen.getByText('Access key id')).toBeInTheDocument();
        expect(screen.getByText('AKIAEXAMPLE')).toBeInTheDocument();
        expect(screen.getByText('Session token')).toBeInTheDocument();
        // No empty username/password rows for a cloud credential.
        expect(screen.queryByText('Username')).not.toBeInTheDocument();
        expect(screen.queryByText('Password')).not.toBeInTheDocument();
        // expiration is shown as the "Expires …" line, not a copy row.
        expect(screen.queryByText('Expiration')).not.toBeInTheDocument();
    });
});

describe('LeasesPanel', () => {
    it('shows a loading message while leases load', () => {
        leasesLoading = true;
        render(<LeasesPanel configId={5} canManage />);
        expect(screen.getByText('Loading leases…')).toBeInTheDocument();
    });

    it('shows an empty state when there are no leases', () => {
        render(<LeasesPanel configId={5} canManage />);
        expect(screen.getByText('No leases issued yet.')).toBeInTheDocument();
    });

    it('renders every lease status style, expiry, and role/leaseId fallback', () => {
        leasesData = [
            {
                leaseId: 'lease-active',
                roleName: 'readonly-role',
                status: 'active',
                expiresAt: '2026-06-15T12:00:00Z',
            },
            { leaseId: 'lease-expired', roleName: '', status: 'expired' },
            { leaseId: 'lease-failed', roleName: 'admin-role', status: 'revoke_failed' },
            { leaseId: 'lease-revoked', roleName: 'old-role', status: 'revoked' },
        ];
        render(<LeasesPanel configId={5} canManage />);

        expect(screen.getByText('active')).toBeInTheDocument();
        expect(screen.getByText('expired')).toBeInTheDocument();
        expect(screen.getByText('revoke failed')).toBeInTheDocument();
        expect(screen.getByText('revoked')).toBeInTheDocument();

        // roleName fallback: falls back to the leaseId when roleName is blank.
        expect(screen.getByText('lease-expired')).toBeInTheDocument();
        expect(screen.getByText('readonly-role')).toBeInTheDocument();

        // expiresAt renders for the active lease only.
        expect(screen.getByText(/expires/i)).toBeInTheDocument();

        // Only the active lease is revocable.
        expect(screen.getAllByTitle('Revoke lease')).toHaveLength(1);
    });

    it('hides revoke controls for non-managers even on an active lease', () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'active' }];
        render(<LeasesPanel configId={5} canManage={false} />);
        expect(screen.queryByTitle('Revoke lease')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /issue credential/i })).not.toBeInTheDocument();
    });

    it('revokes a single lease and surfaces a fallback error when the server gives no detail', async () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'active' }];
        revokeMutate.mockImplementation((_id, opts) => opts.onError({}));

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByTitle('Revoke lease'));
        await answerConfirm(/^Revoke this lease\?/, 'accept');

        await waitFor(() => expect(revokeMutate).toHaveBeenCalledWith('lease-1', expect.anything()));
        expect(await screen.findByText('Failed to revoke lease.')).toBeInTheDocument();
    });

    it('hides "Revoke all" when there are no active leases, shows it (with a count) when there are', () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'expired' }];
        const { rerender } = render(<LeasesPanel configId={5} canManage />);
        expect(screen.queryByRole('button', { name: /revoke all/i })).not.toBeInTheDocument();

        leasesData = [
            { leaseId: 'lease-1', roleName: 'role', status: 'active' },
            { leaseId: 'lease-2', roleName: 'role2', status: 'active' },
        ];
        rerender(<LeasesPanel configId={5} canManage />);
        expect(screen.getByRole('button', { name: 'Revoke all (2)' })).toBeInTheDocument();
    });

    it('revokes all active leases and surfaces the server error message on failure', async () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'active' }];
        revokeAllMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'Vault unreachable' } } })
        );

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: /revoke all/i }));
        await answerConfirm(/^Revoke all 1 active lease/, 'accept');

        await waitFor(() => expect(revokeAllMutate).toHaveBeenCalled());
        expect(await screen.findByText('Vault unreachable')).toBeInTheDocument();
    });

    it('shows the server message when issuing a credential fails', () => {
        issueMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { error: 'backend disabled' } } })
        );

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));

        expect(screen.getByText('backend disabled')).toBeInTheDocument();
    });

    it('shows a database-style credential as username/password copy rows, without an expiry line', async () => {
        issueMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({
                leaseId: 'lease-db',
                username: 'app_user',
                password: 'super-secret',
            })
        );

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));

        expect(screen.getByText('Username')).toBeInTheDocument();
        expect(screen.getByText('app_user')).toBeInTheDocument();
        expect(screen.getByText('Password')).toBeInTheDocument();
        expect(screen.getByText('super-secret')).toBeInTheDocument();
        // No expiry line when the credential carries no expiresAt.
        expect(screen.queryByText(/^Expires/)).not.toBeInTheDocument();

        // Copying a field writes it to the clipboard and flips the button label.
        const copyButtons = screen.getAllByRole('button', { name: 'Copy' });
        fireEvent.click(copyButtons[0]);
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('app_user');
        await waitFor(() => expect(screen.getAllByRole('button', { name: 'Copied' })).toHaveLength(1));
    });

    const REVOKE_ONE = 'Revoke this lease? The credential will stop working immediately.';
    const REVOKE_ALL_2 = 'Revoke all 2 active lease(s)? Every issued credential will stop working immediately.';
    const twoLeases = () => [
        { leaseId: 'lease-1', roleName: 'role', status: 'active' },
        { leaseId: 'lease-2', roleName: 'role2', status: 'active' },
    ];

    it('asks for confirmation before revoking a single lease, and does not revoke when declined', async () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'active' }];

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByTitle('Revoke lease'));
        await answerConfirm(REVOKE_ONE, 'cancel');

        expect(revokeMutate).not.toHaveBeenCalled();
        expect(window.confirm).not.toHaveBeenCalled();
    });

    it('revokes a single lease once the confirmation is accepted', async () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'active' }];

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByTitle('Revoke lease'));
        expect(revokeMutate).not.toHaveBeenCalled();
        await answerConfirm(REVOKE_ONE, 'accept');

        await waitFor(() => expect(revokeMutate).toHaveBeenCalledWith('lease-1', expect.anything()));
        expect(revokeMutate).toHaveBeenCalledTimes(1);
        expect(window.confirm).not.toHaveBeenCalled();
    });

    it('asks for confirmation before revoking all leases, and does not revoke when declined', async () => {
        leasesData = twoLeases();

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: 'Revoke all (2)' }));
        await answerConfirm(REVOKE_ALL_2, 'cancel');

        expect(revokeAllMutate).not.toHaveBeenCalled();
        expect(window.confirm).not.toHaveBeenCalled();
    });

    it('revokes all leases once the confirmation is accepted', async () => {
        leasesData = twoLeases();

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: 'Revoke all (2)' }));
        expect(revokeAllMutate).not.toHaveBeenCalled();
        await answerConfirm(REVOKE_ALL_2, 'accept');

        await waitFor(() => expect(revokeAllMutate).toHaveBeenCalled());
        expect(revokeAllMutate).toHaveBeenCalledTimes(1);
        expect(window.confirm).not.toHaveBeenCalled();
    });

    // A lease whose revoke attempt failed is still LIVE upstream (the backend
    // treats revoke_failed as active — see CountActiveLeases/ListExpiredActiveLeases)
    // so the operator must be able to see why it failed and retry from this panel.
    describe('revoke_failed leases (incident-response gap)', () => {
        it('shows a retry affordance and the revokeError message for a revoke_failed lease', () => {
            leasesData = [
                {
                    leaseId: 'lease-failed',
                    roleName: 'admin-role',
                    status: 'revoke_failed',
                    revokeError: 'target database unreachable: dial tcp: i/o timeout',
                },
            ];
            render(<LeasesPanel configId={5} canManage />);

            expect(screen.getByText('target database unreachable: dial tcp: i/o timeout')).toBeInTheDocument();
            expect(screen.getByTitle('Retry revoke')).toBeInTheDocument();
            expect(screen.queryByTitle('Revoke lease')).not.toBeInTheDocument();
        });

        it('does not render a revokeError message when the field is absent', () => {
            leasesData = [{ leaseId: 'lease-failed', roleName: 'admin-role', status: 'revoke_failed' }];
            render(<LeasesPanel configId={5} canManage />);

            expect(screen.getByTitle('Retry revoke')).toBeInTheDocument();
        });

        it('retries revoking a revoke_failed lease via the same revoke mutation, after a distinct confirmation', async () => {
            leasesData = [
                { leaseId: 'lease-failed', roleName: 'admin-role', status: 'revoke_failed', revokeError: 'timeout' },
            ];

            render(<LeasesPanel configId={5} canManage />);
            fireEvent.click(screen.getByTitle('Retry revoke'));
            await answerConfirm(
                'Retry revoking this lease? The credential is still live upstream until this succeeds.',
                'accept'
            );

            await waitFor(() => expect(revokeMutate).toHaveBeenCalledWith('lease-failed', expect.anything()));
        });

        it('hides the retry control for non-managers even on a revoke_failed lease', () => {
            leasesData = [
                { leaseId: 'lease-failed', roleName: 'admin-role', status: 'revoke_failed', revokeError: 'timeout' },
            ];
            render(<LeasesPanel configId={5} canManage={false} />);
            expect(screen.queryByTitle('Retry revoke')).not.toBeInTheDocument();
        });
    });

    // revokeAll's response carries a {revoked, failed} breakdown (api.ts) — a
    // partial failure must be visibly distinct from a full success, not silently
    // swallowed by only wiring onError.
    describe('revoke all: partial-failure visibility', () => {
        it('shows a warning notice distinguishing a partial failure from full success', async () => {
            leasesData = [
                { leaseId: 'lease-1', roleName: 'role', status: 'active' },
                { leaseId: 'lease-2', roleName: 'role2', status: 'active' },
            ];
            revokeAllMutate.mockImplementation((_vars, opts) => opts.onSuccess({ revoked: 4, failed: 2 }));

            render(<LeasesPanel configId={5} canManage />);
            fireEvent.click(screen.getByRole('button', { name: /revoke all/i }));
            await answerConfirm(/^Revoke all 2 active lease/, 'accept');

            expect(await screen.findByText(/revoked 4 of 6 lease\(s\) — 2 failed/i)).toBeInTheDocument();
        });

        it('shows a plain success notice (no partial-failure wording) when nothing failed', async () => {
            leasesData = [
                { leaseId: 'lease-1', roleName: 'role', status: 'active' },
                { leaseId: 'lease-2', roleName: 'role2', status: 'active' },
            ];
            revokeAllMutate.mockImplementation((_vars, opts) => opts.onSuccess({ revoked: 2, failed: 0 }));

            render(<LeasesPanel configId={5} canManage />);
            fireEvent.click(screen.getByRole('button', { name: /revoke all/i }));
            await answerConfirm(/^Revoke all 2 active lease/, 'accept');

            expect(await screen.findByText('Revoked 2 lease(s).')).toBeInTheDocument();
            expect(screen.queryByText(/failed/i)).not.toBeInTheDocument();
        });
    });

    it('dismisses the "Revoke all" partial-failure/success notice via its own dismiss control', async () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'active' }];
        revokeAllMutate.mockImplementation((_vars, opts) => opts.onSuccess({ revoked: 1, failed: 0 }));

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: /revoke all/i }));
        await answerConfirm(/^Revoke all 1 active lease/, 'accept');
        expect(await screen.findByText('Revoked 1 lease(s).')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
        expect(screen.queryByText('Revoked 1 lease(s).')).not.toBeInTheDocument();
    });

    it('reverts a copy button from "Copied" back to "Copy" after the timeout elapses', async () => {
        issueMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({ leaseId: 'lease-copy', username: 'app_user', password: 'super-secret' })
        );
        // shouldAdvanceTime: copy() now routes through the async copyToClipboard
        // util, so the label flip lands on a microtask after the click, not
        // synchronously -- waitFor's internal polling needs real timer ticks to
        // observe that, even though the timers below are otherwise faked.
        vi.useFakeTimers({ shouldAdvanceTime: true });

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));

        const copyButtons = screen.getAllByRole('button', { name: 'Copy' });
        fireEvent.click(copyButtons[0]);
        await waitFor(() => expect(screen.getAllByRole('button', { name: 'Copied' })).toHaveLength(1));

        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });

        expect(screen.queryByRole('button', { name: 'Copied' })).not.toBeInTheDocument();
        expect(screen.getAllByRole('button', { name: 'Copy' })).toHaveLength(2);

        vi.useRealTimers();
    });

    it('falls back to an empty string for a cloud-credential field whose value is missing', () => {
        issueMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({
                leaseId: 'lease-cloud-missing-field',
                username: '',
                password: '',
                fields: {
                    access_key_id: 'AKIAEXAMPLE',
                    secret_access_key: undefined,
                },
            })
        );

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));

        expect(screen.getByText('Secret access key')).toBeInTheDocument();
        // The field's value is undefined, so the row falls back to rendering an
        // empty string rather than throwing or literally showing "undefined".
        const label = screen.getByText('Secret access key');
        const row = label.closest('.flex.items-stretch');
        expect(row?.querySelector('code')).toHaveTextContent('');
    });

    it('closes the credential modal via the close (X) control and via Done', () => {
        issueMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({ leaseId: 'lease-x', username: 'u', password: 'p' })
        );

        render(<LeasesPanel configId={5} canManage />);

        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
        expect(screen.getByText('Credential issued')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByText('Credential issued')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
        expect(screen.getByText('Credential issued')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Done' }));
        expect(screen.queryByText('Credential issued')).not.toBeInTheDocument();
    });

    // G28: the one-time credential must not linger indefinitely with no explicit close.
    describe('auto-clear (G28)', () => {
        afterEach(() => {
            vi.useRealTimers();
        });

        it('auto-closes the credential modal after the idle timeout elapses, without an explicit close', async () => {
            issueMutate.mockImplementation((_vars, opts) =>
                opts.onSuccess({ leaseId: 'lease-idle', username: 'app_user', password: 'idle-secret' })
            );
            vi.useFakeTimers();

            render(<LeasesPanel configId={5} canManage />);
            fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
            expect(screen.getByText('idle-secret')).toBeInTheDocument();

            await act(async () => {
                await vi.advanceTimersByTimeAsync(DEFAULT_SENSITIVE_IDLE_MS);
            });

            expect(screen.queryByText('idle-secret')).not.toBeInTheDocument();
            expect(screen.queryByText('Credential issued')).not.toBeInTheDocument();
        });

        it('auto-closes the credential modal when the tab is backgrounded, without an explicit close', () => {
            issueMutate.mockImplementation((_vars, opts) =>
                opts.onSuccess({ leaseId: 'lease-bg', username: 'app_user', password: 'bg-secret' })
            );

            render(<LeasesPanel configId={5} canManage />);
            fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
            expect(screen.getByText('bg-secret')).toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
            act(() => {
                document.dispatchEvent(new Event('visibilitychange'));
            });

            expect(screen.queryByText('bg-secret')).not.toBeInTheDocument();
            expect(screen.queryByText('Credential issued')).not.toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
        });
    });
});
