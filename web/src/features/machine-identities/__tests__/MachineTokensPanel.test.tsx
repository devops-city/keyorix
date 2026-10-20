import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '../../../test/test-utils';
import { MachineTokensPanel } from '../MachineTokensPanel';
import { answerConfirm } from '../../../test/confirm';

const REVOKE_MSG = /^Revoke token ".*"\? Any client using it will lose access immediately\.$/;
import { DEFAULT_SENSITIVE_IDLE_MS } from '../../../hooks/useAutoClearOnIdle';

const issueMutate = vi.fn();
const revokeMutate = vi.fn();
const classifyMutate = vi.fn();

let tokensData: any[] = [];
let tokensLoading = false;

const defaultTokens = [
    { id: 11, name: 'ci-token', prefix: 'kx_machine_ab12cd', revoked: false, classification: 'restricted' },
    { id: 12, name: 'old', prefix: 'kx_machine_ee99ff', revoked: true, classification: '' },
];

vi.mock('../api', () => ({
    useMachineTokens: () => ({ data: tokensData, isLoading: tokensLoading }),
    useIssueMachineToken: () => ({ mutate: issueMutate, isPending: false }),
    useRevokeMachineToken: () => ({ mutate: revokeMutate, isPending: false }),
    useClassifyMachineToken: () => ({ mutate: classifyMutate, isPending: false }),
}));

beforeEach(() => {
    tokensData = defaultTokens;
    tokensLoading = false;
    issueMutate.mockReset();
    revokeMutate.mockReset();
    classifyMutate.mockReset();
    // Revoke is confirmation-gated (G27); default to confirmed so existing
    // revoke-flow tests below don't have to opt in individually.
    vi.spyOn(window, 'confirm').mockReturnValue(true);
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('MachineTokensPanel', () => {
    it('admins issue tokens and reclassify them', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);

        // Issue requires a name.
        fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'deploy' } });
        fireEvent.click(screen.getByRole('button', { name: /issue token/i }));
        expect(issueMutate).toHaveBeenCalledTimes(1);
        expect(issueMutate.mock.calls[0][0]).toMatchObject({ name: 'deploy' });

        // Reclassify the active token.
        const picker = screen.getByLabelText('Classification for token kx_machine_ab12cd') as HTMLSelectElement;
        expect(picker.value).toBe('restricted');
        fireEvent.change(picker, { target: { value: 'confidential' } });
        expect(classifyMutate).toHaveBeenCalledWith({ tokenId: 11, classification: 'confidential' }, expect.anything());
    });

    it('non-admins see read-only classification badges, no issue/revoke', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage={false} />);

        expect(screen.queryByPlaceholderText('Token name…')).not.toBeInTheDocument();
        const badges = screen.getAllByTestId('mt-classification-badge');
        expect(badges[0]).toHaveTextContent('Restricted');
        expect(screen.queryByLabelText('Classification for token kx_machine_ab12cd')).not.toBeInTheDocument();
    });

    it('shows a loading message while tokens load', () => {
        tokensLoading = true;
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        expect(screen.getByText('Loading tokens…')).toBeInTheDocument();
    });

    it('shows an empty state when there are no tokens', () => {
        tokensData = [];
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        expect(screen.getByText('No tokens issued yet.')).toBeInTheDocument();
    });

    it('does not issue with a blank/whitespace-only name', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: '   ' } });
        fireEvent.click(screen.getByRole('button', { name: /issue token/i }));
        expect(issueMutate).not.toHaveBeenCalled();
    });

    it('does not issue when Enter is pressed with a blank/whitespace-only name', () => {
        // The Issue button is disabled for a blank name, but Enter bypasses it —
        // the handler's own trim() guard is what stops the issue here.
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        const nameInput = screen.getByPlaceholderText('Token name…');
        fireEvent.change(nameInput, { target: { value: '   ' } });
        fireEvent.keyDown(nameInput, { key: 'Enter' });
        expect(issueMutate).not.toHaveBeenCalled();
    });

    it('issues via the Enter key and shows the one-time token modal, then Copy + Done', async () => {
        issueMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({ token: 'kx_machine_raw_secret', id: 99, prefix: 'kx_machine_9999', classification: '' });
        });

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        const nameInput = screen.getByPlaceholderText('Token name…');
        fireEvent.change(nameInput, { target: { value: 'ci-deploy' } });
        fireEvent.keyDown(nameInput, { key: 'Enter' });

        expect(issueMutate).toHaveBeenCalledTimes(1);
        expect(screen.getByText('Machine token issued')).toBeInTheDocument();
        expect(screen.getByText('kx_machine_raw_secret')).toBeInTheDocument();
        // The name field is cleared after a successful issue.
        expect((screen.getByPlaceholderText('Token name…') as HTMLInputElement).value).toBe('');

        fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('kx_machine_raw_secret');
        await waitFor(() => expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument());

        fireEvent.click(screen.getByRole('button', { name: 'Done' }));
        expect(screen.queryByText('Machine token issued')).not.toBeInTheDocument();
    });

    it('clears the issued token modal when closed via the Modal close button', () => {
        issueMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({ token: 'kx_machine_x_close', id: 103, prefix: 'kx_machine_xc', classification: '' });
        });

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'x-close-test' } });
        fireEvent.click(screen.getByRole('button', { name: /issue token/i }));
        expect(screen.getByText('Machine token issued')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close' }));

        expect(screen.queryByText('Machine token issued')).not.toBeInTheDocument();
    });

    describe('copy-to-clipboard reset', () => {
        afterEach(() => {
            vi.useRealTimers();
        });

        it('reverts the Copy button label back to "Copy" after the timeout elapses', async () => {
            issueMutate.mockImplementation((_vars, opts) => {
                opts.onSuccess({
                    token: 'kx_machine_copy_secret',
                    id: 102,
                    prefix: 'kx_machine_copy',
                    classification: '',
                });
            });
            // shouldAdvanceTime: copy() now routes through the async copyToClipboard
            // util, so the label flip lands on a microtask after the click, not
            // synchronously -- waitFor's internal polling needs real timer ticks to
            // observe that, even though the timers below are otherwise faked.
            vi.useFakeTimers({ shouldAdvanceTime: true });

            render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
            fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'copy-test' } });
            fireEvent.click(screen.getByRole('button', { name: /issue token/i }));

            fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
            await waitFor(() => expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument());

            act(() => {
                vi.advanceTimersByTime(2000);
            });

            expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
        });
    });

    it('an Enter keypress on the name field is a no-op when Enter is not pressed', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        const nameInput = screen.getByPlaceholderText('Token name…');
        fireEvent.change(nameInput, { target: { value: 'ci-deploy' } });
        fireEvent.keyDown(nameInput, { key: 'a' });
        expect(issueMutate).not.toHaveBeenCalled();
    });

    it('shows the server message when issuing a token fails', () => {
        issueMutate.mockImplementation((_vars, opts) => {
            opts.onError({ response: { data: { message: 'Quota exceeded' } } });
        });

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'deploy' } });
        fireEvent.click(screen.getByRole('button', { name: /issue token/i }));

        expect(screen.getByText('Quota exceeded')).toBeInTheDocument();
    });

    it('reclassifying to the same value is a no-op', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        const picker = screen.getByLabelText('Classification for token kx_machine_ab12cd') as HTMLSelectElement;
        fireEvent.change(picker, { target: { value: 'restricted' } });
        expect(classifyMutate).not.toHaveBeenCalled();
    });

    it('shows the error.error field fallback when reclassifying fails', () => {
        classifyMutate.mockImplementation((_vars, opts) => {
            opts.onError({ response: { data: { error: 'not permitted' } } });
        });

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        const picker = screen.getByLabelText('Classification for token kx_machine_ab12cd') as HTMLSelectElement;
        fireEvent.change(picker, { target: { value: 'confidential' } });

        expect(screen.getByText('not permitted')).toBeInTheDocument();
    });

    it('revokes an active token and surfaces a fallback error when the server gives no detail', async () => {
        revokeMutate.mockImplementation((_id, opts) => {
            opts.onError({});
        });

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.click(screen.getByTitle('Revoke token'));
        await answerConfirm(REVOKE_MSG, 'accept');

        await waitFor(() => expect(revokeMutate).toHaveBeenCalledWith(11, expect.anything()));
        expect(await screen.findByText('Failed to revoke token.')).toBeInTheDocument();
    });

    it('falls back to "(unnamed)" and Unclassified for a token with no name/classification, and can reclassify it', () => {
        tokensData = [{ id: 13, name: '', prefix: 'kx_machine_zz00', revoked: false, classification: undefined }];

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);

        expect(screen.getByText('(unnamed)')).toBeInTheDocument();
        const picker = screen.getByLabelText('Classification for token kx_machine_zz00') as HTMLSelectElement;
        expect(picker.value).toBe('');

        fireEvent.change(picker, { target: { value: 'confidential' } });
        expect(classifyMutate).toHaveBeenCalledWith({ tokenId: 13, classification: 'confidential' }, expect.anything());
    });

    it('shows the Unclassified badge for a token with no classification (read-only view)', () => {
        tokensData = [{ id: 13, name: 'svc', prefix: 'kx_machine_zz00', revoked: false, classification: undefined }];

        render(<MachineTokensPanel projectId={3} machineId={7} canManage={false} />);

        expect(screen.getByTestId('mt-classification-badge')).toHaveTextContent('Unclassified');
    });

    it('falls back to the prefix in the revoke confirmation when the token has no name', async () => {
        tokensData = [{ id: 13, name: '', prefix: 'kx_machine_zz00', revoked: false, classification: '' }];

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.click(screen.getByTitle('Revoke token'));
        await answerConfirm(
            'Revoke token "kx_machine_zz00"? Any client using it will lose access immediately.',
            'accept'
        );

        await waitFor(() => expect(revokeMutate).toHaveBeenCalledWith(13, expect.anything()));
    });

    it('hides the revoke action for already-revoked tokens', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        // Only one active (non-revoked) token → only one revoke button.
        expect(screen.getAllByTitle('Revoke token')).toHaveLength(1);
    });

    it('asks for confirmation before revoking, and does not revoke when declined', async () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.click(screen.getByTitle('Revoke token'));
        await answerConfirm(REVOKE_MSG, 'cancel');

        expect(revokeMutate).not.toHaveBeenCalled();
        expect(window.confirm).not.toHaveBeenCalled();
    });

    it('revokes the token once the confirmation is accepted', async () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.click(screen.getByTitle('Revoke token'));
        expect(revokeMutate).not.toHaveBeenCalled();
        await answerConfirm(REVOKE_MSG, 'accept');

        await waitFor(() => expect(revokeMutate).toHaveBeenCalledWith(11, expect.anything()));
        expect(revokeMutate).toHaveBeenCalledTimes(1);
        expect(window.confirm).not.toHaveBeenCalled();
    });

    // G28: the one-time token must not linger indefinitely with no explicit close.
    describe('auto-clear (G28)', () => {
        afterEach(() => {
            vi.useRealTimers();
        });

        it('auto-closes the token modal after the idle timeout elapses, without an explicit close', async () => {
            issueMutate.mockImplementation((_vars, opts) => {
                opts.onSuccess({
                    token: 'kx_machine_idle_secret',
                    id: 100,
                    prefix: 'kx_machine_idle',
                    classification: '',
                });
            });
            vi.useFakeTimers();

            render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
            fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'idle-test' } });
            fireEvent.click(screen.getByRole('button', { name: /issue token/i }));
            expect(screen.getByText('kx_machine_idle_secret')).toBeInTheDocument();

            await act(async () => {
                await vi.advanceTimersByTimeAsync(DEFAULT_SENSITIVE_IDLE_MS);
            });

            expect(screen.queryByText('kx_machine_idle_secret')).not.toBeInTheDocument();
            expect(screen.queryByText('Machine token issued')).not.toBeInTheDocument();
        });

        it('auto-closes the token modal when the tab is backgrounded, without an explicit close', () => {
            issueMutate.mockImplementation((_vars, opts) => {
                opts.onSuccess({ token: 'kx_machine_bg_secret', id: 101, prefix: 'kx_machine_bg', classification: '' });
            });

            render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
            fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'bg-test' } });
            fireEvent.click(screen.getByRole('button', { name: /issue token/i }));
            expect(screen.getByText('kx_machine_bg_secret')).toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
            act(() => {
                document.dispatchEvent(new Event('visibilitychange'));
            });

            expect(screen.queryByText('kx_machine_bg_secret')).not.toBeInTheDocument();
            expect(screen.queryByText('Machine token issued')).not.toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
        });
    });
});
