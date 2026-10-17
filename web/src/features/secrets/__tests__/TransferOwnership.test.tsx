import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '../../../test/test-utils';
import { TransferOwnership } from '../TransferOwnership';
import { usersApi } from '../../../services/users';
import { answerConfirm, answerConfirmSync, queryConfirm } from '../../../test/confirm';

const mockMutate = vi.fn();
const mockReset = vi.fn();
let mockTransferState: { isPending: boolean; isError: boolean; error: unknown } = {
    isPending: false,
    isError: false,
    error: null,
};

vi.mock('../api', () => ({
    useTransferOwnership: () => ({
        mutate: mockMutate,
        reset: mockReset,
        isPending: mockTransferState.isPending,
        isError: mockTransferState.isError,
        error: mockTransferState.error,
    }),
}));

vi.mock('../../../services/users', () => ({
    usersApi: {
        search: vi.fn(async () => [
            { id: 5, name: 'alice', type: 'user', email: 'alice@test.com' },
            { id: 6, name: 'devs', type: 'group' }, // groups must be filtered out
        ]),
    },
}));

describe('TransferOwnership', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockTransferState = { isPending: false, isError: false, error: null };
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('is collapsed by default, showing a trigger', () => {
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        expect(screen.getByText('Transfer ownership')).toBeInTheDocument();
        expect(screen.queryByPlaceholderText(/Search by name/i)).not.toBeInTheDocument();
    });

    it('searches users (excluding groups) and transfers to the chosen one', async () => {
        const confirmSpy = vi.spyOn(window, 'confirm');
        render(<TransferOwnership secretId={1} currentOwner="bob" />);

        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'a' } });

        // alice (user) appears; devs (group) is filtered out.
        const alice = await screen.findByText(/alice/);
        expect(screen.queryByText(/devs/)).not.toBeInTheDocument();

        fireEvent.click(alice);
        fireEvent.click(screen.getByRole('button', { name: /^Transfer$/i }));
        expect(mockMutate).not.toHaveBeenCalled(); // nothing happens until the dialog is answered
        await answerConfirm('Transfer ownership of this secret to alice? You will no longer own it.', 'accept');

        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        expect(mockMutate.mock.calls[0][0]).toBe(5); // new owner id
        expect(confirmSpy).not.toHaveBeenCalled(); // in-app dialog, not window.confirm
        confirmSpy.mockRestore();
    });

    it('does not transfer when the confirm is declined', async () => {
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'a' } });
        fireEvent.click(await screen.findByText(/alice/));
        fireEvent.click(screen.getByRole('button', { name: /^Transfer$/i }));
        await answerConfirm(/Transfer ownership of this secret to alice\?/, 'cancel');
        await waitFor(() => expect(queryConfirm(/Transfer ownership of this secret to alice\?/)).toBeNull());
        expect(mockMutate).not.toHaveBeenCalled();
    });

    it('renders a result without an email as just the name', async () => {
        vi.mocked(usersApi.search).mockResolvedValueOnce([{ id: 9, name: 'carol', type: 'user' }]);
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'c' } });

        const result = await screen.findByText('carol');
        expect(result.textContent).toBe('carol');
    });

    it('collapses back to the trigger when Cancel is clicked, resetting the mutation', () => {
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'a' } });

        fireEvent.click(screen.getByRole('button', { name: /^Cancel$/i }));

        expect(screen.getByText('Transfer ownership')).toBeInTheDocument();
        expect(screen.queryByPlaceholderText(/Search by name/i)).not.toBeInTheDocument();
        expect(mockReset).toHaveBeenCalled();
    });

    it('clears results (rather than crashing) when the user search rejects', async () => {
        vi.mocked(usersApi.search).mockRejectedValueOnce(new Error('network down'));
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'a' } });

        await waitFor(() => expect(usersApi.search).toHaveBeenCalledWith('a'));
        // No results are rendered — the failed search resolved to an empty list.
        await waitFor(() => expect(screen.queryByText(/alice/)).not.toBeInTheDocument());
    });

    it('does not update state from a search that resolves after the query changed (cancelled)', async () => {
        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        let resolveSearch!: (v: unknown) => void;
        vi.mocked(usersApi.search).mockImplementationOnce(
            () =>
                new Promise((resolve) => {
                    resolveSearch = resolve;
                })
        );
        const { unmount } = render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'a' } });

        // Wait for the 200ms debounce to fire and invoke usersApi.search.
        await waitFor(() => expect(usersApi.search).toHaveBeenCalledWith('a'));

        // Unmount before the search resolves — the effect cleanup marks it cancelled.
        unmount();
        resolveSearch([{ id: 5, name: 'alice', type: 'user' }]);
        await Promise.resolve();

        // No "state update on an unmounted component" warning was logged.
        expect(consoleErrorSpy).not.toHaveBeenCalled();
        consoleErrorSpy.mockRestore();
    });

    it('does not update state from a search that rejects after the query changed (cancelled)', async () => {
        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        let rejectSearch!: (err: unknown) => void;
        vi.mocked(usersApi.search).mockImplementationOnce(
            () =>
                new Promise((_resolve, reject) => {
                    rejectSearch = reject;
                })
        );
        const { unmount } = render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'a' } });

        // Wait for the 200ms debounce to fire and invoke usersApi.search.
        await waitFor(() => expect(usersApi.search).toHaveBeenCalledWith('a'));

        // Unmount before the search rejects — the effect cleanup marks it cancelled, so the
        // catch block's `if (!cancelled)` guard must skip the setResults([]) call.
        unmount();
        rejectSearch(new Error('network down'));
        await Promise.resolve();

        // No "state update on an unmounted component" warning was logged.
        expect(consoleErrorSpy).not.toHaveBeenCalled();
        consoleErrorSpy.mockRestore();
    });

    it('shows the pending label while a transfer is in flight', () => {
        mockTransferState = { isPending: true, isError: false, error: null };
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        expect(screen.getByRole('button', { name: /Transferring…/i })).toBeInTheDocument();
    });

    it('shows the Error instance message when the transfer fails', () => {
        mockTransferState = { isPending: false, isError: true, error: new Error('secret is locked') };
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        expect(screen.getByText('secret is locked')).toBeInTheDocument();
    });

    it('falls back to a generic error message when the error is not an Error instance', () => {
        mockTransferState = { isPending: false, isError: true, error: 'oops' };
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        expect(screen.getByText('Failed to transfer ownership.')).toBeInTheDocument();
    });

    it('shows a success message, fires onSuccess, and auto-resets after a successful transfer', async () => {
        vi.useFakeTimers();
        const onSuccess = vi.fn();
        mockMutate.mockImplementationOnce((_id: number, opts?: { onSuccess?: () => void }) => opts?.onSuccess?.());
        render(<TransferOwnership secretId={1} currentOwner="bob" onSuccess={onSuccess} />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'a' } });

        await act(async () => {
            await vi.advanceTimersByTimeAsync(200);
        });

        fireEvent.click(screen.getByText(/alice/));
        fireEvent.click(screen.getByRole('button', { name: /^Transfer$/i }));
        answerConfirmSync(/Transfer ownership of this secret to alice\?/, 'accept');
        await act(async () => {
            await vi.advanceTimersByTimeAsync(0); // let the confirm promise resolve
        });

        expect(screen.getByText('Transferred')).toBeInTheDocument();
        expect(onSuccess).toHaveBeenCalledTimes(1);

        await act(async () => {
            await vi.advanceTimersByTimeAsync(1200);
        });

        expect(screen.getByText('Transfer ownership')).toBeInTheDocument();
    });

    // NOTE: handleTransfer's `if (!selected) return;` guard (line 56) is not exercised
    // here — the Transfer button is `disabled={!selected || ...}`, and a disabled native
    // button does not dispatch click handlers, so that guard is unreachable via user
    // interaction. It is purely defensive, duplicating the disabled state.
});
