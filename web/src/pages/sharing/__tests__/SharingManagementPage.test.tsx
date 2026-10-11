import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, within, waitFor, act } from '../../../test/test-utils';
import { SharingManagementPage, shareExpiry } from '../SharingManagementPage';

const NOW = new Date('2026-08-01T12:00:00.000Z');

const {
    deleteMutate,
    bulkDeleteMutate,
    updateMutate,
    updateReset,
    refetchMock,
    sharesQueryMock,
    openModalMock,
    closeModalMock,
    expiresAtFromPresetMock,
} = vi.hoisted(() => ({
    deleteMutate: vi.fn(),
    bulkDeleteMutate: vi.fn(),
    updateMutate: vi.fn(),
    updateReset: vi.fn(),
    refetchMock: vi.fn(),
    sharesQueryMock: vi.fn(),
    openModalMock: vi.fn(),
    closeModalMock: vi.fn(),
    expiresAtFromPresetMock: vi.fn((preset: string) => (preset === 'never' ? undefined : `iso-${preset}`)),
}));

const sharesState = vi.hoisted(() => ({
    data: undefined as any,
    isLoading: false,
    error: null as unknown,
}));

const mutationState = vi.hoisted(() => ({
    delete: { isPending: false },
    bulkDelete: { isPending: false },
    update: { isPending: false, isError: false, error: null as unknown },
}));

vi.mock('../../../features/sharing', () => ({
    useShares: (params: any) => {
        sharesQueryMock(params);
        return {
            data: sharesState.data,
            isLoading: sharesState.isLoading,
            error: sharesState.error,
            refetch: refetchMock,
        };
    },
    useDeleteShare: () => ({ mutate: deleteMutate, ...mutationState.delete }),
    useBulkDeleteShares: () => ({ mutate: bulkDeleteMutate, ...mutationState.bulkDelete }),
    useUpdateShare: () => ({ mutate: updateMutate, reset: updateReset, ...mutationState.update }),
    expiresAtFromPreset: (preset: string) => expiresAtFromPresetMock(preset),
}));

// useUIStore is mocked with a real React.useState-backed implementation so the
// page's own openModal/closeModal calls actually re-render it (mirrors the
// pattern used for feature-hook mocks elsewhere in this test suite). Spies
// wrap the setters so call arguments can be asserted directly.
vi.mock('../../../store/uiStore', () => ({
    useUIStore: () => {
        const [activeModal, setActiveModal] = React.useState<string | null>(null);
        const [modalData, setModalData] = React.useState<any>(null);
        const openModal = (id: string, data: any = null) => {
            openModalMock(id, data);
            setActiveModal(id);
            setModalData(data);
        };
        const closeModal = () => {
            closeModalMock();
            setActiveModal(null);
            setModalData(null);
        };
        return { activeModal, modalData, openModal, closeModal };
    },
}));

const shareAlice = {
    id: 1,
    secretId: 101,
    recipientType: 'user' as const,
    recipientId: 11,
    recipientName: 'Alice Anderson',
    permission: 'read' as const,
    createdAt: '2026-07-15T12:00:00.000Z',
    createdBy: 'alice',
    expiresAt: undefined as string | undefined,
};

const shareOps = {
    id: 2,
    secretId: 102,
    recipientType: 'group' as const,
    recipientId: 22,
    recipientName: 'Ops Group',
    permission: 'write' as const,
    createdAt: '2026-07-20T12:00:00.000Z',
    createdBy: 'bob',
    expiresAt: '2026-07-01T00:00:00.000Z', // in the past relative to NOW -> expired
};

const shareCarol = {
    id: 3,
    secretId: 103,
    recipientType: 'user' as const,
    recipientId: 33,
    recipientName: 'Carol Smith',
    permission: 'read' as const,
    createdAt: '2026-07-25T12:00:00.000Z',
    createdBy: 'carol',
    expiresAt: '2026-08-01T17:00:00.000Z', // NOW + 5h -> "in 5h"
};

const allShares = [shareAlice, shareOps, shareCarol];

function makeResponse(data: typeof allShares, overrides: Partial<{ total: number; totalPages: number }> = {}) {
    return {
        data,
        total: overrides.total ?? data.length,
        page: 1,
        pageSize: 20,
        totalPages: overrides.totalPages ?? 1,
    };
}

function resetState() {
    sharesState.data = makeResponse(allShares);
    sharesState.isLoading = false;
    sharesState.error = null;
    mutationState.delete = { isPending: false };
    mutationState.bulkDelete = { isPending: false };
    mutationState.update = { isPending: false, isError: false, error: null };
}

function rowFor(recipientName: string): HTMLElement {
    return screen.getByText(recipientName).closest('tr') as HTMLElement;
}

beforeEach(() => {
    vi.clearAllMocks();
    resetState();
    // setSystemTime alone (without useFakeTimers) mocks Date without touching
    // setTimeout — real timers stay live, so the search-debounce setTimeout
    // and waitFor's own polling still work instead of freezing forever.
    vi.setSystemTime(NOW);
    window.history.pushState({}, '', '/');
});

afterEach(() => {
    vi.useRealTimers();
});

describe('SharingManagementPage — loading / empty / error states', () => {
    it('shows a loading indicator while shares are loading', () => {
        sharesState.isLoading = true;
        render(<SharingManagementPage />);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('shows an error alert and retries on click', () => {
        sharesState.error = new Error('boom');
        render(<SharingManagementPage />);
        expect(screen.getByText('Failed to load shares')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
        expect(refetchMock).toHaveBeenCalled();
    });

    it('shows an empty state with no-filter copy when there are no shares and no filters', () => {
        sharesState.data = makeResponse([]);
        render(<SharingManagementPage />);
        expect(screen.getByText('No shares found')).toBeInTheDocument();
        expect(screen.getByText('No secrets have been shared yet.')).toBeInTheDocument();
    });

    it('shows filtered-empty copy when a filter is active but yields no rows', () => {
        sharesState.data = makeResponse([]);
        render(<SharingManagementPage />);
        const [, permissionSelect] = screen.getAllByRole('combobox');
        fireEvent.change(permissionSelect!, { target: { value: 'write' } });
        expect(screen.getByText('Try adjusting your filters.')).toBeInTheDocument();
    });

    it('renders the empty state without crashing when data is undefined (e.g. before the first successful fetch)', () => {
        sharesState.data = undefined;
        render(<SharingManagementPage />);
        expect(screen.getByText('No shares found')).toBeInTheDocument();
        expect(screen.getByText('No secrets have been shared yet.')).toBeInTheDocument();
    });
});

describe('SharingManagementPage — table rendering', () => {
    it('renders recipient, type, permission, creator, and expiry badge for each share', () => {
        render(<SharingManagementPage />);

        const aliceRow = rowFor('Alice Anderson');
        expect(within(aliceRow).getByText('user')).toBeInTheDocument();
        expect(within(aliceRow).getByText('Read Only')).toBeInTheDocument();
        expect(within(aliceRow).getByText('alice')).toBeInTheDocument();
        expect(within(aliceRow).getByText('Permanent')).toBeInTheDocument();
        expect(within(aliceRow).getByText(/2026/)).toBeInTheDocument();

        const opsRow = rowFor('Ops Group');
        expect(within(opsRow).getByText('group')).toBeInTheDocument();
        expect(within(opsRow).getByText('Update value/metadata, rotate')).toBeInTheDocument();
        expect(within(opsRow).getByText('Expired')).toBeInTheDocument();

        const carolRow = rowFor('Carol Smith');
        expect(within(carolRow).getByText('in 5h')).toBeInTheDocument();
    });

    it('initially queries useShares with only page and pageSize', () => {
        render(<SharingManagementPage />);
        expect(sharesQueryMock).toHaveBeenCalledWith({ page: 1, pageSize: 20 });
    });
});

describe('SharingManagementPage — shareExpiry (pure function)', () => {
    it('renders Permanent for an undefined expiresAt', () => {
        expect(shareExpiry(undefined, NOW.getTime())).toEqual({
            label: 'Permanent',
            className: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
        });
    });

    it('renders Permanent for an unparsable expiresAt (NaN branch)', () => {
        expect(shareExpiry('not-a-real-date', NOW.getTime()).label).toBe('Permanent');
    });

    it('renders Expired for a past timestamp', () => {
        expect(shareExpiry('2026-01-01T00:00:00.000Z', NOW.getTime()).label).toBe('Expired');
    });

    it('renders a minute countdown, flooring to at least 1m', () => {
        const in10Seconds = new Date(NOW.getTime() + 10_000).toISOString();
        expect(shareExpiry(in10Seconds, NOW.getTime()).label).toBe('in 1m');
        const in30Minutes = new Date(NOW.getTime() + 30 * 60_000).toISOString();
        expect(shareExpiry(in30Minutes, NOW.getTime()).label).toBe('in 30m');
    });

    it('renders an hour countdown between 1h and 24h', () => {
        const in2Hours = new Date(NOW.getTime() + 2 * 3_600_000).toISOString();
        expect(shareExpiry(in2Hours, NOW.getTime()).label).toBe('in 2h');
    });

    it('renders a day countdown at 24h or beyond', () => {
        const in3Days = new Date(NOW.getTime() + 3 * 86_400_000).toISOString();
        expect(shareExpiry(in3Days, NOW.getTime()).label).toBe('in 3d');
    });
});

describe('SharingManagementPage — search / filters', () => {
    it('debounces the search box and filters rows client-side after 300ms', async () => {
        render(<SharingManagementPage />);
        fireEvent.change(screen.getByPlaceholderText('Search recipients or creators...'), {
            target: { value: 'alice' },
        });

        // Not yet applied — debounce hasn't elapsed.
        expect(screen.getByText('Ops Group')).toBeInTheDocument();

        await waitFor(() => expect(screen.queryByText('Ops Group')).not.toBeInTheDocument(), { timeout: 1000 });
        expect(screen.getByText('Alice Anderson')).toBeInTheDocument();
        expect(screen.getByText(/Search: alice/)).toBeInTheDocument();
    });

    it('matches search against createdBy as well as recipientName', async () => {
        render(<SharingManagementPage />);
        fireEvent.change(screen.getByPlaceholderText('Search recipients or creators...'), {
            target: { value: 'bob' },
        });
        await waitFor(() => expect(screen.getByText(/Search: bob/)).toBeInTheDocument(), { timeout: 1000 });
        expect(screen.getByText('Ops Group')).toBeInTheDocument();
        expect(screen.queryByText('Alice Anderson')).not.toBeInTheDocument();
    });

    it('sends recipientType to the query and resets to page 1', () => {
        // Start on totalPages > 1 and move off page 1 so the reset is observable.
        sharesState.data = makeResponse(allShares, { total: 45, totalPages: 3 });
        render(<SharingManagementPage />);
        fireEvent.click(screen.getByRole('button', { name: '2' }));

        const [recipientTypeSelect] = screen.getAllByRole('combobox');
        fireEvent.change(recipientTypeSelect!, { target: { value: 'user' } });

        const lastCall = sharesQueryMock.mock.calls.at(-1)![0];
        expect(lastCall).toEqual({ page: 1, pageSize: 20, recipientType: 'user' });
    });

    it('filters by permission client-side without sending it to the query', () => {
        render(<SharingManagementPage />);
        const [, permissionSelect] = screen.getAllByRole('combobox');
        fireEvent.change(permissionSelect!, { target: { value: 'write' } });

        expect(screen.getByText('Ops Group')).toBeInTheDocument();
        expect(screen.queryByText('Alice Anderson')).not.toBeInTheDocument();
        const lastCall = sharesQueryMock.mock.calls.at(-1)![0];
        expect(lastCall).not.toHaveProperty('permission');
        expect(screen.getByText(/Permission: write/)).toBeInTheDocument();
    });

    it('clears all filters via "Clear all"', async () => {
        render(<SharingManagementPage />);
        const [recipientTypeSelect] = screen.getAllByRole('combobox');
        fireEvent.change(recipientTypeSelect!, { target: { value: 'user' } });
        expect(screen.getByText(/Type: user/)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
        expect(screen.queryByText(/Type: user/)).not.toBeInTheDocument();
        expect(screen.getByPlaceholderText('Search recipients or creators...')).toHaveValue('');
    });
});

describe('SharingManagementPage — pagination', () => {
    it('shows the results summary and page buttons, disabling Previous on page 1', () => {
        sharesState.data = makeResponse(allShares, { total: 45, totalPages: 3 });
        render(<SharingManagementPage />);

        expect(screen.getByText(/Showing/)).toBeInTheDocument();
        expect(screen.getByText('45')).toBeInTheDocument();
        const prevButtons = screen.getAllByRole('button', { name: 'Previous' });
        expect(prevButtons[0]).toBeDisabled();
    });

    it('advances to the next page and queries with the new page number', () => {
        sharesState.data = makeResponse(allShares, { total: 45, totalPages: 3 });
        render(<SharingManagementPage />);

        const nextButtons = screen.getAllByRole('button', { name: 'Next' });
        fireEvent.click(nextButtons[0]!);

        const lastCall = sharesQueryMock.mock.calls.at(-1)![0];
        expect(lastCall).toEqual({ page: 2, pageSize: 20 });
    });

    it('jumps to a specific page number', () => {
        sharesState.data = makeResponse(allShares, { total: 45, totalPages: 3 });
        render(<SharingManagementPage />);

        fireEvent.click(screen.getByRole('button', { name: '3' }));
        const lastCall = sharesQueryMock.mock.calls.at(-1)![0];
        expect(lastCall).toEqual({ page: 3, pageSize: 20 });
    });

    it('moves back a page via both the mobile and desktop Previous buttons, and forward via the desktop Next button', () => {
        sharesState.data = makeResponse(allShares, { total: 45, totalPages: 3 });
        render(<SharingManagementPage />);

        fireEvent.click(screen.getByRole('button', { name: '2' }));
        expect(sharesQueryMock.mock.calls.at(-1)![0]).toEqual({ page: 2, pageSize: 20 });

        const prevButtons = screen.getAllByRole('button', { name: 'Previous' });
        fireEvent.click(prevButtons[0]!); // mobile Previous
        expect(sharesQueryMock.mock.calls.at(-1)![0]).toEqual({ page: 1, pageSize: 20 });

        fireEvent.click(screen.getByRole('button', { name: '2' }));
        fireEvent.click(prevButtons[1]!); // desktop Previous
        expect(sharesQueryMock.mock.calls.at(-1)![0]).toEqual({ page: 1, pageSize: 20 });

        const nextButtons = screen.getAllByRole('button', { name: 'Next' });
        fireEvent.click(nextButtons[1]!); // desktop Next
        expect(sharesQueryMock.mock.calls.at(-1)![0]).toEqual({ page: 2, pageSize: 20 });
    });

    it('does not render pagination controls for a single page', () => {
        render(<SharingManagementPage />);
        expect(screen.queryByRole('button', { name: 'Next' })).not.toBeInTheDocument();
    });
});

describe('SharingManagementPage — bulk selection and bulk revoke', () => {
    it('tracks selection via per-row checkboxes and shows a running count', () => {
        render(<SharingManagementPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Select' }));

        const aliceCheckbox = within(rowFor('Alice Anderson')).getByRole('checkbox');
        fireEvent.click(aliceCheckbox);
        expect(screen.getByText('1 selected')).toBeInTheDocument();
    });

    it('selects and clears all rows via the header checkbox', () => {
        render(<SharingManagementPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Select' }));

        const headerCheckbox = screen.getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox);
        expect(screen.getByText('3 selected')).toBeInTheDocument();

        fireEvent.click(headerCheckbox);
        expect(screen.getByText('0 selected')).toBeInTheDocument();
    });

    it('Cancel exits bulk mode and clears the selection', () => {
        render(<SharingManagementPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Select' }));
        fireEvent.click(within(rowFor('Alice Anderson')).getByRole('checkbox'));
        expect(screen.getByText('1 selected')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
    });

    it('opens the confirm dialog for bulk revoke; confirming triggers the bulk mutation and closes on success', () => {
        render(<SharingManagementPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Select' }));
        fireEvent.click(within(rowFor('Alice Anderson')).getByRole('checkbox'));
        fireEvent.click(within(rowFor('Carol Smith')).getByRole('checkbox'));

        fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));

        expect(openModalMock).toHaveBeenCalledWith(
            'confirm-delete',
            expect.objectContaining({
                title: 'Delete Multiple Shares',
                message: 'Are you sure you want to revoke 2 share(s)?',
                onConfirm: expect.any(Function),
            })
        );

        const dialog = screen.getByRole('dialog');
        // Modal also renders an sr-only <h2> with the same text for the dialog's
        // accessible name (Dialog.tsx passes hideTitleVisually) — scope to the
        // visible <h3> Dialog.tsx itself renders, not just any matching text.
        expect(within(dialog).getByRole('heading', { level: 3, name: 'Delete Multiple Shares' })).toBeInTheDocument();
        expect(within(dialog).getByText('Are you sure you want to revoke 2 share(s)?')).toBeInTheDocument();

        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        expect(bulkDeleteMutate).toHaveBeenCalledWith(
            [1, 3],
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );

        // Simulate the mutation's onSuccess: selection clears, bulk mode exits, dialog closes.
        const { onSuccess } = bulkDeleteMutate.mock.calls[0]![1];
        act(() => onSuccess());
        expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('toggles a row checkbox off again on a second click', () => {
        render(<SharingManagementPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Select' }));

        const aliceCheckbox = within(rowFor('Alice Anderson')).getByRole('checkbox');
        fireEvent.click(aliceCheckbox);
        expect(screen.getByText('1 selected')).toBeInTheDocument();

        fireEvent.click(aliceCheckbox);
        expect(screen.getByText('0 selected')).toBeInTheDocument();
    });

    it('the Revoke bulk action is disabled with nothing selected', () => {
        render(<SharingManagementPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Select' }));
        expect(screen.getByRole('button', { name: 'Revoke' })).toBeDisabled();
        expect(screen.getByText('0 selected')).toBeInTheDocument();
    });
});

describe('SharingManagementPage — per-row actions', () => {
    it('View secret opens the view-secret modal request', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('View secret'));
        expect(openModalMock).toHaveBeenCalledWith('view-secret', { secretId: 101 });
    });

    it('Revoke access opens the confirm dialog; confirming deletes the share and closes on success', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Revoke access'));

        expect(openModalMock).toHaveBeenCalledWith(
            'confirm-delete',
            expect.objectContaining({
                title: 'Delete Share',
                message: 'Are you sure you want to revoke access for "Alice Anderson"?',
                onConfirm: expect.any(Function),
            })
        );

        const dialog = screen.getByRole('dialog');
        // Modal also renders an sr-only <h2> with the same text for the dialog's
        // accessible name (Dialog.tsx passes hideTitleVisually) — scope to the
        // visible <h3> Dialog.tsx itself renders, not just any matching text.
        expect(within(dialog).getByRole('heading', { level: 3, name: 'Delete Share' })).toBeInTheDocument();
        expect(
            within(dialog).getByText('Are you sure you want to revoke access for "Alice Anderson"?')
        ).toBeInTheDocument();

        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        expect(deleteMutate).toHaveBeenCalledWith(1, expect.objectContaining({ onSuccess: expect.any(Function) }));

        // Simulate the mutation's onSuccess: the dialog closes.
        const { onSuccess } = deleteMutate.mock.calls[0]![1];
        act(() => onSuccess());
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('cancelling the confirm dialog closes it without deleting', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Revoke access'));

        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

        expect(closeModalMock).toHaveBeenCalled();
        expect(deleteMutate).not.toHaveBeenCalled();
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
});

describe('SharingManagementPage — edit share modal', () => {
    it('opens pre-filled with the target share\'s permission and a "keep current" expiry', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Ops Group')).getByTitle('Edit permissions'));

        expect(screen.getByText('Edit share — Ops Group')).toBeInTheDocument();
        expect(screen.getByLabelText('Permission')).toHaveValue('write');
        expect(screen.getByLabelText('Access expires')).toHaveValue('keep');
    });

    it('shows current-expiry copy only when the share has one and "keep" is selected', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Ops Group')).getByTitle('Edit permissions'));
        expect(screen.getByText(/Currently expires/)).toBeInTheDocument();

        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));
        expect(screen.queryByText(/Currently expires/)).not.toBeInTheDocument();
    });

    it('resets the form fields when switching between shares', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));
        fireEvent.change(screen.getByLabelText('Permission'), { target: { value: 'write' } });
        fireEvent.change(screen.getByLabelText('Access expires'), { target: { value: '24h' } });

        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        fireEvent.click(within(rowFor('Carol Smith')).getByTitle('Edit permissions'));

        expect(screen.getByLabelText('Permission')).toHaveValue('read');
        expect(screen.getByLabelText('Access expires')).toHaveValue('keep');
    });

    it('Cancel closes the modal without submitting', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        expect(closeModalMock).toHaveBeenCalled();
        expect(updateMutate).not.toHaveBeenCalled();
        expect(screen.queryByText('Edit share — Alice Anderson')).not.toBeInTheDocument();
    });

    it('submits {id, permission} only when expiry is left at "keep"', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));
        fireEvent.change(screen.getByLabelText('Permission'), { target: { value: 'write' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));

        expect(updateMutate).toHaveBeenCalledWith(
            { id: 1, permission: 'write' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('submits clearExpiry:true when "No expiry (permanent)" is chosen', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Ops Group')).getByTitle('Edit permissions'));
        fireEvent.change(screen.getByLabelText('Access expires'), { target: { value: 'clear' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));

        expect(updateMutate).toHaveBeenCalledWith(
            { id: 2, permission: 'write', clearExpiry: true },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('submits expiresAt resolved from a duration preset', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));
        fireEvent.change(screen.getByLabelText('Access expires'), { target: { value: '24h' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));

        expect(expiresAtFromPresetMock).toHaveBeenCalledWith('24h');
        expect(updateMutate).toHaveBeenCalledWith(
            { id: 1, permission: 'read', expiresAt: 'iso-24h' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('omits expiresAt from the mutation payload when expiresAtFromPreset resolves to a falsy value', () => {
        expiresAtFromPresetMock.mockImplementationOnce(() => undefined);
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));
        fireEvent.change(screen.getByLabelText('Access expires'), { target: { value: '24h' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));

        expect(expiresAtFromPresetMock).toHaveBeenCalledWith('24h');
        expect(updateMutate).toHaveBeenCalledWith(
            { id: 1, permission: 'read' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('closes the modal and refetches on a successful update', () => {
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));

        const { onSuccess } = updateMutate.mock.calls[0]![1];
        act(() => onSuccess());

        expect(closeModalMock).toHaveBeenCalled();
        expect(refetchMock).toHaveBeenCalled();
        expect(screen.queryByText('Edit share — Alice Anderson')).not.toBeInTheDocument();
    });

    it('shows the mutation error message, falling back to a generic one for non-Error values', () => {
        mutationState.update = { isPending: false, isError: true, error: new Error('permission update failed') };
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));
        expect(screen.getByText('permission update failed')).toBeInTheDocument();
    });

    it('falls back to a generic error message when the error is not an Error instance', () => {
        mutationState.update = { isPending: false, isError: true, error: 'oops' };
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));
        expect(screen.getByText('Failed to update share.')).toBeInTheDocument();
    });

    it('disables the form and shows "Saving…" while the update is pending', () => {
        mutationState.update = { isPending: true, isError: false, error: null };
        render(<SharingManagementPage />);
        fireEvent.click(within(rowFor('Alice Anderson')).getByTitle('Edit permissions'));

        expect(screen.getByLabelText('Permission')).toBeDisabled();
        expect(screen.getByLabelText('Access expires')).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    });
});
