import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderHook, waitFor } from '@testing-library/react';
import {
    useShares,
    useDeleteShare,
    useBulkDeleteShares,
    useUpdateShare,
    useCreateShare,
    useShareSecret,
    searchRecipients,
} from '../api';
import { queryClient as realQueryClient, queryKeys } from '../../../lib/queryClient';
import { ShareRecord, ShareFormData } from '../../../types';

// sharingApi is mocked so these tests exercise only api.ts's own React Query
// wiring (query keys, service-call args, cache invalidation) — not the HTTP
// layer, which is covered separately in src/services/__tests__/sharing.test.ts.
const { listMock, createMock, updateMock, deleteMock } = vi.hoisted(() => ({
    listMock: vi.fn(),
    createMock: vi.fn(),
    updateMock: vi.fn(),
    deleteMock: vi.fn(),
}));

vi.mock('../../../services/sharing', () => ({
    sharingApi: {
        listForManagement: listMock,
        create: createMock,
        update: updateMock,
        delete: deleteMock,
    },
}));

const { searchMock } = vi.hoisted(() => ({
    searchMock: vi.fn(),
}));

vi.mock('../../../services/users', () => ({
    usersApi: {
        search: searchMock,
    },
}));

function createWrapper() {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    return function Wrapper({ children }: { children: React.ReactNode }) {
        return React.createElement(QueryClientProvider, { client }, children);
    };
}

const share: ShareRecord = {
    id: 1,
    secretId: 42,
    recipientType: 'user',
    recipientId: 7,
    recipientName: 'bob',
    permission: 'read',
    createdAt: '2026-06-01T00:00:00.000Z',
    createdBy: 'alice',
};

const paginated = (items: ShareRecord[]) => ({
    data: items,
    total: items.length,
    page: 1,
    pageSize: 20,
    totalPages: 1,
});

// invalidateQueries.sharing.all()/secrets.all() (src/lib/queryClient.ts) close over
// the module-level `queryClient` singleton rather than whatever client wraps the
// hook under test, so cache-invalidation assertions must spy on that real
// singleton — spying on a locally constructed QueryClient would never see the calls.
describe('features/sharing/api', () => {
    let invalidateSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        listMock.mockReset();
        createMock.mockReset();
        updateMock.mockReset();
        deleteMock.mockReset();
        searchMock.mockReset();
        invalidateSpy = vi.spyOn(realQueryClient, 'invalidateQueries').mockResolvedValue(undefined);
    });

    afterEach(() => {
        invalidateSpy.mockRestore();
    });

    describe('useShares', () => {
        it('transitions from loading to success and returns the service data', async () => {
            listMock.mockResolvedValue(paginated([share]));

            const { result } = renderHook(() => useShares({ secretId: 42 }), { wrapper: createWrapper() });

            expect(result.current.isLoading).toBe(true);

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(result.current.data).toEqual(paginated([share]));
        });

        it('calls sharingApi.listForManagement with the given params', async () => {
            listMock.mockResolvedValue(paginated([]));

            const params = { page: 2, pageSize: 10, secretId: 42, recipientType: 'user' as const };
            const { result } = renderHook(() => useShares(params), { wrapper: createWrapper() });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(listMock).toHaveBeenCalledWith(params);
            expect(listMock).toHaveBeenCalledTimes(1);
        });

        it('calls sharingApi.listForManagement with undefined when no params are given', async () => {
            listMock.mockResolvedValue(paginated([]));

            const { result } = renderHook(() => useShares(), { wrapper: createWrapper() });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(listMock).toHaveBeenCalledWith(undefined);
        });

        it('keys the query on queryKeys.sharing.list(params) so distinct params get distinct cache entries', async () => {
            listMock.mockResolvedValueOnce(paginated([share])).mockResolvedValueOnce(paginated([]));

            const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
            const wrapper = ({ children }: { children: React.ReactNode }) =>
                React.createElement(QueryClientProvider, { client }, children);

            const paramsA = { secretId: 1 };
            const paramsB = { secretId: 2 };

            const { result: resultA } = renderHook(() => useShares(paramsA), { wrapper });
            await waitFor(() => expect(resultA.current.isSuccess).toBe(true));

            const { result: resultB } = renderHook(() => useShares(paramsB), { wrapper });
            await waitFor(() => expect(resultB.current.isSuccess).toBe(true));

            // Two distinct entries in the cache, one per queryKeys.sharing.list(params).
            expect(client.getQueryData(queryKeys.sharing.list(paramsA))).toEqual(paginated([share]));
            expect(client.getQueryData(queryKeys.sharing.list(paramsB))).toEqual(paginated([]));
            expect(listMock).toHaveBeenCalledTimes(2);
        });

        it('keeps the previous page of data visible (placeholderData) while refetching for new params', async () => {
            let resolveSecond: (value: unknown) => void = () => {};
            listMock.mockResolvedValueOnce(paginated([share])).mockImplementationOnce(
                () =>
                    new Promise((resolve) => {
                        resolveSecond = resolve;
                    })
            );

            const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
            const wrapper = ({ children }: { children: React.ReactNode }) =>
                React.createElement(QueryClientProvider, { client }, children);

            const { result, rerender } = renderHook(({ page }: { page: number }) => useShares({ page }), {
                wrapper,
                initialProps: { page: 1 },
            });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));
            expect(result.current.data).toEqual(paginated([share]));

            rerender({ page: 2 });

            // A new query is in flight for page 2, but keepPreviousData means the
            // page-1 data is still what the hook returns while it fetches.
            await waitFor(() => expect(result.current.isFetching).toBe(true));
            expect(result.current.data).toEqual(paginated([share]));
            expect(result.current.isPlaceholderData).toBe(true);

            resolveSecond(paginated([]));
            await waitFor(() => expect(result.current.isPlaceholderData).toBe(false));
            expect(result.current.data).toEqual(paginated([]));
        });
    });

    describe('useDeleteShare', () => {
        it('calls sharingApi.delete with the share id and invalidates sharing + secrets caches', async () => {
            deleteMock.mockResolvedValue(undefined);

            const { result } = renderHook(() => useDeleteShare(), { wrapper: createWrapper() });

            result.current.mutate(1);

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(deleteMock).toHaveBeenCalledWith(1);
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.sharing.all });
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        });

        it('does not invalidate anything when the delete call fails', async () => {
            deleteMock.mockRejectedValue(new Error('boom'));

            const { result } = renderHook(() => useDeleteShare(), { wrapper: createWrapper() });

            result.current.mutate(1);

            await waitFor(() => expect(result.current.isError).toBe(true));

            expect(invalidateSpy).not.toHaveBeenCalled();
        });
    });

    describe('useBulkDeleteShares', () => {
        it('calls sharingApi.delete for every id and resolves with the id list', async () => {
            deleteMock.mockResolvedValue(undefined);

            const { result } = renderHook(() => useBulkDeleteShares(), { wrapper: createWrapper() });

            result.current.mutate([1, 2, 3]);

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(deleteMock).toHaveBeenCalledTimes(3);
            expect(deleteMock).toHaveBeenNthCalledWith(1, 1);
            expect(deleteMock).toHaveBeenNthCalledWith(2, 2);
            expect(deleteMock).toHaveBeenNthCalledWith(3, 3);
            expect(result.current.data).toEqual([1, 2, 3]);
        });

        it('invalidates sharing + secrets caches on success', async () => {
            deleteMock.mockResolvedValue(undefined);

            const { result } = renderHook(() => useBulkDeleteShares(), { wrapper: createWrapper() });

            result.current.mutate([5]);

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.sharing.all });
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        });
    });

    describe('useUpdateShare', () => {
        it('sends only the permission when neither expiry field is set', async () => {
            updateMock.mockResolvedValue(share);

            const { result } = renderHook(() => useUpdateShare(), { wrapper: createWrapper() });

            result.current.mutate({ id: 1, permission: 'write' });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(updateMock).toHaveBeenCalledWith(1, { permission: 'write' });
        });

        it('forwards expiresAt when provided', async () => {
            updateMock.mockResolvedValue(share);
            const iso = '2026-08-01T00:00:00.000Z';

            const { result } = renderHook(() => useUpdateShare(), { wrapper: createWrapper() });

            result.current.mutate({ id: 1, permission: 'read', expiresAt: iso });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(updateMock).toHaveBeenCalledWith(1, { permission: 'read', expiresAt: iso });
        });

        it('forwards clearExpiry when set', async () => {
            updateMock.mockResolvedValue(share);

            const { result } = renderHook(() => useUpdateShare(), { wrapper: createWrapper() });

            result.current.mutate({ id: 1, permission: 'read', clearExpiry: true });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(updateMock).toHaveBeenCalledWith(1, { permission: 'read', clearExpiry: true });
        });

        it('omits a falsy clearExpiry rather than sending clearExpiry: false', async () => {
            updateMock.mockResolvedValue(share);

            const { result } = renderHook(() => useUpdateShare(), { wrapper: createWrapper() });

            result.current.mutate({ id: 1, permission: 'read', clearExpiry: false });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            // clearExpiry is spread in only when truthy, so `false` is dropped entirely.
            expect(updateMock).toHaveBeenCalledWith(1, { permission: 'read' });
        });

        it('invalidates sharing + secrets caches on success', async () => {
            updateMock.mockResolvedValue(share);

            const { result } = renderHook(() => useUpdateShare(), { wrapper: createWrapper() });

            result.current.mutate({ id: 1, permission: 'read' });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.sharing.all });
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        });
    });

    describe('useCreateShare', () => {
        it('passes the form data straight through to sharingApi.create', async () => {
            createMock.mockResolvedValue(share);

            const data: ShareFormData & { secretId: number } = {
                secretId: 42,
                recipientType: 'user',
                recipientId: 7,
                permission: 'read',
            };

            const { result } = renderHook(() => useCreateShare(), { wrapper: createWrapper() });

            result.current.mutate(data);

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(createMock).toHaveBeenCalledWith(data);
        });

        it('invalidates sharing + secrets caches on success', async () => {
            createMock.mockResolvedValue(share);

            const { result } = renderHook(() => useCreateShare(), { wrapper: createWrapper() });

            result.current.mutate({
                secretId: 42,
                recipientType: 'group',
                recipientId: 3,
                permission: 'write',
            });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.sharing.all });
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        });
    });

    describe('searchRecipients', () => {
        it('is a thin pass-through to usersApi.search', async () => {
            const recipients = [{ id: 1, name: 'bob', type: 'user' as const, email: 'bob@test.com' }];
            searchMock.mockResolvedValue(recipients);

            const result = await searchRecipients('bo');

            expect(searchMock).toHaveBeenCalledWith('bo');
            expect(result).toBe(recipients);
        });
    });

    describe('useShareSecret', () => {
        it('searches by username, matches case-insensitively, and creates the share', async () => {
            searchMock.mockResolvedValue([
                { id: 7, name: 'Bob', type: 'user' as const, email: 'bob@test.com' },
                { id: 8, name: 'carol', type: 'user' as const, email: 'carol@test.com' },
            ]);
            createMock.mockResolvedValue(share);

            const { result } = renderHook(() => useShareSecret(42), { wrapper: createWrapper() });

            result.current.mutate({ username: '  BOB  ', permission: 'read' });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(searchMock).toHaveBeenCalledWith('BOB');
            expect(createMock).toHaveBeenCalledWith({
                secretId: 42,
                recipientType: 'user',
                recipientId: 7,
                permission: 'read',
            });
        });

        it('forwards expiresAt to sharingApi.create when provided', async () => {
            searchMock.mockResolvedValue([{ id: 7, name: 'bob', type: 'user' as const, email: 'bob@test.com' }]);
            createMock.mockResolvedValue(share);
            const iso = '2026-08-02T00:00:00.000Z';

            const { result } = renderHook(() => useShareSecret(42), { wrapper: createWrapper() });

            result.current.mutate({ username: 'bob', permission: 'write', expiresAt: iso });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(createMock).toHaveBeenCalledWith({
                secretId: 42,
                recipientType: 'user',
                recipientId: 7,
                permission: 'write',
                expiresAt: iso,
            });
        });

        it('rejects with a not-found error and never calls create when no user matches', async () => {
            searchMock.mockResolvedValue([{ id: 7, name: 'bob', type: 'user' as const, email: 'bob@test.com' }]);

            const { result } = renderHook(() => useShareSecret(42), { wrapper: createWrapper() });

            result.current.mutate({ username: 'nobody', permission: 'read' });

            await waitFor(() => expect(result.current.isError).toBe(true));

            expect(result.current.error).toEqual(new Error('User "nobody" not found.'));
            expect(createMock).not.toHaveBeenCalled();
            expect(invalidateSpy).not.toHaveBeenCalled();
        });

        it('invalidates sharing + secrets caches on success', async () => {
            searchMock.mockResolvedValue([{ id: 7, name: 'bob', type: 'user' as const, email: 'bob@test.com' }]);
            createMock.mockResolvedValue(share);

            const { result } = renderHook(() => useShareSecret(42), { wrapper: createWrapper() });

            result.current.mutate({ username: 'bob', permission: 'read' });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.sharing.all });
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        });

        // Regression test for the id-pinning fix: the recipient id captured at
        // dropdown-selection time must be used as-is, never re-derived from a
        // fresh username search at submit time. Without the fix, if the
        // username-to-id mapping changed between selection and submit (a
        // rename, or a different account claiming the same username), the
        // share would silently land on whoever the re-search happens to
        // match instead of the account the sharer actually picked.
        it('uses the recipientId captured at selection time and never re-resolves by username, even if a fresh search would return a different account', async () => {
            // If the (buggy) re-search path ran, it would resolve to id 99 —
            // a different account than the one originally selected (id 7).
            searchMock.mockResolvedValue([{ id: 99, name: 'bob', type: 'user' as const, email: 'impostor@test.com' }]);
            createMock.mockResolvedValue(share);

            const { result } = renderHook(() => useShareSecret(42), { wrapper: createWrapper() });

            // Selecting 'bob' (id=7) from the autocomplete dropdown, then submitting.
            result.current.mutate({ username: 'bob', recipientId: 7, permission: 'read' });

            await waitFor(() => expect(result.current.isSuccess).toBe(true));

            expect(createMock).toHaveBeenCalledWith({
                secretId: 42,
                recipientType: 'user',
                recipientId: 7,
                permission: 'read',
            });
            // The id was supplied, so no re-resolution by username should ever occur.
            expect(searchMock).not.toHaveBeenCalled();
        });
    });
});
