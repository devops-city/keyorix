import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AxiosError, AxiosHeaders } from 'axios';
import { BREAK_GLASS_KEYS, useBreakGlassActivations } from '../breakGlass';

const { listMock, authState } = vi.hoisted(() => ({
    listMock: vi.fn(),
    authState: { user: { id: 1 } as { id: number } | null },
}));

vi.mock('../../../services/breakGlass', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../services/breakGlass')>();
    return { ...actual, breakGlassApi: { list: listMock, activate: vi.fn(), revoke: vi.fn() } };
});
vi.mock('../../auth/api', () => ({ useAuth: () => authState }));

const makeWrapper = (client: QueryClient) => {
    const Wrapper = ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
    return Wrapper;
};

beforeEach(() => {
    vi.clearAllMocks();
    authState.user = { id: 1 };
});

describe('useBreakGlassActivations', () => {
    it('never serves one user’s cached list to the next user on the same browser', async () => {
        const client = new QueryClient();
        listMock.mockResolvedValueOnce({
            scope: 'project',
            activations: [{ id: 1, userId: 3, justification: 'admin-only text' }],
        });
        const first = renderHook(() => useBreakGlassActivations(5), { wrapper: makeWrapper(client) });
        await waitFor(() => expect(first.result.current.data?.scope).toBe('project'));
        first.unmount();

        // Nothing is kept for an unobserved key (the justification text is sensitive)...
        await waitFor(() => expect(client.getQueryCache().findAll({ queryKey: BREAK_GLASS_KEYS.all })).toHaveLength(0));

        // ...and the next account gets its own fetch, under its own key.
        authState.user = { id: 2 };
        listMock.mockResolvedValueOnce({ scope: 'own', activations: [] });
        const second = renderHook(() => useBreakGlassActivations(5), { wrapper: makeWrapper(client) });
        await waitFor(() => expect(second.result.current.data?.scope).toBe('own'));
        expect(listMock).toHaveBeenCalledTimes(2);
        expect(second.result.current.data?.activations).toEqual([]);
    });

    it('keys the cache by user even while the first user’s entry is still observed', () => {
        expect(BREAK_GLASS_KEYS.list(5, 1)).not.toEqual(BREAK_GLASS_KEYS.list(5, 2));
    });

    it('does not fetch without a signed-in user', () => {
        authState.user = null;
        const client = new QueryClient();
        renderHook(() => useBreakGlassActivations(5), { wrapper: makeWrapper(client) });
        expect(listMock).not.toHaveBeenCalled();
    });

    it('does not retry a 403 refusal', async () => {
        const client = new QueryClient();
        listMock.mockRejectedValue(
            new AxiosError('Request failed', 'ERR_BAD_REQUEST', undefined, undefined, {
                status: 403,
                statusText: '',
                data: { error: 'Forbidden' },
                headers: {},
                config: { headers: new AxiosHeaders() },
            })
        );
        const { result } = renderHook(() => useBreakGlassActivations(5), { wrapper: makeWrapper(client) });
        await waitFor(() => expect(result.current.isError).toBe(true));
        expect(listMock).toHaveBeenCalledTimes(1);
    });
});
