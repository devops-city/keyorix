import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/secrets', () => ({
    secretsApi: {
        list: vi.fn(),
        get: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        getVersions: vi.fn(),
        getValue: vi.fn(),
        rotate: vi.fn(),
        rollback: vi.fn(),
        transferOwnership: vi.fn(),
        suspend: vi.fn(),
        resume: vi.fn(),
        accessList: vi.fn(),
        accessLog: vi.fn(),
        auditTrail: vi.fn(),
        description: vi.fn(),
        setDescription: vi.fn(),
        policy: vi.fn(),
        copy: vi.fn(),
        tags: vi.fn(),
        setTags: vi.fn(),
        risk: vi.fn(),
        classify: vi.fn(),
        setAutoRotate: vi.fn(),
        dependencies: vi.fn(),
        addDependency: vi.fn(),
        removeDependency: vi.fn(),
        certificate: vi.fn(),
        impact: vi.fn(),
    },
}));

import { secretsApi } from '../../../services/secrets';
import { queryClient, queryKeys } from '../../../lib/queryClient';
import {
    useSecrets,
    useSecret,
    useSecretVersions,
    useSecretValue,
    useCreateSecret,
    useUpdateSecret,
    useSecretRisk,
    useRotateSecret,
    useRollbackSecret,
    useSecretAccessors,
    useSecretAccessLog,
    useSecretAuditTrail,
    useSecretPolicy,
    useCopySecret,
    useSecretDescription,
    useSetSecretDescription,
    useSecretTags,
    useSetSecretTags,
    useSecretDependencies,
    useSecretImpact,
    useSecretCertificate,
    useAddSecretDependency,
    useRemoveSecretDependency,
    useSuspendSecret,
    useResumeSecret,
    useTransferOwnership,
    useClassifySecret,
    useSetAutoRotate,
    useDeleteSecret,
    useBulkClassifySecrets,
    useBulkDeleteSecrets,
    useDuplicateSecret,
    useSearchSecrets,
    useSecretStats,
    usePrefetchSecret,
    useOptimisticSecretUpdate,
} from '../api';

const mock = secretsApi as unknown as Record<string, ReturnType<typeof vi.fn>>;

const wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: queryClient }, children);

beforeEach(() => {
    vi.clearAllMocks();
    queryClient.clear();
});

afterEach(() => {
    // Safety net: if a fake-timers test fails before it restores real timers,
    // a leaked fake clock freezes waitFor's internal polling in every test
    // that runs after it.
    vi.useRealTimers();
});

// ── plain queries ─────────────────────────────────────────────────────────────

describe('useSecrets', () => {
    it('fetches the secrets list with params', async () => {
        mock.list!.mockResolvedValueOnce({ data: [{ id: 1 }], total: 1 });
        const { result } = renderHook(() => useSecrets({ search: 'db' }), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.list).toHaveBeenCalledWith({ search: 'db' });
    });
});

describe('useSecret', () => {
    it('fetches a secret by id', async () => {
        mock.get!.mockResolvedValueOnce({ id: 1, name: 'db-password' });
        const { result } = renderHook(() => useSecret(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.get).toHaveBeenCalledWith(1);
    });

    it('does not fetch when disabled', async () => {
        renderHook(() => useSecret(1, false), { wrapper });
        await act(async () => {});
        expect(mock.get).not.toHaveBeenCalled();
    });
});

describe('useSecretVersions', () => {
    it('fetches versions for a secret', async () => {
        mock.getVersions!.mockResolvedValueOnce([{ VersionNumber: 1 }]);
        const { result } = renderHook(() => useSecretVersions(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.getVersions).toHaveBeenCalledWith(1);
    });
});

// #2450: useSecretValue (GET /secrets/{id}?include_value=true via
// secretsApi.getValue) is the ONLY source of the actual plaintext --
// useSecretVersions, above, never carries a value field.
describe('useSecretValue', () => {
    it('fetches the current plaintext value for a secret', async () => {
        mock.getValue!.mockResolvedValueOnce('sup3r-secret');
        const { result } = renderHook(() => useSecretValue(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.getValue).toHaveBeenCalledWith(1);
        expect(result.current.data).toBe('sup3r-secret');
    });

    it('does not fetch when disabled', async () => {
        renderHook(() => useSecretValue(1, false), { wrapper });
        await act(async () => {});
        expect(mock.getValue).not.toHaveBeenCalled();
    });
});

describe('useSecretRisk', () => {
    it('fetches the risk score', async () => {
        mock.risk!.mockResolvedValueOnce({ score: 42, band: 'medium', factors: [] });
        const { result } = renderHook(() => useSecretRisk(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.risk).toHaveBeenCalledWith(1);
    });
});

describe('useSecretAccessors', () => {
    it('fetches the accessors list', async () => {
        mock.accessList!.mockResolvedValueOnce([{ user_id: 1 }]);
        const { result } = renderHook(() => useSecretAccessors(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.accessList).toHaveBeenCalledWith(1);
    });
});

describe('useSecretAccessLog', () => {
    it('defaults to a 30-day window', async () => {
        mock.accessLog!.mockResolvedValueOnce([]);
        const { result } = renderHook(() => useSecretAccessLog(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.accessLog).toHaveBeenCalledWith(1, 30);
    });

    it('forwards an explicit day window', async () => {
        mock.accessLog!.mockResolvedValueOnce([]);
        const { result } = renderHook(() => useSecretAccessLog(1, 7), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.accessLog).toHaveBeenCalledWith(1, 7);
    });
});

describe('useSecretAuditTrail', () => {
    it('defaults to a limit of 50', async () => {
        mock.auditTrail!.mockResolvedValueOnce([]);
        const { result } = renderHook(() => useSecretAuditTrail(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.auditTrail).toHaveBeenCalledWith(1, 50);
    });
});

describe('useSecretPolicy', () => {
    it('fetches the active create-time policy', async () => {
        mock.policy!.mockResolvedValueOnce({ min_length: 8 });
        const { result } = renderHook(() => useSecretPolicy(), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.policy).toHaveBeenCalled();
    });
});

describe('useSecretDescription', () => {
    it('fetches the description', async () => {
        mock.description!.mockResolvedValueOnce('prod db password');
        const { result } = renderHook(() => useSecretDescription(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.description).toHaveBeenCalledWith(1);
    });
});

describe('useSecretTags', () => {
    it('fetches the tags', async () => {
        mock.tags!.mockResolvedValueOnce(['prod', 'db']);
        const { result } = renderHook(() => useSecretTags(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.tags).toHaveBeenCalledWith(1);
    });
});

describe('useSecretDependencies / useSecretImpact / useSecretCertificate', () => {
    it('fetches dependencies', async () => {
        mock.dependencies!.mockResolvedValueOnce({ dependsOn: [], dependents: [] });
        const { result } = renderHook(() => useSecretDependencies(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.dependencies).toHaveBeenCalledWith(1);
    });

    it('fetches impact', async () => {
        mock.impact!.mockResolvedValueOnce({ dependents: [] });
        const { result } = renderHook(() => useSecretImpact(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.impact).toHaveBeenCalledWith(1);
    });

    it('fetches certificate metadata', async () => {
        mock.certificate!.mockResolvedValueOnce({ subject: 'CN=example.com' });
        const { result } = renderHook(() => useSecretCertificate(1), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.certificate).toHaveBeenCalledWith(1);
    });
});

// ── mutations with cache effects ────────────────────────────────────────────

describe('useCreateSecret', () => {
    it('creates a secret, invalidates the secrets cache, and seeds the detail cache', async () => {
        const created = { id: 9, name: 'new-secret' };
        mock.create!.mockResolvedValueOnce(created);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const setSpy = vi.spyOn(queryClient, 'setQueryData');
        const { result } = renderHook(() => useCreateSecret(), { wrapper });

        act(() => {
            result.current.mutate({ name: 'new-secret', value: 'v', type: 'text', environment: 'prod' } as any);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        expect(setSpy).toHaveBeenCalledWith(queryKeys.secrets.detail(9), created);
    });
});

describe('useUpdateSecret', () => {
    it('updates a secret, seeds its detail cache, and invalidates the lists', async () => {
        const updated = { id: 1, name: 'renamed' };
        mock.update!.mockResolvedValueOnce(updated);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const setSpy = vi.spyOn(queryClient, 'setQueryData');
        const { result } = renderHook(() => useUpdateSecret(1), { wrapper });

        act(() => {
            result.current.mutate({ name: 'renamed' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.update).toHaveBeenCalledWith(1, { name: 'renamed' });
        expect(setSpy).toHaveBeenCalledWith(queryKeys.secrets.detail(1), updated);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.lists() });
    });
});

describe('useRotateSecret', () => {
    it('rotates the value and invalidates versions, detail, and lists', async () => {
        mock.rotate!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRotateSecret(1), { wrapper });

        act(() => {
            result.current.mutate('new-value');
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.rotate).toHaveBeenCalledWith(1, 'new-value');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.versions(1) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.lists() });
    });
});

describe('useRollbackSecret', () => {
    it('rolls back to a version and invalidates versions, detail, and lists', async () => {
        mock.rollback!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRollbackSecret(1), { wrapper });

        act(() => {
            result.current.mutate(2);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.rollback).toHaveBeenCalledWith(1, 2);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.versions(1) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
    });
});

describe('useCopySecret', () => {
    it('copies to another environment and invalidates the lists', async () => {
        mock.copy!.mockResolvedValueOnce({ id: 2 });
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useCopySecret(1), { wrapper });

        act(() => {
            result.current.mutate({ environmentId: 3, name: 'copy-name' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.copy).toHaveBeenCalledWith(1, 3, 'copy-name');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.lists() });
    });
});

describe('useSetSecretDescription', () => {
    it('sets the description and invalidates the detail cache', async () => {
        mock.setDescription!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useSetSecretDescription(1), { wrapper });

        act(() => {
            result.current.mutate('new description');
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.setDescription).toHaveBeenCalledWith(1, 'new description');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
    });
});

describe('useSetSecretTags', () => {
    it('sets tags and invalidates the detail cache', async () => {
        mock.setTags!.mockResolvedValueOnce(['a', 'b']);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useSetSecretTags(1), { wrapper });

        act(() => {
            result.current.mutate(['a', 'b']);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.setTags).toHaveBeenCalledWith(1, ['a', 'b']);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
    });
});

describe('useAddSecretDependency / useRemoveSecretDependency', () => {
    it('adds a dependency and invalidates both dependency and impact caches', async () => {
        mock.addDependency!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useAddSecretDependency(1), { wrapper });

        act(() => {
            result.current.mutate({ dependsOnId: 2, note: 'shared config' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.addDependency).toHaveBeenCalledWith(1, 2, 'shared config');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: [...queryKeys.secrets.detail(1), 'dependencies'] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: [...queryKeys.secrets.detail(1), 'impact'] });
    });

    it('removes a dependency and invalidates both dependency and impact caches', async () => {
        mock.removeDependency!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRemoveSecretDependency(1), { wrapper });

        act(() => {
            result.current.mutate(5);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.removeDependency).toHaveBeenCalledWith(1, 5);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: [...queryKeys.secrets.detail(1), 'dependencies'] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: [...queryKeys.secrets.detail(1), 'impact'] });
    });
});

describe('useSuspendSecret / useResumeSecret', () => {
    it('suspends a secret and invalidates detail and lists', async () => {
        mock.suspend!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useSuspendSecret(1), { wrapper });

        act(() => {
            result.current.mutate('rotating soon');
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.suspend).toHaveBeenCalledWith(1, 'rotating soon');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.lists() });
    });

    it('resumes a secret and invalidates detail and lists', async () => {
        mock.resume!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useResumeSecret(1), { wrapper });

        act(() => {
            result.current.mutate();
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.resume).toHaveBeenCalledWith(1);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
    });
});

describe('useTransferOwnership', () => {
    it('transfers ownership and invalidates detail and lists', async () => {
        mock.transferOwnership!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useTransferOwnership(1), { wrapper });

        act(() => {
            result.current.mutate(7);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.transferOwnership).toHaveBeenCalledWith(1, 7);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.lists() });
    });
});

describe('useClassifySecret', () => {
    it('classifies a secret and invalidates detail and lists', async () => {
        mock.classify!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useClassifySecret(1), { wrapper });

        act(() => {
            result.current.mutate('restricted');
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.classify).toHaveBeenCalledWith(1, 'restricted');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.lists() });
    });
});

describe('useSetAutoRotate', () => {
    it('configures auto-rotate and invalidates detail and lists', async () => {
        mock.setAutoRotate!.mockResolvedValueOnce(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useSetAutoRotate(1), { wrapper });

        act(() => {
            result.current.mutate({ enabled: true, length: 20 });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.setAutoRotate).toHaveBeenCalledWith(1, { enabled: true, length: 20 });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.lists() });
    });
});

describe('useDeleteSecret', () => {
    it('deletes a secret, removes its detail cache, and invalidates all secrets', async () => {
        mock.delete!.mockResolvedValueOnce(undefined);
        const removeSpy = vi.spyOn(queryClient, 'removeQueries');
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useDeleteSecret(), { wrapper });

        act(() => {
            result.current.mutate(1);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.delete).toHaveBeenCalledWith(1);
        expect(removeSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
    });
});

describe('useBulkClassifySecrets', () => {
    it('classifies every id and invalidates the lists once', async () => {
        mock.classify!.mockResolvedValue(undefined);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useBulkClassifySecrets(), { wrapper });

        act(() => {
            result.current.mutate({ ids: [1, 2, 3], classification: 'internal' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.classify).toHaveBeenCalledTimes(3);
        expect(mock.classify).toHaveBeenCalledWith(1, 'internal');
        expect(mock.classify).toHaveBeenCalledWith(3, 'internal');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.lists() });
    });
});

describe('useBulkDeleteSecrets', () => {
    it('deletes every id, removes each detail cache, and invalidates all secrets', async () => {
        mock.delete!.mockResolvedValue(undefined);
        const removeSpy = vi.spyOn(queryClient, 'removeQueries');
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useBulkDeleteSecrets(), { wrapper });

        act(() => {
            result.current.mutate([1, 2]);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.delete).toHaveBeenCalledWith(1);
        expect(mock.delete).toHaveBeenCalledWith(2);
        expect(removeSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(1) });
        expect(removeSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.detail(2) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
    });
});

describe('useDuplicateSecret', () => {
    it('fetches the original, merges overrides, and creates a "-copy" duplicate by default', async () => {
        const original = {
            name: 'db-password',
            type: 'password',
            environment: 'prod',
            metadata: { owner: 'alice' },
            tags: ['prod'],
        };
        mock.get!.mockResolvedValueOnce(original);
        const created = { id: 2, name: 'db-password-copy' };
        mock.create!.mockResolvedValueOnce(created);
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const setSpy = vi.spyOn(queryClient, 'setQueryData');
        const { result } = renderHook(() => useDuplicateSecret(), { wrapper });

        act(() => {
            result.current.mutate({ originalId: 1, newData: {} });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.get).toHaveBeenCalledWith(1);
        expect(mock.create).toHaveBeenCalledWith({
            name: 'db-password-copy',
            value: '',
            type: 'password',
            environment: 'prod',
            metadata: { owner: 'alice' },
            tags: ['prod'],
        });
        expect(setSpy).toHaveBeenCalledWith(queryKeys.secrets.detail(2), created);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
    });

    it('lets newData override name/type/environment/tags and merge metadata', async () => {
        const original = {
            name: 'db-password',
            type: 'password',
            environment: 'prod',
            metadata: { owner: 'alice' },
            tags: ['prod'],
        };
        mock.get!.mockResolvedValueOnce(original);
        mock.create!.mockResolvedValueOnce({ id: 3 });
        const { result } = renderHook(() => useDuplicateSecret(), { wrapper });

        act(() => {
            result.current.mutate({
                originalId: 1,
                newData: {
                    name: 'staging-copy',
                    type: 'text',
                    environment: 'staging',
                    metadata: { note: 'x' },
                    tags: ['staging'],
                },
            });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.create).toHaveBeenCalledWith({
            name: 'staging-copy',
            value: '',
            type: 'text',
            environment: 'staging',
            metadata: { owner: 'alice', note: 'x' },
            tags: ['staging'],
        });
    });
});

describe('useSearchSecrets', () => {
    it('debounces the query and only enables once it reaches 2 characters', async () => {
        vi.useFakeTimers();
        mock.list!.mockResolvedValue({ data: [], total: 0 });
        const { result, rerender } = renderHook(({ query }) => useSearchSecrets(query), {
            wrapper,
            initialProps: { query: '' },
        });

        expect(mock.list).not.toHaveBeenCalled();

        rerender({ query: 'db' });
        // advanceTimersByTimeAsync (not advanceTimersByTime + waitFor) so the debounce's
        // setTimeout and the subsequent react-query fetch's promise chain both flush —
        // waitFor's own internal polling uses real timers, which are frozen once fake
        // timers are active, so it would otherwise hang forever.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(300);
        });
        // One more flush: the debounce firing triggers a state update that starts the
        // query on the *next* render, so the fetch itself resolves a tick after 300ms.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(0);
        });

        expect(result.current.isSuccess).toBe(true);
        expect(mock.list).toHaveBeenCalledWith({ search: 'db' });
        vi.useRealTimers();
    });
});

describe('useSecretStats', () => {
    it('fetches a single-page listing and returns just the total', async () => {
        mock.list!.mockResolvedValueOnce({ data: [], total: 123 });
        const { result } = renderHook(() => useSecretStats(), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.list).toHaveBeenCalledWith({ pageSize: 1 });
        expect(result.current.data).toEqual({ total: 123 });
    });
});

describe('usePrefetchSecret', () => {
    it('prefetches a secret detail query', async () => {
        mock.get!.mockResolvedValueOnce({ id: 4 });
        const prefetchSpy = vi.spyOn(queryClient, 'prefetchQuery');
        const { result } = renderHook(() => usePrefetchSecret(), { wrapper });

        await act(async () => {
            await result.current(4);
        });

        expect(prefetchSpy).toHaveBeenCalledWith(expect.objectContaining({ queryKey: queryKeys.secrets.detail(4) }));
        expect(mock.get).toHaveBeenCalledWith(4);
    });
});

describe('useOptimisticSecretUpdate', () => {
    it('merges the update into existing cached data', async () => {
        queryClient.setQueryData(queryKeys.secrets.detail(5), { id: 5, name: 'old-name' });
        const { result } = renderHook(() => useOptimisticSecretUpdate(5), { wrapper });

        act(() => {
            result.current({ name: 'new-name' });
        });

        expect(queryClient.getQueryData(queryKeys.secrets.detail(5))).toEqual({ id: 5, name: 'new-name' });
    });

    it('leaves the cache untouched when there is no existing data', () => {
        const { result } = renderHook(() => useOptimisticSecretUpdate(6), { wrapper });

        act(() => {
            result.current({ name: 'new-name' });
        });

        expect(queryClient.getQueryData(queryKeys.secrets.detail(6))).toBeUndefined();
    });
});

// DEMO-UI-2: History (audit) and Recent access (access-log) are derived from the audit log,
// so every hook that changes a secret, or reads its value, must refresh both panels.
describe('secret activity panels stay fresh', () => {
    const auditKey = [...queryKeys.secrets.detail(7), 'audit'];
    const accessLogKey = [...queryKeys.secrets.detail(7), 'access-log'];

    const mutations: Array<[string, () => unknown, unknown]> = [
        ['rotate', () => useRotateSecret(7), 'new-value'],
        ['rollback', () => useRollbackSecret(7), 2],
        ['update', () => useUpdateSecret(7), { name: 'x' }],
        ['suspend', () => useSuspendSecret(7), undefined],
        ['resume', () => useResumeSecret(7), undefined],
        ['classify', () => useClassifySecret(7), 'high'],
        ['transfer ownership', () => useTransferOwnership(7), 3],
        ['set tags', () => useSetSecretTags(7), ['a']],
        ['set description', () => useSetSecretDescription(7), 'd'],
        ['copy', () => useCopySecret(7), { environmentId: 2 }],
        ['auto-rotate', () => useSetAutoRotate(7), { enabled: true }],
    ];
    const apiFor: Record<string, string> = {
        rotate: 'rotate',
        rollback: 'rollback',
        update: 'update',
        suspend: 'suspend',
        resume: 'resume',
        classify: 'classify',
        'transfer ownership': 'transferOwnership',
        'set tags': 'setTags',
        'set description': 'setDescription',
        copy: 'copy',
        'auto-rotate': 'setAutoRotate',
    };

    it.each(mutations)('%s invalidates the audit trail and the access log', async (name, hook, vars) => {
        mock[apiFor[name]!]!.mockResolvedValueOnce({});
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => hook() as ReturnType<typeof useRotateSecret>, { wrapper });
        act(() => {
            result.current.mutate(vars as never);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: auditKey });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: accessLogKey });
    });

    it('revealing the value (a read) invalidates the audit trail and the access log', async () => {
        mock.getValue!.mockResolvedValueOnce('s3cret');
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useSecretValue(7, true), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: auditKey });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: accessLogKey });
    });
});
