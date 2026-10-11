import React from 'react';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { secretsApi } from '../../services/secrets';
import { queryClient, queryKeys, invalidateQueries, SENSITIVE_GC_TIME } from '../../lib/queryClient';
import { Secret, SecretFormData } from '../../types';

export const useSecrets = (params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    type?: string;
    environment?: string;
    tags?: string[];
}) => {
    return useQuery({
        queryKey: queryKeys.secrets.list(params),
        queryFn: () => secretsApi.list(params),
        placeholderData: keepPreviousData,
    });
};

// A secret's History (audit trail) and Recent access (access log) panels are
// derived from the audit log, so every action that writes an audit event for the
// secret -- including a plain value read -- makes them stale. Call this from
// every such mutation; invalidating the narrower keys explicitly keeps it working
// even if the detail prefix is ever narrowed.
export const invalidateSecretActivity = (id: number) => {
    const detail = queryKeys.secrets.detail(id);
    queryClient.invalidateQueries({ queryKey: [...detail, 'audit'] });
    queryClient.invalidateQueries({ queryKey: [...detail, 'access-log'] });
};

export const useSecret = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.secrets.detail(id),
        queryFn: () => secretsApi.get(id),
        enabled,
    });
};

export const useSecretVersions = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.secrets.versions(id),
        queryFn: () => secretsApi.getVersions(id),
        enabled,
    });
};

// useSecretValue fetches the secret's current plaintext (GET
// /secrets/{id}?include_value=true via secretsApi.getValue) -- separate from
// useSecretVersions, which only ever returns version metadata. G28: this
// response carries decrypted secret plaintext, so gcTime MUST be
// SENSITIVE_GC_TIME (evicted from the cache as soon as the last observer
// unmounts, not left around for the default 10 minutes).
export const useSecretValue = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.secrets.value(id),
        queryFn: async () => {
            const value = await secretsApi.getValue(id);
            // The read itself is an audit event: refresh History and Recent access.
            invalidateSecretActivity(id);
            return value;
        },
        enabled,
        gcTime: SENSITIVE_GC_TIME,
    });
};

export const useCreateSecret = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (data: SecretFormData) => secretsApi.create(data),
        onSuccess: (newSecret) => {
            invalidateQueries.secrets.all();
            queryClient.setQueryData(queryKeys.secrets.detail(newSecret.id), newSecret);
        },
    });
};

export const useUpdateSecret = (id: number) => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (data: Partial<SecretFormData>) => secretsApi.update(id, data),
        onSuccess: (updatedSecret) => {
            queryClient.setQueryData(queryKeys.secrets.detail(id), updatedSecret);
            invalidateSecretActivity(id);
            invalidateQueries.secrets.lists();
        },
    });
};

export const useSecretRisk = (id: number, enabled = true) => {
    return useQuery({
        queryKey: [...queryKeys.secrets.detail(id), 'risk'],
        queryFn: () => secretsApi.risk(id),
        enabled,
        staleTime: 2 * 60 * 1000,
    });
};

export const useRotateSecret = (id: number) => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (newValue: string) => secretsApi.rotate(id, newValue),
        onSuccess: () => {
            // A rotation stores a new version and stamps last_rotated_at, so the
            // version history, the secret detail, and the lists are all stale.
            queryClient.invalidateQueries({ queryKey: queryKeys.secrets.versions(id) });
            invalidateQueries.secrets.detail(id);
            invalidateSecretActivity(id);
            invalidateQueries.secrets.lists();
        },
    });
};

export const useRollbackSecret = (id: number) => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (version: number) => secretsApi.rollback(id, version),
        onSuccess: () => {
            // Rollback appends a new version (with the old value), so the same caches
            // as a rotation are stale.
            queryClient.invalidateQueries({ queryKey: queryKeys.secrets.versions(id) });
            invalidateQueries.secrets.detail(id);
            invalidateSecretActivity(id);
            invalidateQueries.secrets.lists();
        },
    });
};

export const useSecretAccessors = (id: number, enabled = true) => {
    return useQuery({
        queryKey: [...queryKeys.secrets.detail(id), 'access'],
        queryFn: () => secretsApi.accessList(id),
        enabled,
        staleTime: 60 * 1000,
    });
};

export const useSecretAccessLog = (id: number, days = 30, enabled = true) => {
    return useQuery({
        queryKey: [...queryKeys.secrets.detail(id), 'access-log', days],
        queryFn: () => secretsApi.accessLog(id, days),
        enabled,
        staleTime: 60 * 1000,
    });
};

export const useSecretAuditTrail = (id: number, limit = 50, enabled = true) => {
    return useQuery({
        queryKey: [...queryKeys.secrets.detail(id), 'audit', limit],
        queryFn: () => secretsApi.auditTrail(id, limit),
        enabled,
        staleTime: 60 * 1000,
    });
};

// useSecretPolicy fetches the active create-time policies once, for the create form's
// convention hint + client-side pre-validation. Cached generously (rarely changes).
export const useSecretPolicy = () => {
    return useQuery({
        queryKey: ['secret-policy'],
        queryFn: () => secretsApi.policy(),
        staleTime: 5 * 60 * 1000,
        retry: false,
    });
};

export const useCopySecret = (id: number) => {
    return useMutation({
        mutationFn: (vars: { environmentId: number; name?: string }) =>
            secretsApi.copy(id, vars.environmentId, vars.name),
        onSuccess: () => {
            invalidateQueries.secrets.lists();
            invalidateSecretActivity(id);
        },
    });
};

export const useSecretDescription = (id: number, enabled = true) => {
    return useQuery({
        queryKey: [...queryKeys.secrets.detail(id), 'description'],
        queryFn: () => secretsApi.description(id),
        enabled,
        staleTime: 60 * 1000,
    });
};

export const useSetSecretDescription = (id: number) => {
    return useMutation({
        mutationFn: (description: string) => secretsApi.setDescription(id, description),
        onSuccess: () => {
            invalidateQueries.secrets.detail(id);
            invalidateSecretActivity(id);
        },
    });
};

export const useSecretTags = (id: number, enabled = true) => {
    return useQuery({
        queryKey: [...queryKeys.secrets.detail(id), 'tags'],
        queryFn: () => secretsApi.tags(id),
        enabled,
        staleTime: 60 * 1000,
    });
};

export const useSetSecretTags = (id: number) => {
    return useMutation({
        mutationFn: (tags: string[]) => secretsApi.setTags(id, tags),
        onSuccess: () => {
            invalidateQueries.secrets.detail(id);
            invalidateSecretActivity(id);
        },
    });
};

// --- secret dependency graph (ADR-052) ---

export const useSecretDependencies = (id: number, enabled = true) => {
    return useQuery({
        queryKey: [...queryKeys.secrets.detail(id), 'dependencies'],
        queryFn: () => secretsApi.dependencies(id),
        enabled,
        staleTime: 60 * 1000,
    });
};

export const useSecretImpact = (id: number, enabled = true) => {
    return useQuery({
        queryKey: [...queryKeys.secrets.detail(id), 'impact'],
        queryFn: () => secretsApi.impact(id),
        enabled,
        staleTime: 60 * 1000,
    });
};

// Certificate metadata (ADR-054) — only fetched for certificate-typed secrets.
export const useSecretCertificate = (id: number, enabled = true) => {
    return useQuery({
        queryKey: [...queryKeys.secrets.detail(id), 'certificate'],
        queryFn: () => secretsApi.certificate(id),
        enabled,
        staleTime: 60 * 1000,
        retry: false, // a non-certificate value 400s — don't retry
    });
};

// invalidateSecretGraph refreshes both the dependency and impact views after a change.
const invalidateSecretGraph = (queryClient: ReturnType<typeof useQueryClient>, id: number) => {
    queryClient.invalidateQueries({ queryKey: [...queryKeys.secrets.detail(id), 'dependencies'] });
    queryClient.invalidateQueries({ queryKey: [...queryKeys.secrets.detail(id), 'impact'] });
};

export const useAddSecretDependency = (id: number) => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (vars: { dependsOnId: number; note?: string }) =>
            secretsApi.addDependency(id, vars.dependsOnId, vars.note),
        onSuccess: () => invalidateSecretGraph(queryClient, id),
    });
};

export const useRemoveSecretDependency = (id: number) => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (edgeId: number) => secretsApi.removeDependency(id, edgeId),
        onSuccess: () => invalidateSecretGraph(queryClient, id),
    });
};

export const useSuspendSecret = (id: number) => {
    return useMutation({
        mutationFn: (reason?: string) => secretsApi.suspend(id, reason),
        onSuccess: () => {
            invalidateQueries.secrets.detail(id);
            invalidateSecretActivity(id);
            invalidateQueries.secrets.lists();
        },
    });
};

export const useResumeSecret = (id: number) => {
    return useMutation({
        mutationFn: () => secretsApi.resume(id),
        onSuccess: () => {
            invalidateQueries.secrets.detail(id);
            invalidateSecretActivity(id);
            invalidateQueries.secrets.lists();
        },
    });
};

export const useTransferOwnership = (id: number) => {
    return useMutation({
        mutationFn: (newOwnerId: number) => secretsApi.transferOwnership(id, newOwnerId),
        onSuccess: () => {
            // Ownership changes who can manage/share the secret — refresh the detail
            // (owner field) and the lists.
            invalidateQueries.secrets.detail(id);
            invalidateSecretActivity(id);
            invalidateQueries.secrets.lists();
        },
    });
};

export const useClassifySecret = (id: number) => {
    return useMutation({
        mutationFn: (classification: string) => secretsApi.classify(id, classification),
        onSuccess: () => {
            // Classification feeds the compliance posture's per-level counts and the
            // secret lists, so refresh both; the detail badge updates from local state.
            invalidateQueries.secrets.detail(id);
            invalidateSecretActivity(id);
            invalidateQueries.secrets.lists();
        },
    });
};

export const useSetAutoRotate = (id: number) => {
    return useMutation({
        mutationFn: (opts: { enabled: boolean; length?: number; charset?: string; backend?: string; ref?: string }) =>
            secretsApi.setAutoRotate(id, opts),
        onSuccess: () => {
            invalidateQueries.secrets.detail(id);
            invalidateSecretActivity(id);
            invalidateQueries.secrets.lists();
        },
    });
};

export const useDeleteSecret = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (id: number) => secretsApi.delete(id),
        onSuccess: (_, deletedId) => {
            queryClient.removeQueries({ queryKey: queryKeys.secrets.detail(deletedId) });
            invalidateQueries.secrets.all();
        },
    });
};

// useBulkClassifySecrets applies one classification level to many secrets at once
// (ISO A.5.12 bulk labelling), then refreshes the lists so the posture counts update.
export const useBulkClassifySecrets = () => {
    return useMutation({
        mutationFn: ({ ids, classification }: { ids: number[]; classification: string }) =>
            Promise.all(ids.map((id) => secretsApi.classify(id, classification))),
        onSuccess: () => {
            invalidateQueries.secrets.lists();
        },
    });
};

export const useBulkDeleteSecrets = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (secretIds: number[]) => {
            await Promise.all(secretIds.map((id) => secretsApi.delete(id)));
            return secretIds;
        },
        onSuccess: (deletedIds) => {
            deletedIds.forEach((id) => {
                queryClient.removeQueries({ queryKey: queryKeys.secrets.detail(id) });
            });
            invalidateQueries.secrets.all();
        },
    });
};

export const useDuplicateSecret = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async ({ originalId, newData }: { originalId: number; newData: Partial<SecretFormData> }) => {
            const original = await secretsApi.get(originalId);
            const duplicateData: SecretFormData = {
                name: newData.name || `${original.name}-copy`,
                value: '',
                type: newData.type || original.type,
                environment: newData.environment || original.environment,
                metadata: { ...original.metadata, ...newData.metadata },
                tags: newData.tags || original.tags,
            };
            return secretsApi.create(duplicateData);
        },
        onSuccess: (newSecret) => {
            queryClient.setQueryData(queryKeys.secrets.detail(newSecret.id), newSecret);
            invalidateQueries.secrets.all();
        },
    });
};

export const useSearchSecrets = (query: string, delay = 300) => {
    const [debouncedQuery, setDebouncedQuery] = React.useState(query);

    React.useEffect(() => {
        const timer = setTimeout(() => {
            setDebouncedQuery(query);
        }, delay);
        return () => clearTimeout(timer);
    }, [query, delay]);

    return useQuery({
        queryKey: queryKeys.secrets.list({ search: debouncedQuery }),
        queryFn: () => secretsApi.list({ search: debouncedQuery }),
        enabled: debouncedQuery.length >= 2,
        placeholderData: keepPreviousData,
    });
};

export const useSecretStats = () => {
    return useQuery({
        queryKey: ['secrets', 'stats'],
        queryFn: async () => {
            const response = await secretsApi.list({ pageSize: 1 });
            return { total: response.total };
        },
        staleTime: 5 * 60 * 1000,
    });
};

export const usePrefetchSecret = () => {
    const queryClient = useQueryClient();

    return React.useCallback(
        (id: number) => {
            queryClient.prefetchQuery({
                queryKey: queryKeys.secrets.detail(id),
                queryFn: () => secretsApi.get(id),
                staleTime: 2 * 60 * 1000,
            });
        },
        [queryClient]
    );
};

export const useOptimisticSecretUpdate = (id: number) => {
    const queryClient = useQueryClient();

    return React.useCallback(
        (updatedData: Partial<Secret>) => {
            queryClient.setQueryData(queryKeys.secrets.detail(id), (oldData: Secret | undefined) => {
                if (!oldData) return oldData;
                return { ...oldData, ...updatedData };
            });
        },
        [queryClient, id]
    );
};
