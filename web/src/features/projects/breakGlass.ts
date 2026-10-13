import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { breakGlassApi, classifyBreakGlassError } from '../../services/breakGlass';
import { useAuth } from '../auth/api';

// The list is shaped by WHO asks: roles.read sees every activation, a plain member only their
// own. So the cache key carries the signed-in user, and the data is dropped as soon as nothing
// observes it (gcTime 0): a justification typed by one user must never be served to the next
// account that signs in on this browser, and the justification text is sensitive in itself.
export const BREAK_GLASS_KEYS = {
    all: ['break-glass'] as const,
    list: (projectId: number, userId: number | string | undefined) =>
        [...BREAK_GLASS_KEYS.all, 'list', projectId, userId ?? 'anonymous'] as const,
};

export function useBreakGlassActivations(projectId: number) {
    const { user } = useAuth();
    return useQuery({
        queryKey: BREAK_GLASS_KEYS.list(projectId, user?.id),
        queryFn: () => breakGlassApi.list(projectId),
        enabled: !!projectId && !!user,
        gcTime: 0,
        staleTime: 0,
        // A refusal (403: not a member, MFA required) is an answer, not a blip.
        retry: (count, error) => classifyBreakGlassError(error) === 'other' && count < 1,
    });
}

export function useActivateBreakGlass(projectId: number) {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: ({ justification, ttl }: { justification: string; ttl?: string | undefined }) =>
            breakGlassApi.activate(projectId, justification, ttl),
        onSettled: () => qc.invalidateQueries({ queryKey: BREAK_GLASS_KEYS.all }),
    });
}

export function useRevokeBreakGlass(projectId: number) {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: (activationId: number) => breakGlassApi.revoke(projectId, activationId),
        onSettled: () => qc.invalidateQueries({ queryKey: BREAK_GLASS_KEYS.all }),
    });
}
