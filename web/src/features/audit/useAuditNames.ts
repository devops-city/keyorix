import { useQuery } from '@tanstack/react-query';
import { rbacApi } from '../../services/rbac';
import { groupsApi } from '../../services/groups';
import { apiClient } from '../../services/client';
import { useAuth } from '../auth';
import type { User } from '../../types';

// RBAC audit descriptions carry raw ids ("role 9 assigned to user 2"). The stored
// text is part of the tamper-evident chain and must not be rewritten at the
// source, so the ids are turned into names at display time. The lookups are
// admin-only endpoints: for anyone else they are not requested (no 403s, no
// console errors) and the ids stay as the server wrote them.

const RBAC_EVENT_PREFIXES = ['role.', 'group.', 'permission.'];
export const isRbacEvent = (eventType: string): boolean => RBAC_EVENT_PREFIXES.some((p) => eventType.startsWith(p));

export function useAuditNames(): (eventType: string, description: string) => string {
    const { isAdmin } = useAuth();
    const { data: roles } = useQuery({
        queryKey: ['rbac', 'roles'],
        queryFn: () => rbacApi.getRoles(),
        staleTime: 5 * 60 * 1000,
        enabled: isAdmin,
    });
    const { data: groups } = useQuery({
        queryKey: ['rbac', 'groups', undefined],
        queryFn: () => groupsApi.list(undefined),
        staleTime: 5 * 60 * 1000,
        enabled: isAdmin,
    });
    const { data: users = [] } = useQuery<User[]>({
        queryKey: ['audit-user-map'],
        queryFn: async () => {
            const res = await apiClient.get('/api/v1/users', { params: { page_size: 100 } });
            const payload = res.data?.data ?? res.data ?? {};
            return (payload.users ?? payload.data ?? []) as User[];
        },
        staleTime: 5 * 60 * 1000,
        enabled: isAdmin,
    });

    const userById = new Map<number, string>();
    users.forEach((u) => userById.set(u.id, u.displayName || u.email || u.username));
    const roleById = new Map<number, string>();
    (roles ?? []).forEach((r) => roleById.set(r.id, r.name));
    const groupById = new Map<number, string>();
    (groups?.groups ?? []).forEach((g: { id: number; name: string }) => groupById.set(g.id, g.name));

    return (eventType, description) =>
        !description || !isRbacEvent(eventType)
            ? description
            : description
                  .replace(/\brole (\d+)\b/g, (m: string, id: string) => roleById.get(Number(id)) ?? m)
                  .replace(/\bgroup (\d+)\b/g, (m: string, id: string) => groupById.get(Number(id)) ?? m)
                  .replace(/\buser (\d+)\b/g, (m: string, id: string) => userById.get(Number(id)) ?? m);
}
