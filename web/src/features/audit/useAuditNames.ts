import { useQuery } from '@tanstack/react-query';
import { rbacApi } from '../../services/rbac';
import { groupsApi } from '../../services/groups';
import { secretsApi } from '../../services/secrets';
import { projectsApi } from '../../services/projects';
import { apiClient } from '../../services/client';
import { useAuth } from '../auth';
import type { User } from '../../types';
import { resolveAuditIds, toNameMap } from './auditNames';

// Audit descriptions carry raw ids ("role 9 assigned to user 2", "secret 3 restored").
// The stored text is part of the tamper-evident chain and must not be rewritten at the
// source, so the ids are turned into names at display time (auditNames.ts). Roles, groups
// and users come from admin-only endpoints: for anyone else they are not requested (no
// 403s, no console errors) and the ids stay as the server wrote them. Secrets and
// projects come from the lists every viewer already has; an id missing from them reads
// "secret #3" (deleted, or not visible to this viewer).

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

    const { data: secrets } = useQuery({
        queryKey: ['audit-secret-map'],
        queryFn: () => secretsApi.list({ page: 1, pageSize: 100 }),
        staleTime: 5 * 60 * 1000,
    });
    const { data: projects } = useQuery({
        queryKey: ['audit-project-map'],
        queryFn: () => projectsApi.list(),
        staleTime: 5 * 60 * 1000,
    });

    const maps = {
        users: isAdmin
            ? toNameMap(
                  users,
                  (u) => u.id,
                  (u) => u.displayName || u.email || u.username
              )
            : undefined,
        roles:
            isAdmin && roles
                ? toNameMap(
                      roles,
                      (r) => r.id,
                      (r) => r.name
                  )
                : undefined,
        groups:
            isAdmin && groups
                ? toNameMap(
                      groups.groups as { id: number; name: string }[],
                      (g) => g.id,
                      (g) => g.name
                  )
                : undefined,
        secrets: secrets
            ? toNameMap(
                  secrets.data,
                  (s) => s.id,
                  (s) => s.name
              )
            : undefined,
        projects: projects
            ? toNameMap(
                  projects,
                  (p) => p.id,
                  (p) => p.name
              )
            : undefined,
    };

    return (_eventType, description) => resolveAuditIds(description, maps);
}
