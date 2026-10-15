import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { apiClient } from '../../services/client';

export interface AuditLogEntry {
    id: number;
    event_type: string;
    actor: string;
    actor_type: string; // 'user' | 'machine_identity' | 'system' (ADR-023)
    description: string;
    timestamp: string;
}

export const useAuditLog = (params?: {
    page?: number;
    pageSize?: number;
    action?: string;
    projectId?: number;
    actor?: string;
    dateFrom?: string;
    dateTo?: string;
}) => {
    return useQuery({
        queryKey: ['audit-log', params],
        queryFn: async () => {
            const response = await apiClient.get('/api/v1/audit/logs', {
                params: {
                    page: params?.page ?? 1,
                    page_size: params?.pageSize ?? 100,
                    ...(params?.action ? { action: params.action } : {}),
                    ...(params?.projectId ? { project_id: params.projectId } : {}),
                    ...(params?.actor ? { actor: params.actor } : {}),
                    ...(params?.dateFrom ? { date_from: params.dateFrom } : {}),
                    ...(params?.dateTo ? { date_to: params.dateTo } : {}),
                },
            });
            const data = response.data.data;
            return {
                data: (data.logs ?? []) as AuditLogEntry[],
                total: data.total ?? 0,
                page: data.page ?? 1,
                pageSize: data.page_size ?? 100,
                totalPages: data.total_pages ?? 1,
            };
        },
    });
};

interface AuditFeedPage {
    logs: AuditLogEntry[];
    total?: number | undefined;
    totalExact?: boolean;
    nextCursor?: string;
}

/**
 * The audit list as a "load more" feed: the first page, then each further page
 * after the previous page's next_cursor (keyset paging, newest first; see
 * docs/specs/audit-list-keyset.md). Only the first page carries the total,
 * which is exact up to 10,000 and capped there (totalExact false).
 */
export const useAuditLogFeed = (params?: { pageSize?: number; projectId?: number }) => {
    const query = useInfiniteQuery({
        queryKey: ['audit-log-feed', params],
        initialPageParam: '',
        queryFn: async ({ pageParam }): Promise<AuditFeedPage> => {
            const response = await apiClient.get('/api/v1/audit/logs', {
                params: {
                    page_size: params?.pageSize ?? 100,
                    ...(params?.projectId ? { project_id: params.projectId } : {}),
                    ...(pageParam ? { cursor: pageParam } : {}),
                },
            });
            const data = response.data.data ?? {};
            return {
                logs: (data.logs ?? []) as AuditLogEntry[],
                total: data.total,
                totalExact: data.total_exact,
                nextCursor: data.next_cursor ?? undefined,
            };
        },
        getNextPageParam: (last) => last.nextCursor || undefined,
        // Bounds what one tab keeps in memory: 100 pages (10,000 events at the
        // default page size). Beyond that the oldest pages loaded are dropped.
        maxPages: 100,
    });
    const pages = query.data?.pages ?? [];
    return {
        entries: pages.flatMap((p) => p.logs),
        total: pages[0]?.total,
        totalExact: pages[0]?.totalExact ?? true,
        isLoading: query.isLoading,
        error: query.error,
        isError: query.isError,
        hasNextPage: query.hasNextPage,
        isFetchingNextPage: query.isFetchingNextPage,
        fetchNextPage: query.fetchNextPage,
    };
};
