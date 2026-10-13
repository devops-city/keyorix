import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { dashboardApi } from '../../services/dashboard';
import { systemApi } from '../../services/system';
import { auditApi } from '../../services/audit';
import { usersApi } from '../../services/users';
import { groupsApi } from '../../services/groups';
import { queryKeys } from '../../lib/queryClient';

// ── Dashboard ──────────────────────────────────────────────────────────────

export const useDashboardStats = () => {
    return useQuery({
        queryKey: queryKeys.dashboard.stats(),
        queryFn: () => dashboardApi.getStats(),
        staleTime: 0,
        refetchInterval: 10 * 1000,
        refetchOnWindowFocus: true,
        refetchOnMount: true,
    });
};

export const useDashboardActivity = (params?: { page?: number; pageSize?: number; type?: string }) => {
    return useQuery({
        queryKey: queryKeys.dashboard.activity(params),
        queryFn: () => dashboardApi.getActivity(params),
        staleTime: 1 * 60 * 1000,
        refetchInterval: 2 * 60 * 1000,
    });
};

// ── System ─────────────────────────────────────────────────────────────────

export const useSystemInfo = (options: { enabled?: boolean } = {}) => {
    return useQuery({
        queryKey: ['systemInfo'],
        queryFn: () => systemApi.getInfo(),
        staleTime: 5 * 60 * 1000,
        enabled: options.enabled ?? true,
    });
};

export const useSystemMetrics = () => {
    return useQuery({
        queryKey: ['systemMetrics'],
        queryFn: () => systemApi.getMetrics(),
        staleTime: 30 * 1000,
        refetchInterval: 60 * 1000,
    });
};

export const useAuthConfig = () => {
    return useQuery({
        queryKey: ['authConfig'],
        queryFn: () => systemApi.getAuthConfig(),
        staleTime: 5 * 60 * 1000,
    });
};

export const useEncryptionConfig = () => {
    return useQuery({
        queryKey: ['encryptionConfig'],
        queryFn: () => systemApi.getEncryptionConfig(),
        staleTime: 5 * 60 * 1000,
    });
};

// ── Anomaly alerts ─────────────────────────────────────────────────────────

export const useAnomalyAlerts = (unacknowledgedOnly = true) => {
    return useQuery({
        queryKey: ['anomalyAlerts', unacknowledgedOnly],
        queryFn: () => auditApi.getAnomalyAlerts(unacknowledgedOnly),
        refetchInterval: 5 * 60 * 1000,
    });
};

export const useAcknowledgeAnomaly = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => auditApi.acknowledgeAnomalyAlert(id),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['anomalyAlerts'] });
        },
    });
};

// ── Users ──────────────────────────────────────────────────────────────────

export const useUsers = (params?: { page?: number; pageSize?: number; search?: string }) => {
    return useQuery({
        queryKey: queryKeys.users.list(params),
        queryFn: () => usersApi.list(params),
        enabled: true,
        staleTime: 5 * 60 * 1000,
    });
};

export const useUser = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.users.detail(id),
        queryFn: () => usersApi.get(id),
        enabled: enabled && id > 0,
        staleTime: 5 * 60 * 1000,
    });
};

// ── Groups ─────────────────────────────────────────────────────────────────

export const useGroups = (params?: { page?: number; pageSize?: number; search?: string }) => {
    return useQuery({
        queryKey: queryKeys.groups.list(params),
        queryFn: () => groupsApi.list(params),
        enabled: true,
        staleTime: 5 * 60 * 1000,
    });
};

export const useGroup = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.groups.detail(id),
        queryFn: () => groupsApi.get(id),
        enabled: enabled && id > 0,
        staleTime: 5 * 60 * 1000,
    });
};
