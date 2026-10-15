import { apiClient } from './client';
import { ApiResponse } from '../types';

// Mirrors server/http/handlers/system.go's PoolInfo/DatabaseInfo/SecurityInfo/SystemInfo.
export interface SystemPoolInfo {
    max_connections: number;
    active_connections: number;
    idle_connections: number;
}

// Mirrors internal/solewriter's Status; present only when storage.database.single_writer is on.
export interface SystemSingleWriterStatus {
    enabled: boolean;
    state: 'settling' | 'authoritative' | 'confirming';
    reason?: string;
    holder_pid: number;
    since: string;
    fenced_tables: string[];
    epoch: number;
    last_poll_age_ms: number;
    last_poll_error?: string;
    unattributed_bumps: number;
    authoritative: boolean;
    emergency_sql: string;
}

export interface SystemDatabaseInfo {
    type: string;
    connected: boolean;
    version: string;
    pool: SystemPoolInfo;
    single_writer?: SystemSingleWriterStatus;
}

export interface SystemSecurityInfo {
    tls_enabled: boolean;
    auth_enabled: boolean;
    encryption_method: string;
    audit_enabled: boolean;
    /**
     * storage.database.insecure_audit_skip_reads (ADR-112 Amendment 4): true
     * means successful secret-value reads are NOT audited on this install.
     * Drives AuditReadsSkippedBanner. Optional for older servers.
     */
    audit_reads_skipped?: boolean;
}

export interface SystemInfo {
    version: string;
    build_time: string;
    git_commit: string;
    go_version: string;
    os: string;
    arch: string;
    uptime: string;
    environment: string;
    features: Record<string, boolean | undefined>;
    database: SystemDatabaseInfo;
    security: SystemSecurityInfo;
}

// Mirrors server/http/handlers/system.go's SystemMetrics and its nested types.
// NOTE: as of writing, HTTP/Database/Secrets counters below are NOT
// instrumented server-side — GetMetrics returns them as zero-valued structs
// (see the handler's own comment: "not instrumented in the HTTP handler
// path... left at their zero value here rather than fabricated values").
// Don't build UI that presents these as live monitored data until that
// changes on the backend.
export interface SystemHttpMetrics {
    requests_total: number;
    requests_per_sec: number;
    avg_response_time: number;
    error_rate: number;
    active_connections: number;
}

export interface SystemDatabaseMetrics {
    queries_total: number;
    queries_per_sec: number;
    avg_query_time: number;
    slow_queries: number;
    connections_active: number;
    connections_idle: number;
}

export interface SystemSecretsMetrics {
    total_secrets: number;
    active_secrets: number;
    expired_secrets: number;
    secrets_created_24h: number;
    secrets_accessed_24h: number;
    encryption_ops_24h: number;
    decryption_ops_24h: number;
}

// Mirrors MemoryMetrics — populated from runtime.MemStats, genuinely live.
export interface SystemMemoryMetrics {
    alloc: number;
    total_alloc: number;
    sys: number;
    lookups: number;
    mallocs: number;
    frees: number;
    heap_alloc: number;
    heap_sys: number;
    heap_idle: number;
    heap_inuse: number;
    heap_released: number;
    heap_objects: number;
    stack_inuse: number;
    stack_sys: number;
}

// Mirrors GCMetrics — genuinely live.
export interface SystemGCMetrics {
    num_gc: number;
    pause_total: number;
    pause_ns: number[];
    next_gc: number;
    last_gc: number;
    gc_cpu_fraction: number;
}

export interface SystemMetrics {
    memory: SystemMemoryMetrics;
    goroutines: number;
    gc: SystemGCMetrics;
    http: SystemHttpMetrics;
    database: SystemDatabaseMetrics;
    secrets: SystemSecretsMetrics;
    uptime: string;
    timestamp: string;
}

// Mirrors server/http/handlers/settings.go's AuthConfigResponse and its
// nested types — a read-only, already-redacted summary (no client secrets,
// no SAML metadata, no OIDC issuer/client details).
export interface SessionSummary {
    access_ttl: string;
    absolute_ttl: string;
}

export interface PasswordPolicySummary {
    min_length: number;
    require_uppercase: boolean;
    require_lowercase: boolean;
    require_digit: boolean;
    require_special: boolean;
    reject_personal_info: boolean;
    reject_common_passwords: boolean;
    history_count: number;
    max_age_days: number;
}

export interface LoginLockoutSummary {
    enabled: boolean;
    max_attempts: number;
    window: string;
    base_cooldown: string;
    max_cooldown: string;
}

export interface WebAuthnSummary {
    enabled: boolean;
    rp_id: string;
    rp_display_name: string;
    rp_origins: string[];
}

export interface SSOProviderSummary {
    name: string;
    type: string;
    auto_provision: boolean;
    group_sync: boolean;
}

export interface SSOSummary {
    enabled: boolean;
    providers: SSOProviderSummary[];
}

export interface AuthConfigResponse {
    session: SessionSummary;
    password_policy: PasswordPolicySummary;
    login_lockout: LoginLockoutSummary;
    require_mfa: boolean;
    webauthn: WebAuthnSummary;
    sso: SSOSummary;
}

// Mirrors server/http/handlers/settings.go's EncryptionConfigResponse — the
// KEK provider's file paths, exec commands, env var names, and KMS key IDs
// are deliberately never returned by the server, so there's nothing for the
// frontend to accidentally leak either.
export interface KeyProviderSummary {
    type: string;
    shamir_commitment?: string;
    fallback_count: number;
}

export interface EncryptionConfigResponse {
    enabled: boolean;
    key_provider: KeyProviderSummary;
}

export const systemApi = {
    async getInfo(): Promise<SystemInfo> {
        const response = await apiClient.get<ApiResponse<SystemInfo>>('/api/v1/system/info');
        return response.data.data;
    },

    async getMetrics(): Promise<SystemMetrics> {
        const response = await apiClient.get<ApiResponse<SystemMetrics>>('/api/v1/system/metrics');
        return response.data.data;
    },

    async getAuthConfig(): Promise<AuthConfigResponse> {
        const response = await apiClient.get<ApiResponse<AuthConfigResponse>>('/api/v1/system/auth-config');
        return response.data.data;
    },

    async getEncryptionConfig(): Promise<EncryptionConfigResponse> {
        const response = await apiClient.get<ApiResponse<EncryptionConfigResponse>>('/api/v1/system/encryption-config');
        return response.data.data;
    },
};
