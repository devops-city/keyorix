// Core application types
export interface User {
    id: number;
    username: string;
    displayName?: string;
    email: string;
    role: string;
    roles: string[];
    permissions: string[];
    preferences: UserPreferences;
    lastLogin: string;
    // ADR-025: when true the account must change its password before using the
    // app; the RequirePasswordChange guard confines it to the profile page.
    passwordChangeRequired?: boolean;
    accountState?: string;
}

export interface UserPreferences {
    language: string;
    timezone: string;
    theme: 'light' | 'dark' | 'system';
    notifications: NotificationSettings;
}

export interface NotificationSettings {
    email: boolean;
    browser: boolean;
    sharing: boolean;
    security: boolean;
}

// Secret management types
export interface Secret {
    id: number;
    name: string;
    type: SecretType;
    projectId?: number;
    environment: string;
    isShared: boolean;
    shareCount: number;
    // The signed-in user's per-secret grant from the list response ('read' | 'write' for a
    // share or ACL grant), '' / undefined when they hold none. A 'write' share elevates the
    // user on this one secret even when their roles do not (the role union in useCan cannot
    // see that), so Edit / Rotate follow it.
    userPermission?: string;
    lastModified: string;
    owner: string;
    permissions: string[];
    metadata: Record<string, string>;
    tags: string[];
    Expiration?: string | null;
    lastRotatedAt?: string | null;
    // Data-sensitivity label (ISO 27001 A.5.12). '' / undefined = unclassified.
    classification?: SecretClassification | '';
    // Lifecycle status: 'active' or 'suspended' (value reads blocked while suspended).
    status?: string;
}

export type SecretType = 'text' | 'password' | 'api_key' | 'certificate' | 'json';

export type SecretClassification = 'public' | 'internal' | 'confidential' | 'restricted';

export interface SecretFormData {
    name: string;
    value: string;
    type: SecretType;
    project_id?: number;
    environment_id?: number;
    environment: string;
    metadata: Record<string, string>;
    tags: string[];
}

// Sharing types
export interface ShareRecord {
    id: number;
    secretId: number;
    recipientType: 'user' | 'group';
    recipientId: number;
    recipientName: string;
    permission: 'read' | 'write';
    createdAt: string;
    createdBy: string;
    // expiresAt (ISO 8601), when present, is when this time-bound share lapses;
    // absent/undefined = a permanent share.
    expiresAt?: string;
    // secretName / projectId / projectName are set only when the caller may read the
    // secret; otherwise the UI falls back to "Secret #<secretId>".
    secretName?: string;
    projectId?: number;
    projectName?: string;
}

export interface ShareFormData {
    recipientType: 'user' | 'group';
    recipientId: number;
    permission: 'read' | 'write';
    // expiresAt, when set (ISO 8601), makes the share time-bound (JIT access): it
    // stops authorizing once it passes. Omitted/undefined = a permanent share.
    expiresAt?: string;
}

// SecretAccessLogEntry is one recorded read of a secret, from
// GET /secrets/{id}/access-log (server JSON is snake_case -- see
// server/http/handlers/secrets_access_history.go and openapi.yaml).
export interface SecretAccessLogEntry {
    id: number;
    secret_version_id: number;
    accessed_by: string;
    access_time: string;
    action: string;
    ip_address: string;
    user_agent?: string;
}

// SecretAuditEntry is one lifecycle event of a secret, from GET /secrets/{id}/audit
// (created, rotated, rolled-back, suspended/resumed, shared, owner-transferred,
// reclassified, …). The diff marker never carries a plaintext value.
export interface SecretAuditEntry {
    id: number;
    event_type: string;
    timestamp: string;
    actor_type: string;
    user_id?: number;
    description: string;
    success: boolean;
    // Omitted when the event recorded no diff / was not made under impersonation.
    diff?: Record<string, unknown>;
    impersonation?: boolean;
}

// SecretPolicy is the active create-time policy set, from GET /secrets/policy.
export interface SecretPolicy {
    name: { enabled: boolean; pattern?: string; max_length?: number };
    value: { enabled: boolean; min_length?: number; reject_common?: boolean };
}

// SecretAccessor is one user who can read a secret, from GET /secrets/{id}/access.
export interface SecretAccessor {
    user_id: number;
    username: string;
    // The EFFECTIVE level: for a project member, the higher of their role and any
    // active share (#2941).
    permission: string; // read | write | owner
    source: string; // the grant giving it: owner | role | acl | direct_share | group_share:<group>
    // Every grant the user holds on the secret, e.g. ['role:read', 'direct_share:write'].
    grants?: string[];
}

// SecretAccessReport is GET /secrets/{id}/access. When degraded is true the list is an
// under-count (part of it was withheld from this caller, or a lookup failed), and the
// UI must say so.
export interface SecretAccessReport {
    accessors: SecretAccessor[];
    degraded: boolean;
    degradedReasons: string[];
}

export interface Recipient {
    id: number;
    name: string;
    type: 'user' | 'group';
    email?: string;
    memberCount?: number;
}

// Dashboard types
export interface StatTrend {
    value: number;
    isPositive: boolean;
}

export interface ExpiringSecret {
    id: number;
    name: string;
    environment: string;
    expiresAt: string;
    daysLeft: number;
}

export interface AnomalyAlert {
    ID: number;
    SecretName: string;
    AlertType: string;
    Severity: string;
    Description: string;
    AccessedBy: string;
    IPAddress: string;
    DetectedAt: string;
    Acknowledged: boolean;
}

export interface DashboardStats {
    totalSecrets: number;
    sharedSecrets: number;
    secretsSharedWithMe: number;
    activeUsers: number;
    auditEvents30d: number;
    auditLogins30d: number;
    auditSecretReads30d: number;
    failedAuthAttempts24h: number;
    inactiveUsers: number;
    prevTotalSecrets?: number;
    totalSecretsTrend?: StatTrend;
    sharedSecretsTrend?: StatTrend;
    sharedWithMeTrend?: StatTrend;
    expiringSecrets?: ExpiringSecret[];
}

export interface ActivityItem {
    id: number;
    type: 'created' | 'updated' | 'shared' | 'accessed' | 'versions_listed' | 'metadata_read' | (string & {});
    secretName: string;
    timestamp: string;
    actor: string;
    /** Raw audit event type, e.g. "secret.dependency_invalidated" (absent on older servers). */
    eventType?: string;
    /** Readable phrase to show after the actor (absent on older servers). */
    label?: string;
}

// Navigation types
export interface NavigationItem {
    name: string;
    href: string;
    icon: React.ComponentType;
    current: boolean;
    badge?: number;
}

// API types
export interface ApiResponse<T> {
    data: T;
    message: string;
    success: boolean;
}

export interface PaginatedResponse<T> {
    data: T[];
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
}

// ApiError mirrors the server's error body (sendError, helpers.go): `error` is a
// short type label, `message` the human text, `code` the HTTP status.
export interface ApiError {
    success: boolean;
    code: number;
    error: string;
    message: string;
    details?: Record<string, unknown> | null;
    // On a 403 from the account-setup gate (#3024): the setup steps still owed
    // ("change_password", "enroll_mfa").
    pending_steps?: string[];
}

// Form types
export interface ValidationError {
    field: string;
    message: string;
}

// UI types
export interface AppNotification {
    id: string;
    type: 'success' | 'error' | 'warning' | 'info';
    title: string;
    message: string;
    timestamp: string;
    read: boolean;
}

// Filter and pagination types
export interface SecretFilters {
    search: string;
    type: SecretType | 'all';
    classification: SecretClassification | 'unclassified' | '';
    environment: string;
    tags: string[];
}

export interface PaginationState {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
}

// Authentication types
export interface LoginFormData {
    username: string;
    password: string;
    rememberMe: boolean;
}

export interface AuthState {
    user: User | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    // True once the initial checkAuth() bootstrap has resolved at least once
    // (success or failure). Distinct from isLoading, which also flips true/false
    // for every subsequent login/logout/refresh call — route guards should key
    // their full-page spinner off this, not isLoading, or a plain login attempt
    // unmounts the login page mid-request (see PublicRoute/ProtectedRoute).
    hasCheckedAuth: boolean;
    error: string | null;
}

// ImpersonatedBy describes the real admin behind an active impersonation
// session, as reported by GET /auth/profile's `impersonation` field — the
// server-validated source of truth for the impersonation banner now that the
// session token itself is an httpOnly cookie the client can't stash a second
// copy of.
export interface ImpersonatedBy {
    adminId: number;
    adminUsername: string;
    adminDisplayName?: string | undefined;
}

// ProfileImpersonation mirrors the backend's snake_case `impersonation` field
// on the profile response, before authStore translates it into ImpersonatedBy.
export interface ProfileImpersonation {
    admin_id: number;
    admin_username: string;
    admin_display_name?: string;
}

export interface LoginResponse {
    // expires_at is when the current session cookie lapses — the client refreshes
    // silently before this. absolute_expires_at, when present, is the hard ceiling
    // past which refresh is refused and the user must re-authenticate.
    // Note: no `token` field — auth is cookie-based (httpOnly), not Bearer.
    expires_at: string;
    absolute_expires_at?: string;
    user_id: number;
    username: string;
    email: string;
    display_name?: string;
    role?: string;
    roles?: string[];
    permissions?: string[];
    password_change_required?: boolean;
    account_state?: string;

    // mfa_required (and the three fields below) are present INSTEAD of the
    // identity fields above when the account has MFA enabled and a correct
    // password alone isn't sufficient yet (server/http/handlers/auth.go's
    // Login: HTTP 200, no session cookie set). authStore.login() must branch
    // on mfa_required before treating a response as a completed session —
    // every other field on this type is meaningless when it's true.
    mfa_required?: boolean;
    mfa_challenge?: string;
    totp_available?: boolean;
    webauthn_available?: boolean;
}

// MfaChallengeState is the client-side shape of a pending login-time MFA
// challenge — derived from LoginResponse's mfa_required branch, held in
// authStore until verifyMfa() (or clearMfaChallenge()) resolves it.
export interface MfaChallengeState {
    challenge: string;
    totpAvailable: boolean;
    webauthnAvailable: boolean;
}

export interface RefreshTokenResponse {
    // snake_case to match the backend payload ({expires_at, absolute_expires_at}).
    // Note: no `token` field — auth is cookie-based (httpOnly), not Bearer.
    expires_at: string;
    absolute_expires_at?: string;
}

export interface PasswordResetRequest {
    email: string;
}

export interface PasswordResetConfirm {
    token: string;
    newPassword: string;
    confirmPassword: string;
}

// Rotation policy types
export interface RotationPolicy {
    id: number;
    name: string;
    description: string;
    scope: 'project' | 'environment';
    project_id: number | null;
    environment_id: number | null;
    interval_days: number;
    alert_days_before: number;
    notify_on_breach: boolean;
    is_active: boolean;
    created_by: string;
    created_at: string;
    updated_at: string;
}

export interface RotationPolicyEvaluation {
    policy_id: number;
    policy_name: string;
    secret_id: number;
    secret_name: string;
    project_id: number;
    last_rotated_at: string | null;
    days_overdue: number;
    is_overdue: boolean;
    is_approaching: boolean;
}

export interface SecretUsageStat {
    secret_id: number;
    secret_name: string;
    environment_id: number;
    read_count: number;
    last_read: string | null;
}

export interface UnusedSecretStat {
    secret_id: number;
    secret_name: string;
    environment_id: number;
    last_read: string | null;
}

export type RiskBand = 'low' | 'medium' | 'high';

export interface SecretRiskFactor {
    key: string;
    label: string;
    score: number; // 0-100 risk (higher = riskier)
    weight: number;
    detail: string;
}

export interface SecretRiskScore {
    secret_id: number;
    secret_name: string;
    score: number; // 0-100 weighted composite
    band: RiskBand;
    factors: SecretRiskFactor[];
    // true when the exposure factor could not be fully computed: treat score/band
    // as a floor, not a verified value.
    degraded: boolean;
}

export type RotationStatus = 'overdue' | 'due_soon' | 'ok';

export interface RotationStatusEntry {
    policy_id: number;
    policy_name: string;
    interval_days: number;
    alert_days_before: number;
    secret_id: number;
    secret_name: string;
    environment_id: number;
    last_rotated_at: string | null;
    days_since_rotation: number;
    days_overdue: number;
    status: RotationStatus;
    // Whether the covered secret self-rotates (ADR-046/047) and via which backend
    // ("" / undefined = regenerated in Keyorix). Lets the status view distinguish a
    // self-rotating secret from a reminder-only one.
    auto_rotate?: boolean;
    rotation_backend?: string;
}

export interface CreateRotationPolicyPayload {
    name: string;
    description: string;
    scope: 'project' | 'environment';
    project_id: number | null;
    environment_id: number | null;
    interval_days: number;
    alert_days_before: number;
    notify_on_breach: boolean;
}

// Environment types
export interface EnvironmentConfig {
    API_BASE_URL: string;
    API_TIMEOUT: number;
    APP_NAME: string;
    APP_VERSION: string;
    APP_DESCRIPTION: string;
    ENVIRONMENT: 'development' | 'staging' | 'production';
    ENABLE_DEBUG: boolean;
    ENABLE_DEVTOOLS: boolean;
    SESSION_TIMEOUT: number;
    CLIPBOARD_CLEAR_TIMEOUT: number;
    DEFAULT_LANGUAGE: string;
    DEFAULT_THEME: 'light' | 'dark' | 'system';
    ITEMS_PER_PAGE: number;
}
