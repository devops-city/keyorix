// Application constants

export const APP_CONFIG = {
    NAME: 'Keyorix',
    VERSION: '1.0.0',
    DESCRIPTION: 'Secure Secret Management System',
} as const;

export const API_ENDPOINTS = {
    AUTH: {
        LOGIN: '/auth/login',
        LOGOUT: '/auth/logout',
        REFRESH: '/auth/refresh',
        PROFILE: '/api/v1/auth/profile',
        // Unauthenticated MFA login second-step — the bearer is the single-use
        // challenge LOGIN just issued, not a session (server/http/router.go).
        MFA_VERIFY: '/auth/mfa/verify',
    },
    PROJECTS: {
        LIST: '/api/v1/projects',
        CREATE: '/api/v1/projects',
        GET: (id: number) => `/api/v1/projects/${id}`,
        ENVIRONMENTS: (id: number) => `/api/v1/projects/${id}/environments`,
    },
    SECRETS: {
        LIST: '/api/v1/secrets',
        CREATE: '/api/v1/secrets',
        GET: (id: number) => `/api/v1/secrets/${id}`,
        UPDATE: (id: number) => `/api/v1/secrets/${id}`,
        DELETE: (id: number) => `/api/v1/secrets/${id}`,
        VERSIONS: (id: number) => `/api/v1/secrets/${id}/versions`,
        CLASSIFY: (id: number) => `/api/v1/secrets/${id}/classification`,
    },
    SHARING: {
        LIST: '/api/v1/shares',
        // Owner-scoped list (SHARE-3): the shares the caller created, in projects they are
        // a member of. The Sharing Management page uses it when LIST is refused.
        OWNED: '/api/v1/shares/owned',
        CREATE: (secretId: number) => `/api/v1/secrets/${secretId}/share`,
        GET: (id: number) => `/api/v1/shares/${id}`,
        UPDATE: (id: number) => `/api/v1/shares/${id}`,
        DELETE: (id: number) => `/api/v1/shares/${id}`,
        SELF_REMOVE: (id: number) => `/api/v1/shares/${id}/self-remove`,
        // Project-scoped recipient search for the Share dialog (SHARE-2).
        RECIPIENTS: (projectId: number) => `/api/v1/projects/${projectId}/share-recipients`,
    },
    ENVIRONMENTS: {
        LIST: '/api/v1/environments',
    },
    USERS: {
        LIST: '/api/v1/users',
        GET: (id: number) => `/api/v1/users/${id}`,
        SEARCH: '/api/v1/users/search',
    },
    GROUPS: {
        LIST: '/api/v1/groups',
        GET: (id: number) => `/api/v1/groups/${id}`,
        SEARCH: '/api/v1/groups/search',
    },
    ADMIN: {
        STATS: '/api/v1/admin/stats',
        USERS: '/api/v1/admin/users',
        ROLES: '/api/v1/admin/roles',
        AUDIT: '/api/v1/admin/audit',
    },
} as const;

export const ROUTES = {
    HOME: '/',
    LOGIN: '/login',
    DASHBOARD: '/dashboard',
    // Legacy flat secrets (keep for sidebar "All Secrets" child link)
    SECRETS: '/secrets',
    SECRET_DETAIL: (id: number) => `/secrets/${id}`,
    CREATE_SECRET: '/secrets/new',
    EDIT_SECRET: (id: number) => `/secrets/${id}/edit`,
    // Projects hierarchy
    PROJECTS: '/projects',
    PROJECT_DETAIL: (id: number) => `/projects/${id}`,
    PROJECT_SECRETS: (id: number) => `/projects/${id}/secrets`,
    PROJECT_MEMBERS: (id: number) => `/projects/${id}/members`,
    PROJECT_ACTIVITY: (id: number) => `/projects/${id}/activity`,
    PROJECT_SETTINGS: (id: number) => `/projects/${id}/settings`,
    // Other
    SHARING: '/sharing',
    SHARED_WITH_ME: '/sharing/with-me',
    SHARED_BY_ME: '/sharing/by-me',
    PROFILE: '/profile',
    SETTINGS: '/settings',
    SECURITY: '/security',
    AUDIT: '/audit',
    ADMIN: '/admin',
    ADMIN_BILLING: '/admin/billing',
    ADMIN_USERS: '/admin/users',
    ADMIN_USER_DETAIL: (id: number | string) => `/admin/users/${id}`,
    ADMIN_ROLES: '/admin/roles',
    ADMIN_SETTINGS: '/admin/settings',
    ADMIN_NOTIFICATION_CHANNELS: '/admin/notification-channels',
    COMPLIANCE: '/compliance',
    CONNECT: '/integrations/connect',
    SDKS_CLI: '/integrations/sdks',
    SETTINGS_AUTH: '/settings/auth',
    SETTINGS_ENCRYPTION: '/settings/encryption',
    SETTINGS_HEALTH: '/settings/health',
    SETTINGS_LICENSE: '/settings/license',
    ROADMAP: '/roadmap',
} as const;

export const SECRET_TYPES = {
    TEXT: 'text',
    PASSWORD: 'password',
    API_KEY: 'api_key',
    CERTIFICATE: 'certificate',
    JSON: 'json',
} as const;

export const PERMISSIONS = {
    READ: 'read',
    WRITE: 'write',
} as const;

export const THEMES = {
    LIGHT: 'light',
    DARK: 'dark',
    SYSTEM: 'system',
} as const;

export const LANGUAGES = {
    EN: 'en',
    RU: 'ru',
    ES: 'es',
    FR: 'fr',
    DE: 'de',
} as const;

export const NOTIFICATION_TYPES = {
    SUCCESS: 'success',
    ERROR: 'error',
    WARNING: 'warning',
    INFO: 'info',
} as const;

export const ACTIVITY_TYPES = {
    CREATED: 'created',
    UPDATED: 'updated',
    SHARED: 'shared',
    ACCESSED: 'accessed',
    DELETED: 'deleted',
} as const;

export const DEFAULT_VALUES = {
    PAGE_SIZE: 20,
    SESSION_TIMEOUT: 3600000, // 1 hour in milliseconds
    CLIPBOARD_CLEAR_TIMEOUT: 30000, // 30 seconds
    DEBOUNCE_DELAY: 300, // milliseconds
    API_TIMEOUT: 30000, // 30 seconds
} as const;

export const VALIDATION_RULES = {
    PASSWORD: {
        MIN_LENGTH: 8,
        REQUIRE_UPPERCASE: true,
        REQUIRE_LOWERCASE: true,
        REQUIRE_NUMBERS: true,
        REQUIRE_SPECIAL_CHARS: true,
    },
    SECRET_NAME: {
        MIN_LENGTH: 1,
        MAX_LENGTH: 255,
        PATTERN: /^[a-zA-Z0-9_-]+$/,
    },
    EMAIL: {
        PATTERN: /^[^\s@]+@[^\s@.]+\.[^\s@.]+$/,
    },
} as const;
