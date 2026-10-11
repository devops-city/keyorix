// Utility functions for the application

/**
 * Combines class names conditionally
 */
export function cn(...classes: (string | undefined | null | boolean)[]): string {
    return classes.filter(Boolean).join(' ');
}

/**
 * Parses a server-emitted timestamp into a Date, treating a timestamp with no
 * zone designator as UTC. Server timestamps are UTC, but some paths (raw SQL
 * scans, e.g. project last_activity) emit "2026-10-03 10:00:00.123" or
 * "...+00" forms. `new Date()` reads a zone-less date-time as LOCAL time, which
 * skews every relative time by the viewer's UTC offset ("6 hours ago" for a
 * project created minutes earlier). Every relative-time call site must parse
 * through this helper rather than `new Date(str)`.
 */
export function parseServerDate(value: string | Date): Date {
    if (value instanceof Date) return value;
    let s = value.trim();
    // "YYYY-MM-DD HH:MM" -> ISO "T" separator.
    s = s.replace(/^(\d{4}-\d{2}-\d{2}) (\d{2}:)/, '$1T$2');
    // Only date-time strings can be zone-less; date-only ISO is already UTC.
    if (/^\d{4}-\d{2}-\d{2}T/.test(s)) {
        // Trim sub-millisecond digits (not universally parseable).
        s = s.replace(/(\.\d{3})\d+/, '$1');
        if (/[+-]\d{2}$/.test(s))
            s += ':00'; // "+00" -> "+00:00"
        else if (!/(Z|[+-]\d{2}:?\d{2})$/i.test(s)) s += 'Z'; // no zone -> UTC
    }
    return new Date(s);
}

/**
 * Formats a date string to a human-readable format
 */
export function formatDate(dateString: string): string {
    const date = parseServerDate(dateString);
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        timeZoneName: 'short',
    }).format(date);
}

/**
 * Formats a relative time (e.g., "2 hours ago")
 */
export function formatRelativeTime(dateString: string): string {
    const date = parseServerDate(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffInSeconds < 60) return 'just now';
    const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? '' : 's'} ago`;
    if (diffInSeconds < 3600) return plural(Math.floor(diffInSeconds / 60), 'minute');
    if (diffInSeconds < 86400) return plural(Math.floor(diffInSeconds / 3600), 'hour');
    if (diffInSeconds < 2592000) return plural(Math.floor(diffInSeconds / 86400), 'day');

    return formatDate(dateString);
}

/**
 * Masks sensitive data for display
 */
export function maskSensitiveData(value: string, visibleChars = 4): string {
    if (value.length <= visibleChars) {
        return '*'.repeat(value.length);
    }
    return value.slice(0, visibleChars) + '*'.repeat(value.length - visibleChars);
}

/**
 * Copies text to clipboard and clears it after a timeout
 */
export async function copyToClipboard(
    text: string,
    clearTimeout = getEnvConfig().CLIPBOARD_CLEAR_TIMEOUT
): Promise<void> {
    try {
        await navigator.clipboard.writeText(text);

        // Clear clipboard after timeout
        setTimeout(async () => {
            try {
                await navigator.clipboard.writeText('');
            } catch (error) {
                console.warn('Failed to clear clipboard:', error);
            }
        }, clearTimeout);
    } catch (error) {
        console.error('Failed to copy to clipboard:', error);
        throw new Error('Failed to copy to clipboard', { cause: error });
    }
}

/**
 * Sanitizes user input to prevent XSS
 */
export function sanitizeInput(input: string): string {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

/**
 * Validates email format
 */
export function isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/;
    return emailRegex.test(email);
}

/**
 * Formats a date string as a short date (no time) with a dash fallback for empty/invalid values.
 */
export function formatDateShort(iso: string | null | undefined): string {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
    } catch {
        return iso;
    }
}

/**
 * Triggers a browser download for a Blob (e.g. a CSV fetched with responseType:'blob').
 */
export function triggerBlobDownload(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

/**
 * Generates a cryptographically random 32-character URL-safe string.
 */
export function generateSecret(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const arr = new Uint8Array(32);
    window.crypto.getRandomValues(arr);
    return Array.from(arr)
        .map((b) => chars[b % chars.length])
        .join('');
}

/**
 * Generates a random ID
 */
export function generateId(): string {
    // crypto.randomUUID() is exposed only in a *secure context* (HTTPS or
    // localhost). Over plain HTTP on a LAN IP — the first thing an on-prem /
    // air-gapped operator hits before configuring TLS — it is undefined and
    // throws. Fall back to a getRandomValues()-based UUIDv4 (getRandomValues is
    // available in insecure contexts too) so the app keeps working.
    const c: Crypto | undefined = globalThis.crypto;
    if (typeof c?.randomUUID === 'function') {
        return c.randomUUID();
    }
    if (typeof c?.getRandomValues === 'function') {
        const bytes = c.getRandomValues(new Uint8Array(16));
        bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40; // version 4
        bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80; // variant 10xx
        const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'));
        return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10, 16).join('')}`;
    }
    // Last resort (no Web Crypto at all — should never happen in a browser).
    // These ids are only used for request correlation / DOM ids, never security.
    return `id-${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 10)}`;
}

/**
 * Debounces a function call
 */
export function debounce<T extends (...args: unknown[]) => unknown>(
    func: T,
    wait: number
): (...args: Parameters<T>) => void {
    let timeout: ReturnType<typeof setTimeout>;
    return (...args: Parameters<T>) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => func(...args), wait);
    };
}

/**
 * Throttles a function call
 */
export function throttle<T extends (...args: unknown[]) => unknown>(
    func: T,
    limit: number
): (...args: Parameters<T>) => void {
    let inThrottle: boolean;
    return (...args: Parameters<T>) => {
        if (!inThrottle) {
            func(...args);
            inThrottle = true;
            setTimeout(() => (inThrottle = false), limit);
        }
    };
}

/**
 * Gets environment configuration
 */
export function getEnvConfig() {
    return {
        API_BASE_URL: import.meta.env.VITE_API_BASE_URL || '',
        API_TIMEOUT: Number.parseInt(import.meta.env.VITE_API_TIMEOUT || '30000'),
        APP_NAME: import.meta.env.VITE_APP_NAME || 'Keyorix',
        APP_VERSION: import.meta.env.VITE_APP_VERSION || '1.0.0',
        APP_DESCRIPTION: import.meta.env.VITE_APP_DESCRIPTION || 'Secure Secret Management System',
        ENVIRONMENT: import.meta.env.VITE_ENVIRONMENT || 'development',
        ENABLE_DEBUG: import.meta.env.VITE_ENABLE_DEBUG === 'true',
        ENABLE_DEVTOOLS: import.meta.env.VITE_ENABLE_DEVTOOLS === 'true',
        SESSION_TIMEOUT: Number.parseInt(import.meta.env.VITE_SESSION_TIMEOUT || '3600000'),
        CLIPBOARD_CLEAR_TIMEOUT: Number.parseInt(import.meta.env.VITE_CLIPBOARD_CLEAR_TIMEOUT || '30000'),
        DEFAULT_LANGUAGE: import.meta.env.VITE_DEFAULT_LANGUAGE || 'en',
        DEFAULT_THEME: import.meta.env.VITE_DEFAULT_THEME || 'system',
        ITEMS_PER_PAGE: Number.parseInt(import.meta.env.VITE_ITEMS_PER_PAGE || '20'),
    };
}

/**
 * Storage utilities for localStorage with error handling
 */
export const storage = {
    get: <T>(key: string, defaultValue?: T): T | null => {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : (defaultValue ?? null);
        } catch (error) {
            // JS template literal, not a printf-style format string; no %-specifier
            // parsing step exists for `key` to hijack. Same reasoning for the two
            // identical patterns below (set/remove).
            console.error(`Error reading from localStorage key "${key}":`, error); // nosemgrep: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring
            return defaultValue ?? null;
        }
    },

    set: <T>(key: string, value: T): void => {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch (error) {
            console.error(`Error writing to localStorage key "${key}":`, error); // nosemgrep: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring
        }
    },

    remove: (key: string): void => {
        try {
            localStorage.removeItem(key);
        } catch (error) {
            console.error(`Error removing localStorage key "${key}":`, error); // nosemgrep: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring
        }
    },

    clear: (): void => {
        try {
            localStorage.clear();
        } catch (error) {
            console.error('Error clearing localStorage:', error);
        }
    },
};

/**
 * URL utilities
 */
export const url = {
    /**
     * Builds a URL with query parameters
     */
    buildUrl: (base: string, params: Record<string, string | number | boolean>): string => {
        const url = new URL(base, window.location.origin);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== undefined && value !== null) {
                url.searchParams.set(key, String(value));
            }
        });
        return url.toString();
    },

    /**
     * Parses query parameters from current URL
     */
    getQueryParams: (): Map<string, string> => {
        // Map has no prototype surface, so user-supplied URL param keys
        // cannot cause property injection (CodeQL js/remote-property-injection).
        return new Map(new URLSearchParams(window.location.search));
    },
};

// Re-export auth utilities
export * from './auth';
// Re-export routing utilities
export * from './routing';
