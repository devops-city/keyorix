import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import { useAuthStore, shouldRefreshToken, isTokenExpired } from '../store/authStore';
import { getEnvConfig, generateId } from '../utils';
import { getCsrfToken, CSRF_HEADER_NAME, CSRF_PROTECTED_METHODS } from '../utils/auth';

const config = getEnvConfig();

const logError = (error: AxiosError) => {
    // This is a JS template literal, not a printf-style format string; there is no
    // %-specifier parsing step for a value to hijack. The rule flags any
    // console.x(`...`, extraArg) call shape regardless. message/details extracted,
    // and the console.error call kept to one line, so Prettier has no multi-line
    // object literal to reflow the trailing nosemgrep comment out of.
    if (getEnvConfig().ENABLE_DEBUG) {
        const message = `[API Error] ${error.config?.method?.toUpperCase()} ${error.config?.url}`;
        const details = {
            status: error.response?.status,
            data: error.response?.data,
            message: error.message,
        };
        console.error(message, details); // nosemgrep: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring
    }
};

export const apiClient: AxiosInstance = axios.create({
    baseURL: '',
    timeout: config.API_TIMEOUT,
    withCredentials: true,
    headers: {
        'Content-Type': 'application/json',
    },
});

apiClient.interceptors.request.use(
    async (interceptorConfig) => {
        const authStore = useAuthStore.getState();

        const isAuthEndpoint =
            interceptorConfig.url?.includes('/auth/login') || interceptorConfig.url?.includes('/auth/refresh');

        // The session itself now rides an httpOnly cookie the browser attaches
        // automatically (withCredentials: true, below) — this interceptor no
        // longer reads or attaches a token. It still owns proactive refresh
        // scheduling: expiry bookkeeping lives in separate localStorage keys
        // (utils/auth.ts), not the token itself, so this needs no other change.
        if (!isAuthEndpoint && authStore.isAuthenticated) {
            if (isTokenExpired()) {
                await authStore.logout();
                throw new Error('Session expired');
            }

            if (shouldRefreshToken()) {
                await authStore.refreshToken();
            }
        }

        const method = interceptorConfig.method?.toLowerCase();
        if (method && CSRF_PROTECTED_METHODS.has(method)) {
            const csrfToken = getCsrfToken();
            if (csrfToken) {
                interceptorConfig.headers[CSRF_HEADER_NAME] = csrfToken;
            }
        }

        interceptorConfig.headers['X-Request-ID'] = `req_${Date.now()}_${generateId().slice(0, 8)}`;

        return interceptorConfig;
    },
    (error) => {
        logError(error);
        throw error;
    }
);

// Marks a request config as already having gone through one refresh+retry
// round trip — the conventional axios interceptor loop guard. Kept as a
// narrow intersection type rather than augmenting AxiosRequestConfig globally,
// since only handle401 ever reads/writes this flag.
type RetriableConfig = AxiosRequestConfig & { _retry?: boolean };

// #3024 / RECOVER-1: the step that finishes a restricted account's setup (change the one-time
// password, enrol a second factor) also ends the calling session, and says so with
// `data.reauthentication_required: true` on its 200 response. The page that made the call
// still has something to show (the new recovery codes, "password changed"), so the flag only
// remembers the fact; the next request, which the server will now answer 401, is the moment
// to send the user to sign in again, with a message that says why, instead of trying to
// refresh a session that no longer exists and reporting a generic "session expired".
let sessionEndedByServer = false;

const sessionEndFlag = (body: unknown): boolean => {
    const b = body as { reauthentication_required?: unknown; data?: { reauthentication_required?: unknown } } | null;
    return b?.reauthentication_required === true || b?.data?.reauthentication_required === true;
};

const handle401 = async (
    error: AxiosError,
    authStore: ReturnType<typeof useAuthStore.getState>
): Promise<AxiosResponse | void> => {
    if (!authStore.isAuthenticated) {
        return;
    }
    if (sessionEndedByServer || sessionEndFlag(error.response?.data)) {
        sessionEndedByServer = false;
        authStore.endSessionForReauth();
        return;
    }
    if (error.config?.url?.includes('/auth/refresh')) {
        await authStore.logout();
        authStore.setError('Your session has expired. Please log in again.');
        return;
    }
    // Loop guard: this exact request has already been retried once after a
    // successful refresh and still came back 401. That means the failure
    // isn't session expiry (refreshToken() would have thrown otherwise) — it's
    // something else about this endpoint (a backend bug, a step-up-auth
    // requirement, a flaky proxy). Refreshing and retrying again would loop
    // forever, hammering /auth/refresh. Don't force a logout either — the
    // session may still be perfectly valid — just fail through to the caller.
    if ((error.config as RetriableConfig | undefined)?._retry) {
        return;
    }
    try {
        await authStore.refreshToken();
        // The retry rides the rotated session cookie automatically —
        // no header to reattach, unlike the old Bearer-token flow.
        if (error.config) {
            (error.config as RetriableConfig)._retry = true;
            return apiClient.request(error.config);
        }
    } catch {
        await authStore.logout();
        authStore.setError('Your session has expired. Please log in again.');
    }
};

// Where MFAEnrollmentRequired sends the user; ProfilePage reads `tab` and `mfa`.
export const MFA_ENROLMENT_URL = '/profile?tab=security&mfa=required';

const handle403 = (error: AxiosError, authStore: ReturnType<typeof useAuthStore.getState>): void => {
    // ADR-025: a restricted account is blocked from everything but the
    // password change. Route it to the profile page rather than just
    // showing a permission error (robust across reloads / a lost flag).
    const code = (error.response?.data as { error?: string } | undefined)?.error;
    if (code === 'PasswordChangeRequired') {
        if (!window.location.pathname.startsWith('/profile')) {
            window.location.href = '/profile';
        }
    } else if (code === 'MFAEnrollmentRequired') {
        // #2924 / ADR-112: security.require_mfa is on and this session has no second
        // factor, so the server confines it to the enrolment endpoints and answers
        // everything else with this 403. Take the user to the one place that can fix
        // it (Profile -> Security -> Enable) instead of a "no permission" error. On
        // /profile itself the 403s are expected (e.g. the recovery-code status call):
        // no redirect, and no generic permission error either.
        if (!window.location.pathname.startsWith('/profile')) {
            window.location.href = MFA_ENROLMENT_URL;
        }
    } else {
        authStore.setError('You do not have permission to perform this action.');
    }
};

// axios words every non-2xx as "Request failed with status code N". That string reaches
// users through any `error.message` a dialog renders (the 13 sites SHARE-2 moved to
// apiErrorMessage, and every one nobody has found yet). Replace it once, here, with the
// server's own reason when the body carries one; for a bare 403 say what is true: the
// action is not permitted and the server gave no reason.
const AXIOS_GENERIC_MESSAGE = /^Request failed with status code \d+$/;
export const NO_PERMISSION_MESSAGE = 'You do not have permission to do this. Ask a project admin for access.';

export const humanizeRefusal = (error: AxiosError): void => {
    if (!AXIOS_GENERIC_MESSAGE.test(error.message ?? '')) return;
    const data = error.response?.data as { message?: unknown; error?: unknown } | undefined;
    if (typeof data?.message === 'string' && data.message) {
        error.message = data.message;
    } else if (error.response?.status === 403) {
        error.message = NO_PERMISSION_MESSAGE;
    }
};

const handleErrorByStatus = async (
    error: AxiosError,
    authStore: ReturnType<typeof useAuthStore.getState>
): Promise<AxiosResponse | void> => {
    const status = error.response?.status;
    if (status === 401) {
        return handle401(error, authStore);
    }
    if (status === 403) {
        handle403(error, authStore);
    } else if (status === 429) {
        authStore.setError('Too many requests. Please wait a moment and try again.');
    } else if (status && status >= 500) {
        authStore.setError('Server error. Please try again later.');
    } else if (error.code === 'ECONNABORTED') {
        authStore.setError('Request timeout. Please check your connection and try again.');
    } else if (!error.response) {
        authStore.setError('Network error. Please check your connection.');
    }
};

apiClient.interceptors.response.use(
    (response: AxiosResponse) => {
        if (sessionEndFlag(response.data)) {
            sessionEndedByServer = true;
        }
        return response;
    },
    async (error: AxiosError) => {
        logError(error);

        const authStore = useAuthStore.getState();
        const result = await handleErrorByStatus(error, authStore);
        if (result !== undefined) {
            return result;
        }

        humanizeRefusal(error);
        throw error;
    }
);

export const makeAuthenticatedRequest = async <T>(reqConfig: AxiosRequestConfig): Promise<T> => {
    const response = await apiClient.request<T>(reqConfig);
    return response.data;
};

// apiErrorMessage extracts the human-readable reason from an API error, preferring
// the server's `message` (e.g. a validation reason like "secret value is a known weak
// or placeholder value") over the `error` type code. Use this where the message is
// shown to the user; handleApiError keeps its legacy code-first ordering.
// apiErrorMessage is what a dialog shows for a failed request: the server's own
// reason (`message`, else `error`) when there is one, so a refusal reads e.g. "You
// can't edit this secret: ..." instead of axios's "Request failed with status code
// 403"; otherwise the Error's message; otherwise `fallback`.
export const apiErrorMessage = (error: unknown, fallback = 'An unexpected error occurred'): string => {
    if (axios.isAxiosError(error)) {
        const data = error.response?.data as { message?: string; error?: string } | undefined;
        if (data?.message) return data.message;
        if (data?.error) return data.error;
        if (error.message) return error.message;
    }
    if (error instanceof Error) return error.message;
    return fallback;
};

export const handleApiError = (error: unknown): string => {
    if (axios.isAxiosError(error)) {
        if (error.response?.data?.error) {
            return error.response.data.error;
        }
        if (error.response?.data?.message) {
            return error.response.data.message;
        }
        if (error.message) {
            return error.message;
        }
    }

    if (error instanceof Error) {
        return error.message;
    }

    return 'An unexpected error occurred';
};
