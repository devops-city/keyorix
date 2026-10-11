import { describe, it, expect, vi, beforeEach } from 'vitest';

// apiClient is a private axios instance created via axios.create() inside
// client.ts (mirrors the auth.ts/setup.ts test convention). We mock axios.create
// itself so we can capture the registered request/response interceptor
// functions and invoke them directly, plus a `request` spy to observe the
// 401-retry path (handle401 calls apiClient.request(error.config)).
const { mockRequest, mockRequestUse, mockResponseUse } = vi.hoisted(() => ({
    mockRequest: vi.fn(),
    mockRequestUse: vi.fn(),
    mockResponseUse: vi.fn(),
}));

vi.mock('axios', async () => {
    const actual = await vi.importActual<typeof import('axios')>('axios');
    return {
        ...actual,
        default: {
            ...actual.default,
            create: vi.fn(() => ({
                request: mockRequest,
                interceptors: {
                    request: { use: mockRequestUse },
                    response: { use: mockResponseUse },
                },
            })),
            isAxiosError: actual.isAxiosError,
        },
        isAxiosError: actual.isAxiosError,
    };
});

// client.ts imports useAuthStore plus the standalone shouldRefreshToken/
// isTokenExpired helpers from store/authStore. Mock the whole module so each
// test controls isAuthenticated / logout / refreshToken / setError and the
// two expiry helpers independently, without pulling in the real zustand store
// (persist middleware, cross-tab storage listener, etc.).
const { mockGetState, mockShouldRefreshToken, mockIsTokenExpired } = vi.hoisted(() => ({
    mockGetState: vi.fn(),
    mockShouldRefreshToken: vi.fn(),
    mockIsTokenExpired: vi.fn(),
}));

vi.mock('../../store/authStore', () => ({
    useAuthStore: { getState: mockGetState },
    shouldRefreshToken: mockShouldRefreshToken,
    isTokenExpired: mockIsTokenExpired,
}));

// client.ts also reads the CSRF double-submit cookie via getCsrfToken() from
// utils/auth. Mock just that function; keep the real CSRF_HEADER_NAME /
// CSRF_PROTECTED_METHODS constants since they're plain values the code
// branches on.
const { mockGetCsrfToken } = vi.hoisted(() => ({
    mockGetCsrfToken: vi.fn(),
}));

vi.mock('../../utils/auth', async () => {
    const actual = await vi.importActual<typeof import('../../utils/auth')>('../../utils/auth');
    return {
        ...actual,
        getCsrfToken: mockGetCsrfToken,
    };
});

// client.ts also calls getEnvConfig() — once at module load for the axios
// instance's timeout, and again on every error inside logError() to gate the
// [API Error] console.error behind ENABLE_DEBUG. Mock it so a single test can
// flip ENABLE_DEBUG on without depending on real import.meta.env values.
const { mockGetEnvConfig } = vi.hoisted(() => ({
    // Real default so the module-load call (`const config = getEnvConfig();`
    // at the top of client.ts) succeeds before the first beforeEach runs.
    mockGetEnvConfig: vi.fn(() => ({ ENABLE_DEBUG: false, API_TIMEOUT: 30000 })),
}));

vi.mock('../../utils', () => ({
    getEnvConfig: mockGetEnvConfig,
    // client.ts stamps X-Request-ID via generateId() (utils); provide a v4-shaped stub.
    generateId: () => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
}));

import type { AxiosError } from 'axios';
import { makeAuthenticatedRequest, handleApiError } from '../client';

// The module registers exactly one request interceptor and one response
// interceptor as a side effect of the import above — capture the
// (onFulfilled, onRejected) pairs right now, once, into module-scope
// constants. They must NOT be re-read from mock.calls inside a test/beforeEach:
// vi.clearAllMocks()/vi.resetAllMocks() clears recorded calls on these same
// spies, which would wipe this one-time registration.
const [requestOnFulfilled, requestOnRejected] = mockRequestUse.mock.calls[0];
const [responseOnFulfilled, responseOnRejected] = mockResponseUse.mock.calls[0];

function makeAuthStore(overrides: Partial<Record<string, unknown>> = {}) {
    return {
        isAuthenticated: false,
        logout: vi.fn().mockResolvedValue(undefined),
        refreshToken: vi.fn().mockResolvedValue(undefined),
        setError: vi.fn(),
        endSessionForReauth: vi.fn(),
        ...overrides,
    };
}

function axiosErr(overrides: Record<string, unknown> = {}) {
    return Object.assign(new Error('Request failed'), {
        isAxiosError: true,
        config: { url: '/api/foo', method: 'get' },
        ...overrides,
    }) as AxiosError;
}

beforeEach(() => {
    // resetAllMocks (not clearAllMocks) so any mockResolvedValueOnce/
    // mockRejectedValueOnce left queued on mockRequest by a test doesn't leak
    // into the next one. This only touches vi.fn() spies (mockRequest,
    // mockRequestUse, mockResponseUse, mockGetState, mockShouldRefreshToken,
    // mockIsTokenExpired, mockGetCsrfToken, mockGetEnvConfig) — the captured
    // interceptor closures above are plain functions, unaffected by mock resets.
    vi.resetAllMocks();
    mockShouldRefreshToken.mockReturnValue(false);
    mockIsTokenExpired.mockReturnValue(false);
    mockGetCsrfToken.mockReturnValue(undefined);
    mockGetState.mockReturnValue(makeAuthStore());
    mockGetEnvConfig.mockReturnValue({ ENABLE_DEBUG: false, API_TIMEOUT: 30000 });
});

// ── request interceptor ─────────────────────────────────────────────────────

describe('request interceptor', () => {
    it('passes an unauthenticated request through untouched (no expiry/refresh checks)', async () => {
        mockGetState.mockReturnValue(makeAuthStore({ isAuthenticated: false }));

        const config = { headers: {} as Record<string, string>, method: 'get', url: '/api/foo' };
        const result = await requestOnFulfilled(config);

        expect(mockIsTokenExpired).not.toHaveBeenCalled();
        expect(mockShouldRefreshToken).not.toHaveBeenCalled();
        expect(result).toBe(config);
    });

    it('lets an authenticated, non-expired request through when no refresh is due', async () => {
        mockGetState.mockReturnValue(makeAuthStore({ isAuthenticated: true }));
        mockIsTokenExpired.mockReturnValue(false);
        mockShouldRefreshToken.mockReturnValue(false);

        const config = { headers: {} as Record<string, string>, method: 'get', url: '/api/foo' };
        const result = await requestOnFulfilled(config);

        expect(result).toBe(config);
    });

    it('logs out and throws "Session expired" when the token is expired', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        mockIsTokenExpired.mockReturnValue(true);

        const config = { headers: {} as Record<string, string>, method: 'get', url: '/api/foo' };
        await expect(requestOnFulfilled(config)).rejects.toThrow('Session expired');
        expect(store.logout).toHaveBeenCalledTimes(1);
    });

    it('proactively refreshes the token when shouldRefreshToken() is true (and lets the request through)', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        mockIsTokenExpired.mockReturnValue(false);
        mockShouldRefreshToken.mockReturnValue(true);

        const config = { headers: {} as Record<string, string>, method: 'get', url: '/api/foo' };
        const result = await requestOnFulfilled(config);

        expect(store.refreshToken).toHaveBeenCalledTimes(1);
        expect(result).toBe(config);
    });

    it.each(['/auth/login', '/auth/refresh'])(
        'skips expiry/refresh bookkeeping entirely for the %s auth endpoint, even if authenticated and expired',
        async (url) => {
            const store = makeAuthStore({ isAuthenticated: true });
            mockGetState.mockReturnValue(store);
            mockIsTokenExpired.mockReturnValue(true);

            const config = { headers: {} as Record<string, string>, method: 'post', url };
            const result = await requestOnFulfilled(config);

            expect(mockIsTokenExpired).not.toHaveBeenCalled();
            expect(store.logout).not.toHaveBeenCalled();
            expect(result).toBe(config);
        }
    );

    it('attaches the CSRF header on a state-changing method when a CSRF token is available', async () => {
        mockGetCsrfToken.mockReturnValue('csrf-abc');

        const config = { headers: {} as Record<string, string>, method: 'post', url: '/api/foo' };
        const result = await requestOnFulfilled(config);

        expect(result.headers['X-CSRF-Token']).toBe('csrf-abc');
    });

    it('does not attach a CSRF header on a state-changing method when no CSRF token is available', async () => {
        mockGetCsrfToken.mockReturnValue(undefined);

        const config = { headers: {} as Record<string, string>, method: 'post', url: '/api/foo' };
        const result = await requestOnFulfilled(config);

        expect(result.headers['X-CSRF-Token']).toBeUndefined();
    });

    it('never attaches a CSRF header on a safe method (GET), even when a token is available', async () => {
        mockGetCsrfToken.mockReturnValue('csrf-abc');

        const config = { headers: {} as Record<string, string>, method: 'get', url: '/api/foo' };
        const result = await requestOnFulfilled(config);

        expect(result.headers['X-CSRF-Token']).toBeUndefined();
        expect(mockGetCsrfToken).not.toHaveBeenCalled();
    });

    it('stamps every request with a unique X-Request-ID header', async () => {
        const config = { headers: {} as Record<string, string>, method: 'get', url: '/api/foo' };
        const result = await requestOnFulfilled(config);

        expect(result.headers['X-Request-ID']).toMatch(/^req_\d+_.{1,8}$/);
    });

    it('rethrows on the request-setup error path', () => {
        const err = new Error('setup failed');

        expect(() => requestOnRejected(err)).toThrow('setup failed');
    });
});

// ── response interceptor: success path ──────────────────────────────────────

describe('response interceptor (success)', () => {
    it('passes a successful response through unchanged', () => {
        const response = { data: { ok: true }, status: 200 };

        expect(responseOnFulfilled(response)).toBe(response);
    });
});

// ── response interceptor: error path ────────────────────────────────────────

describe('response interceptor (error): 401 handling', () => {
    it('rethrows the original error when not authenticated (no logout/refresh attempted)', async () => {
        const store = makeAuthStore({ isAuthenticated: false });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 401, data: {} } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(store.logout).not.toHaveBeenCalled();
        expect(store.refreshToken).not.toHaveBeenCalled();
    });

    it('logs out (without retrying) when the failing request was itself the refresh call', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({
            config: { url: '/auth/refresh' },
            response: { status: 401, data: {} },
        });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(store.logout).toHaveBeenCalledTimes(1);
        expect(store.refreshToken).not.toHaveBeenCalled();
        expect(store.setError).toHaveBeenCalledWith('Your session has expired. Please log in again.');
    });

    it('refreshes the token and retries the original request on a 401 from a non-refresh endpoint', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const retriedResponse = { data: { retried: true }, status: 200 };
        mockRequest.mockResolvedValueOnce(retriedResponse);
        const originalConfig = { url: '/secrets', method: 'get' };
        const err = axiosErr({ config: originalConfig, response: { status: 401, data: {} } });

        const result = await responseOnRejected(err);

        expect(store.refreshToken).toHaveBeenCalledTimes(1);
        expect(store.logout).not.toHaveBeenCalled();
        expect(mockRequest).toHaveBeenCalledWith(originalConfig);
        expect(result).toBe(retriedResponse);
    });

    it('does not refresh+retry again when the same request already carries the _retry marker (loop guard)', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const retriedResponse = { data: { retried: true }, status: 200 };
        mockRequest.mockResolvedValueOnce(retriedResponse);
        const originalConfig: Record<string, unknown> = { url: '/secrets', method: 'get' };
        const firstErr = axiosErr({ config: originalConfig, response: { status: 401, data: {} } });

        // First 401: refresh + retry once, stamping the config with _retry.
        const firstResult = await responseOnRejected(firstErr);
        expect(firstResult).toBe(retriedResponse);
        expect(store.refreshToken).toHaveBeenCalledTimes(1);
        expect(mockRequest).toHaveBeenCalledTimes(1);
        expect(originalConfig['_retry']).toBe(true);

        // Second 401 on the SAME logical request (same config object, now
        // carrying _retry) — simulates the retried request itself failing with
        // 401 again despite the refresh having succeeded. Must NOT refresh or
        // retry a second time, and must not force a logout (the session may
        // still be valid — this could be an unrelated backend/proxy issue).
        const secondErr = axiosErr({ config: originalConfig, response: { status: 401, data: {} } });
        await expect(responseOnRejected(secondErr)).rejects.toBe(secondErr);

        expect(store.refreshToken).toHaveBeenCalledTimes(1);
        expect(mockRequest).toHaveBeenCalledTimes(1);
        expect(store.logout).not.toHaveBeenCalled();
    });

    it('refreshes the token but does not retry when the error carries no config to replay', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ config: undefined, response: { status: 401, data: {} } });

        await expect(responseOnRejected(err)).rejects.toBe(err);

        expect(store.refreshToken).toHaveBeenCalledTimes(1);
        expect(store.logout).not.toHaveBeenCalled();
        expect(mockRequest).not.toHaveBeenCalled();
    });

    it('logs out when the refresh attempt itself fails, and rethrows the original error', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        store.refreshToken.mockRejectedValueOnce(new Error('refresh failed'));
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ config: { url: '/secrets' }, response: { status: 401, data: {} } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(store.logout).toHaveBeenCalledTimes(1);
        expect(store.setError).toHaveBeenCalledWith('Your session has expired. Please log in again.');
        expect(mockRequest).not.toHaveBeenCalled();
    });
});

describe('response interceptor: the server ended the session (reauthentication_required, #3024)', () => {
    it('after a 200 that says the session ended, the next 401 sends the user to sign in again, without a refresh', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);

        // The setup-finishing call itself succeeds and is returned untouched (the page can still
        // show recovery codes / "password changed").
        const done = { status: 200, data: { success: true, data: { reauthentication_required: true } } };
        expect(responseOnFulfilled(done)).toBe(done);
        expect(store.endSessionForReauth).not.toHaveBeenCalled();

        const err = axiosErr({ config: { url: '/api/v1/secrets' }, response: { status: 401, data: {} } });
        await expect(responseOnRejected(err)).rejects.toBe(err);

        expect(store.endSessionForReauth).toHaveBeenCalledTimes(1);
        expect(store.refreshToken).not.toHaveBeenCalled();
        expect(store.logout).not.toHaveBeenCalled();
        expect(store.setError).not.toHaveBeenCalled();
    });

    it('a 401 that itself carries reauthentication_required also goes to sign-in, not through a refresh', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 401, data: { reauthentication_required: true } } });

        await expect(responseOnRejected(err)).rejects.toBe(err);

        expect(store.endSessionForReauth).toHaveBeenCalledTimes(1);
        expect(store.refreshToken).not.toHaveBeenCalled();
    });

    it('an ordinary 200 or an ordinary 401 is unaffected (refresh as before)', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        responseOnFulfilled({ status: 200, data: { success: true, data: { reauthentication_required: false } } });
        const err = axiosErr({ config: undefined, response: { status: 401, data: {} } });

        await expect(responseOnRejected(err)).rejects.toBe(err);

        expect(store.endSessionForReauth).not.toHaveBeenCalled();
        expect(store.refreshToken).toHaveBeenCalledTimes(1);
    });
});

describe('response interceptor (error): 403 handling (ADR-025 password-change gate)', () => {
    let location: { pathname: string; href: string };

    beforeEach(() => {
        location = { pathname: '/secrets', href: '' };
        Object.defineProperty(window, 'location', { configurable: true, value: location });
    });

    it('redirects to /profile on a PasswordChangeRequired error when not already there', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 403, data: { error: 'PasswordChangeRequired' } } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(location.href).toBe('/profile');
        expect(store.setError).not.toHaveBeenCalled();
    });

    it('does not redirect again when already on the /profile page', async () => {
        location.pathname = '/profile';
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 403, data: { error: 'PasswordChangeRequired' } } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(location.href).toBe('');
    });

    // #2924 / ADR-112: security.require_mfa confines a session with no second factor to the
    // enrolment endpoints; everything else answers 403 MFAEnrollmentRequired.
    it('redirects to MFA enrolment on an MFAEnrollmentRequired error, without a permission error', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 403, data: { error: 'MFAEnrollmentRequired' } } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(location.href).toBe('/profile?tab=security&mfa=required');
        expect(store.setError).not.toHaveBeenCalled();
    });

    it('does not redirect (or complain) on MFAEnrollmentRequired when already on /profile', async () => {
        // The Security tab's own recovery-code status call 403s for a user who has not
        // enrolled yet; redirecting again would loop, and a generic "no permission"
        // error would be wrong.
        location.pathname = '/profile';
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 403, data: { error: 'MFAEnrollmentRequired' } } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(location.href).toBe('');
        expect(store.setError).not.toHaveBeenCalled();
    });

    it('sets a generic permission-error message for any other 403', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 403, data: { error: 'Forbidden' } } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(location.href).toBe('');
        expect(store.setError).toHaveBeenCalledWith('You do not have permission to perform this action.');
    });
});

describe('response interceptor (error): other statuses', () => {
    it('sets a rate-limit message on 429', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 429, data: {} } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(store.setError).toHaveBeenCalledWith('Too many requests. Please wait a moment and try again.');
    });

    it('sets a server-error message on a 5xx status', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 503, data: {} } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(store.setError).toHaveBeenCalledWith('Server error. Please try again later.');
    });

    it('sets a timeout message on ECONNABORTED', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ code: 'ECONNABORTED' });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(store.setError).toHaveBeenCalledWith('Request timeout. Please check your connection and try again.');
    });

    it('sets a network-error message when there is no response and no recognized error code', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({});

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(store.setError).toHaveBeenCalledWith('Network error. Please check your connection.');
    });

    it('passes an unrecognized status (e.g. 400) through without setting any error message', async () => {
        const store = makeAuthStore({ isAuthenticated: true });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 400, data: {} } });

        await expect(responseOnRejected(err)).rejects.toBe(err);
        expect(store.setError).not.toHaveBeenCalled();
    });
});

// ── logError debug logging ──────────────────────────────────────────────────

describe('logError (gated behind ENABLE_DEBUG)', () => {
    it('logs the request method/url and error details to console when ENABLE_DEBUG is on', async () => {
        mockGetEnvConfig.mockReturnValue({ ENABLE_DEBUG: true, API_TIMEOUT: 30000 });
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const store = makeAuthStore({ isAuthenticated: false });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 400, data: { foo: 'bar' } } });

        await expect(responseOnRejected(err)).rejects.toBe(err);

        expect(consoleSpy).toHaveBeenCalledWith(
            '[API Error] GET /api/foo',
            expect.objectContaining({ status: 400, data: { foo: 'bar' }, message: 'Request failed' })
        );
        consoleSpy.mockRestore();
    });

    it('does not log to console when ENABLE_DEBUG is off', async () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const store = makeAuthStore({ isAuthenticated: false });
        mockGetState.mockReturnValue(store);
        const err = axiosErr({ response: { status: 400, data: {} } });

        await expect(responseOnRejected(err)).rejects.toBe(err);

        expect(consoleSpy).not.toHaveBeenCalled();
        consoleSpy.mockRestore();
    });
});

// ── makeAuthenticatedRequest ────────────────────────────────────────────────

describe('makeAuthenticatedRequest', () => {
    it('unwraps and returns response.data', async () => {
        mockRequest.mockResolvedValueOnce({ data: { id: 1, name: 'secret' } });

        const result = await makeAuthenticatedRequest<{ id: number; name: string }>({ url: '/secrets/1' });

        expect(mockRequest).toHaveBeenCalledWith({ url: '/secrets/1' });
        expect(result).toEqual({ id: 1, name: 'secret' });
    });

    it('propagates a rejection from apiClient.request', async () => {
        mockRequest.mockRejectedValueOnce(new Error('boom'));

        await expect(makeAuthenticatedRequest({ url: '/secrets/1' })).rejects.toThrow('boom');
    });
});

// ── handleApiError (legacy code-first ordering, distinct from apiErrorMessage) ─
// apiErrorMessage's message-first ordering is already covered end-to-end by
// apiErrorMessage.test.ts; these tests exercise handleApiError's inverted
// (error-code-first) precedence instead.

describe('handleApiError', () => {
    it('prefers response.data.error over response.data.message', () => {
        const err = axiosErr({ response: { status: 400, data: { error: 'ValidationError', message: 'bad input' } } });

        expect(handleApiError(err)).toBe('ValidationError');
    });

    it('falls back to response.data.message when there is no .error', () => {
        const err = axiosErr({ response: { status: 400, data: { message: 'bad input' } } });

        expect(handleApiError(err)).toBe('bad input');
    });

    it('falls back to the axios error message when the response body has neither field', () => {
        const err = axiosErr({ response: { status: 500, data: {} } });

        expect(handleApiError(err)).toBe('Request failed');
    });

    it('falls through to the plain-Error message when the axios error message is itself empty', () => {
        const err = axiosErr({ message: '', response: { status: 500, data: {} } });

        expect(handleApiError(err)).toBe('');
    });

    it('handles a plain (non-axios) Error', () => {
        expect(handleApiError(new Error('network down'))).toBe('network down');
    });

    it('falls back to the generic message for a non-error value', () => {
        expect(handleApiError('nope')).toBe('An unexpected error occurred');
    });
});
