import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { useAuthStore, shouldRefreshToken, isTokenExpired } from '../authStore';
import { authService } from '../../services/auth';
import * as authUtils from '../../utils/auth';
import type { User, LoginResponse, RefreshTokenResponse } from '../../types';

// Phase 4 coverage sweep: authStore.ts's own action/reducer logic is exercised
// today only indirectly (via mocked-store page tests and the existing
// stores.test.ts / impersonation.test.ts / multiTabSync.test.ts files in this
// directory). This file is deliberately SEPARATE from stores.test.ts rather
// than an addition to it — editing a shared file risks merge conflicts with
// unrelated in-flight work in this multi-phase effort, and a second focused
// file matches the sweep's established "one file, one PR" pattern. It targets
// the actions/branches those three existing files don't reach: completeSetup,
// completeSSOLogin, logout, refreshToken (including its absolute-expiry and
// single-flight paths), checkAuth's re-entrancy guard and redirect branches,
// clearPasswordChangeRequired, and the shouldRefreshToken/isTokenExpired
// helpers — plus a couple of login/completeSetup response-shaping branches
// (account_state, password_change_required, role/roles/permissions defaults)
// that the existing happy-path login tests don't cover.

vi.mock('../../services/auth', () => ({
    authService: {
        login: vi.fn(),
        verifyMfa: vi.fn(),
        logout: vi.fn(),
        refreshToken: vi.fn(),
        getProfile: vi.fn(),
    },
}));

vi.mock('../../utils/auth', () => ({
    persistAuthData: vi.fn(),
    clearPersistedAuthData: vi.fn(),
    updateTokenExpiry: vi.fn(),
    updateAbsoluteTokenExpiry: vi.fn(),
    isAbsoluteExpiryPassed: vi.fn(() => false),
    isTokenValid: vi.fn(() => true),
    getTimeUntilExpiry: vi.fn(() => 0),
}));

const makeUser = (overrides: Partial<User> = {}): User =>
    ({
        id: 1,
        username: 'alice',
        email: 'alice@example.com',
        role: 'user',
        roles: [],
        permissions: [],
        preferences: {
            language: 'en',
            timezone: 'UTC',
            theme: 'system',
            notifications: { email: true, browser: true, sharing: true, security: true },
        },
        lastLogin: '2026-06-05T00:00:00Z',
        ...overrides,
    }) as User;

// Profile-shaped fixture matching what authService.getProfile() resolves to.
const profileFixture = (user: User) => ({ ...user, impersonation: undefined });

// Replaces window.location with a plain, mutable object so logout()/checkAuth()
// assigning `window.location.href` and reading `window.location.pathname`
// don't trigger jsdom's "Not implemented: navigation" error. Restored after
// every test. Mirrors the pattern already used in
// src/components/ui/__tests__/ErrorBoundary.test.tsx.
const originalLocation = window.location;
let locationMock: { href: string; pathname: string };

function stubLocation(pathname = '/dashboard') {
    locationMock = { href: '', pathname };
    Object.defineProperty(window, 'location', {
        configurable: true,
        value: locationMock,
    });
}

describe('authStore', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        stubLocation();
        useAuthStore.setState({
            user: null,
            isAuthenticated: false,
            impersonatedBy: null,
            isLoading: false,
            hasCheckedAuth: false,
            error: null,
            mfaChallenge: null,
        });
    });

    afterEach(() => {
        Object.defineProperty(window, 'location', {
            configurable: true,
            value: originalLocation,
        });
    });

    describe('login response shaping', () => {
        const baseResponse: LoginResponse = {
            expires_at: '2030-01-01T00:00:00Z',
            user_id: 5,
            username: 'bob',
            email: 'bob@example.com',
        };

        it('defaults role/roles/permissions and carries account_state through when present', async () => {
            vi.mocked(authService.login).mockResolvedValueOnce({
                ...baseResponse,
                account_state: 'pending_review',
                password_change_required: true,
            });

            await useAuthStore.getState().login({ username: 'bob', password: 'pw' } as never);

            const user = useAuthStore.getState().user;
            expect(user?.role).toBe('user');
            expect(user?.roles).toEqual([]);
            expect(user?.permissions).toEqual([]);
            expect(user?.accountState).toBe('pending_review');
            expect(user?.passwordChangeRequired).toBe(true);
        });

        it('omits accountState entirely when the response has no account_state', async () => {
            vi.mocked(authService.login).mockResolvedValueOnce(baseResponse);

            await useAuthStore.getState().login({ username: 'bob', password: 'pw' } as never);

            const user = useAuthStore.getState().user;
            expect(user).not.toHaveProperty('accountState');
            expect(user?.passwordChangeRequired).toBe(false);
        });

        it("falls back to a generic 'Login failed' message when the rejection isn't an Error instance", async () => {
            // authService.login can reject with whatever the underlying axios/error
            // path throws; the store's `error instanceof Error ? ... : 'Login failed'`
            // fallback only fires for the non-Error shape, which no other test drives.
            vi.mocked(authService.login).mockRejectedValueOnce('network exploded');

            await expect(useAuthStore.getState().login({ username: 'bob', password: 'pw' } as never)).rejects.toBe(
                'network exploded'
            );

            expect(useAuthStore.getState().error).toBe('Login failed');
        });
    });

    // #2442: login() previously ignored mfa_required entirely and built a User
    // from an all-undefined response, landing isAuthenticated: true with no
    // real session. These assert the fix: a pending challenge instead, and
    // isAuthenticated/user left untouched.
    describe('login (mfa_required)', () => {
        it('stores a pending mfaChallenge and does not authenticate, on an mfa_required response', async () => {
            vi.mocked(authService.login).mockResolvedValueOnce({
                mfa_required: true,
                mfa_challenge: 'chal-abc123',
                totp_available: true,
                webauthn_available: false,
            } as never);

            await useAuthStore.getState().login({ username: 'bob', password: 'pw' } as never);

            const state = useAuthStore.getState();
            expect(state.isAuthenticated).toBe(false);
            expect(state.user).toBeNull();
            expect(state.isLoading).toBe(false);
            expect(state.error).toBeNull();
            expect(state.mfaChallenge).toEqual({
                challenge: 'chal-abc123',
                totpAvailable: true,
                webauthnAvailable: false,
            });
        });

        it('defaults totpAvailable/webauthnAvailable to false and challenge to "" when the fields are absent', async () => {
            vi.mocked(authService.login).mockResolvedValueOnce({ mfa_required: true } as never);

            await useAuthStore.getState().login({ username: 'bob', password: 'pw' } as never);

            expect(useAuthStore.getState().mfaChallenge).toEqual({
                challenge: '',
                totpAvailable: false,
                webauthnAvailable: false,
            });
        });

        it('clears any previous mfaChallenge at the start of a fresh login() call', async () => {
            useAuthStore.setState({
                mfaChallenge: { challenge: 'stale', totpAvailable: true, webauthnAvailable: false },
            });
            vi.mocked(authService.login).mockResolvedValueOnce({
                expires_at: '2030-01-01T00:00:00Z',
                user_id: 5,
                username: 'bob',
                email: 'bob@example.com',
            } as never);

            await useAuthStore.getState().login({ username: 'bob', password: 'pw' } as never);

            expect(useAuthStore.getState().mfaChallenge).toBeNull();
            expect(useAuthStore.getState().isAuthenticated).toBe(true);
        });
    });

    describe('verifyMfa', () => {
        const baseResponse: LoginResponse = {
            expires_at: '2030-01-01T00:00:00Z',
            user_id: 5,
            username: 'bob',
            email: 'bob@example.com',
        };

        beforeEach(() => {
            useAuthStore.setState({
                mfaChallenge: { challenge: 'chal-abc123', totpAvailable: true, webauthnAvailable: false },
            });
        });

        it('rejects with no pending challenge, without calling the API', async () => {
            useAuthStore.setState({ mfaChallenge: null });

            await expect(useAuthStore.getState().verifyMfa('123456')).rejects.toThrow(
                'No pending MFA challenge to verify'
            );
            expect(authService.verifyMfa).not.toHaveBeenCalled();
        });

        it('calls authService.verifyMfa with the stored challenge and the code, then lands the session', async () => {
            vi.mocked(authService.verifyMfa).mockResolvedValueOnce(baseResponse);

            await useAuthStore.getState().verifyMfa('123456');

            expect(authService.verifyMfa).toHaveBeenCalledWith('chal-abc123', '123456');
            const state = useAuthStore.getState();
            expect(state.isAuthenticated).toBe(true);
            expect(state.user?.username).toBe('bob');
            expect(state.mfaChallenge).toBeNull();
            expect(state.isLoading).toBe(false);
            expect(state.error).toBeNull();
        });

        it('surfaces the rejection message and keeps the challenge for a retry on failure', async () => {
            vi.mocked(authService.verifyMfa).mockRejectedValueOnce(new Error('Invalid or expired code'));

            await expect(useAuthStore.getState().verifyMfa('000000')).rejects.toThrow('Invalid or expired code');

            const state = useAuthStore.getState();
            expect(state.isAuthenticated).toBe(false);
            expect(state.error).toBe('Invalid or expired code');
            // Deliberately still set — the user can retry against the same
            // challenge without being bounced back to the username/password step.
            expect(state.mfaChallenge).toEqual({
                challenge: 'chal-abc123',
                totpAvailable: true,
                webauthnAvailable: false,
            });
        });

        it("falls back to a generic 'Verification failed' message when the rejection isn't an Error instance", async () => {
            vi.mocked(authService.verifyMfa).mockRejectedValueOnce('network exploded');

            await expect(useAuthStore.getState().verifyMfa('123456')).rejects.toBe('network exploded');
            expect(useAuthStore.getState().error).toBe('Verification failed');
        });
    });

    describe('clearMfaChallenge', () => {
        it('clears a pending challenge and any error', () => {
            useAuthStore.setState({
                mfaChallenge: { challenge: 'chal-abc123', totpAvailable: true, webauthnAvailable: false },
                error: 'Invalid or expired code',
            });

            useAuthStore.getState().clearMfaChallenge();

            expect(useAuthStore.getState().mfaChallenge).toBeNull();
            expect(useAuthStore.getState().error).toBeNull();
        });
    });

    describe('completeSetup (ADR-028: land a setup-link consume response without re-authenticating)', () => {
        it('authenticates the user synchronously and persists bookkeeping, forcing isLoading false', () => {
            // Start from a deliberately "mid-request" isLoading:true to prove
            // completeSetup unconditionally settles it to false.
            useAuthStore.setState({ isLoading: true });

            const response: LoginResponse = {
                expires_at: '2030-01-01T00:00:00Z',
                absolute_expires_at: '2030-06-01T00:00:00Z',
                user_id: 9,
                username: 'carol',
                email: 'carol@example.com',
                display_name: 'Carol Setup',
            };

            useAuthStore.getState().completeSetup(response);

            const state = useAuthStore.getState();
            expect(state.isAuthenticated).toBe(true);
            expect(state.isLoading).toBe(false);
            expect(state.error).toBeNull();
            expect(state.user?.username).toBe('carol');
            expect(state.user?.displayName).toBe('Carol Setup');
            expect(authUtils.persistAuthData).toHaveBeenCalledWith(
                expect.objectContaining({
                    expiresAt: '2030-01-01T00:00:00Z',
                    absoluteExpiresAt: '2030-06-01T00:00:00Z',
                })
            );
        });

        it('carries account_state through onto the user when the response includes it', () => {
            const response: LoginResponse = {
                expires_at: '2030-01-01T00:00:00Z',
                user_id: 10,
                username: 'dana',
                email: 'dana@example.com',
                account_state: 'pending_review',
            };

            useAuthStore.getState().completeSetup(response);

            expect(useAuthStore.getState().user?.accountState).toBe('pending_review');
        });
    });

    describe('completeSSOLogin (backend already set the session cookie on its redirect; this just loads the profile)', () => {
        it('populates the user via checkAuth and persists the passed-in expiry bookkeeping', async () => {
            vi.mocked(authService.getProfile).mockResolvedValueOnce(profileFixture(makeUser({ username: 'dora' })));

            await useAuthStore.getState().completeSSOLogin('2031-01-01T00:00:00Z', '2031-06-01T00:00:00Z');

            const state = useAuthStore.getState();
            expect(state.isAuthenticated).toBe(true);
            expect(state.isLoading).toBe(false);
            expect(state.user?.username).toBe('dora');
            expect(authUtils.persistAuthData).toHaveBeenCalledWith({
                user: expect.objectContaining({ username: 'dora' }),
                expiresAt: '2031-01-01T00:00:00Z',
                absoluteExpiresAt: '2031-06-01T00:00:00Z',
            });
        });

        it('defaults expiresAt to an empty string when the SSO callback fragment omits it', async () => {
            vi.mocked(authService.getProfile).mockResolvedValueOnce(profileFixture(makeUser({ username: 'dora' })));

            await useAuthStore.getState().completeSSOLogin();

            expect(authUtils.persistAuthData).toHaveBeenCalledWith(
                expect.objectContaining({ expiresAt: '', absoluteExpiresAt: undefined })
            );
        });

        it('does not persist anything when the profile fetch fails (checkAuth clears the user)', async () => {
            vi.mocked(authService.getProfile).mockRejectedValueOnce(new Error('unauthorized'));

            await useAuthStore.getState().completeSSOLogin('2031-01-01T00:00:00Z');

            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
            expect(authUtils.persistAuthData).not.toHaveBeenCalled();
        });
    });

    describe('endSessionForReauth', () => {
        it('drops local state and goes to sign-in with the reauth notice, without calling the server (the session is already gone)', () => {
            useAuthStore.setState({ user: makeUser(), isAuthenticated: true, error: 'stale error' });

            useAuthStore.getState().endSessionForReauth();

            expect(authService.logout).not.toHaveBeenCalled();
            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
            expect(state.error).toBeNull();
            expect(authUtils.clearPersistedAuthData).toHaveBeenCalledOnce();
            expect(window.location.href).toBe('/login?reauth=1');
        });
    });

    describe('logout', () => {
        it('clears local state, wipes persisted data, and redirects to /login on success', async () => {
            useAuthStore.setState({
                user: makeUser(),
                isAuthenticated: true,
                impersonatedBy: { adminId: 1, adminUsername: 'admin' },
                error: 'stale error',
            });
            vi.mocked(authService.logout).mockResolvedValueOnce(undefined);

            await useAuthStore.getState().logout();

            expect(authService.logout).toHaveBeenCalledOnce();
            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
            expect(state.impersonatedBy).toBeNull();
            expect(state.isLoading).toBe(false);
            expect(state.error).toBeNull();
            expect(authUtils.clearPersistedAuthData).toHaveBeenCalledOnce();
            expect(window.location.href).toBe('/login');
        });

        it('still clears local state and redirects even when the server logout call fails, but surfaces the failure via a logout_error query param instead of silently succeeding (G65)', async () => {
            useAuthStore.setState({ user: makeUser(), isAuthenticated: true });
            vi.mocked(authService.logout).mockRejectedValueOnce(new Error('network blip'));
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

            await useAuthStore.getState().logout();

            expect(warnSpy).toHaveBeenCalledWith('Logout request failed:', expect.any(Error));
            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
            expect(authUtils.clearPersistedAuthData).toHaveBeenCalledOnce();
            // G65: pre-fix this asserted plain '/login' — the exact same URL as
            // the success path — meaning a failed server-side logout was
            // indistinguishable from a clean one. LoginPage reads this param
            // (mirroring the existing sso_error pattern) and shows a banner.
            expect(window.location.href).toBe('/login?logout_error=1');

            warnSpy.mockRestore();
        });

        it('does NOT append logout_error when the server logout call succeeds (only a genuine failure is surfaced)', async () => {
            useAuthStore.setState({ user: makeUser(), isAuthenticated: true });
            vi.mocked(authService.logout).mockResolvedValueOnce(undefined);

            await useAuthStore.getState().logout();

            expect(window.location.href).toBe('/login');
        });
    });

    describe('persisted snapshot never carries permissions (G65)', () => {
        // Regression coverage for the two G65 gaps together: (1) logout()
        // clearing the whole 'auth-storage' key on every session-ending path
        // that runs through it, and (2) the persist middleware's own
        // partialize() never writing `permissions` to localStorage in the
        // first place — so even a session-ending path that DOESN'T run any
        // client-side code at all (tab crash, forced browser close) can't
        // leave a stale permissions snapshot behind, because nothing
        // sensitive was ever written to disk to begin with.
        function withLocalStorageBacking() {
            const backing = new Map<string, string>();
            vi.mocked(localStorage.getItem).mockImplementation((key: string) => backing.get(key) ?? null);
            vi.mocked(localStorage.setItem).mockImplementation((key: string, value: string) => {
                backing.set(key, value);
            });
            vi.mocked(localStorage.removeItem).mockImplementation((key: string) => {
                backing.delete(key);
            });
            return backing;
        }

        it('never writes permissions to the auth-storage entry, even while the session is active', () => {
            withLocalStorageBacking();

            useAuthStore.setState({
                user: makeUser({ permissions: ['secrets:read', 'secrets:write', 'admin:users'] }),
                isAuthenticated: true,
            });

            const raw = localStorage.getItem('auth-storage');
            expect(raw).not.toBeNull();
            const parsed = JSON.parse(raw as string);
            expect(parsed.state.user.permissions).toEqual([]);
            // Sanity check: the in-memory store still has the real permissions
            // (only the on-disk copy is scrubbed) — checkAuth()/login() still
            // populate the real value for hasPermission()/route guards to use.
            expect(useAuthStore.getState().user?.permissions).toEqual(['secrets:read', 'secrets:write', 'admin:users']);
        });

        it('leaves no stale permissions in localStorage after a non-logout session-ending path (checkAuth detecting a server-side revocation)', async () => {
            const backing = withLocalStorageBacking();

            // Start from an authenticated session whose on-disk snapshot
            // already exists (permissions scrubbed per the above, but present).
            useAuthStore.setState({
                user: makeUser({ permissions: ['secrets:read'] }),
                isAuthenticated: true,
            });
            expect(backing.has('auth-storage')).toBe(true);

            // Simulate the session ending some way OTHER than the user
            // clicking "log out" — e.g. the server revoked the session and
            // the next checkAuth() (inactivity-timeout re-check, tab focus,
            // multi-tab sync, etc.) discovers it via a 401. This is the same
            // clearPersistedAuthData() call the inactivity-timeout and
            // 401-forced-logout paths ultimately reach via logout(); checkAuth
            // reaches it directly on its own failure branch.
            vi.mocked(authService.getProfile).mockRejectedValueOnce(new Error('unauthorized'));
            await useAuthStore.getState().checkAuth();

            expect(authUtils.clearPersistedAuthData).toHaveBeenCalled();
            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
        });
    });

    describe('refreshToken', () => {
        it('advances the token expiry bookkeeping and clears any stale error on success', async () => {
            useAuthStore.setState({ error: 'stale error' });
            const response: RefreshTokenResponse = {
                expires_at: '2027-01-01T00:00:00Z',
                absolute_expires_at: '2027-06-01T00:00:00Z',
            };
            vi.mocked(authService.refreshToken).mockResolvedValueOnce(response);

            await useAuthStore.getState().refreshToken();

            expect(useAuthStore.getState().error).toBeNull();
            expect(authUtils.updateTokenExpiry).toHaveBeenCalledWith('2027-01-01T00:00:00Z');
            expect(authUtils.updateAbsoluteTokenExpiry).toHaveBeenCalledWith('2027-06-01T00:00:00Z');
        });

        it('logs the user out and rethrows the original error when the refresh request itself fails', async () => {
            vi.mocked(authService.logout).mockResolvedValueOnce(undefined);
            vi.mocked(authService.refreshToken).mockRejectedValueOnce(new Error('refresh rejected'));

            await expect(useAuthStore.getState().refreshToken()).rejects.toThrow('refresh rejected');

            expect(authService.logout).toHaveBeenCalledOnce();
            expect(window.location.href).toBe('/login');
        });

        it('skips the network round-trip and logs out exactly once when the absolute session ceiling has passed', async () => {
            // Regression test: the isAbsoluteExpiryPassed() early-exit throw lives
            // in its own inner try/catch, separate from the one wrapping the actual
            // authService.refreshToken() call. That keeps get().logout() from being
            // invoked a second time by the outer catch when the thrown
            // "Session lifetime exceeded" error propagates.
            vi.mocked(authUtils.isAbsoluteExpiryPassed).mockReturnValueOnce(true);
            vi.mocked(authService.logout).mockResolvedValue(undefined);

            await expect(useAuthStore.getState().refreshToken()).rejects.toThrow('Session lifetime exceeded');

            expect(authService.refreshToken).not.toHaveBeenCalled();
            expect(authService.logout).toHaveBeenCalledOnce();
        });

        it('coalesces concurrent callers onto a single in-flight POST /auth/refresh', async () => {
            let resolveRefresh!: (value: RefreshTokenResponse) => void;
            const pending = new Promise<RefreshTokenResponse>((resolve) => {
                resolveRefresh = resolve;
            });
            vi.mocked(authService.refreshToken).mockReturnValueOnce(pending);

            const first = useAuthStore.getState().refreshToken();
            const second = useAuthStore.getState().refreshToken();

            resolveRefresh({ expires_at: '2027-01-01T00:00:00Z' });
            await expect(Promise.all([first, second])).resolves.toBeDefined();

            expect(authService.refreshToken).toHaveBeenCalledTimes(1);
        });
    });

    describe('checkAuth', () => {
        it('populates the user, marks hasCheckedAuth true, and reports no impersonation on a plain profile', async () => {
            vi.mocked(authService.getProfile).mockResolvedValueOnce(profileFixture(makeUser({ username: 'erin' })));

            await useAuthStore.getState().checkAuth();

            const state = useAuthStore.getState();
            expect(state.isAuthenticated).toBe(true);
            expect(state.isLoading).toBe(false);
            expect(state.hasCheckedAuth).toBe(true);
            expect(state.user?.username).toBe('erin');
            expect(state.impersonatedBy).toBeNull();
        });

        it('redirects to /login when the profile fetch fails and the user is elsewhere', async () => {
            stubLocation('/secrets');
            vi.mocked(authService.getProfile).mockRejectedValueOnce(new Error('unauthorized'));

            await useAuthStore.getState().checkAuth();

            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
            expect(state.hasCheckedAuth).toBe(true);
            expect(authUtils.clearPersistedAuthData).toHaveBeenCalledOnce();
            expect(window.location.href).toBe('/login');
        });

        it('does not re-navigate when the profile fetch fails while already on /login', async () => {
            stubLocation('/login');
            vi.mocked(authService.getProfile).mockRejectedValueOnce(new Error('unauthorized'));

            await useAuthStore.getState().checkAuth();

            expect(window.location.href).toBe('');
            expect(useAuthStore.getState().hasCheckedAuth).toBe(true);
        });

        it('applies field defaults (role/roles/permissions/preferences/lastLogin) when the profile omits them', async () => {
            vi.mocked(authService.getProfile).mockResolvedValueOnce({
                id: 42,
                username: 'minimal',
                email: 'minimal@example.com',
                // role, roles, permissions, preferences, lastLogin, passwordChangeRequired,
                // impersonation all deliberately omitted.
            } as never);

            const before = Date.now();
            await useAuthStore.getState().checkAuth();
            const after = Date.now();

            const user = useAuthStore.getState().user;
            expect(user?.role).toBe('user');
            expect(user?.roles).toEqual([]);
            expect(user?.permissions).toEqual([]);
            expect(user?.preferences).toEqual({
                language: 'en',
                timezone: 'UTC',
                theme: 'system',
                notifications: { email: true, browser: true, sharing: true, security: true },
            });
            expect(user?.passwordChangeRequired).toBe(false);
            // lastLogin defaults to "now" when the profile omits it.
            const lastLoginMs = new Date(user!.lastLogin).getTime();
            expect(lastLoginMs).toBeGreaterThanOrEqual(before);
            expect(lastLoginMs).toBeLessThanOrEqual(after);
        });

        it('re-entrancy guard: a checkAuth() call in flight makes a concurrent call a no-op', async () => {
            let resolveProfile!: (value: ReturnType<typeof profileFixture>) => void;
            const pending = new Promise<ReturnType<typeof profileFixture>>((resolve) => {
                resolveProfile = resolve;
            });
            vi.mocked(authService.getProfile).mockReturnValueOnce(pending);

            const first = useAuthStore.getState().checkAuth();
            const second = useAuthStore.getState().checkAuth();

            resolveProfile(profileFixture(makeUser({ username: 'frank' })));
            await Promise.all([first, second]);

            expect(authService.getProfile).toHaveBeenCalledTimes(1);
            expect(useAuthStore.getState().user?.username).toBe('frank');
        });
    });

    describe('clearPasswordChangeRequired (ADR-025: lift the password-change gate once changed)', () => {
        it('flips the flag to false on the current user, preserving other fields', () => {
            useAuthStore.setState({ user: makeUser({ username: 'gina', passwordChangeRequired: true }) });

            useAuthStore.getState().clearPasswordChangeRequired();

            const user = useAuthStore.getState().user;
            expect(user?.passwordChangeRequired).toBe(false);
            expect(user?.username).toBe('gina');
        });

        it('is a no-op when there is no current user', () => {
            useAuthStore.setState({ user: null });

            expect(() => useAuthStore.getState().clearPasswordChangeRequired()).not.toThrow();
            expect(useAuthStore.getState().user).toBeNull();
        });
    });

    describe('shouldRefreshToken helper (wraps utils/auth getTimeUntilExpiry)', () => {
        it('is true when the token expires within the next 5 minutes', () => {
            vi.mocked(authUtils.getTimeUntilExpiry).mockReturnValueOnce(60_000);
            expect(shouldRefreshToken()).toBe(true);
        });

        it('is false when the token has already expired (0 remaining)', () => {
            vi.mocked(authUtils.getTimeUntilExpiry).mockReturnValueOnce(0);
            expect(shouldRefreshToken()).toBe(false);
        });

        it('is false when the token has more than 5 minutes left', () => {
            vi.mocked(authUtils.getTimeUntilExpiry).mockReturnValueOnce(10 * 60 * 1000);
            expect(shouldRefreshToken()).toBe(false);
        });
    });

    describe('multi-tab storage listener', () => {
        // Mirrors the backing-map technique from multiTabSync.test.ts: the global
        // localStorage mock (src/test/setup.ts) is a bare vi.fn() with no backing
        // store, so getItem needs to actually reflect what setItem wrote for the
        // rehydrate-on-storage-event listener under test to have anything to read.
        function mkStorageEvent(key: string | null): Event {
            return Object.assign(new Event('storage'), { key });
        }

        beforeEach(() => {
            const backing = new Map<string, string>();
            vi.mocked(localStorage.getItem).mockImplementation((key: string) => backing.get(key) ?? null);
            vi.mocked(localStorage.setItem).mockImplementation((key: string, value: string) => {
                backing.set(key, value);
            });
        });

        it('ignores a storage event for an unrelated key (neither auth-storage nor a clear signal)', () => {
            useAuthStore.setState({ isAuthenticated: true, user: makeUser({ username: 'kept' }) });

            window.dispatchEvent(mkStorageEvent('some-other-key'));

            // Synchronous: no rehydrate/checkAuth should have been triggered.
            expect(authService.getProfile).not.toHaveBeenCalled();
            expect(useAuthStore.getState().user?.username).toBe('kept');
        });

        it('re-validates with the server after accepting cross-tab state written under auth-storage', async () => {
            vi.mocked(authService.getProfile).mockResolvedValueOnce(
                profileFixture(makeUser({ username: 'other-tab' }))
            );
            localStorage.setItem('auth-storage', JSON.stringify({ state: { isAuthenticated: true }, version: 0 }));

            window.dispatchEvent(mkStorageEvent('auth-storage'));
            // The listener chains persist.rehydrate().then(() => checkAuth()); flush both.
            await Promise.resolve();
            await Promise.resolve();
            await Promise.resolve();

            expect(authService.getProfile).toHaveBeenCalled();
        });

        it('re-validates on a storage.clear() signal (key: null)', async () => {
            vi.mocked(authService.getProfile).mockResolvedValueOnce(profileFixture(makeUser({ username: 'cleared' })));
            useAuthStore.setState({ isAuthenticated: true });

            window.dispatchEvent(mkStorageEvent(null));
            await Promise.resolve();
            await Promise.resolve();
            await Promise.resolve();

            expect(authService.getProfile).toHaveBeenCalled();
        });

        it('resets hasCheckedAuth to false synchronously, before the async re-validation resolves (matches the initial-mount pending-state guard)', async () => {
            // A same-origin-writable localStorage value (e.g. written by a
            // malicious extension content script or XSS in a sibling tab)
            // could claim an elevated role. Route guards (ProtectedRoute/
            // AdminRoute) gate purely on hasCheckedAuth + isAuthenticated +
            // user.role, so this must go pending immediately — not just after
            // checkAuth() eventually corrects it.
            let resolveProfile!: (v: ReturnType<typeof profileFixture>) => void;
            vi.mocked(authService.getProfile).mockReturnValueOnce(
                new Promise((resolve) => {
                    resolveProfile = resolve;
                })
            );
            useAuthStore.setState({ hasCheckedAuth: true, isAuthenticated: true, user: makeUser({ role: 'user' }) });
            localStorage.setItem(
                'auth-storage',
                JSON.stringify({ state: { isAuthenticated: true, user: makeUser({ role: 'admin' }) }, version: 0 })
            );

            window.dispatchEvent(mkStorageEvent('auth-storage'));

            // Synchronous assertion — before rehydrate()/checkAuth() have had
            // any chance to resolve.
            expect(useAuthStore.getState().hasCheckedAuth).toBe(false);

            resolveProfile(profileFixture(makeUser({ username: 'other-tab', role: 'admin' })));
            await Promise.resolve();
            await Promise.resolve();
            await Promise.resolve();

            expect(useAuthStore.getState().hasCheckedAuth).toBe(true);
            expect(authService.getProfile).toHaveBeenCalled();
        });

        it('settles hasCheckedAuth back to true when the rehydrated state is unauthenticated (checkAuth never runs to do it)', async () => {
            useAuthStore.setState({ hasCheckedAuth: true, isAuthenticated: true });
            // e.g. a logout in the other tab clears auth-storage to a logged-out shape.
            localStorage.setItem(
                'auth-storage',
                JSON.stringify({ state: { isAuthenticated: false, user: null }, version: 0 })
            );

            window.dispatchEvent(mkStorageEvent('auth-storage'));
            expect(useAuthStore.getState().hasCheckedAuth).toBe(false);

            await Promise.resolve();
            await Promise.resolve();
            await Promise.resolve();

            expect(useAuthStore.getState().hasCheckedAuth).toBe(true);
            expect(authService.getProfile).not.toHaveBeenCalled();
        });
    });

    describe('isTokenExpired helper (wraps utils/auth isTokenValid)', () => {
        it('is true when isTokenValid() reports false', () => {
            vi.mocked(authUtils.isTokenValid).mockReturnValueOnce(false);
            expect(isTokenExpired()).toBe(true);
        });

        it('is false when isTokenValid() reports true', () => {
            vi.mocked(authUtils.isTokenValid).mockReturnValueOnce(true);
            expect(isTokenExpired()).toBe(false);
        });
    });

    describe('module-level browser guard (typeof window !== "undefined")', () => {
        // This suite runs under jsdom, where `window` always exists, so the
        // `typeof window !== 'undefined'` guard around the cross-tab storage
        // listener registration (bottom of authStore.ts) only ever takes its
        // true branch through every other test in this file. Force a fresh
        // module evaluation with `window` shadowed to undefined — simulating
        // the SSR/non-browser context the guard exists for — to prove the
        // module still loads cleanly and skips registering the listener,
        // without touching product code to make the branch reachable another
        // way.
        it('reimporting the module without a global window does not throw and skips wiring the storage listener', async () => {
            const originalWindow = globalThis.window;
            vi.resetModules();
            // @ts-expect-error deliberately simulating an environment without `window`
            globalThis.window = undefined;

            try {
                const mod = await import('../authStore');
                expect(mod.useAuthStore).toBeDefined();
                expect(mod.useAuthStore.getState().isLoading).toBe(true);
            } finally {
                globalThis.window = originalWindow;
            }
        });
    });
});
