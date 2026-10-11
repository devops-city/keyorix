import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { AuthState, User, LoginFormData, LoginResponse, ImpersonatedBy, MfaChallengeState } from '../types';
import { authService } from '../services/auth';
import {
    persistAuthData,
    clearPersistedAuthData,
    updateTokenExpiry,
    updateAbsoluteTokenExpiry,
    isAbsoluteExpiryPassed,
    isTokenValid,
    getTimeUntilExpiry,
} from '../utils/auth';

interface AuthStore extends AuthState {
    // Impersonation state is now derived entirely from the server (GET
    // /auth/profile's `impersonation` field, populated from the session — see
    // checkAuth) rather than tracked client-side. Under cookie auth there is no
    // client-readable token to stash/swap, so "return to admin" is resolved
    // server-side by the backend's OriginalSessionID linkage; the client's job
    // is just to call the endpoints and re-sync via checkAuth().
    impersonatedBy: ImpersonatedBy | null;

    // Non-null between a login() call that got back `mfa_required` and either
    // verifyMfa() succeeding or clearMfaChallenge() abandoning it. #2442: this
    // is what login() previously dropped on the floor, landing the UI in a
    // bogus "authenticated" state built from an all-undefined response.
    mfaChallenge: MfaChallengeState | null;

    // Actions
    login: (credentials: LoginFormData) => Promise<void>;
    // Completes a pending mfaChallenge with a TOTP or recovery code, then lands
    // the session exactly like a non-MFA login would.
    verifyMfa: (code: string) => Promise<void>;
    // Abandons a pending mfaChallenge (e.g. "back to login") without verifying.
    clearMfaChallenge: () => void;
    // ADR-028: land the user logged in from a setup-link consume response (which is
    // login-shaped) without re-authenticating with a password.
    completeSetup: (response: LoginResponse) => void;
    // Land the user logged in from an SSO callback: the backend has already set
    // the session cookie on its redirect response, so this just loads the
    // profile and persists the expiry bookkeeping.
    completeSSOLogin: (expiresAt?: string, absoluteExpiresAt?: string) => Promise<void>;
    logout: () => Promise<void>;
    // The server has already ended this session (setup finished, RECOVER-1): drop the local
    // state without calling the server and go to the sign-in page with an explanation.
    endSessionForReauth: () => void;
    refreshToken: () => Promise<void>;
    checkAuth: () => Promise<void>;
    clearError: () => void;
    setUser: (user: User | null) => void;
    setLoading: (loading: boolean) => void;
    setError: (error: string | null) => void;
    // ADR-025: lift the password-change gate once the user has changed it.
    clearPasswordChangeRequired: () => void;
    // End impersonation: tell the server (which restores the admin's original
    // session cookie, or clears it if that session is gone), then re-sync.
    endImpersonation: () => Promise<void>;
}

// buildUserFromLoginResponse is the shared shaping logic behind every path
// that lands an authenticated session from a login-shaped response: login()'s
// non-MFA branch, verifyMfa()'s success branch, and completeSetup(). Kept as
// a pure function (no `set`) so it can't silently diverge between the three
// call sites the way three independent copies eventually would.
function buildUserFromLoginResponse(response: LoginResponse): User {
    return {
        id: response.user_id,
        username: response.username,
        displayName: response.display_name || response.username,
        email: response.email,
        role: response.role || 'user',
        roles: response.roles || [],
        permissions: response.permissions || [],
        preferences: {
            language: 'en',
            timezone: 'UTC',
            theme: 'system',
            notifications: { email: true, browser: true, sharing: true, security: true },
        },
        lastLogin: new Date().toISOString(),
        passwordChangeRequired: response.password_change_required || false,
        ...(response.account_state ? { accountState: response.account_state } : {}),
    };
}

// Shared in-flight refresh promise so concurrent callers coalesce onto a single
// POST /auth/refresh (see refreshToken). Module-scoped: there is one auth store.
let inFlightRefresh: Promise<void> | null = null;

// Re-entrancy guard for checkAuth, separate from isLoading — isLoading starts
// true by design (to hold route guards in the spinner state until the first
// check resolves), so gating checkAuth on isLoading would make its own very
// first call a no-op.
let checkAuthInFlight = false;

export const useAuthStore = create<AuthStore>()(
    persist(
        (set, get) => {
            // Shared by login()'s non-MFA branch, verifyMfa()'s success branch, and
            // completeSetup() — builds the User, flips isAuthenticated, and persists
            // the non-credential expiry bookkeeping. Needs `set`, so it lives here
            // rather than alongside the pure buildUserFromLoginResponse above.
            const landAuthenticatedSession = (response: LoginResponse) => {
                const user = buildUserFromLoginResponse(response);
                set({
                    user,
                    isAuthenticated: true,
                    isLoading: false,
                    error: null,
                    mfaChallenge: null,
                });
                persistAuthData({
                    user,
                    expiresAt: response.expires_at,
                    absoluteExpiresAt: response.absolute_expires_at,
                });
            };

            return {
                // Initial state — isLoading: true holds every route guard in the
                // spinner state until rehydrate() + checkAuth() have both resolved.
                // skipHydration (below) prevents the persist middleware from loading
                // stale localStorage values synchronously before the server validates
                // the session, which would let a manipulated auth-storage entry pass
                // ProtectedRoute before checkAuth fires.
                user: null,
                isAuthenticated: false,
                impersonatedBy: null,
                isLoading: true,
                hasCheckedAuth: false,
                error: null,
                mfaChallenge: null,

                // Actions
                login: async (credentials: LoginFormData) => {
                    set({ isLoading: true, error: null, mfaChallenge: null });

                    try {
                        const response = await authService.login(credentials);

                        // #2442: a correct password on an MFA-enabled account returns this
                        // shape INSTEAD of the identity fields landAuthenticatedSession
                        // needs — every field below is undefined when mfa_required is true,
                        // so this must be checked before touching any of them. Not an
                        // error: stop here with a pending challenge and let the UI render
                        // a code-entry step; isAuthenticated stays false.
                        if (response.mfa_required) {
                            set({
                                isLoading: false,
                                error: null,
                                mfaChallenge: {
                                    challenge: response.mfa_challenge ?? '',
                                    totpAvailable: !!response.totp_available,
                                    webauthnAvailable: !!response.webauthn_available,
                                },
                            });
                            return;
                        }

                        landAuthenticatedSession(response);
                    } catch (error) {
                        const errorMessage = error instanceof Error ? error.message : 'Login failed';
                        set({
                            user: null,
                            isAuthenticated: false,
                            isLoading: false,
                            error: errorMessage,
                        });
                        throw error;
                    }
                },

                verifyMfa: async (code: string) => {
                    const challenge = get().mfaChallenge;
                    if (!challenge) {
                        // Programmer error (called with no pending challenge) — not a
                        // server-reported failure, so not routed through `error`.
                        throw new Error('No pending MFA challenge to verify');
                    }
                    set({ isLoading: true, error: null });
                    try {
                        const response = await authService.verifyMfa(challenge.challenge, code);
                        landAuthenticatedSession(response);
                    } catch (error) {
                        // Deliberately just the message authService.verifyMfa surfaced —
                        // see its own doc comment: the backend already collapses wrong
                        // code / expired challenge / account lockout into one generic
                        // string, and this must not try to add its own guess on top.
                        const errorMessage = error instanceof Error ? error.message : 'Verification failed';
                        set({ isLoading: false, error: errorMessage });
                        throw error;
                    }
                },

                clearMfaChallenge: () => {
                    set({ mfaChallenge: null, error: null });
                },

                completeSetup: (response: LoginResponse) => {
                    landAuthenticatedSession(response);
                },

                completeSSOLogin: async (expiresAt?: string, absoluteExpiresAt?: string) => {
                    // The backend already set the session cookie on its redirect response
                    // (see sso.go/saml.go) — nothing to stash here, just load the profile.
                    set({ isLoading: true, error: null });
                    await get().checkAuth(); // populates user, or clears + redirects on failure
                    const user = get().user;
                    if (user) {
                        persistAuthData({
                            user,
                            expiresAt: expiresAt ?? '',
                            absoluteExpiresAt,
                        });
                    }
                },

                logout: async () => {
                    set({ isLoading: true });

                    // G65: track whether the server-side session invalidation
                    // itself failed, so it can be surfaced below instead of
                    // silently reported as a clean logout. authService.logout()
                    // rethrows on failure (it no longer swallows the error
                    // itself); this is the only place that catches it.
                    let serverLogoutFailed = false;
                    try {
                        await authService.logout();
                    } catch (error) {
                        serverLogoutFailed = true;
                        console.warn('Logout request failed:', error);
                    } finally {
                        // Always clear local state regardless of server response —
                        // a failed server-side logout must not trap the user in a
                        // "logged in" UI state.
                        set({
                            user: null,
                            isAuthenticated: false,
                            impersonatedBy: null,
                            isLoading: false,
                            error: null,
                        });

                        // Clear stored data
                        clearPersistedAuthData();
                        // Redirect to login. This is a hard navigation
                        // (window.location.href), so no in-memory React/store
                        // state survives it — a server-side logout failure is
                        // surfaced via a query param instead, mirroring the
                        // sso_error pattern LoginPage already reads. The user
                        // needs to know their session may still be valid
                        // server-side (e.g. on a shared machine) even though the
                        // client has cleared its own local state.
                        window.location.href = serverLogoutFailed ? '/login?logout_error=1' : '/login';
                    }
                },

                endSessionForReauth: () => {
                    set({ user: null, isAuthenticated: false, impersonatedBy: null, isLoading: false, error: null });
                    clearPersistedAuthData();
                    window.location.href = '/login?reauth=1';
                },

                refreshToken: async () => {
                    // Single-flight: several in-flight requests can hit expiry at once.
                    // Without dedup each would POST /auth/refresh and rotate the session
                    // cookie out from under the others (every rotation deletes the prior
                    // session → cascading 401s). Share one refresh across concurrent
                    // callers instead.
                    if (inFlightRefresh) {
                        return inFlightRefresh;
                    }
                    inFlightRefresh = (async () => {
                        try {
                            // Past the absolute ceiling there is nothing to refresh into —
                            // re-authentication is required. Skip the round-trip and log out.
                            if (isAbsoluteExpiryPassed()) {
                                await get().logout();
                                throw new Error('Session lifetime exceeded');
                            }

                            try {
                                const response = await authService.refreshToken();
                                set({ error: null });

                                // Advance the access window and carry the (possibly absent)
                                // ceiling. Note: the field is expires_at to match the backend
                                // payload — reading the old camelCase expiresAt silently stored
                                // undefined and logged the user out on the next request.
                                updateTokenExpiry(response.expires_at);
                                updateAbsoluteTokenExpiry(response.absolute_expires_at);
                            } catch (error) {
                                // If refresh fails, logout user
                                await get().logout();
                                throw error;
                            }
                        } finally {
                            inFlightRefresh = null;
                        }
                    })();
                    return inFlightRefresh;
                },

                checkAuth: async () => {
                    // Always attempt the profile fetch — under cookie auth there is no
                    // client-visible token to gate on; a 401 from the request itself is
                    // the only way to know the session is gone.
                    if (checkAuthInFlight) return;
                    checkAuthInFlight = true;
                    set({ isLoading: true });
                    try {
                        const profile = await authService.getProfile();
                        const user: User = {
                            id: profile.id,
                            username: profile.username,
                            email: profile.email,
                            role: profile.role || 'user',
                            roles: profile.roles || [],
                            permissions: profile.permissions || [],
                            preferences: profile.preferences || {
                                language: 'en',
                                timezone: 'UTC',
                                theme: 'system',
                                notifications: { email: true, browser: true, sharing: true, security: true },
                            },
                            lastLogin: profile.lastLogin || new Date().toISOString(),
                            // Carry the server's flag forward on every reload so
                            // RequirePasswordChange stays effective past the first session.
                            passwordChangeRequired: profile.passwordChangeRequired ?? false,
                        };
                        // impersonation is present only while the session is actively
                        // impersonating — server-validated, not a client claim (see
                        // services/auth.ts's getProfile doc comment).
                        const impersonatedBy = profile.impersonation
                            ? {
                                  adminId: profile.impersonation.admin_id,
                                  adminUsername: profile.impersonation.admin_username,
                                  adminDisplayName: profile.impersonation.admin_display_name,
                              }
                            : null;
                        set({ user, isAuthenticated: true, isLoading: false, error: null, impersonatedBy });
                    } catch {
                        set({ user: null, isAuthenticated: false, isLoading: false, impersonatedBy: null });
                        clearPersistedAuthData();
                        if (window.location.pathname !== '/login') {
                            window.location.href = '/login';
                        }
                    } finally {
                        checkAuthInFlight = false;
                        set({ hasCheckedAuth: true });
                    }
                },

                clearError: () => {
                    set({ error: null });
                },

                setUser: (user: User | null) => {
                    set({ user, isAuthenticated: !!user });
                },

                setLoading: (loading: boolean) => {
                    set({ isLoading: loading });
                },

                setError: (error: string | null) => {
                    set({ error });
                },

                clearPasswordChangeRequired: () => {
                    const { user } = get();
                    if (user) {
                        set({ user: { ...user, passwordChangeRequired: false } });
                    }
                },

                endImpersonation: async () => {
                    // The server restores the admin's original session cookie (or clears
                    // it if that session is gone) as part of this call — see
                    // internal/core/impersonation.go's EndImpersonation and the
                    // OriginalSessionID linkage. The client never holds a second
                    // credential to swap back to; checkAuth() re-syncs to whichever
                    // session is now active. If the request itself fails (network blip,
                    // backend hiccup), this rejects without touching local state, so the
                    // caller (ImpersonationBanner) can offer a retry instead of a false
                    // "you're back to normal" UI.
                    await authService.endImpersonation();
                    await get().checkAuth();
                },
            };
        },
        {
            name: 'auth-storage',
            // G65: never write `permissions` (or other authorization-shaping
            // fields, should this list grow) to localStorage. The persisted
            // snapshot is purely optimistic pre-paint bookkeeping — merge()
            // below forces hasCheckedAuth: false on every rehydrate, and
            // every route guard (ProtectedRoute/AdminRoute) gates its render
            // on hasCheckedAuth, so a rehydrated user is never actually used
            // for an authorization decision before checkAuth() re-validates
            // and repopulates the real permissions into (non-persisted)
            // in-memory state. Scrubbing it here means there is no sensitive
            // permission snapshot left on disk to go stale in the first
            // place — closing the gap for every session-ending path,
            // including ones no client-side code can react to at all (tab
            // crash, forced browser close, server-side revocation before the
            // next request), not just the two functions (logout/checkAuth)
            // that proactively clear the whole `auth-storage` key today.
            partialize: (state) => ({
                user: state.user ? { ...state.user, permissions: [] } : state.user,
                isAuthenticated: state.isAuthenticated,
            }),
            // Prevent synchronous localStorage hydration on store creation.
            // Without this, persist rehydrates before checkAuth runs, so a
            // manipulated auth-storage entry (isAuthenticated: true, role:
            // 'admin') would pass ProtectedRoute/AdminRoute for the first
            // render cycle. useAuth's init() calls rehydrate() + checkAuth()
            // in sequence under isLoading: true, which keeps the guards in the
            // spinner state until the server validates the session.
            skipHydration: true,
            // Force hasCheckedAuth: false as part of the SAME atomic state
            // replacement that applies a rehydrated isAuthenticated/user pair
            // (initial mount OR the cross-tab storage-sync path below) — never
            // as a separate setState call before/after. A separate call would
            // (a) itself go through persist's wrapped setState, which
            // re-serializes and writes the CURRENT (pre-rehydrate) state back
            // to the 'auth-storage' key, clobbering whatever the other tab
            // just wrote there before rehydrate() gets a chance to read it,
            // and (b) leave a render-cycle window where a same-origin-
            // writable (so potentially tampered) rehydrated value is visible
            // under a stale hasCheckedAuth. Folding it into merge() keeps both
            // atomic with the single `set(stateFromStorage, true)` call
            // zustand's hydrate() performs internally.
            merge: (persistedState, currentState) => ({
                ...(currentState as AuthStore),
                ...(persistedState as Partial<AuthStore>),
                hasCheckedAuth: false,
            }),
        }
    )
);

// Multi-tab session sync: zustand's persist writes every state change to the
// 'auth-storage' localStorage key, but only OTHER tabs get a native `storage`
// event for it (the tab that made the change doesn't). Without this, a logout
// or token refresh in one tab left every other open tab holding a stale,
// possibly-revoked token in memory until it happened to make its own request
// and get a 401. Re-hydrating here on every cross-tab change (including a
// storage.clear(), signaled by event.key === null) keeps all tabs in sync with
// whichever tab last wrote the session state.
if (typeof window !== 'undefined') {
    window.addEventListener('storage', (event) => {
        if (event.key === 'auth-storage' || event.key === null) {
            // Match the initial-mount defense: rehydrate() applies
            // hasCheckedAuth: false atomically with the incoming
            // isAuthenticated/user pair (see the `merge` option above), so
            // route guards (ProtectedRoute/AdminRoute — gated purely on
            // hasCheckedAuth + isAuthenticated + user.role) never observe a
            // same-origin-writable (so potentially tampered — e.g. a
            // malicious extension content script or XSS in a sibling tab)
            // rehydrated value before it's marked pending re-validation.
            //
            // Re-validate with the server after accepting cross-tab state.
            // Rehydrate alone is insufficient: a tampered auth-storage written
            // by another same-origin context would set isAuthenticated: true
            // without the session cookie that actually lets API calls through.
            Promise.resolve(useAuthStore.persist.rehydrate()).then(() => {
                const { isAuthenticated } = useAuthStore.getState();
                if (isAuthenticated) {
                    useAuthStore.getState().checkAuth();
                } else {
                    // Nothing to re-validate (e.g. a cross-tab logout/clear) —
                    // checkAuth() won't run to flip this back, so settle it
                    // here instead of leaving guards pending forever.
                    useAuthStore.setState({ hasCheckedAuth: true });
                }
            });
        }
    });
}

// Helper function to check if token needs refresh
export const shouldRefreshToken = (): boolean => {
    const timeUntilExpiry = getTimeUntilExpiry();
    const fiveMinutes = 5 * 60 * 1000;

    return timeUntilExpiry > 0 && timeUntilExpiry < fiveMinutes;
};

// Helper function to check if token is expired
export const isTokenExpired = (): boolean => {
    return !isTokenValid();
};
