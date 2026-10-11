import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router';
import { LoginForm, MfaChallengeForm, PasswordResetForm, useAuth } from '../../features/auth';
import { authService } from '../../services/auth';
import { LoginFormData, PasswordResetRequest } from '../../types';
import { ROUTES } from '../../constants';
import { isSafeReturnTo } from '../../utils/routing';

type AuthMode = 'login' | 'reset' | 'reset-success' | 'mfa';

export const LoginPage: React.FC = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const { login, verifyMfa, mfaChallenge, clearMfaChallenge, isAuthenticated, isLoading, error, clearError } =
        useAuth();

    const [mode, setMode] = useState<AuthMode>('login');
    const [resetLoading, setResetLoading] = useState(false);
    const [resetError, setResetError] = useState<string | null>(null);
    const [ssoProviders, setSsoProviders] = useState<string[]>([]);
    const ssoError = new URLSearchParams(location.search).get('sso_error');
    // G65: authStore.logout() redirects here via window.location.href (a hard
    // navigation, so no in-memory error state survives it) when the
    // server-side session invalidation call itself failed. The client still
    // clears its own local state as a fail-safe, but the user needs to know
    // the server may still consider the old session valid.
    const logoutError = new URLSearchParams(location.search).get('logout_error');
    // The server ended the session because account setup just finished (one-time password
    // replaced / second factor enrolled): not an error, the user only has to sign in again.
    const reauthRequired = new URLSearchParams(location.search).get('reauth') === '1';

    useEffect(() => {
        let active = true;
        authService.getSSOProviders().then((p) => {
            if (active) setSsoProviders(p);
        });
        return () => {
            active = false;
        };
    }, []);

    // Where to land after SSO — preserve the originally-requested route. Validated
    // the same way SSOCompletePage validates its own return_to on the way back
    // (isSafeReturnTo), so a crafted `from` can't be smuggled through either leg.
    const requestedFrom = (location.state as any)?.from?.pathname;
    const safeFrom = requestedFrom && isSafeReturnTo(requestedFrom) ? requestedFrom : ROUTES.DASHBOARD;
    const ssoReturnTo = safeFrom;
    const ssoHref = (name: string) =>
        `/auth/sso/${encodeURIComponent(name)}/login?return_to=${encodeURIComponent(ssoReturnTo)}`;

    useEffect(() => {
        if (isAuthenticated) {
            navigate(safeFrom, { replace: true });
        }
    }, [isAuthenticated, navigate, safeFrom]);

    // #2442: login() returning with a pending mfaChallenge (instead of either
    // throwing or landing an authenticated session) is the signal to show the
    // code-entry step — it never resolves this any other way.
    useEffect(() => {
        if (mfaChallenge) {
            setMode('mfa');
        }
    }, [mfaChallenge]);

    useEffect(() => {
        clearError();
        setResetError(null);
    }, [mode, clearError]);

    const handleLogin = async (data: LoginFormData) => {
        try {
            await login(data);
        } catch {
            // Error handled by auth store
        }
    };

    const handleVerifyMfa = async (code: string) => {
        try {
            await verifyMfa(code);
        } catch {
            // Error handled by auth store (same pattern as handleLogin) — stay on
            // the code-entry step so the user can retry against the same challenge.
        }
    };

    const handleBackToLogin = () => {
        clearMfaChallenge();
        setMode('login');
    };

    const handlePasswordReset = async (data: PasswordResetRequest) => {
        setResetLoading(true);
        setResetError(null);
        try {
            await authService.requestPasswordReset(data);
            setMode('reset-success');
        } catch (error) {
            setResetError(error instanceof Error ? error.message : 'Password reset failed');
        } finally {
            setResetLoading(false);
        }
    };

    if (isLoading && isAuthenticated) {
        return (
            <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--bg-app)' }}>
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
                    <p style={{ color: 'var(--text-secondary)' }}>Loading...</p>
                </div>
            </div>
        );
    }

    return (
        <div
            className="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8"
            style={{ backgroundColor: 'var(--bg-app)' }}
        >
            <div className="max-w-md w-full space-y-8">
                <div className="text-center">
                    <div className="inline-flex items-center justify-center h-12 w-12 bg-blue-600 rounded-xl mb-4">
                        <span className="text-white font-bold text-lg">K</span>
                    </div>
                    <h1 className="text-3xl font-bold mb-2" style={{ color: 'var(--text-primary)' }}>
                        Keyorix
                    </h1>
                    <p style={{ color: 'var(--text-secondary)' }}>Secrets management for your infrastructure</p>
                </div>

                <div
                    className="py-8 px-6 shadow-lg rounded-lg border"
                    style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                >
                    {mode === 'login' && (
                        <>
                            {logoutError && (
                                <div
                                    className="mb-4 rounded-lg px-3 py-2 text-sm"
                                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                                >
                                    Sign-out could not be confirmed with the server. Your previous session may still be
                                    active — for safety on a shared device, consider changing your password.
                                </div>
                            )}
                            {reauthRequired && (
                                <div
                                    role="status"
                                    className="mb-4 rounded-lg px-3 py-2 text-sm"
                                    style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-primary)' }}
                                >
                                    Your account setup is complete and your setup session has ended. Please sign in
                                    again to continue.
                                </div>
                            )}
                            {ssoError && (
                                <div
                                    className="mb-4 rounded-lg px-3 py-2 text-sm"
                                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                                >
                                    SSO sign-in failed: {ssoError}
                                </div>
                            )}
                            <LoginForm
                                onSubmit={handleLogin}
                                isLoading={isLoading}
                                error={error}
                                onForgotPassword={() => setMode('reset')}
                            />
                            {ssoProviders.length > 0 && (
                                <div className="mt-6">
                                    <div className="relative flex items-center my-4">
                                        <div className="grow border-t" style={{ borderColor: 'var(--border)' }} />
                                        <span
                                            className="mx-3 text-xs uppercase tracking-wider"
                                            style={{ color: 'var(--text-muted)' }}
                                        >
                                            or
                                        </span>
                                        <div className="grow border-t" style={{ borderColor: 'var(--border)' }} />
                                    </div>
                                    <div className="space-y-2">
                                        {ssoProviders.map((name) => (
                                            <a
                                                key={name}
                                                href={ssoHref(name)}
                                                className="block w-full text-center px-4 py-2 rounded-lg text-sm font-medium border capitalize"
                                                style={{
                                                    borderColor: 'var(--border)',
                                                    color: 'var(--text-primary)',
                                                    backgroundColor: 'var(--bg-app)',
                                                }}
                                            >
                                                Sign in with {name}
                                            </a>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                    {mode === 'mfa' && (
                        <MfaChallengeForm
                            onSubmit={handleVerifyMfa}
                            onBack={handleBackToLogin}
                            isLoading={isLoading}
                            error={error}
                        />
                    )}
                    {(mode === 'reset' || mode === 'reset-success') && (
                        <PasswordResetForm
                            onSubmit={handlePasswordReset}
                            onBack={() => {
                                setMode('login');
                                setResetError(null);
                            }}
                            isLoading={resetLoading}
                            error={resetError}
                            success={mode === 'reset-success'}
                        />
                    )}
                </div>
            </div>
        </div>
    );
};
