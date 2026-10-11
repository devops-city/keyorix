import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { LoginPage } from '../LoginPage';

const authState = vi.hoisted(() => ({
    user: null as unknown,
    isAuthenticated: false,
    isLoading: false,
    hasCheckedAuth: true,
    error: null as string | null,
    mfaChallenge: null as { challenge: string; totpAvailable: boolean; webauthnAvailable: boolean } | null,
}));

const loginMock = vi.hoisted(() => vi.fn());
const verifyMfaMock = vi.hoisted(() => vi.fn());
const clearMfaChallengeMock = vi.hoisted(() => vi.fn());
const logoutMock = vi.hoisted(() => vi.fn());
const refreshTokenMock = vi.hoisted(() => vi.fn());
const checkAuthMock = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
const clearErrorMock = vi.hoisted(() => vi.fn());
const setErrorMock = vi.hoisted(() => vi.fn());
const rehydrateMock = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));

vi.mock('../../../store/authStore', () => {
    const useAuthStore = () => ({
        user: authState.user,
        isAuthenticated: authState.isAuthenticated,
        isLoading: authState.isLoading,
        hasCheckedAuth: authState.hasCheckedAuth,
        error: authState.error,
        mfaChallenge: authState.mfaChallenge,
        login: loginMock,
        verifyMfa: verifyMfaMock,
        clearMfaChallenge: clearMfaChallengeMock,
        logout: logoutMock,
        refreshToken: refreshTokenMock,
        checkAuth: checkAuthMock,
        clearError: clearErrorMock,
        setError: setErrorMock,
    });
    useAuthStore.persist = { rehydrate: rehydrateMock };
    return { useAuthStore };
});

const getSSOProvidersMock = vi.hoisted(() => vi.fn().mockResolvedValue([]));
const requestPasswordResetMock = vi.hoisted(() => vi.fn());

vi.mock('../../../services/auth', () => ({
    authService: {
        getSSOProviders: (...args: unknown[]) => getSSOProvidersMock(...args),
        requestPasswordReset: (...args: unknown[]) => requestPasswordResetMock(...args),
    },
}));

const navigateMock = vi.hoisted(() => vi.fn());

vi.mock('react-router', async (importOriginal) => {
    const actual = await importOriginal<typeof import('react-router')>();
    return {
        ...actual,
        useNavigate: () => navigateMock,
    };
});

beforeEach(() => {
    window.history.pushState({}, '', '/');
    authState.user = null;
    authState.isAuthenticated = false;
    authState.isLoading = false;
    authState.hasCheckedAuth = true;
    authState.error = null;
    authState.mfaChallenge = null;
    loginMock.mockReset();
    verifyMfaMock.mockReset();
    clearMfaChallengeMock.mockReset();
    logoutMock.mockReset();
    refreshTokenMock.mockReset();
    checkAuthMock.mockReset().mockResolvedValue(undefined);
    clearErrorMock.mockReset();
    setErrorMock.mockReset();
    rehydrateMock.mockReset().mockResolvedValue(undefined);
    getSSOProvidersMock.mockReset().mockResolvedValue([]);
    requestPasswordResetMock.mockReset();
    navigateMock.mockReset();
});

describe('LoginPage', () => {
    it('renders branding and the login form when unauthenticated', async () => {
        render(<LoginPage />);

        expect(screen.getByText('Keyorix')).toBeInTheDocument();
        expect(screen.getByText('Secrets management for your infrastructure')).toBeInTheDocument();
        expect(screen.getByTestId('username-input')).toBeInTheDocument();
        expect(screen.getByTestId('password-input')).toBeInTheDocument();
        expect(screen.getByTestId('login-button')).toBeInTheDocument();

        await waitFor(() => expect(getSSOProvidersMock).toHaveBeenCalled());
    });

    it('submits the login form with the entered credentials', async () => {
        loginMock.mockResolvedValue(undefined);
        render(<LoginPage />);

        fireEvent.change(screen.getByTestId('username-input'), { target: { value: 'dana' } });
        fireEvent.change(screen.getByTestId('password-input'), { target: { value: 'Str0ngPass!' } });
        fireEvent.click(screen.getByTestId('login-button'));

        await waitFor(() =>
            expect(loginMock).toHaveBeenCalledWith({
                username: 'dana',
                password: 'Str0ngPass!',
                rememberMe: false,
            })
        );
    });

    it('does not throw when login rejects (error is surfaced via the auth store)', async () => {
        loginMock.mockRejectedValue(new Error('Invalid credentials'));
        render(<LoginPage />);

        fireEvent.change(screen.getByTestId('username-input'), { target: { value: 'dana' } });
        fireEvent.change(screen.getByTestId('password-input'), { target: { value: 'Str0ngPass!' } });
        fireEvent.click(screen.getByTestId('login-button'));

        await waitFor(() => expect(loginMock).toHaveBeenCalled());
    });

    // #2442: login() ignoring mfa_required previously meant this never rendered
    // anything beyond the login form — these assert the fix.
    it('shows the MFA code-entry step once a pending mfaChallenge appears', async () => {
        loginMock.mockImplementation(async () => {
            authState.mfaChallenge = { challenge: 'chal-abc123', totpAvailable: true, webauthnAvailable: false };
        });
        render(<LoginPage />);

        fireEvent.change(screen.getByTestId('username-input'), { target: { value: 'dana' } });
        fireEvent.change(screen.getByTestId('password-input'), { target: { value: 'Str0ngPass!' } });
        fireEvent.click(screen.getByTestId('login-button'));

        expect(await screen.findByTestId('mfa-code-input')).toBeInTheDocument();
        expect(screen.queryByTestId('username-input')).not.toBeInTheDocument();
    });

    it('submits the entered code via verifyMfa once on the MFA step', async () => {
        authState.mfaChallenge = { challenge: 'chal-abc123', totpAvailable: true, webauthnAvailable: false };
        verifyMfaMock.mockResolvedValue(undefined);
        render(<LoginPage />);

        fireEvent.change(screen.getByTestId('mfa-code-input'), { target: { value: '123456' } });
        fireEvent.click(screen.getByTestId('mfa-verify-button'));

        await waitFor(() => expect(verifyMfaMock).toHaveBeenCalledWith('123456'));
    });

    it('does not throw when verifyMfa rejects (error is surfaced via the auth store)', async () => {
        authState.mfaChallenge = { challenge: 'chal-abc123', totpAvailable: true, webauthnAvailable: false };
        verifyMfaMock.mockRejectedValue(new Error('Invalid or expired code'));
        render(<LoginPage />);

        fireEvent.change(screen.getByTestId('mfa-code-input'), { target: { value: '000000' } });
        fireEvent.click(screen.getByTestId('mfa-verify-button'));

        await waitFor(() => expect(verifyMfaMock).toHaveBeenCalled());
    });

    it('renders the auth-store error on the MFA step too', async () => {
        authState.mfaChallenge = { challenge: 'chal-abc123', totpAvailable: true, webauthnAvailable: false };
        authState.error = 'Invalid or expired code';
        render(<LoginPage />);

        expect(await screen.findByText('Invalid or expired code')).toBeInTheDocument();
    });

    it('returns to the login form via "Back to login", clearing the pending challenge', async () => {
        authState.mfaChallenge = { challenge: 'chal-abc123', totpAvailable: true, webauthnAvailable: false };
        render(<LoginPage />);

        expect(await screen.findByTestId('mfa-code-input')).toBeInTheDocument();
        fireEvent.click(screen.getByText('Back to login'));

        expect(clearMfaChallengeMock).toHaveBeenCalled();
        expect(screen.getByTestId('username-input')).toBeInTheDocument();
    });

    it('renders the auth-store error via the login form alert', async () => {
        authState.error = 'Invalid username or password';
        render(<LoginPage />);

        expect(await screen.findByText('Invalid username or password')).toBeInTheDocument();
    });

    it('shows a full-page loading state when already authenticated and still loading', () => {
        authState.isAuthenticated = true;
        authState.isLoading = true;
        render(<LoginPage />);

        expect(screen.getByText('Loading...')).toBeInTheDocument();
        expect(screen.queryByTestId('username-input')).not.toBeInTheDocument();
    });

    it('redirects to the dashboard when already authenticated', () => {
        authState.isAuthenticated = true;
        authState.isLoading = false;
        render(<LoginPage />);

        expect(navigateMock).toHaveBeenCalledWith('/dashboard', { replace: true });
    });

    it('redirects to the originally-requested route preserved in location state', () => {
        window.history.pushState({ usr: { from: { pathname: '/secrets' } } }, '', '/login');
        authState.isAuthenticated = true;
        authState.isLoading = false;
        render(<LoginPage />);

        expect(navigateMock).toHaveBeenCalledWith('/secrets', { replace: true });
    });

    it('falls back to the dashboard rather than navigating to an unsafe protocol-relative from-path', () => {
        window.history.pushState({ usr: { from: { pathname: '//evil.example.com/phish' } } }, '', '/login');
        authState.isAuthenticated = true;
        authState.isLoading = false;
        render(<LoginPage />);

        expect(navigateMock).toHaveBeenCalledWith('/dashboard', { replace: true });
        expect(navigateMock).not.toHaveBeenCalledWith('//evil.example.com/phish', expect.anything());
    });

    it('shows an SSO error banner from the sso_error query param', () => {
        window.history.pushState({}, '', '/login?sso_error=access_denied');
        render(<LoginPage />);

        expect(screen.getByText('SSO sign-in failed: access_denied')).toBeInTheDocument();
    });

    it('does not show an SSO error banner when there is no sso_error param', () => {
        render(<LoginPage />);

        expect(screen.queryByText(/SSO sign-in failed/)).not.toBeInTheDocument();
    });

    it('shows a logout-failure banner from the logout_error query param (G65: surfaced instead of a silent redirect)', () => {
        window.history.pushState({}, '', '/login?logout_error=1');
        render(<LoginPage />);

        expect(screen.getByText(/Sign-out could not be confirmed with the server/)).toBeInTheDocument();
    });

    it('explains a server-ended setup session from the reauth query param, as a notice and not an error', () => {
        window.history.pushState({}, '', '/login?reauth=1');
        render(<LoginPage />);

        expect(screen.getByRole('status')).toHaveTextContent(/account setup is complete.*sign in again/i);
        expect(screen.queryByText(/Sign-out could not be confirmed/)).not.toBeInTheDocument();
    });

    it('shows no reauth notice on a plain visit to the login page', () => {
        render(<LoginPage />);

        expect(screen.queryByText(/setup session has ended/)).not.toBeInTheDocument();
    });

    it('does not show a logout-failure banner when there is no logout_error param (e.g. a clean logout)', () => {
        render(<LoginPage />);

        expect(screen.queryByText(/Sign-out could not be confirmed/)).not.toBeInTheDocument();
    });

    it('renders SSO provider links once they load, targeting the default dashboard return_to', async () => {
        getSSOProvidersMock.mockResolvedValue(['google', 'okta']);
        render(<LoginPage />);

        const googleLink = await screen.findByRole('link', { name: 'Sign in with google' });
        expect(googleLink).toHaveAttribute('href', '/auth/sso/google/login?return_to=%2Fdashboard');

        const oktaLink = screen.getByRole('link', { name: 'Sign in with okta' });
        expect(oktaLink).toHaveAttribute('href', '/auth/sso/okta/login?return_to=%2Fdashboard');
    });

    it('falls back to the dashboard in the SSO return_to param for an unsafe protocol-relative from-path', async () => {
        window.history.pushState({ usr: { from: { pathname: '//evil.example.com/phish' } } }, '', '/login');
        getSSOProvidersMock.mockResolvedValue(['google']);
        render(<LoginPage />);

        const googleLink = await screen.findByRole('link', { name: 'Sign in with google' });
        expect(googleLink).toHaveAttribute('href', '/auth/sso/google/login?return_to=%2Fdashboard');
    });

    it('preserves the originally-requested route in the SSO return_to param', async () => {
        window.history.pushState({ usr: { from: { pathname: '/secrets' } } }, '', '/login');
        getSSOProvidersMock.mockResolvedValue(['google']);
        render(<LoginPage />);

        const googleLink = await screen.findByRole('link', { name: 'Sign in with google' });
        expect(googleLink).toHaveAttribute('href', '/auth/sso/google/login?return_to=%2Fsecrets');
    });

    it('does not render the SSO divider or links when no providers are configured', async () => {
        render(<LoginPage />);

        await waitFor(() => expect(getSSOProvidersMock).toHaveBeenCalled());
        expect(screen.queryByText('or')).not.toBeInTheDocument();
        expect(screen.queryByRole('link', { name: /Sign in with/ })).not.toBeInTheDocument();
    });

    it('switches to the password-reset form via the "Forgot password?" link', async () => {
        render(<LoginPage />);

        await waitFor(() => expect(getSSOProvidersMock).toHaveBeenCalled());
        fireEvent.click(screen.getByText('Forgot password?'));

        expect(screen.getByText('Reset Password')).toBeInTheDocument();
        expect(screen.queryByTestId('username-input')).not.toBeInTheDocument();
    });

    it('requests a password reset and shows the success state', async () => {
        requestPasswordResetMock.mockResolvedValue(undefined);
        render(<LoginPage />);

        fireEvent.click(screen.getByText('Forgot password?'));
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'dana@example.com' } });
        fireEvent.click(screen.getByText('Send Reset Link'));

        await waitFor(() => expect(requestPasswordResetMock).toHaveBeenCalledWith({ email: 'dana@example.com' }));
        expect(await screen.findByText('Reset Link Sent')).toBeInTheDocument();
    });

    it('surfaces the Error message when the password-reset request fails', async () => {
        requestPasswordResetMock.mockRejectedValue(new Error('No account with that email'));
        render(<LoginPage />);

        fireEvent.click(screen.getByText('Forgot password?'));
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'dana@example.com' } });
        fireEvent.click(screen.getByText('Send Reset Link'));

        expect(await screen.findByText('No account with that email')).toBeInTheDocument();
    });

    it('falls back to a generic message when the password-reset rejection is not an Error', async () => {
        requestPasswordResetMock.mockRejectedValue('network down');
        render(<LoginPage />);

        fireEvent.click(screen.getByText('Forgot password?'));
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'dana@example.com' } });
        fireEvent.click(screen.getByText('Send Reset Link'));

        expect(await screen.findByText('Password reset failed')).toBeInTheDocument();
    });

    it('returns to the login form via "Back to Login", clearing any reset error', async () => {
        requestPasswordResetMock.mockRejectedValue(new Error('No account with that email'));
        render(<LoginPage />);

        fireEvent.click(screen.getByText('Forgot password?'));
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'dana@example.com' } });
        fireEvent.click(screen.getByText('Send Reset Link'));
        expect(await screen.findByText('No account with that email')).toBeInTheDocument();

        fireEvent.click(screen.getByText('Back to Login'));

        expect(screen.getByTestId('username-input')).toBeInTheDocument();
        expect(screen.queryByText('No account with that email')).not.toBeInTheDocument();
    });

    it('ignores a late SSO providers response after the component unmounts', async () => {
        let resolveProviders: (value: string[]) => void = () => {};
        const pending = new Promise<string[]>((resolve) => {
            resolveProviders = resolve;
        });
        getSSOProvidersMock.mockReturnValue(pending);

        const { unmount } = render(<LoginPage />);
        unmount();
        resolveProviders(['google']);

        // Resolves without updating state on the unmounted component (the effect's
        // cleanup flips `active` to false, so the .then callback is a no-op).
        await expect(pending).resolves.toEqual(['google']);
    });

    // NOTE: handlePasswordReset (lines 56-67) and the onBack callback passed to
    // PasswordResetForm (lines 146-149) are unreachable for the same reason as the
    // BUG documented above — mode never becomes 'reset', so PasswordResetForm (and
    // its callback props) never mount. Left uncovered deliberately.
});
