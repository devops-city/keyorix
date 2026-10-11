import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within } from '../../../test/test-utils';
import { AuthenticationPage } from '../AuthenticationPage';

const useAuthConfig = vi.fn();

vi.mock('../../../features/dashboard', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../features/dashboard')>();
    return {
        ...actual,
        useAuthConfig: (...args: any[]) => useAuthConfig(...args),
    };
});

const baseAuthConfig = {
    session: { access_ttl: '24h0m0s', absolute_ttl: '0s' },
    password_policy: {
        min_length: 12,
        require_uppercase: true,
        require_lowercase: true,
        require_digit: true,
        require_special: false,
        reject_personal_info: true,
        reject_common_passwords: true,
        history_count: 5,
        max_age_days: 0,
    },
    login_lockout: { enabled: true, max_attempts: 5, window: '15m0s', base_cooldown: '1m0s', max_cooldown: '1h0m0s' },
    require_mfa: false,
    webauthn: { enabled: true, rp_id: 'keyorix.example.com', rp_display_name: 'Keyorix', rp_origins: [] },
    sso: {
        enabled: true,
        providers: [{ name: 'okta', type: 'oidc', auto_provision: true, group_sync: false }],
    },
};

beforeEach(() => {
    vi.clearAllMocks();
    useAuthConfig.mockReturnValue({ data: baseAuthConfig, isLoading: false, isError: false });
});

describe('AuthenticationPage — loading and error states', () => {
    it('shows a spinner while data is loading', () => {
        useAuthConfig.mockReturnValue({ data: undefined, isLoading: true, isError: false });
        render(<AuthenticationPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an error message when the fetch fails', () => {
        useAuthConfig.mockReturnValue({ data: undefined, isLoading: false, isError: true });
        render(<AuthenticationPage />);
        expect(screen.getByText(/Unable to load authentication configuration/)).toBeInTheDocument();
    });
});

describe('AuthenticationPage — success state', () => {
    it('shows session TTLs, formatting a zero absolute TTL as "No ceiling"', () => {
        render(<AuthenticationPage />);
        expect(screen.getByText('24 hours')).toBeInTheDocument();
        expect(screen.getByText('No ceiling')).toBeInTheDocument();
    });

    it('shows password policy fields and complexity pills', () => {
        render(<AuthenticationPage />);
        expect(screen.getByText('12')).toBeInTheDocument();
        expect(screen.getByText('Uppercase')).toBeInTheDocument();
        expect(screen.getByText('Lowercase')).toBeInTheDocument();
        expect(screen.getByText('Digit')).toBeInTheDocument();
        expect(screen.getByText('Special char')).toBeInTheDocument();
        expect(screen.getByText('5 passwords')).toBeInTheDocument();
        expect(screen.getByText('Never expires')).toBeInTheDocument();
    });

    it('shows max age in days when set', () => {
        useAuthConfig.mockReturnValue({
            data: { ...baseAuthConfig, password_policy: { ...baseAuthConfig.password_policy, max_age_days: 90 } },
            isLoading: false,
            isError: false,
        });
        render(<AuthenticationPage />);
        expect(screen.getByText('90 days')).toBeInTheDocument();
    });

    it('shows login lockout settings', () => {
        render(<AuthenticationPage />);
        expect(screen.getByText('5')).toBeInTheDocument();
        expect(screen.getByText('15 minutes')).toBeInTheDocument();
        expect(screen.getByText('1 minute')).toBeInTheDocument();
        expect(screen.getByText('1 hour')).toBeInTheDocument();
    });

    it('shows WebAuthn relying-party details only when enabled', () => {
        render(<AuthenticationPage />);
        expect(screen.getByText('keyorix.example.com')).toBeInTheDocument();
        expect(screen.getByText('Keyorix')).toBeInTheDocument();
    });

    it('hides WebAuthn relying-party rows when disabled', () => {
        useAuthConfig.mockReturnValue({
            data: { ...baseAuthConfig, webauthn: { ...baseAuthConfig.webauthn, enabled: false } },
            isLoading: false,
            isError: false,
        });
        render(<AuthenticationPage />);
        expect(screen.queryByText('Relying party ID')).not.toBeInTheDocument();
    });

    it('lists SSO providers without exposing issuer, client ID, or client secret', () => {
        render(<AuthenticationPage />);
        expect(screen.getByText('okta')).toBeInTheDocument();
        expect(screen.getByText('oidc')).toBeInTheDocument();
        expect(screen.getByText('Auto-provision')).toBeInTheDocument();
        expect(screen.queryByText('Group sync')).not.toBeInTheDocument();
        expect(screen.getByText(/client secret are never exposed here/)).toBeInTheDocument();
    });

    it('shows an empty state and no redaction note when no SSO providers are configured', () => {
        useAuthConfig.mockReturnValue({
            data: { ...baseAuthConfig, sso: { enabled: false, providers: [] } },
            isLoading: false,
            isError: false,
        });
        render(<AuthenticationPage />);
        expect(screen.getByText('No SSO providers configured.')).toBeInTheDocument();
        expect(screen.queryByText(/client secret are never exposed here/)).not.toBeInTheDocument();
    });

    it('shows Yes/No for boolean settings', () => {
        render(<AuthenticationPage />);
        const requireMfaRow = screen.getByText('Require MFA (org-wide)').closest('div');
        expect(within(requireMfaRow as HTMLElement).getByText('No')).toBeInTheDocument();
    });

    it('shows "No" for login lockout when disabled and "Yes" when org-wide MFA is required', () => {
        useAuthConfig.mockReturnValue({
            data: {
                ...baseAuthConfig,
                login_lockout: { ...baseAuthConfig.login_lockout, enabled: false },
                require_mfa: true,
            },
            isLoading: false,
            isError: false,
        });
        render(<AuthenticationPage />);

        // "Enabled" is also the SSO section's row label; Login lockout renders first.
        const [lockoutEnabledLabel] = screen.getAllByText('Enabled');
        const lockoutRow = lockoutEnabledLabel.closest('div');
        expect(within(lockoutRow as HTMLElement).getByText('No')).toBeInTheDocument();

        const requireMfaRow = screen.getByText('Require MFA (org-wide)').closest('div');
        expect(within(requireMfaRow as HTMLElement).getByText('Yes')).toBeInTheDocument();
    });

    it('falls back to an em dash for missing WebAuthn relying-party details', () => {
        useAuthConfig.mockReturnValue({
            data: { ...baseAuthConfig, webauthn: { ...baseAuthConfig.webauthn, rp_id: '', rp_display_name: '' } },
            isLoading: false,
            isError: false,
        });
        render(<AuthenticationPage />);

        const rpIdRow = screen.getByText('Relying party ID').closest('div');
        expect(within(rpIdRow as HTMLElement).getByText('—')).toBeInTheDocument();
        const rpNameRow = screen.getByText('Relying party name').closest('div');
        expect(within(rpNameRow as HTMLElement).getByText('—')).toBeInTheDocument();
    });

    it('shows a Group sync pill when an SSO provider has group sync enabled', () => {
        useAuthConfig.mockReturnValue({
            data: {
                ...baseAuthConfig,
                sso: {
                    enabled: true,
                    providers: [{ name: 'okta', type: 'oidc', auto_provision: false, group_sync: true }],
                },
            },
            isLoading: false,
            isError: false,
        });
        render(<AuthenticationPage />);

        expect(screen.getByText('Group sync')).toBeInTheDocument();
        expect(screen.queryByText('Auto-provision')).not.toBeInTheDocument();
    });
});
