import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { MfaGraceBanner } from '../MfaGraceBanner';
import { useAuthStore, mfaGraceFromWire } from '../../../store/authStore';
import type { User } from '../../../types';

const setSession = (isAuthenticated: boolean, mfaGrace?: User['mfaGrace']) =>
    useAuthStore.setState({
        isAuthenticated,
        user: isAuthenticated ? ({ id: 1, mfaGrace } as unknown as User) : null,
    });

describe('MfaGraceBanner (ADR-112 require_mfa upgrade grace period, #2923)', () => {
    beforeEach(() => setSession(false));

    it('shows a persistent alert with the days left and a link to enrol', () => {
        setSession(true, mfaGraceFromWire({ ends_at: '2026-11-16T09:00:00Z', days_left: 12 }));
        render(<MfaGraceBanner />);
        const banner = screen.getByTestId('mfa-grace-banner');
        expect(banner).toHaveAttribute('role', 'alert');
        expect(banner).toHaveTextContent('Multi-factor authentication will be required in 12 days');
        expect(banner).toHaveTextContent('sent to MFA enrolment');
        expect(screen.getByRole('link', { name: 'Enrol now' })).toHaveAttribute('href', '/profile?tab=security');
        expect(screen.queryByRole('button')).not.toBeInTheDocument();
    });

    it('says "1 day" on the last day', () => {
        setSession(true, { endsAt: '2026-11-16T09:00:00Z', daysLeft: 1 });
        render(<MfaGraceBanner />);
        expect(screen.getByTestId('mfa-grace-banner')).toHaveTextContent('required in 1 day ');
    });

    it('renders nothing without a grace period (enrolled, ended, or an older server)', () => {
        setSession(true);
        render(<MfaGraceBanner />);
        expect(screen.queryByTestId('mfa-grace-banner')).not.toBeInTheDocument();
    });

    it('renders nothing when signed out', () => {
        setSession(false);
        render(<MfaGraceBanner />);
        expect(screen.queryByTestId('mfa-grace-banner')).not.toBeInTheDocument();
    });
});
