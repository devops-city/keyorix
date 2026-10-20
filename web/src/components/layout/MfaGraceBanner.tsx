import React from 'react';
import { Link } from 'react-router';
import { useAuthStore } from '../../store/authStore';
import { ROUTES } from '../../constants';

/**
 * MfaGraceBanner is a persistent warning bar shown on every page while the server
 * is in ADR-112's security.require_mfa upgrade grace period (#2923) and the
 * signed-in account has no second factor. MFA is not enforced yet; it is at the
 * end date, or as soon as the first administrator enrols a second factor, and
 * from then on this account is sent to MFA enrolment when it signs in. It cannot
 * be dismissed: it goes away when the account enrols or the grace period ends.
 * Read from the login response / GET /auth/profile (mfa_grace).
 */
export const MfaGraceBanner: React.FC = () => {
    const grace = useAuthStore((s) => (s.isAuthenticated ? s.user?.mfaGrace : undefined));
    if (!grace) {
        return null;
    }
    const ends = new Date(grace.endsAt);
    const endsText = Number.isNaN(ends.getTime()) ? grace.endsAt : ends.toLocaleDateString();
    const days = grace.daysLeft === 1 ? '1 day' : `${grace.daysLeft} days`;

    return (
        <div
            role="alert"
            data-testid="mfa-grace-banner"
            className="flex flex-wrap items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--warning, #b45309)' }}
        >
            <span>
                <strong>Multi-factor authentication will be required in {days}</strong> (on {endsText}, or sooner once
                the first administrator enrols). After that you will be sent to MFA enrolment when you sign in.
            </span>
            <Link
                to={`${ROUTES.PROFILE}?tab=security`}
                className="rounded-sm bg-white/20 px-3 py-1 font-semibold hover:bg-white/30"
            >
                Enrol now
            </Link>
        </div>
    );
};
