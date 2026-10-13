import React from 'react';
import { Navigate, useLocation } from 'react-router';
import { useAuth } from '../../features/auth';
import { userOwesMfaEnrolment } from '../../features/auth/setup';
import { ROUTES } from '../../constants';
import { MFA_ENROLMENT_URL } from '../../services/client';
import { matchesRoutePrefix } from '../../utils/routing';

interface RequireMfaEnrolmentProps {
    children: React.ReactNode;
}

/**
 * RequireMfaEnrolment confines a session that owes MFA enrolment (security.require_mfa,
 * #2924 / ADR-112) to the profile page, BEFORE any protected page renders (#3155).
 *
 * The server already refuses everything but the enrolment endpoints with 403
 * MFAEnrollmentRequired, and says so up front (login response / GET /auth/profile
 * `pending_steps`). Without this guard the SPA rendered /dashboard, fired its queries,
 * and only reacted to the first 403. This is the UX half of the same confinement; it
 * grants nothing and the server remains the gate.
 */
export const RequireMfaEnrolment: React.FC<RequireMfaEnrolmentProps> = ({ children }) => {
    const { user } = useAuth();
    const location = useLocation();

    if (userOwesMfaEnrolment(user) && !matchesRoutePrefix(location.pathname, ROUTES.PROFILE)) {
        return <Navigate to={MFA_ENROLMENT_URL} replace />;
    }

    return <>{children}</>;
};
