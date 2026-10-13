import type { User } from '../../types';

// Step names as the server reports them (core.SetupStep*, pending_steps).
export const SETUP_STEP_ENROLL_MFA = 'enroll_mfa';

// userOwesMfaEnrolment: the session is confined to MFA enrolment (security.require_mfa,
// #2924 / ADR-112), known up front from the login response / GET /auth/profile rather
// than discovered through 403s on protected pages' queries (#3155).
export const userOwesMfaEnrolment = (user: User | null | undefined): boolean =>
    user?.pendingSteps?.includes(SETUP_STEP_ENROLL_MFA) ?? false;
