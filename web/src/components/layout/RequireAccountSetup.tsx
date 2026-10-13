import React from 'react';
import { RequireMfaEnrolment } from './RequireMfaEnrolment';
import { RequirePasswordChange } from './RequirePasswordChange';

/**
 * RequireAccountSetup is the SPA half of the account-setup confinement
 * (server/middleware.EnforceAccountSetup): MFA enrolment first (it sends the session to
 * the enrolment page before anything protected renders, #3155), then the password-change
 * confinement. Wrap every authenticated route with it, inside ProtectedRoute.
 */
export const RequireAccountSetup: React.FC<{ children: React.ReactNode }> = ({ children }) => (
    <RequireMfaEnrolment>
        <RequirePasswordChange>{children}</RequirePasswordChange>
    </RequireMfaEnrolment>
);
