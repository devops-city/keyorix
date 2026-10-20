import React from 'react';
import { useSystemInfo } from '../../features/dashboard/api';
import { userOwesMfaEnrolment } from '../../features/auth/setup';
import { useAuthStore } from '../../store/authStore';

/**
 * AuditOwedBanner warns an administrator while audit records are missing from the
 * audit log: a plain suspend blocks reads at once, and break-glass grants emergency
 * access (BREAKGLASS-OWED-1), even when the audit log refuses their rows; the server
 * writes the rows later, once the audit log accepts writes again. Read from GET
 * /api/v1/system/info (security.audit_owed, present only for system.write callers).
 * It goes away by itself when every owed row has been written.
 */
export const AuditOwedBanner: React.FC = () => {
    const canFetchInfo = useAuthStore((s) => s.isAuthenticated && !userOwesMfaEnrolment(s.user));
    const { data: sysInfo } = useSystemInfo({ enabled: canFetchInfo });

    const owed = sysInfo?.security?.audit_owed;
    if (!owed || owed.pending === 0) {
        return null;
    }

    const what =
        owed.pending < 0
            ? 'Some audit records may be missing from the audit log'
            : `${owed.pending} audit record${owed.pending === 1 ? ' is' : 's are'} missing from the audit log`;

    return (
        <div
            role="alert"
            data-testid="audit-owed-banner"
            className="flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--warning, #b45309)' }}
        >
            <span>
                <strong>{what}.</strong> The changes they describe (suspensions, emergency access) took effect at once,
                but the audit log refused the records. The server writes them as soon as the audit log accepts writes
                again; check the server log (SECURITY lines) and the audit storage.
            </span>
        </div>
    );
};
