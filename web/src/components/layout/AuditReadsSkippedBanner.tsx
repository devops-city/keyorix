import React from 'react';
import { useSystemInfo } from '../../features/dashboard/api';
import { userOwesMfaEnrolment } from '../../features/auth/setup';
import { useAuthStore } from '../../store/authStore';

/**
 * AuditReadsSkippedBanner is a persistent warning bar shown on every page while
 * the server runs with storage.database.insecure_audit_skip_reads (ADR-112
 * Amendment 4): successful secret reads are not audited. It cannot be
 * dismissed; it goes away only when the setting is removed from the server's
 * config file. Read from GET /api/v1/system/info (security.audit_reads_skipped).
 */
export const AuditReadsSkippedBanner: React.FC = () => {
    // Same gate as the footer: an MFA-enrolment-confined session cannot read
    // /system/info.
    const canFetchInfo = useAuthStore((s) => s.isAuthenticated && !userOwesMfaEnrolment(s.user));
    const { data: sysInfo } = useSystemInfo({ enabled: canFetchInfo });

    if (!sysInfo?.security?.audit_reads_skipped) {
        return null;
    }

    return (
        <div
            role="alert"
            data-testid="audit-reads-skipped-banner"
            className="flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--danger, #b91c1c)' }}
        >
            <span>
                <strong>Secret reads are not audited.</strong> This server runs with{' '}
                <code>storage.database.insecure_audit_skip_reads</code>: reading a secret's value leaves no audit
                record. Changes, sign-ins, denied reads and admin actions are still audited.
            </span>
        </div>
    );
};
