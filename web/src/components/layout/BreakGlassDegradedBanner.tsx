import React from 'react';
import { useSystemInfo } from '../../features/dashboard/api';
import { userOwesMfaEnrolment } from '../../features/auth/setup';
import { useAuthStore } from '../../store/authStore';

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/**
 * BreakGlassDegradedBanner alerts an administrator while emergency access granted
 * during an audit outage needs attention (BREAKGLASS-OWED-1): the server granted it
 * while the audit log refused writes, recorded it as owed, and cut its lifetime. The
 * banner stays while its audit records are not in the audit trail yet or its mandatory
 * review is outstanding. Read from GET /api/v1/system/info (security.break_glass_degraded,
 * present only for system.write callers).
 */
export const BreakGlassDegradedBanner: React.FC = () => {
    const canFetchInfo = useAuthStore((s) => s.isAuthenticated && !userOwesMfaEnrolment(s.user));
    const { data: sysInfo } = useSystemInfo({ enabled: canFetchInfo });

    const bg = sysInfo?.security?.break_glass_degraded;
    if (!bg || (bg.unsettled === 0 && bg.unreviewed === 0)) {
        return null;
    }

    const parts: string[] = [];
    if (bg.unsettled < 0 || bg.unreviewed < 0) {
        parts.push('the server could not read their state');
    }
    if (bg.unsettled > 0) {
        parts.push(`${plural(bg.unsettled, 'activation still owes', 'activations still owe')} audit records`);
    }
    if (bg.unreviewed > 0) {
        parts.push(`${plural(bg.unreviewed, 'needs', 'need')} the mandatory review`);
    }
    const ids = bg.activation_ids ?? [];

    return (
        <div
            role="alert"
            data-testid="break-glass-degraded-banner"
            className="flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--error, #b91c1c)' }}
        >
            <span>
                <strong>Emergency access was granted while the audit log refused writes:</strong> {parts.join('; ')}
                {ids.length > 0 && <> (activation {ids.map((id) => `#${id}`).join(', ')})</>}. Each was short-lived and
                recorded as owed; review it in the project&apos;s break-glass tab and check the audit storage.
            </span>
        </div>
    );
};
