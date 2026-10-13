import React from 'react';
import { clsx } from 'clsx';
import { footerVersionLabel } from '../../utils/buildInfo';
import { useSystemInfo } from '../../features/dashboard/api';
import { userOwesMfaEnrolment } from '../../features/auth/setup';
import { useAuthStore } from '../../store/authStore';

export interface FooterProps {
    className?: string;
}

const Footer: React.FC<FooterProps> = ({ className }) => {
    // An MFA-pending (enrolment-confined) session may only reach MFA routes; the confinement
    // refuses /system/info, so the footer asks only once the session is fully authenticated.
    const canFetchInfo = useAuthStore((s) => s.isAuthenticated && !userOwesMfaEnrolment(s.user));
    const { data: sysInfo } = useSystemInfo({ enabled: canFetchInfo });
    return (
        <footer
            className={clsx('border-t', className)}
            style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
        >
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
                <p className="text-xs text-center" style={{ color: 'var(--text-muted)' }}>
                    {footerVersionLabel(sysInfo?.version)}
                </p>
            </div>
        </footer>
    );
};

export { Footer };
