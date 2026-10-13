import React from 'react';
import { clsx } from 'clsx';
import { footerVersionLabel } from '../../utils/buildInfo';
import { useSystemInfo } from '../../features/dashboard/api';

export interface FooterProps {
    className?: string;
}

const Footer: React.FC<FooterProps> = ({ className }) => {
    const { data: sysInfo } = useSystemInfo();
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
