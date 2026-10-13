import React from 'react';
import { useNavigate } from 'react-router';
import { clsx } from 'clsx';
import {
    Bars3Icon,
    UserCircleIcon,
    ArrowRightStartOnRectangleIcon,
    SunIcon,
    MoonIcon,
    ComputerDesktopIcon,
} from '@heroicons/react/24/outline';
import { Dropdown, DropdownItem } from '../ui/Dropdown';

import { useAuth } from '../../features/auth';
import { userOwesMfaEnrolment } from '../../features/auth/setup';
import { NotificationBell } from '../../features/notifications';
import { useUIStore } from '../../store/uiStore';
import { ROUTES } from '../../constants';

export interface HeaderProps {
    onMenuClick: () => void;
    className?: string;
}

const Header: React.FC<HeaderProps> = ({ onMenuClick, className }) => {
    const { user, logout } = useAuth();
    const navigate = useNavigate();
    const { theme, setTheme } = useUIStore();

    const handleLogout = async () => {
        try {
            await logout();
            navigate('/login');
        } catch (error) {
            console.error('Logout failed:', error);
        }
    };

    const userMenuItems: DropdownItem[] = [
        {
            label: 'My Account',
            value: 'account',
            icon: UserCircleIcon,
            onClick: () => navigate(ROUTES.PROFILE),
        },
        {
            label: 'Sign out',
            value: 'logout',
            icon: ArrowRightStartOnRectangleIcon,
            onClick: handleLogout,
            danger: true,
        },
    ];

    const userMenuTrigger = (
        <button
            type="button"
            data-testid="user-menu-button"
            className="flex items-center space-x-2 text-sm rounded-full focus:outline-hidden focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 p-1"
        >
            <div
                className="h-8 w-8 rounded-full flex items-center justify-center"
                style={{ backgroundColor: 'var(--bg-muted)' }}
            >
                <UserCircleIcon className="h-6 w-6" style={{ color: 'var(--text-secondary)' }} />
            </div>
            <span className="hidden md:block font-medium" style={{ color: 'var(--text-secondary)' }}>
                {user?.displayName || user?.username || 'User'}
            </span>
        </button>
    );

    let nextTheme: 'light' | 'system' | 'dark' = 'dark';
    if (theme === 'dark') nextTheme = 'light';
    else if (theme === 'light') nextTheme = 'system';

    let themeTitle = 'System mode (click for dark)';
    if (theme === 'dark') themeTitle = 'Dark mode (click for light)';
    else if (theme === 'light') themeTitle = 'Light mode (click for system)';

    let themeAriaLabel = 'System mode';
    if (theme === 'dark') themeAriaLabel = 'Dark mode';
    else if (theme === 'light') themeAriaLabel = 'Light mode';

    let themeIcon = <ComputerDesktopIcon className="h-5 w-5" aria-hidden="true" />;
    if (theme === 'dark') themeIcon = <MoonIcon className="h-5 w-5" aria-hidden="true" />;
    else if (theme === 'light') themeIcon = <SunIcon className="h-5 w-5" aria-hidden="true" />;

    return (
        <header
            className={clsx('shadow-xs border-b', className)}
            style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
        >
            <div className="px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between items-center h-16">
                    {/* Left — mobile menu button */}
                    <div className="flex items-center">
                        <button
                            type="button"
                            className="p-2 rounded-md focus:outline-hidden focus:ring-2 focus:ring-inset focus:ring-blue-500 lg:hidden"
                            style={{ color: 'var(--text-muted)' }}
                            onClick={onMenuClick}
                        >
                            <span className="sr-only">Open sidebar</span>
                            <Bars3Icon className="h-6 w-6" aria-hidden="true" />
                        </button>
                    </div>

                    {/* Right — theme toggle + notifications + user menu */}
                    <div className="flex items-center space-x-2">
                        {/* Notifications (ADR-024) — unread badge + dropdown. */}
                        {/* Not under the MFA-enrolment confinement (#3155): its poll would 403. */}
                        {!userOwesMfaEnrolment(user) && <NotificationBell />}

                        {/* Theme toggle — cycles dark → light → system */}
                        <button
                            type="button"
                            onClick={() => setTheme(nextTheme)}
                            className="p-2 rounded-md transition-colors focus:outline-hidden focus:ring-2 focus:ring-inset focus:ring-blue-500"
                            style={{ color: 'var(--text-muted)' }}
                            title={themeTitle}
                            aria-label={themeAriaLabel}
                        >
                            {themeIcon}
                        </button>

                        {/* User menu */}
                        <Dropdown trigger={userMenuTrigger} items={userMenuItems} align="right" />
                    </div>
                </div>
            </div>
        </header>
    );
};

export { Header };
