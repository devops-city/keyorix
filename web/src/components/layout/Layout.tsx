import React, { useState, useEffect } from 'react';
import { clsx } from 'clsx';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { Footer } from './Footer';
import { Breadcrumb, BreadcrumbItem } from './Breadcrumb';
import { ImpersonationBanner } from './ImpersonationBanner';
import { CmdKSearch } from '../ui/CmdKSearch';
import { isPaletteShortcut } from '../../utils/platform';

export interface LayoutProps {
    children: React.ReactNode;
    breadcrumbs?: BreadcrumbItem[];
    showFooter?: boolean;
    className?: string;
}

const Layout: React.FC<LayoutProps> = ({ children, breadcrumbs, showFooter = true, className }) => {
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const [cmdkOpen, setCmdkOpen] = useState(false);

    // Global Cmd-K / Ctrl-K listener
    useEffect(() => {
        const handler = (e: KeyboardEvent) => {
            if (isPaletteShortcut(e)) {
                e.preventDefault();
                setCmdkOpen((prev) => !prev);
            }
        };
        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
    }, []);

    return (
        <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-app)' }}>
            {/* Sidebar */}
            <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

            {/* Main content area */}
            <div className="lg:pl-64 flex flex-col min-h-screen">
                {/* Impersonation banner + header stick together at the top of the
                    viewport (not just the banner) so the header never scrolls up
                    underneath the sticky banner and clips against it — see
                    ImpersonationBanner's own `sticky` for why the banner must never
                    scroll out of view during an impersonated session. */}
                <div className="sticky top-0 z-50 flex flex-col">
                    {/* Impersonation warning bar (visible only while impersonating) */}
                    <ImpersonationBanner />

                    {/* Header */}
                    <Header onMenuClick={() => setSidebarOpen(true)} />
                </div>

                {/* Main content */}
                <main className="flex-1">
                    {/* Breadcrumbs */}
                    {breadcrumbs && breadcrumbs.length > 0 && (
                        <div
                            className="border-b"
                            style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                        >
                            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                                <div className="py-4">
                                    <Breadcrumb items={breadcrumbs} />
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Page content */}
                    <div className={clsx('flex-1', className)}>{children}</div>
                </main>

                {/* Footer */}
                {showFooter && <Footer />}
            </div>

            {/* Cmd-K global search overlay */}
            {cmdkOpen && <CmdKSearch onClose={() => setCmdkOpen(false)} />}
        </div>
    );
};

// Simple page wrapper for consistent spacing
export interface PageProps {
    children: React.ReactNode;
    title?: string;
    subtitle?: string;
    actions?: React.ReactNode;
    className?: string;
}

const Page: React.FC<PageProps> = ({ children, title, subtitle, actions, className }) => {
    return (
        <div className={clsx('max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8', className)}>
            {(title || subtitle || actions) && (
                <div className="mb-8">
                    <div className="md:flex md:items-center md:justify-between">
                        <div className="flex-1 min-w-0">
                            {title && (
                                <h1
                                    className="text-2xl font-bold leading-7 sm:text-3xl sm:truncate"
                                    style={{ color: 'var(--text-primary)' }}
                                >
                                    {title}
                                </h1>
                            )}
                            {subtitle && (
                                <p className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                                    {subtitle}
                                </p>
                            )}
                        </div>
                        {actions && <div className="mt-4 flex md:mt-0 md:ml-4">{actions}</div>}
                    </div>
                </div>
            )}
            {children}
        </div>
    );
};

export { Layout, Page };
