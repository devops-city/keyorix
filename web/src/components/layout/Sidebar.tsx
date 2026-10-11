import React from 'react';
import { Link, useLocation } from 'react-router';
import { Dialog } from 'radix-ui';
import { cn } from '@/lib/utils';
import { clsx } from 'clsx';
import {
    XMarkIcon,
    HomeIcon,
    KeyIcon,
    FolderIcon,
    DocumentTextIcon,
    ChevronDownIcon,
    ShieldCheckIcon,
    Cog6ToothIcon,
    PuzzlePieceIcon,
    ScaleIcon,
    RocketLaunchIcon,
    ShareIcon,
    BanknotesIcon,
} from '@heroicons/react/24/outline';
import { useUIStore } from '../../store/uiStore';
import { useAuth } from '../../features/auth';
import { useLicenseStatus } from '../../features/license';
import { ProjectSwitcher } from './ProjectSwitcher';
import { appVersionLabel } from '../../utils/buildInfo';
import { paletteShortcutLabel } from '../../utils/platform';

export interface SidebarProps {
    isOpen: boolean;
    onClose: () => void;
    className?: string;
}

export interface NavLeaf {
    kind: 'leaf';
    name: string;
    href: string;
    icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>;
    soon?: boolean;
    adminOnly?: boolean; // hidden from non-admins, independent of the parent group
    needs?: string; // hidden unless the user holds this permission (admins always do)
    commercialOnly?: boolean; // hidden on community builds (the feature does not exist there)
}

export interface NavGroup {
    kind: 'group';
    id: string;
    name: string;
    icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
    children: NavLeaf[];
    adminOnly?: boolean; // hidden from non-admins (install-admin roles only)
}

export type NavItem = NavLeaf | NavGroup;

// Exported for src/__tests__/structure/routeReachability.test.ts, which checks every
// route App.tsx declares is reachable from here (or explicitly allowlisted) and every
// href here resolves to a declared route.
export const NAV: NavItem[] = [
    {
        kind: 'leaf',
        name: 'Dashboard',
        href: '/dashboard',
        icon: HomeIcon,
    },
    {
        kind: 'leaf',
        name: 'Projects',
        href: '/projects',
        icon: FolderIcon,
    },
    {
        kind: 'group',
        id: 'secrets',
        name: 'Secrets',
        icon: KeyIcon,
        children: [
            { kind: 'leaf', name: 'All Secrets', href: '/secrets' },
            { kind: 'leaf', name: 'Secret Expiry', href: '/secrets/expiry' },
            { kind: 'leaf', name: 'Secrets Health', href: '/secrets/health' },
            { kind: 'leaf', name: 'Usage Analytics', href: '/secrets/usage' },
            { kind: 'leaf', name: 'Dynamic Secrets', href: '/secrets/dynamic' },
            { kind: 'leaf', name: 'Rotation Policies', href: '/secrets/rotation' },
        ],
    },
    {
        kind: 'leaf',
        name: 'Sharing',
        href: '/sharing',
        icon: ShareIcon,
    },
    {
        kind: 'leaf',
        name: 'Audit Logs',
        href: '/audit',
        icon: DocumentTextIcon,
        needs: 'audit.read',
    },
    {
        kind: 'group',
        id: 'access',
        name: 'Access Control',
        icon: ShieldCheckIcon,
        adminOnly: true,
        children: [
            { kind: 'leaf', name: 'Users', href: '/admin/users' },
            { kind: 'leaf', name: 'Groups', href: '/admin/groups' },
            { kind: 'leaf', name: 'Roles & Policies', href: '/admin/roles' },
            { kind: 'leaf', name: 'Machine Identities', href: '/admin/machine-identities' },
        ],
    },
    {
        kind: 'group',
        id: 'integrations',
        name: 'Integrations',
        icon: PuzzlePieceIcon,
        children: [
            { kind: 'leaf', name: 'SDKs & CLI', href: '/integrations/sdks' },
            { kind: 'leaf', name: 'Keyorix Connect', href: '/integrations/connect' },
            { kind: 'leaf', name: 'Notification Channels', href: '/admin/notification-channels', adminOnly: true },
        ],
    },
    {
        kind: 'leaf',
        name: 'Compliance',
        href: '/compliance',
        icon: ScaleIcon,
    },
    {
        kind: 'leaf',
        name: 'Billing',
        href: '/admin/billing',
        icon: BanknotesIcon,
        adminOnly: true,
        commercialOnly: true,
    },
    {
        kind: 'leaf',
        name: 'Roadmap',
        href: '/roadmap',
        icon: RocketLaunchIcon,
    },
    {
        kind: 'group',
        id: 'settings',
        name: 'Settings',
        icon: Cog6ToothIcon,
        children: [
            { kind: 'leaf', name: 'Appearance', href: '/settings/appearance' },
            { kind: 'leaf', name: 'Authentication', href: '/settings/auth', adminOnly: true },
            { kind: 'leaf', name: 'Encryption & Keys', href: '/settings/encryption', adminOnly: true },
            { kind: 'leaf', name: 'License', href: '/settings/license', adminOnly: true },
            { kind: 'leaf', name: 'System Health', href: '/settings/health', adminOnly: true },
        ],
    },
];

// ── Leaf link ────────────────────────────────────────────────────────────
interface LeafProps {
    item: NavLeaf;
    indent?: boolean;
    isActive: (href: string) => boolean;
    onClose: () => void;
}

export const Leaf: React.FC<LeafProps> = ({ item, indent, isActive, onClose }) => {
    const active = isActive(item.href);
    const leafColor = item.soon ? 'var(--text-muted)' : 'var(--text-secondary)';
    const color = active ? 'var(--accent-text)' : leafColor;
    return (
        <Link
            to={item.soon ? '#' : item.href}
            onClick={item.soon ? (e) => e.preventDefault() : onClose}
            className={clsx(
                'group flex items-center justify-between px-3 py-1.5 text-sm rounded-md transition-colors duration-100',
                indent ? 'ml-6' : '',
                active ? 'font-medium' : 'font-normal',
                item.soon && 'cursor-default'
            )}
            style={{
                backgroundColor: active ? 'var(--accent-subtle)' : undefined,
                color,
            }}
            onMouseEnter={(e) => {
                if (!active && !item.soon) (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)';
            }}
            onMouseLeave={(e) => {
                if (!active) (e.currentTarget as HTMLElement).style.backgroundColor = '';
            }}
        >
            <span className="flex items-center gap-2.5 truncate">
                {item.icon && (
                    <item.icon
                        className="h-4 w-4 shrink-0"
                        style={{ color: active ? 'var(--accent)' : 'var(--text-muted)' }}
                    />
                )}
                {item.name}
            </span>
            {item.soon && (
                <span
                    className="text-[10px] font-semibold px-1.5 py-0.5 rounded-sm uppercase tracking-wide shrink-0"
                    style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }}
                >
                    Soon
                </span>
            )}
        </Link>
    );
};

// ── Group row ────────────────────────────────────────────────────────────
interface GroupProps {
    item: NavGroup;
    isActive: (href: string) => boolean;
    isGroupActive: (group: NavGroup) => boolean;
    toggleSidebarGroup: (id: string) => void;
    sidebarExpanded: Record<string, boolean>;
    onClose: () => void;
}

const Group: React.FC<GroupProps> = ({
    item,
    isActive,
    isGroupActive,
    toggleSidebarGroup,
    sidebarExpanded,
    onClose,
}) => {
    const active = isGroupActive(item);
    const expanded = (sidebarExpanded[item.id] ?? false) || active;
    return (
        <div>
            <button
                type="button"
                onClick={() => toggleSidebarGroup(item.id)}
                className="w-full flex items-center justify-between px-3 py-1.5 text-sm rounded-md transition-colors duration-100"
                style={{
                    color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                    fontWeight: active ? 500 : 400,
                }}
                onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)')}
                onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.backgroundColor = '')}
            >
                <span className="flex items-center gap-2.5">
                    <item.icon
                        className="h-4 w-4 shrink-0"
                        style={{ color: active ? 'var(--accent)' : 'var(--text-muted)' }}
                    />
                    {item.name}
                </span>
                <ChevronDownIcon
                    className={clsx('h-3.5 w-3.5 shrink-0 transition-transform duration-200', expanded && 'rotate-180')}
                    style={{ color: 'var(--text-muted)' }}
                />
            </button>
            {expanded && (
                <div className="mt-0.5 space-y-0.5">
                    {item.children.map((child) => (
                        <Leaf key={child.href} item={child} indent isActive={isActive} onClose={onClose} />
                    ))}
                </div>
            )}
        </div>
    );
};

// ── Sidebar content ──────────────────────────────────────────────────────
interface SidebarContentProps {
    navItems: NavItem[];
    isActive: (href: string) => boolean;
    isGroupActive: (group: NavGroup) => boolean;
    toggleSidebarGroup: (id: string) => void;
    sidebarExpanded: Record<string, boolean>;
    onClose: () => void;
}

const SidebarContent: React.FC<SidebarContentProps> = ({
    navItems,
    isActive,
    isGroupActive,
    toggleSidebarGroup,
    sidebarExpanded,
    onClose,
}) => (
    <div className="flex flex-col h-full" style={{ backgroundColor: 'var(--bg-surface)' }}>
        {/* Logo */}
        <div className="flex items-center px-5 py-5 border-b shrink-0" style={{ borderColor: 'var(--border)' }}>
            <Link to="/dashboard" className="flex items-center space-x-2" onClick={onClose}>
                <div className="h-8 w-8 bg-blue-600 rounded-lg flex items-center justify-center shrink-0">
                    <span className="text-white font-bold text-sm">K</span>
                </div>
                <span className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                    Keyorix
                </span>
            </Link>
        </div>

        {/* Project switcher */}
        <div className="pt-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <ProjectSwitcher onNavigate={onClose} />
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-0.5">
            {navItems.map((item) =>
                item.kind === 'leaf' ? (
                    <Leaf key={item.href} item={item} isActive={isActive} onClose={onClose} />
                ) : (
                    <Group
                        key={item.id}
                        item={item}
                        isActive={isActive}
                        isGroupActive={isGroupActive}
                        toggleSidebarGroup={toggleSidebarGroup}
                        sidebarExpanded={sidebarExpanded}
                        onClose={onClose}
                    />
                )
            )}
        </nav>

        {/* Footer */}
        <div
            className="px-4 py-3 border-t shrink-0 flex items-center justify-between"
            style={{ borderColor: 'var(--border)' }}
        >
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {appVersionLabel()}
            </p>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                <kbd className="px-1 py-0.5 rounded-sm text-[10px]" style={{ backgroundColor: 'var(--bg-muted)' }}>
                    {paletteShortcutLabel()}
                </kbd>{' '}
                search
            </span>
        </div>
    </div>
);

const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose, className }) => {
    const location = useLocation();
    const { sidebarExpanded, toggleSidebarGroup } = useUIStore();
    const { isAdmin, hasPermission } = useAuth();
    // Billing reports are a licensed feature: on a community build the page can only
    // answer 403 (and log a console error), so the entry is not offered. Unknown (still
    // loading, or the lookup failed) counts as not licensed. Only admins can read the
    // licence status, so nobody else triggers the request.
    const { data: license } = useLicenseStatus(isAdmin);
    const hasBilling = !!license?.grants && license.features.includes('billing');

    // Hide every adminOnly entry from a non-admin, in all three shapes a nav
    // entry can take: an adminOnly GROUP (Access Control), an adminOnly LEAF
    // INSIDE a group (Notification Channels, under Integrations), and an
    // adminOnly TOP-LEVEL LEAF (Billing).
    //
    // That third case used to be missed (#2774): the filter predicate was
    // `item.kind === 'group' && item.adminOnly && !isAdmin`, which is false for
    // a leaf no matter what `adminOnly` says, so a top-level adminOnly leaf was
    // always kept. Billing is the only one today, so the effect was one nav
    // item every non-admin could see and none of them could reach -- clicking
    // it hit <AdminRoute> and bounced silently back to /dashboard.
    //
    // `hidden` is written once and applied to both shapes deliberately: the
    // previous version expressed the same rule twice, in two different places,
    // and the two disagreed. The backend still enforces every API; this only
    // keeps the nav from offering a destination the user cannot reach.
    const hidden = (item: { adminOnly?: boolean; needs?: string; commercialOnly?: boolean }) =>
        (!!item.adminOnly && !isAdmin) ||
        (!!item.needs && !isAdmin && !hasPermission(item.needs)) ||
        (!!item.commercialOnly && !hasBilling);
    const navItems = NAV.filter((item) => !hidden(item)).map((item) =>
        item.kind === 'group' ? { ...item, children: item.children.filter((child) => !hidden(child)) } : item
    );

    const isActive = (href: string) => location.pathname === href || location.pathname.startsWith(href + '/');

    const isGroupActive = (group: NavGroup) => group.children.some((c) => isActive(c.href));

    return (
        <>
            {/* Mobile — Radix Dialog used for focus-trap + Esc handling */}
            <Dialog.Root
                open={isOpen}
                onOpenChange={(open) => {
                    if (!open) onClose();
                }}
            >
                <Dialog.Portal>
                    <Dialog.Overlay
                        className={cn(
                            'fixed inset-0 z-40 bg-black/60 lg:hidden',
                            'data-[state=open]:animate-in data-[state=open]:fade-in-0',
                            'data-[state=closed]:animate-out data-[state=closed]:fade-out-0',
                            'duration-300'
                        )}
                    />
                    <Dialog.Content
                        className={cn(
                            'fixed inset-y-0 left-0 z-40 flex flex-col max-w-xs w-full lg:hidden',
                            'data-[state=open]:animate-in data-[state=open]:slide-in-from-left',
                            'data-[state=closed]:animate-out data-[state=closed]:slide-out-to-left',
                            'duration-300'
                        )}
                        style={{ backgroundColor: 'var(--bg-surface)' }}
                        aria-describedby={undefined}
                    >
                        <Dialog.Title className="sr-only">Navigation menu</Dialog.Title>
                        <div className="absolute top-0 right-0 -mr-12 pt-2">
                            <Dialog.Close className="ml-1 flex items-center justify-center h-10 w-10 rounded-full focus:outline-hidden focus:ring-2 focus:ring-inset focus:ring-white">
                                <XMarkIcon className="h-6 w-6 text-white" />
                            </Dialog.Close>
                        </div>
                        <SidebarContent
                            navItems={navItems}
                            isActive={isActive}
                            isGroupActive={isGroupActive}
                            toggleSidebarGroup={toggleSidebarGroup}
                            sidebarExpanded={sidebarExpanded}
                            onClose={onClose}
                        />
                    </Dialog.Content>
                </Dialog.Portal>
            </Dialog.Root>

            {/* Desktop */}
            <div className={clsx('hidden lg:flex lg:flex-col lg:w-64 lg:fixed lg:inset-y-0', className)}>
                <div
                    className="flex flex-col grow border-r overflow-y-auto"
                    style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                >
                    <SidebarContent
                        navItems={navItems}
                        isActive={isActive}
                        isGroupActive={isGroupActive}
                        toggleSidebarGroup={toggleSidebarGroup}
                        sidebarExpanded={sidebarExpanded}
                        onClose={onClose}
                    />
                </div>
            </div>
        </>
    );
};

export { Sidebar };
