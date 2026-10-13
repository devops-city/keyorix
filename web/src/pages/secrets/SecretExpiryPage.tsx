import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    ClockIcon,
    ExclamationTriangleIcon,
    CalendarDaysIcon,
    ArrowTopRightOnSquareIcon,
    MagnifyingGlassIcon,
} from '@heroicons/react/24/outline';
import { Link } from 'react-router';
import { secretsApi } from '../../services/secrets';
import { Secret } from '../../types';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Input } from '../../components/ui/Input';
import { useUIStore } from '../../store/uiStore';

// ── helpers ──────────────────────────────────────────────────────────────────

function daysRemaining(expiration: string): number {
    const now = new Date();
    const exp = new Date(expiration);
    return Math.ceil((exp.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

function formatDate(d: string): string {
    return new Intl.DateTimeFormat('en', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    }).format(new Date(d));
}

type Tab = 'all' | 'expired' | 'soon' | 'future';

// ── status badge ─────────────────────────────────────────────────────────────

const STATUS_STYLES = {
    expired: {
        dark: { bg: 'rgba(239,68,68,0.15)', color: '#f87171' },
        light: { bg: '#fee2e2', color: '#991b1b' },
        label: 'Expired',
    },
    soon: {
        dark: { bg: 'rgba(245,158,11,0.15)', color: '#fbbf24' },
        light: { bg: '#fef3c7', color: '#92400e' },
        label: 'Expiring Soon',
    },
    future: {
        dark: { bg: 'rgba(59,130,246,0.15)', color: '#60a5fa' },
        light: { bg: '#dbeafe', color: '#1e40af' },
        label: 'Active',
    },
} as const;

const TYPE_STYLES: Record<
    string,
    { darkBg: string; darkColor: string; lightBg: string; lightColor: string; label: string }
> = {
    password: {
        darkBg: 'rgba(99,102,241,0.15)',
        darkColor: '#818cf8',
        lightBg: '#e0e7ff',
        lightColor: '#3730a3',
        label: 'password',
    },
    api_key: {
        darkBg: 'rgba(16,185,129,0.15)',
        darkColor: '#34d399',
        lightBg: '#dcfce7',
        lightColor: '#166534',
        label: 'api_key',
    },
    text: {
        darkBg: 'rgba(148,163,184,0.15)',
        darkColor: '#94a3b8',
        lightBg: '#f1f5f9',
        lightColor: '#475569',
        label: 'text',
    },
    certificate: {
        darkBg: 'rgba(251,191,36,0.15)',
        darkColor: '#fbbf24',
        lightBg: '#fef9c3',
        lightColor: '#854d0e',
        label: 'cert',
    },
    json: {
        darkBg: 'rgba(251,146,60,0.15)',
        darkColor: '#fb923c',
        lightBg: '#ffedd5',
        lightColor: '#9a3412',
        label: 'json',
    },
};

function statusBucket(days: number): 'expired' | 'soon' | 'future' {
    if (days < 0) return 'expired';
    if (days <= 30) return 'soon';
    return 'future';
}

const StatusBadge: React.FC<{ days: number }> = ({ days }) => {
    const { theme } = useUIStore();
    const isDark =
        theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const bucket = statusBucket(days);
    const s = STATUS_STYLES[bucket];
    const style = isDark ? s.dark : s.light;
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium tracking-wide"
            style={{ backgroundColor: style.bg, color: style.color }}
        >
            {s.label}
        </span>
    );
};

const TypeBadge: React.FC<{ type: string }> = ({ type }) => {
    const { theme } = useUIStore();
    const isDark =
        theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const s = (TYPE_STYLES[type] ?? TYPE_STYLES.text)!;
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium tracking-wide"
            style={{ backgroundColor: isDark ? s.darkBg : s.lightBg, color: isDark ? s.darkColor : s.lightColor }}
        >
            {s.label}
        </span>
    );
};

// ── summary card ─────────────────────────────────────────────────────────────

interface SummaryCardProps {
    label: string;
    count: number;
    icon: React.ReactNode;
    accent: string;
    accentBg: string;
    active: boolean;
    onClick: () => void;
}

const SummaryCard: React.FC<SummaryCardProps> = ({ label, count, icon, accent, accentBg, active, onClick }) => (
    <button
        type="button"
        onClick={onClick}
        className="w-full text-left rounded-lg border p-4 transition-all"
        style={{
            backgroundColor: active ? accentBg : 'var(--bg-surface)',
            borderColor: active ? accent : 'var(--border)',
            boxShadow: active ? `0 0 0 1px ${accent}` : undefined,
        }}
    >
        <div className="flex items-center justify-between mb-2">
            <span style={{ color: accent }}>{icon}</span>
            <span className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
                {count}
            </span>
        </div>
        <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            {label}
        </p>
    </button>
);

// ── days-left display ─────────────────────────────────────────────────────────

const DaysLeftCell: React.FC<{ days: number }> = ({ days }) => {
    if (days < 0) {
        return (
            <span className="text-sm font-medium" style={{ color: '#f87171' }}>
                {Math.abs(days)}d ago
            </span>
        );
    }
    if (days === 0) {
        return (
            <span className="text-sm font-medium" style={{ color: '#f87171' }}>
                Today
            </span>
        );
    }
    if (days <= 7) {
        return (
            <span className="text-sm font-medium" style={{ color: '#fbbf24' }}>
                {days}d
            </span>
        );
    }
    if (days <= 30) {
        return (
            <span className="text-sm font-medium" style={{ color: '#fb923c' }}>
                {days}d
            </span>
        );
    }
    return (
        <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
            {days}d
        </span>
    );
};

// ── table row ─────────────────────────────────────────────────────────────────

const ExpiryRow: React.FC<{ secret: Secret }> = ({ secret }) => {
    const days = daysRemaining(secret.Expiration!);
    return (
        <tr className="hover:bg-subtle transition-colors">
            <td className="px-6 py-4">
                <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                    {secret.name}
                </span>
            </td>
            <td className="px-6 py-4 whitespace-nowrap">
                <TypeBadge type={secret.type} />
            </td>
            <td className="px-6 py-4 whitespace-nowrap">
                <span
                    className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium capitalize"
                    style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-secondary)' }}
                >
                    {secret.environment || 'production'}
                </span>
            </td>
            <td className="px-6 py-4 whitespace-nowrap text-sm" style={{ color: 'var(--text-secondary)' }}>
                {formatDate(secret.Expiration!)}
            </td>
            <td className="px-6 py-4 whitespace-nowrap">
                <DaysLeftCell days={days} />
            </td>
            <td className="px-6 py-4 whitespace-nowrap">
                <StatusBadge days={days} />
            </td>
            <td className="px-6 py-4 whitespace-nowrap text-right">
                <Link
                    to={`/secrets?sort=expiry_asc&highlight=${secret.id}`}
                    className="inline-flex items-center gap-1 text-xs font-medium transition-opacity hover:opacity-70"
                    style={{ color: 'var(--accent-text)' }}
                    title="View in All Secrets"
                >
                    View
                    <ArrowTopRightOnSquareIcon className="h-3.5 w-3.5" />
                </Link>
            </td>
        </tr>
    );
};

// ── empty state ───────────────────────────────────────────────────────────────

const EMPTY_MESSAGES: Record<Tab, { heading: string; body: string }> = {
    all: { heading: 'No secrets with expiration', body: 'Set an expiration date on a secret to track it here.' },
    expired: { heading: 'No expired secrets', body: 'All secrets with expiration dates are still active.' },
    soon: { heading: 'Nothing expiring in 30 days', body: 'No secrets are due to expire in the next 30 days.' },
    future: { heading: 'No future expirations', body: 'No secrets with expiration dates beyond 30 days.' },
};

const EmptyState: React.FC<{ tab: Tab }> = ({ tab }) => {
    const { heading, body } = EMPTY_MESSAGES[tab];
    return (
        <div className="p-12 text-center">
            <CalendarDaysIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
            <h3 className="text-base font-medium mb-1" style={{ color: 'var(--text-primary)' }}>
                {heading}
            </h3>
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                {body}
            </p>
        </div>
    );
};

// ── main page ─────────────────────────────────────────────────────────────────

export function SecretExpiryPage() {
    const [tab, setTab] = useState<Tab>('all');
    const [search, setSearch] = useState('');

    const { data, isLoading, error, refetch } = useQuery({
        queryKey: ['secrets', 'expiry-page'],
        queryFn: () => secretsApi.list({ pageSize: 500 }),
        staleTime: 2 * 60 * 1000,
    });

    const withExpiry = useMemo(() => {
        if (!data?.data) return [];
        return data.data.filter((s) => s.Expiration != null);
    }, [data]);

    const expired = useMemo(() => withExpiry.filter((s) => daysRemaining(s.Expiration!) < 0), [withExpiry]);
    const soon = useMemo(
        () =>
            withExpiry.filter((s) => {
                const d = daysRemaining(s.Expiration!);
                return d >= 0 && d <= 30;
            }),
        [withExpiry]
    );
    const future = useMemo(() => withExpiry.filter((s) => daysRemaining(s.Expiration!) > 30), [withExpiry]);

    const tabSecrets = useMemo(() => {
        const allSorted = [...withExpiry].sort((a, b) => daysRemaining(a.Expiration!) - daysRemaining(b.Expiration!));
        const nonExpiredBase = tab === 'future' ? future : allSorted;
        const soonOrNonExpired = tab === 'soon' ? soon : nonExpiredBase;
        const base = tab === 'expired' ? expired : soonOrNonExpired;

        if (!search.trim()) return base;
        const q = search.toLowerCase();
        return base.filter((s) => s.name.toLowerCase().includes(q) || s.environment?.toLowerCase().includes(q));
    }, [tab, withExpiry, expired, soon, future, search]);

    if (error) {
        return (
            <div className="p-6">
                <Alert
                    type="error"
                    title="Failed to load secrets"
                    message="There was an error fetching secrets. Please try again."
                >
                    <button
                        type="button"
                        onClick={() => refetch()}
                        className="text-sm font-medium underline"
                        style={{ color: 'var(--accent-text)' }}
                    >
                        Retry
                    </button>
                </Alert>
            </div>
        );
    }

    const tabs: [Tab, string][] = [
        ['all', `All (${withExpiry.length})`],
        ['expired', `Expired (${expired.length})`],
        ['soon', `Expiring Soon (${soon.length})`],
        ['future', `Future (${future.length})`],
    ];

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div>
                <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                    Secret Expiry
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Track secrets approaching or past their expiration date
                </p>
            </div>

            {isLoading ? (
                <div className="p-12">
                    <Loading />
                </div>
            ) : (
                <>
                    {/* Summary cards */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <SummaryCard
                            label="Expired"
                            count={expired.length}
                            icon={<ExclamationTriangleIcon className="h-5 w-5" />}
                            accent="#ef4444"
                            accentBg="rgba(239,68,68,0.08)"
                            active={tab === 'expired'}
                            onClick={() => setTab('expired')}
                        />
                        <SummaryCard
                            label="Expiring within 30 days"
                            count={soon.length}
                            icon={<ClockIcon className="h-5 w-5" />}
                            accent="#f59e0b"
                            accentBg="rgba(245,158,11,0.08)"
                            active={tab === 'soon'}
                            onClick={() => setTab('soon')}
                        />
                        <SummaryCard
                            label="Future expirations"
                            count={future.length}
                            icon={<CalendarDaysIcon className="h-5 w-5" />}
                            accent="#3b82f6"
                            accentBg="rgba(59,130,246,0.08)"
                            active={tab === 'future'}
                            onClick={() => setTab('future')}
                        />
                    </div>

                    {/* Search + tabs */}
                    <div className="flex flex-col sm:flex-row sm:items-end gap-4">
                        <div className="w-full sm:w-72">
                            <Input
                                type="text"
                                placeholder="Filter by name or environment…"
                                value={search}
                                onChange={(e) => setSearch(e.target.value)}
                                icon={MagnifyingGlassIcon}
                            />
                        </div>
                        <div className="border-b flex-1" style={{ borderColor: 'var(--border)' }}>
                            {/* overflow-x-auto: the tabs scroll inside the strip on a phone instead of widening the page (#3154). */}
                            <nav className="-mb-px flex space-x-6 overflow-x-auto">
                                {tabs.map(([key, label]) => (
                                    <button
                                        key={key}
                                        type="button"
                                        onClick={() => setTab(key)}
                                        className="pb-3 px-1 text-sm font-medium border-b-2 transition-colors whitespace-nowrap"
                                        style={{
                                            borderColor: tab === key ? 'var(--accent)' : 'transparent',
                                            color: tab === key ? 'var(--accent-text)' : 'var(--text-muted)',
                                        }}
                                    >
                                        {label}
                                    </button>
                                ))}
                            </nav>
                        </div>
                    </div>

                    {/* Table */}
                    <div
                        className="rounded-lg border overflow-hidden"
                        style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                    >
                        {tabSecrets.length === 0 ? (
                            <EmptyState tab={tab} />
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y" style={{ borderColor: 'var(--border)' }}>
                                    <thead style={{ backgroundColor: 'var(--bg-subtle)' }}>
                                        <tr>
                                            {['Name', 'Type', 'Environment', 'Expires', 'Days Left', 'Status', ''].map(
                                                (h, i) => (
                                                    <th
                                                        key={i}
                                                        className={`px-6 py-3 text-xs font-medium uppercase tracking-wider ${i === 6 ? 'text-right' : 'text-left'}`}
                                                        style={{ color: 'var(--text-muted)' }}
                                                    >
                                                        {h}
                                                    </th>
                                                )
                                            )}
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                                        {tabSecrets.map((secret) => (
                                            <ExpiryRow key={secret.id} secret={secret} />
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>

                    {/* Footer note */}
                    {withExpiry.length > 0 && (
                        <p className="text-xs text-center" style={{ color: 'var(--text-muted)' }}>
                            Showing {tabSecrets.length} of {withExpiry.length} secret
                            {withExpiry.length !== 1 ? 's' : ''} with expiration dates set
                            {data && data.total > 500 && ' · fetched from first 500 secrets'}
                        </p>
                    )}
                </>
            )}
        </div>
    );
}
