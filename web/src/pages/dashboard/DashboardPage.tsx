import { useCan } from '../../features/auth/useCan';
import React from 'react';
import { useNavigate } from 'react-router';
import { ROUTES } from '../../constants';
import { useAuthStore } from '../../store/authStore';
import { useUIStore } from '../../store/uiStore';
import { ActivityItem, AnomalyAlert } from '../../types';
import { humanizeAlertType } from '../../utils/anomaly';
import { eventLabel } from '../../utils/eventLabels';
import { formatDateTime } from '../../utils/datetime';
import {
    useDashboardStats,
    useDashboardActivity,
    useSystemInfo,
    useSystemMetrics,
    useAnomalyAlerts,
    useAcknowledgeAnomaly,
    getSystemHealthSeverity,
    HEALTH_STATUS_STYLES,
    parseUptime,
} from '../../features/dashboard';

// ─── Helpers ────────────────────────────────────────────────────────────────

const fmt = (n: number) => n.toLocaleString();
const NOT_VISIBLE = 'Not visible to you';
const fmtDate = (d: string | Date) => formatDateTime(d);

interface SecurityCardData {
    label: string;
    value: string | number;
    sub: string;
    accent: string;
}
function buildSecurityCardData(
    alertCount: number,
    anomalyCount: number,
    expiredCount: number,
    expiringCount: number
): SecurityCardData {
    const plural = anomalyCount === 1 ? 'y' : 'ies';
    return {
        label: alertCount > 0 ? `Alerts (${alertCount})` : 'Security',
        value: alertCount > 0 ? alertCount : '✓',
        sub:
            alertCount > 0
                ? `${anomalyCount} anomal${plural} · ${expiredCount} expired · ${expiringCount} expiring`
                : 'No anomaly or expiry alerts',
        accent: alertCount > 0 ? 'bg-red-500' : 'bg-emerald-500',
    };
}

// A pool of 0 means the server does not report connection stats (the counters are not
// instrumented), not that nothing is connected: say n/a rather than "0 active".
function formatDbConnections(active: number | null | undefined): string {
    return active != null && active > 0 ? `${active} active` : 'n/a';
}

function buildAuditSub(logins: number | null | undefined, reads: number | null | undefined): string {
    if (logins != null && reads != null) return `${logins} logins · ${reads} reads`;
    return 'all events logged';
}

function buildActiveUsersSub(sharedCount: number): string {
    const plural = sharedCount === 1 ? '' : 's';
    return sharedCount > 0 ? `${sharedCount} shared secret${plural}` : 'registered accounts';
}

// ─── Sub-components ─────────────────────────────────────────────────────────

interface StatCardProps {
    label: string;
    value: string | number;
    sub?: string;
    trend?: { value: number; isPositive: boolean };
    prevValue?: number;
    accent: string;
    onClick?: () => void;
    // The caller may not see this number at all (no audit.read, not an admin). Showing 0 would
    // read as "nothing happened"; say it is not visible instead.
    notVisible?: boolean;
}

function buildStatCardClassName(onClick: (() => void) | undefined): string {
    const clickable = onClick ? 'cursor-pointer hover:shadow-md hover:border-base transition-all duration-150' : '';
    return `relative bg-surface border border-base rounded-xl p-6 flex flex-col gap-2 shadow-xs ${clickable}`;
}

const StatCard: React.FC<StatCardProps> = ({
    label,
    value: rawValue,
    sub: rawSub,
    trend,
    prevValue,
    accent,
    onClick: rawOnClick,
    notVisible,
}) => {
    const value = notVisible ? '—' : rawValue;
    const sub = notVisible ? NOT_VISIBLE : rawSub;
    const onClick = notVisible ? undefined : rawOnClick;
    const numericValue = typeof value === 'number' ? value : 0;
    const delta = trend && prevValue != null ? Math.round(numericValue - prevValue) : null;
    const cardClass = buildStatCardClassName(onClick);
    // Derived from the label so every card gets one without a second list to keep
    // in sync: "Total Secrets" -> stat-card-total-secrets-value. Added for #2780's
    // real-backend spec, which has to read this number rather than assert on screen
    // text — the label renders uppercase via CSS while the DOM text is title case,
    // and the value is a sibling span with no distinguishing class of its own.
    const testID = `stat-card-${label
        .toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^a-z0-9-]/g, '')}`;
    const cardContent = (
        <>
            <div className={`absolute left-0 top-4 bottom-4 w-1 rounded-r-full ${accent}`} />
            <span className="text-xs font-semibold text-base-muted uppercase tracking-widest pl-3">{label}</span>
            <span
                data-testid={`${testID}-value`}
                className="text-4xl font-bold text-base-primary pl-3 tabular-nums leading-none"
            >
                {typeof value === 'number' ? fmt(value) : value}
            </span>
            <div className="pl-3 flex items-center gap-2 flex-wrap">
                {trend && (
                    <span className={`text-xs font-semibold ${trend.isPositive ? 'text-emerald-600' : 'text-red-500'}`}>
                        {trend.isPositive ? '↑' : '↓'} {trend.value}%
                        {delta !== null && (
                            <span className="font-normal opacity-70 ml-1">
                                ({delta > 0 ? '+' : ''}
                                {delta})
                            </span>
                        )}
                    </span>
                )}
                {sub && <span className="text-xs text-base-muted">{sub}</span>}
            </div>
        </>
    );
    if (onClick) {
        return (
            <button type="button" onClick={onClick} className={cardClass}>
                {cardContent}
            </button>
        );
    }
    return <div className={cardClass}>{cardContent}</div>;
};

// FeaturePillProps removed — inline props used directly

const FeaturePill: React.FC<{ label: string; active: boolean }> = ({ label, active }) => {
    const { theme } = useUIStore();
    const isDark =
        theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const activeStyle: React.CSSProperties = {
        backgroundColor: isDark ? 'rgba(16,185,129,0.10)' : '#dcfce7',
        borderColor: isDark ? 'rgba(16,185,129,0.25)' : '#86efac',
        color: isDark ? '#34d399' : '#166534',
    };
    const inactiveStyle: React.CSSProperties = {
        backgroundColor: 'var(--bg-subtle)',
        borderColor: 'var(--border)',
        color: 'var(--text-muted)',
    };
    const activeDotColor = isDark ? '#34d399' : '#16a34a';
    const dotColor = active ? activeDotColor : 'var(--text-muted)';
    return (
        <div
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border"
            style={active ? activeStyle : inactiveStyle}
        >
            <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: dotColor }} />
            {label}
        </div>
    );
};

const EVENT_STYLES: Record<string, { dot: string; label: string }> = {
    created: { dot: 'bg-emerald-500', label: 'created secret' },
    updated: { dot: 'bg-blue-500', label: 'updated secret' },
    accessed: { dot: 'bg-amber-500', label: 'accessed secret' },
    versions_listed: { dot: 'bg-gray-400', label: 'listed versions of secret' },
    metadata_read: { dot: 'bg-gray-400', label: 'looked up secret' },
    shared: { dot: 'bg-purple-500', label: 'shared secret' },
    login: { dot: 'bg-gray-400', label: 'logged in' },
    logout: { dot: 'bg-gray-300', label: 'logged out' },
    deleted: { dot: 'bg-red-500', label: 'deleted secret' },
};

const ActivityRow: React.FC<{ item: ActivityItem }> = ({ item }) => {
    // The server sends a readable `label` for every event; the raw audit type stays
    // available as `eventType` (tooltip). Older servers send neither: fall back to a
    // friendly label derived from the type.
    const style = EVENT_STYLES[item.type] ?? { dot: 'bg-gray-400', label: item.label ?? eventLabel(item.type) };
    const secretPart = item.secretName ? ` "${item.secretName}"` : '';
    return (
        <div className="flex items-start gap-3 py-3 border-b border-base last:border-0">
            <div className="mt-1.5 shrink-0">
                <div className={`w-2 h-2 rounded-full ${style.dot}`} />
            </div>
            <div className="flex-1 min-w-0">
                <p className="text-sm text-base-primary">
                    <span className="font-semibold">{item.actor}</span>{' '}
                    <span className="text-base-muted" title={item.eventType ?? item.type}>
                        {style.label}
                        {secretPart}
                    </span>
                </p>
                <p className="text-xs text-base-muted mt-0.5">{fmtDate(item.timestamp)}</p>
            </div>
        </div>
    );
};

type SignalSeverity = 'neutral' | 'warn' | 'alert';

interface SignalCardProps {
    label: string;
    value: number;
    hint: string;
    severity: SignalSeverity;
    onClick?: () => void;
    notVisible?: boolean;
}

function getSignalCardStyles(severity: SignalSeverity, isDark: boolean): React.CSSProperties {
    if (severity === 'neutral') {
        return {
            backgroundColor: 'var(--bg-subtle)',
            borderColor: 'var(--border)',
            color: 'var(--text-secondary)',
        };
    }
    if (severity === 'warn') {
        return {
            backgroundColor: isDark ? 'rgba(245,158,11,0.08)' : 'rgba(245,158,11,0.06)',
            borderColor: isDark ? 'rgba(245,158,11,0.25)' : 'rgba(245,158,11,0.30)',
            color: isDark ? '#fbbf24' : '#92400e',
        };
    }
    return {
        backgroundColor: isDark ? 'rgba(239,68,68,0.08)' : 'rgba(239,68,68,0.06)',
        borderColor: isDark ? 'rgba(239,68,68,0.25)' : 'rgba(239,68,68,0.30)',
        color: isDark ? '#f87171' : '#991b1b',
    };
}

const SignalCard: React.FC<SignalCardProps> = ({
    label,
    value: rawValue,
    hint: rawHint,
    severity: rawSeverity,
    onClick: rawOnClick,
    notVisible,
}) => {
    const value: number | string = notVisible ? '—' : rawValue;
    const hint = notVisible ? NOT_VISIBLE : rawHint;
    const severity: SignalSeverity = notVisible ? 'neutral' : rawSeverity;
    const onClick = notVisible ? undefined : rawOnClick;
    const { theme } = useUIStore();
    const isDark =
        theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

    const styles = getSignalCardStyles(severity, isDark);
    const valueColor = severity === 'neutral' ? 'var(--text-primary)' : (styles.color as string);

    const cardClass = `flex items-center justify-between px-4 py-3 rounded-lg border transition-all duration-100${onClick ? ' cursor-pointer hover:brightness-95' : ''}`;
    const cardContent = (
        <>
            <div>
                <p className="text-xs font-semibold uppercase tracking-wide">{label}</p>
                <p className="text-xs opacity-60 mt-0.5">{hint}</p>
            </div>
            <span className="text-2xl font-bold tabular-nums" style={{ color: valueColor }}>
                {value}
            </span>
        </>
    );
    if (onClick) {
        return (
            <button type="button" onClick={onClick} className={cardClass} style={styles}>
                {cardContent}
            </button>
        );
    }
    return (
        <div className={cardClass} style={styles}>
            {cardContent}
        </div>
    );
};

// ─── Section components ────────────────────────────────────────────────────

type Stats = ReturnType<typeof useDashboardStats>['data'];
type ActivityData = ReturnType<typeof useDashboardActivity>['data'];
type Metrics = ReturnType<typeof useSystemMetrics>['data'];
type SysInfo = ReturnType<typeof useSystemInfo>['data'];

interface StatCardsSectionProps {
    navigate: (path: string) => void;
    stats: Stats;
    securityCard: SecurityCardData;
    totalSecretsSub: string;
    activeUsersSub: string;
    auditEventsSub: string;
    alertCount: number;
}

const StatCardsSection: React.FC<StatCardsSectionProps> = ({
    navigate,
    stats,
    securityCard,
    totalSecretsSub,
    activeUsersSub,
    auditEventsSub,
    alertCount,
}) => {
    const can = useCan();
    return (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
                label="Total Secrets"
                value={stats?.totalSecrets ?? 0}
                {...(stats?.totalSecretsTrend ? { trend: stats.totalSecretsTrend } : {})}
                {...(stats?.prevTotalSecrets != null ? { prevValue: stats.prevTotalSecrets } : {})}
                sub={totalSecretsSub}
                accent="bg-blue-500"
                onClick={() => navigate(ROUTES.SECRETS + '?sort=expiry_asc')}
            />
            <StatCard
                label="Active Users"
                value={stats?.activeUsers ?? 0}
                sub={activeUsersSub}
                accent="bg-purple-500"
                onClick={() => navigate(ROUTES.ADMIN_USERS)}
                notVisible={!can.admin}
            />
            <StatCard
                label="Audit Events (30d)"
                value={stats?.auditEvents30d ?? 0}
                sub={auditEventsSub}
                accent="bg-indigo-500"
                onClick={() => navigate(ROUTES.AUDIT)}
                notVisible={!can.readAudit}
            />
            <StatCard
                label={securityCard.label}
                value={securityCard.value}
                sub={securityCard.sub}
                accent={securityCard.accent}
                {...(alertCount > 0 ? { onClick: () => navigate(ROUTES.AUDIT + '?tab=anomalies') } : {})}
                notVisible={!can.readAudit}
            />
        </div>
    );
};

interface OperationalSignalsSectionProps {
    navigate: (path: string) => void;
    stats: Stats;
    expiring: any[];
    expiringHint: string;
    expiringSeverity: SignalSeverity;
    failedAuth: number;
    failedAuthSeverity: SignalSeverity;
}

// DASH-FAILED-2FA: the failed-login count is a wrong password plus a wrong second factor
// (TOTP / recovery code / passkey). A server that predates the split sends only the total.
function failedLoginsHint(stats: Stats): string {
    const wrongPassword = stats?.failedLoginsWrongPassword24h;
    const wrongSecondFactor = stats?.failedLoginsWrongSecondFactor24h;
    if (wrongPassword === undefined || wrongSecondFactor === undefined) return 'unsuccessful sign-ins';
    return `${wrongPassword} wrong password · ${wrongSecondFactor} wrong second factor`;
}

const OperationalSignalsSection: React.FC<OperationalSignalsSectionProps> = ({
    navigate,
    stats,
    expiring,
    expiringHint,
    expiringSeverity,
    failedAuth,
    failedAuthSeverity,
}) => {
    const can = useCan();
    return (
        <div className="bg-surface border border-base rounded-xl shadow-xs">
            <div className="px-6 py-4 border-b border-base">
                <h2 className="text-sm font-semibold text-base-primary uppercase tracking-widest">
                    Operational Signals
                </h2>
            </div>
            <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                <SignalCard
                    label="Expiring Secrets"
                    value={expiring.length}
                    hint={expiringHint}
                    severity={expiringSeverity}
                    onClick={() => navigate(ROUTES.SECRETS + '?sort=expiry_asc&filter=expiring')}
                />
                <SignalCard
                    label="Failed Logins (24h)"
                    value={failedAuth}
                    hint={failedLoginsHint(stats)}
                    severity={failedAuthSeverity}
                    onClick={() => navigate(ROUTES.AUDIT + '?tab=audit&filter=failed')}
                    notVisible={!can.readAudit}
                />
                <SignalCard
                    label="Refused Secret Reads (24h)"
                    value={stats?.refusedSecretReads24h ?? 0}
                    hint="access denied or blocked"
                    severity={(stats?.refusedSecretReads24h ?? 0) === 0 ? 'neutral' : 'warn'}
                    onClick={() => navigate(ROUTES.AUDIT + '?tab=audit&filter=failed')}
                    notVisible={!can.readAudit}
                />
                <SignalCard
                    label="Inactive Users"
                    value={stats?.inactiveUsers ?? 0}
                    hint="no login in 30 days"
                    severity={(stats?.inactiveUsers ?? 0) === 0 ? 'neutral' : 'warn'}
                    onClick={() => navigate(ROUTES.ADMIN_USERS + '?filter=inactive')}
                    notVisible={!can.admin}
                />
                <SignalCard
                    label="Secret Reads (30d)"
                    value={stats?.auditSecretReads30d ?? 0}
                    hint="access events logged"
                    severity="neutral"
                    onClick={() => navigate(ROUTES.AUDIT + '?tab=audit&filter=reads')}
                    notVisible={!can.readAudit}
                />
            </div>
        </div>
    );
};

interface RecentActivitySectionProps {
    navigate: (path: string) => void;
    activityData: ActivityData;
    // hasSecrets picks the empty-state copy. "Create your first secret to get
    // started" is only true for a genuinely new user; for a project member who can
    // read secrets but has generated no visible audit events — the ordinary case for
    // a read-only persona, since this feed is scoped to the caller's own events
    // without audit.read — it is wrong, and it invites an action they may not be
    // permitted to take. Part of #2780's demo-visible symptom: the misleading copy
    // sat under a count that was also wrong, and fixing only the number would have
    // left the sentence.
    hasSecrets: boolean;
}

const RecentActivitySection: React.FC<RecentActivitySectionProps> = ({ navigate, activityData, hasSecrets }) => (
    <div className="lg:col-span-2 bg-surface border border-base rounded-xl shadow-xs">
        <div className="flex items-center justify-between px-6 py-4 border-b border-base">
            <h2 className="text-sm font-semibold text-base-primary uppercase tracking-widest">Recent Activity</h2>
            <button
                type="button"
                onClick={() => navigate(ROUTES.AUDIT)}
                className="text-xs font-medium text-base-muted hover:text-base-secondary transition-colors"
            >
                View all →
            </button>
        </div>
        <div className="px-6 py-2">
            {!activityData?.data?.length ? (
                <div className="py-12 text-center">
                    <p className="text-sm text-base-muted">
                        {hasSecrets
                            ? 'No recent activity to show.'
                            : 'No activity yet. Create your first secret to get started.'}
                    </p>
                </div>
            ) : (
                activityData.data.slice(0, 8).map((item: ActivityItem) => <ActivityRow key={item.id} item={item} />)
            )}
        </div>
    </div>
);

interface SystemHealthPanelProps {
    metrics: Metrics;
    sysInfo: SysInfo;
    features: Record<string, boolean | undefined>;
    dbMetrics: Record<string, any>;
    hasError: boolean;
}

// Distinct from HEALTH_STATUS_STYLES' 'neutral' — a fetch failure isn't the
// same claim as "checked and found healthy", so it gets its own gray state.
const UNKNOWN_STATUS_STYLE = { dot: 'bg-gray-400', text: 'text-gray-500', label: 'Unknown' };

const SystemHealthPanel: React.FC<SystemHealthPanelProps> = ({ metrics, sysInfo, features, dbMetrics, hasError }) => {
    const severity = getSystemHealthSeverity(metrics, sysInfo);
    const statusStyle = hasError ? UNKNOWN_STATUS_STYLE : HEALTH_STATUS_STYLES[severity];

    return (
        <div className="bg-surface border border-base rounded-xl shadow-xs">
            <div className="px-5 py-4 border-b border-base">
                <h2 className="text-sm font-semibold text-base-primary uppercase tracking-widest">System Health</h2>
            </div>
            <div className="px-5 py-4 space-y-3">
                <div className="flex items-center justify-between">
                    <span className="text-sm text-base-muted">Status</span>
                    <div className="flex items-center gap-1.5">
                        <div className={`w-2 h-2 rounded-full ${statusStyle.dot} animate-pulse`} />
                        <span className={`text-sm font-semibold ${statusStyle.text}`}>{statusStyle.label}</span>
                    </div>
                </div>
                <div className="flex items-center justify-between">
                    <span className="text-sm text-base-muted">Uptime</span>
                    <span className="text-sm font-medium text-base-primary">
                        {parseUptime(metrics?.uptime ?? sysInfo?.uptime ?? '')}
                    </span>
                </div>
                <div className="flex items-center justify-between">
                    <span className="text-sm text-base-muted">DB connections</span>
                    <span className="text-sm font-medium text-base-primary">
                        {formatDbConnections(dbMetrics.connections_active)}
                    </span>
                </div>
                <div className="flex items-center justify-between">
                    <span className="text-sm text-base-muted">Encryption</span>
                    <span className="text-sm font-medium text-base-primary">
                        {sysInfo?.security?.encryption_method ?? 'AES-256-GCM'}
                    </span>
                </div>

                <div className="pt-2 flex flex-wrap gap-1.5">
                    <FeaturePill label="Encryption" active={features.encryption_enabled ?? true} />
                    <FeaturePill label="RBAC" active={features.rbac_enabled ?? true} />
                    <FeaturePill label="Audit" active={features.audit_enabled ?? true} />
                    <FeaturePill label="TLS" active={features.tls_enabled ?? true} />
                </div>
            </div>
        </div>
    );
};

// Cap the alerts rendered inline on the dashboard. The panel is a glanceable
// summary, not the full list — without a cap it grows with the anomaly count
// (hundreds are normal) and overruns the layout. "View all" links to the audit
// anomalies tab for the complete, paginated view.
const MAX_SECURITY_ALERTS = 5;

interface SecurityAlertsPanelProps {
    navigate: (path: string) => void;
    alertCount: number;
    anomalies: AnomalyAlert[];
    expiring: any[];
    acknowledgeAnomaly: ReturnType<typeof useAcknowledgeAnomaly>;
}

const SecurityAlertsPanel: React.FC<SecurityAlertsPanelProps> = ({
    navigate,
    alertCount,
    anomalies,
    expiring,
    acknowledgeAnomaly,
}) => (
    <div className="bg-surface border border-red-200 rounded-xl shadow-xs">
        <div className="px-5 py-4 border-b border-red-50 flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-red-700 uppercase tracking-widest flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                Security Alerts ({alertCount})
            </h2>
            <button
                type="button"
                onClick={() => navigate(ROUTES.AUDIT + '?tab=anomalies')}
                className="text-xs font-medium text-red-600 hover:text-red-700 transition-colors shrink-0"
            >
                View all →
            </button>
        </div>
        <div className="p-4 space-y-2">
            {[...anomalies]
                .sort((a, b) => (b.DetectedAt ?? '').localeCompare(a.DetectedAt ?? ''))
                .slice(0, MAX_SECURITY_ALERTS)
                .map((a) => (
                    <div key={a.ID} className="flex items-start justify-between gap-2 p-3 bg-red-50 rounded-lg">
                        <div className="flex-1 min-w-0">
                            <p className="text-xs font-semibold text-red-700">{humanizeAlertType(a.AlertType)}</p>
                            <p className="text-xs text-red-600 mt-0.5 truncate">{a.SecretName}</p>
                            <p className="text-xs text-base-muted mt-0.5">
                                {a.AccessedBy} · {a.IPAddress}
                            </p>
                        </div>
                        <button
                            type="button"
                            onClick={() => acknowledgeAnomaly.mutate(a.ID)}
                            className="text-xs text-base-muted hover:text-base-secondary shrink-0 mt-0.5"
                            title="Dismiss"
                        >
                            ✓
                        </button>
                    </div>
                ))}
            {expiring.map((s: any) => {
                const urgentBadgeColor = s.daysLeft <= 7 ? 'text-red-600' : 'text-amber-600';
                const expiryBadgeColor = s.expired ? 'bg-red-500/20 text-red-400' : urgentBadgeColor;
                return (
                    <div
                        key={s.id}
                        className={`flex items-center justify-between p-3 rounded-lg ${s.expired ? 'bg-red-950/30 border border-red-900/40' : 'bg-amber-50 dark:bg-amber-950/20'}`}
                    >
                        <div>
                            <p className={`text-xs font-semibold ${s.expired ? 'text-red-400' : 'text-amber-700'}`}>
                                {s.name}
                            </p>
                            <p className={`text-xs ${s.expired ? 'text-red-500' : 'text-amber-600'}`}>
                                {s.environment}
                            </p>
                        </div>
                        <span className={`text-xs font-bold px-1.5 py-0.5 rounded-sm ${expiryBadgeColor}`}>
                            {s.expired ? `${Math.abs(s.daysLeft)}d overdue` : `${s.daysLeft}d`}
                        </span>
                    </div>
                );
            })}
            {anomalies.length > MAX_SECURITY_ALERTS && (
                <button
                    type="button"
                    onClick={() => navigate(ROUTES.AUDIT + '?tab=anomalies')}
                    className="w-full text-center text-xs font-medium text-red-600 hover:text-red-700 transition-colors pt-1"
                >
                    +{anomalies.length - MAX_SECURITY_ALERTS} more{' '}
                    {anomalies.length - MAX_SECURITY_ALERTS === 1 ? 'alert' : 'alerts'} →
                </button>
            )}
        </div>
    </div>
);

interface AuditHealthPanelProps {
    navigate: (path: string) => void;
    stats: Stats;
}

// The four numbers are deployment-wide audit aggregates: the server sends zeros to a caller
// without audit.read. A "0" there reads as "nothing happened", so say they are not visible (#3155).
const AuditHealthPanel: React.FC<AuditHealthPanelProps> = ({ navigate, stats }) => {
    const can = useCan();
    if (!can.readAudit) {
        return (
            <div className="bg-surface border border-base rounded-xl shadow-xs">
                <div className="px-5 py-4 border-b border-base">
                    <h2 className="text-sm font-semibold text-base-primary uppercase tracking-widest">Audit (30d)</h2>
                </div>
                <div className="px-5 py-4">
                    <p className="text-sm text-base-muted" data-testid="audit-panel-not-visible">
                        {NOT_VISIBLE}
                    </p>
                </div>
            </div>
        );
    }
    return <AuditHealthCounts navigate={navigate} stats={stats} />;
};

const AuditHealthCounts: React.FC<AuditHealthPanelProps> = ({ navigate, stats }) => (
    <div className="bg-surface border border-base rounded-xl shadow-xs">
        <div className="px-5 py-4 border-b border-base flex items-center justify-between">
            <h2 className="text-sm font-semibold text-base-primary uppercase tracking-widest">Audit (30d)</h2>
            <button
                type="button"
                onClick={() => navigate(ROUTES.AUDIT)}
                className="text-xs text-base-muted hover:text-base-secondary transition-colors"
            >
                View →
            </button>
        </div>
        <div className="px-5 py-4 space-y-3">
            <div className="flex items-center justify-between">
                <span className="text-sm text-base-muted">Total events</span>
                <span className="text-sm font-semibold text-base-primary tabular-nums">
                    {fmt(stats?.auditEvents30d ?? 0)}
                </span>
            </div>
            <div className="flex items-center justify-between">
                <span className="text-sm text-base-muted">Logins</span>
                <span className="text-sm font-semibold text-blue-600 tabular-nums">
                    {fmt(stats?.auditLogins30d ?? 0)}
                </span>
            </div>
            <div className="flex items-center justify-between">
                <span className="text-sm text-base-muted">Secret reads</span>
                <span className="text-sm font-semibold text-amber-600 tabular-nums">
                    {fmt(stats?.auditSecretReads30d ?? 0)}
                </span>
            </div>
            <div className="flex items-center justify-between">
                <span className="text-sm text-base-muted">Other events</span>
                <span className="text-sm font-semibold text-base-muted tabular-nums">
                    {fmt(
                        Math.max(
                            0,
                            (stats?.auditEvents30d ?? 0) -
                                (stats?.auditLogins30d ?? 0) -
                                (stats?.auditSecretReads30d ?? 0)
                        )
                    )}
                </span>
            </div>
        </div>
    </div>
);

// ─── Main Page ───────────────────────────────────────────────────────────────

function getGreeting(hour: number): string {
    if (hour < 12) return 'Good morning';
    if (hour < 18) return 'Good afternoon';
    return 'Good evening';
}

function getExpiringSeverity(expiringTotal: number, expiredCount: number, urgentCount: number): SignalSeverity {
    if (expiringTotal === 0) return 'neutral';
    if (expiredCount > 0 || urgentCount > 0) return 'alert';
    return 'warn';
}

function getFailedAuthSeverity(failedAuth: number): SignalSeverity {
    if (failedAuth === 0) return 'neutral';
    if (failedAuth >= 5) return 'alert';
    return 'warn';
}

type AnomalyData = ReturnType<typeof useAnomalyAlerts>['data'];

interface DashboardViewModel {
    anomalies: AnomalyAlert[];
    expiring: any[];
    alertCount: number;
    features: Record<string, boolean | undefined>;
    dbMetrics: Record<string, any>;
    greeting: string;
    activeUsersSub: string;
    auditEventsSub: string;
    securityCard: SecurityCardData;
    expiringHint: string;
    expiringSeverity: SignalSeverity;
    failedAuth: number;
    failedAuthSeverity: SignalSeverity;
    totalSecretsSub: string;
}

// Pure derivation of everything the view needs from the raw hook data — kept
// separate from DashboardPage so the component itself is just hooks + render.
function deriveDashboardData(
    stats: Stats,
    anomalyData: AnomalyData,
    sysInfo: SysInfo,
    metrics: Metrics
): DashboardViewModel {
    const anomalies: AnomalyAlert[] = anomalyData?.data?.alerts ?? [];
    const expiring = stats?.expiringSecrets ?? [];
    const expiredSecrets = expiring.filter((s: any) => s.expired);
    const expiringSecrets = expiring.filter((s: any) => !s.expired);
    const alertCount = anomalies.length + expiring.length;

    const features = sysInfo?.features ?? {};
    const dbMetrics = metrics?.database ?? {};

    const greeting = getGreeting(new Date().getHours());

    const sharedCount = stats?.sharedSecrets ?? 0;
    const activeUsersSub = buildActiveUsersSub(sharedCount);
    const auditEventsSub = buildAuditSub(stats?.auditLogins30d, stats?.auditSecretReads30d);
    const securityCard = buildSecurityCardData(
        alertCount,
        anomalies.length,
        expiredSecrets.length,
        expiringSecrets.length
    );

    const expiringHint =
        expiredSecrets.length > 0
            ? `${expiredSecrets.length} expired · ${expiringSecrets.length} expiring in 30d`
            : 'within 30 days';

    const urgentExpiringCount = expiringSecrets.filter((s: any) => s.daysLeft <= 7).length;
    const expiringSeverity = getExpiringSeverity(expiring.length, expiredSecrets.length, urgentExpiringCount);

    const failedAuth = stats?.failedAuthAttempts24h ?? 0;
    const failedAuthSeverity = getFailedAuthSeverity(failedAuth);

    const totalSecretsSub = stats?.totalSecretsTrend ? 'vs last snapshot' : 'across all environments';

    return {
        anomalies,
        expiring,
        alertCount,
        features,
        dbMetrics,
        greeting,
        activeUsersSub,
        auditEventsSub,
        securityCard,
        expiringHint,
        expiringSeverity,
        failedAuth,
        failedAuthSeverity,
        totalSecretsSub,
    };
}

export const DashboardPage: React.FC = () => {
    const navigate = useNavigate();
    const { user } = useAuthStore();

    const { data: stats, error: statsError } = useDashboardStats();
    const { data: activityData } = useDashboardActivity({ pageSize: 8 });
    const { data: metrics, isError: metricsError } = useSystemMetrics();
    const { data: sysInfo, isError: sysInfoError } = useSystemInfo();
    const { data: anomalyData } = useAnomalyAlerts(true);
    const acknowledgeAnomaly = useAcknowledgeAnomaly();

    const {
        anomalies,
        expiring,
        alertCount,
        features,
        dbMetrics,
        greeting,
        activeUsersSub,
        auditEventsSub,
        securityCard,
        expiringHint,
        expiringSeverity,
        failedAuth,
        failedAuthSeverity,
        totalSecretsSub,
    } = deriveDashboardData(stats, anomalyData, sysInfo, metrics);

    return (
        <div className="min-h-screen bg-app">
            <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
                {/* ── Header ─────────────────────────────────────────────── */}
                <div className="flex items-end justify-between">
                    <div>
                        <p className="text-sm text-base-muted mb-1">{greeting}</p>
                        <h1 className="text-2xl font-bold text-base-primary tracking-tight">
                            {(user?.displayName || user?.username || 'admin').split(' ')[0]}
                        </h1>
                    </div>
                </div>

                <StatCardsSection
                    navigate={navigate}
                    stats={stats}
                    securityCard={securityCard}
                    totalSecretsSub={totalSecretsSub}
                    activeUsersSub={activeUsersSub}
                    auditEventsSub={auditEventsSub}
                    alertCount={alertCount}
                />

                <OperationalSignalsSection
                    navigate={navigate}
                    stats={stats}
                    expiring={expiring}
                    expiringHint={expiringHint}
                    expiringSeverity={expiringSeverity}
                    failedAuth={failedAuth}
                    failedAuthSeverity={failedAuthSeverity}
                />

                {/* ── Main Grid ──────────────────────────────────────────── */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <RecentActivitySection
                        navigate={navigate}
                        activityData={activityData}
                        hasSecrets={(stats?.totalSecrets ?? 0) > 0}
                    />

                    {/* Right column */}
                    <div className="space-y-4">
                        <SystemHealthPanel
                            metrics={metrics}
                            sysInfo={sysInfo}
                            features={features}
                            dbMetrics={dbMetrics}
                            hasError={Boolean(metricsError || sysInfoError)}
                        />

                        {/* Quick Actions removed — duplicates sidebar navigation */}

                        {alertCount > 0 && (
                            <SecurityAlertsPanel
                                navigate={navigate}
                                alertCount={alertCount}
                                anomalies={anomalies}
                                expiring={expiring}
                                acknowledgeAnomaly={acknowledgeAnomaly}
                            />
                        )}

                        <AuditHealthPanel navigate={navigate} stats={stats} />
                    </div>
                </div>

                {!!statsError && (
                    <p className="text-xs text-amber-600 text-center">
                        Some statistics unavailable — other features are unaffected.
                    </p>
                )}
            </div>
        </div>
    );
};
