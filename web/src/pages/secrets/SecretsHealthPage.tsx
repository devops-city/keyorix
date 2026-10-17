import React from 'react';
import { Link, useNavigate } from 'react-router';
import {
    ShieldCheckIcon,
    ClockIcon,
    ExclamationTriangleIcon,
    ArrowPathIcon,
    EyeIcon,
    CheckCircleIcon,
} from '@heroicons/react/24/outline';
import { useSecretsHealth } from '../../features/secrets/useSecretsHealth';
import { humanizeAlertType } from '../../utils/anomaly';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { useUIStore } from '../../store/uiStore';

// ── helpers ───────────────────────────────────────────────────────────────────

const fmt = (n: number) => n.toLocaleString();

function scoreColor(score: number): string {
    if (score >= 80) return '#10b981'; // emerald-500
    if (score >= 60) return '#f59e0b'; // amber-500
    return '#ef4444'; // red-500
}

function scoreLabel(score: number): string {
    if (score >= 80) return 'Healthy';
    if (score >= 60) return 'Needs Attention';
    return 'At Risk';
}

// scoreLabelColor uses the same thresholds and palette as scoreColor
const scoreLabelColor = scoreColor;

// ── Health Score Ring ─────────────────────────────────────────────────────────

const RADIUS = 60;
const STROKE = 12;
const CIRC = 2 * Math.PI * RADIUS;

const ScoreRing: React.FC<{ score: number }> = ({ score }) => {
    const color = scoreColor(score);
    const offset = CIRC * (1 - score / 100);
    return (
        <svg width="160" height="160" viewBox="0 0 160 160" className="shrink-0">
            {/* Track */}
            <circle cx="80" cy="80" r={RADIUS} fill="none" stroke="var(--bg-subtle)" strokeWidth={STROKE} />
            {/* Progress */}
            <circle
                cx="80"
                cy="80"
                r={RADIUS}
                fill="none"
                stroke={color}
                strokeWidth={STROKE}
                strokeLinecap="round"
                strokeDasharray={CIRC}
                strokeDashoffset={offset}
                transform="rotate(-90 80 80)"
                style={{ transition: 'stroke-dashoffset 0.6s ease' }}
            />
            {/* Score text */}
            <text
                x="80"
                y="72"
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize="28"
                fontWeight="700"
                fill={color}
                fontFamily="inherit"
            >
                {score}
            </text>
            {/* /100 */}
            <text
                x="80"
                y="92"
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize="11"
                fill="var(--text-muted)"
                fontFamily="inherit"
            >
                / 100
            </text>
        </svg>
    );
};

// ── Component bar ─────────────────────────────────────────────────────────────

interface ComponentRowProps {
    label: string;
    pct: number;
    weight: string;
    unavailable?: boolean;
}

const ComponentRow: React.FC<ComponentRowProps> = ({ label, pct, weight, unavailable }) => {
    const color = unavailable ? 'var(--text-muted)' : scoreColor(pct);
    const barPct = unavailable ? 0 : pct;
    return (
        <div className="space-y-1.5">
            <div className="flex items-center justify-between text-sm">
                <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                <div className="flex items-center gap-2">
                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        {weight}
                    </span>
                    <span className="font-semibold tabular-nums w-12 text-right" style={{ color }}>
                        {unavailable ? 'N/A' : `${pct}%`}
                    </span>
                </div>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-subtle)' }}>
                <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${barPct}%`, backgroundColor: color }}
                />
            </div>
        </div>
    );
};

// ── Section card shell ────────────────────────────────────────────────────────

interface SectionCardProps {
    title: string;
    icon: React.ReactNode;
    linkLabel?: string | undefined;
    linkTo?: string | undefined;
    children: React.ReactNode;
}

const SectionCard: React.FC<SectionCardProps> = ({ title, icon, linkLabel, linkTo, children }) => (
    <div className="bg-surface border border-base rounded-xl shadow-xs">
        <div className="flex items-center justify-between px-6 py-4 border-b border-base">
            <div className="flex items-center gap-2">
                <span style={{ color: 'var(--text-muted)' }}>{icon}</span>
                <h2 className="text-sm font-semibold text-base-primary uppercase tracking-widest">{title}</h2>
            </div>
            {linkLabel && linkTo && (
                <Link
                    to={linkTo}
                    className="text-xs font-medium transition-opacity hover:opacity-70"
                    style={{ color: 'var(--accent-text)' }}
                >
                    {linkLabel}
                </Link>
            )}
        </div>
        <div className="px-6 py-4">{children}</div>
    </div>
);

// ── Stat row inside cards ─────────────────────────────────────────────────────

interface StatRowProps {
    label: string;
    value: number;
    dot?: 'red' | 'amber' | 'green' | 'neutral';
}

const DOT_COLORS = {
    red: '#ef4444',
    amber: '#f59e0b',
    green: '#10b981',
    neutral: 'var(--text-muted)',
};

const StatRow: React.FC<StatRowProps> = ({ label, value, dot }) => (
    <div className="flex items-center justify-between py-2.5 border-b border-base last:border-0">
        <div className="flex items-center gap-2.5">
            {dot && <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: DOT_COLORS[dot] }} />}
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                {label}
            </span>
        </div>
        <span className="text-sm font-semibold tabular-nums" style={{ color: 'var(--text-primary)' }}>
            {fmt(value)}
        </span>
    </div>
);

// ── Expiry card content ───────────────────────────────────────────────────────

interface ExpiryCardContentProps {
    expiry: ReturnType<typeof useSecretsHealth>['expiry'];
    isDark: boolean;
}

const ExpiryCardContent: React.FC<ExpiryCardContentProps> = ({ expiry, isDark }) => (
    <>
        <StatRow label="Expired" value={expiry.expired} dot="red" />
        <StatRow label="Expiring within 7 days" value={expiry.expiring7d} dot="red" />
        <StatRow label="Expiring within 30 days" value={expiry.expiring30d} dot="amber" />
        <StatRow label="Healthy (no expiry or >30d)" value={expiry.healthy} dot="green" />

        {expiry.expired > 0 && (
            <div
                className="mt-4 flex items-center gap-2 px-3 py-2.5 rounded-lg border text-xs font-medium"
                style={{
                    backgroundColor: isDark ? 'rgba(239,68,68,0.08)' : '#fee2e2',
                    borderColor: isDark ? 'rgba(239,68,68,0.25)' : '#fca5a5',
                    color: isDark ? '#f87171' : '#991b1b',
                }}
            >
                <ExclamationTriangleIcon className="h-4 w-4 shrink-0" />
                {expiry.expired} secret{expiry.expired !== 1 ? 's have' : ' has'} already expired and may be breaking
                dependent services.
            </div>
        )}
    </>
);

// ── Rotation card content ─────────────────────────────────────────────────────

interface RotationCardContentProps {
    rotation: ReturnType<typeof useSecretsHealth>['rotation'];
    isDark: boolean;
}

const RotationCardContent: React.FC<RotationCardContentProps> = ({ rotation, isDark }) => {
    if (!rotation.available) {
        return (
            <div className="flex flex-col items-center justify-center py-8 text-center gap-3">
                <ArrowPathIcon className="h-8 w-8" style={{ color: 'var(--text-muted)' }} />
                <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
                    No rotation policies yet
                </p>
                <p className="text-xs max-w-xs" style={{ color: 'var(--text-muted)' }}>
                    Create a rotation policy to track how current your secrets are. Rotation is excluded from the health
                    score until at least one policy applies.
                </p>
            </div>
        );
    }

    return (
        <>
            <StatRow label="Overdue" value={rotation.overdue} dot={rotation.overdue > 0 ? 'red' : 'green'} />
            <StatRow label="Due soon" value={rotation.dueSoon} dot={rotation.dueSoon > 0 ? 'amber' : 'green'} />
            <StatRow label="Up to date" value={rotation.ok} dot="green" />
            <StatRow label="Secrets under policy" value={rotation.covered} dot="neutral" />
            <StatRow label="Self-rotating" value={rotation.items.filter((e) => e.auto_rotate).length} dot="neutral" />

            {rotation.overdue > 0 && (
                <div className="mt-4 space-y-2">
                    {rotation.items
                        .filter((e) => e.status === 'overdue')
                        .sort((a, b) => b.days_overdue - a.days_overdue)
                        .slice(0, 4)
                        .map((e) => (
                            <div
                                key={`${e.policy_id}-${e.secret_id}`}
                                className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg border"
                                style={{
                                    backgroundColor: isDark ? 'rgba(239,68,68,0.06)' : '#fff5f5',
                                    borderColor: isDark ? 'rgba(239,68,68,0.20)' : '#fca5a5',
                                }}
                            >
                                <span
                                    className="text-xs font-medium truncate flex items-center gap-1.5"
                                    style={{ color: isDark ? '#f87171' : '#991b1b' }}
                                >
                                    {e.secret_name}
                                    {e.auto_rotate && (
                                        <span
                                            title={
                                                e.rotation_backend
                                                    ? `Auto-rotates via ${e.rotation_backend}`
                                                    : 'Auto-rotates (Keyorix-generated)'
                                            }
                                            className="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-semibold"
                                            style={{
                                                backgroundColor: isDark ? 'rgba(59,130,246,0.18)' : '#dbeafe',
                                                color: isDark ? '#93c5fd' : '#1e40af',
                                            }}
                                        >
                                            Auto
                                            {e.rotation_backend ? `: ${e.rotation_backend}` : ''}
                                        </span>
                                    )}
                                </span>
                                <span
                                    className="text-xs tabular-nums shrink-0"
                                    style={{ color: isDark ? '#fca5a5' : '#b91c1c' }}
                                >
                                    {e.days_overdue}d overdue · {e.interval_days}d policy
                                </span>
                            </div>
                        ))}
                    {rotation.overdue > 4 && (
                        <p className="text-xs text-center pt-1" style={{ color: 'var(--text-muted)' }}>
                            +{rotation.overdue - 4} more overdue
                        </p>
                    )}
                </div>
            )}
        </>
    );
};

// ── Access card content ───────────────────────────────────────────────────────

interface AccessCardContentProps {
    access: ReturnType<typeof useSecretsHealth>['access'];
    isDark: boolean;
    onFailedAuthClick: () => void;
}

const AccessCardContent: React.FC<AccessCardContentProps> = ({ access, isDark, onFailedAuthClick }) => {
    let failedAuthDot: StatRowProps['dot'] = 'amber';
    if (access.failedAuth24h === 0) failedAuthDot = 'green';
    else if (access.failedAuth24h >= 5) failedAuthDot = 'red';

    return (
        <>
            <StatRow label="Secret reads (last 30d)" value={access.reads30d} dot="neutral" />
            <StatRow label="Failed logins (24h)" value={access.failedAuth24h} dot={failedAuthDot} />
            <StatRow
                label="Inactive users (no login 30d)"
                value={access.inactiveUsers}
                dot={access.inactiveUsers === 0 ? 'green' : 'amber'}
            />

            {access.failedAuth24h >= 5 && (
                <button
                    type="button"
                    className="mt-4 flex items-center gap-2 px-3 py-2.5 rounded-lg border text-xs font-medium cursor-pointer"
                    style={{
                        backgroundColor: isDark ? 'rgba(239,68,68,0.08)' : '#fee2e2',
                        borderColor: isDark ? 'rgba(239,68,68,0.25)' : '#fca5a5',
                        color: isDark ? '#f87171' : '#991b1b',
                    }}
                    onClick={onFailedAuthClick}
                >
                    <ExclamationTriangleIcon className="h-4 w-4 shrink-0" />
                    High number of failed logins. Review audit log for potential brute-force activity.
                </button>
            )}
        </>
    );
};

// ── Anomaly card content ──────────────────────────────────────────────────────

interface AnomalyCardContentProps {
    anomalies: ReturnType<typeof useSecretsHealth>['anomalies'];
    isDark: boolean;
}

const AnomalyCardContent: React.FC<AnomalyCardContentProps> = ({ anomalies, isDark }) => {
    if (anomalies.count === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-8 text-center gap-3">
                <CheckCircleIcon className="h-8 w-8" style={{ color: '#10b981' }} />
                <p className="text-sm font-medium" style={{ color: '#10b981' }}>
                    No active anomalies detected
                </p>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    All access patterns are within expected parameters.
                </p>
            </div>
        );
    }

    return (
        <>
            {/* Severity summary */}
            <div className="mb-4 flex items-center gap-2">
                <div
                    className="px-3 py-1.5 rounded-lg text-sm font-semibold"
                    style={{
                        backgroundColor: isDark ? 'rgba(239,68,68,0.10)' : '#fee2e2',
                        color: isDark ? '#f87171' : '#991b1b',
                    }}
                >
                    {anomalies.count} active anomal{anomalies.count === 1 ? 'y' : 'ies'}
                </div>
            </div>

            {/* Alert list (top 4) */}
            <div className="space-y-2">
                {anomalies.items.slice(0, 4).map((a) => (
                    <div
                        key={a.ID}
                        className="flex items-start gap-3 px-3 py-2.5 rounded-lg border"
                        style={{
                            backgroundColor: isDark ? 'rgba(239,68,68,0.06)' : '#fff5f5',
                            borderColor: isDark ? 'rgba(239,68,68,0.20)' : '#fca5a5',
                        }}
                    >
                        <div className="w-2 h-2 rounded-full shrink-0 mt-1.5" style={{ backgroundColor: '#ef4444' }} />
                        <div className="flex-1 min-w-0">
                            <p className="text-xs font-semibold" style={{ color: isDark ? '#f87171' : '#991b1b' }}>
                                {humanizeAlertType(a.AlertType)}
                            </p>
                            <p className="text-xs truncate" style={{ color: isDark ? '#fca5a5' : '#b91c1c' }}>
                                {a.SecretName} · {a.AccessedBy}
                            </p>
                        </div>
                    </div>
                ))}
                {anomalies.count > 4 && (
                    <p className="text-xs text-center pt-1" style={{ color: 'var(--text-muted)' }}>
                        +{anomalies.count - 4} more —{' '}
                        <Link
                            to="/audit?tab=anomalies"
                            className="underline underline-offset-2"
                            style={{ color: 'var(--accent-text)' }}
                        >
                            view all
                        </Link>
                    </p>
                )}
            </div>
        </>
    );
};

// ── Main page ─────────────────────────────────────────────────────────────────

export function SecretsHealthPage() {
    const navigate = useNavigate();
    const { theme } = useUIStore();
    const isDark =
        theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

    const { score, total, expiry, rotation, access, anomalies, isLoading, error } = useSecretsHealth();

    if (error) {
        return (
            <div className="max-w-7xl mx-auto px-6 py-8">
                <Alert
                    type="error"
                    title="Failed to load health data"
                    message="Could not fetch secrets or dashboard stats. Please try again."
                >
                    <button
                        type="button"
                        onClick={() => window.location.reload()}
                        className="text-sm font-medium underline"
                        style={{ color: 'var(--accent-text)' }}
                    >
                        Retry
                    </button>
                </Alert>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-app">
            <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
                {/* ── Header ──────────────────────────────────────────────── */}
                <div>
                    <h1 className="text-2xl font-bold text-base-primary tracking-tight">Secrets Health</h1>
                    <p className="mt-1 text-sm text-base-muted">
                        Hygiene posture across {fmt(total)} secret{total !== 1 ? 's' : ''} — expiry, rotation, and
                        access coverage
                    </p>
                </div>

                {isLoading ? (
                    <div className="p-12">
                        <Loading />
                    </div>
                ) : (
                    <>
                        {/* ── Health Score Card (full width) ────────────────── */}
                        <div className="bg-surface border border-base rounded-xl shadow-xs">
                            <div className="px-6 py-4 border-b border-base">
                                <h2 className="text-sm font-semibold text-base-primary uppercase tracking-widest">
                                    Secrets Health Score
                                </h2>
                                <p className="text-xs text-base-muted mt-0.5">
                                    Based on expiry, rotation, and access hygiene
                                </p>
                            </div>
                            <div className="p-6 flex flex-col sm:flex-row gap-8 items-center sm:items-start">
                                {/* Ring */}
                                <div className="flex flex-col items-center gap-2 shrink-0">
                                    <ScoreRing score={score} />
                                    <span className="text-sm font-semibold" style={{ color: scoreLabelColor(score) }}>
                                        {scoreLabel(score)}
                                    </span>
                                </div>

                                {/* Component breakdown */}
                                <div className="flex-1 min-w-0 space-y-5 w-full">
                                    <div className="space-y-1">
                                        <p
                                            className="text-xs font-semibold uppercase tracking-widest"
                                            style={{ color: 'var(--text-muted)' }}
                                        >
                                            Score Breakdown
                                        </p>
                                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                            Each component contributes to the overall score based on its weight.
                                        </p>
                                    </div>
                                    <ComponentRow label="Expiry Health" pct={expiry.pct} weight="40%" />
                                    <ComponentRow
                                        label="Rotation Health"
                                        pct={rotation.pct}
                                        weight="30%"
                                        unavailable={!rotation.available}
                                    />
                                    <ComponentRow label="Access Health" pct={access.pct} weight="30%" />

                                    {!rotation.available && (
                                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                            * Rotation score is excluded from the total until a rotation policy applies
                                            to a secret.
                                        </p>
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* ── 2-column grid ─────────────────────────────────── */}
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            {/* Card 1 — Expiry Health */}
                            <SectionCard
                                title="Expiry Health"
                                icon={<ClockIcon className="h-4 w-4" />}
                                linkLabel="View all expiring →"
                                linkTo="/secrets/expiry"
                            >
                                <ExpiryCardContent expiry={expiry} isDark={isDark} />
                            </SectionCard>

                            {/* Card 2 — Rotation Health */}
                            <SectionCard
                                title="Rotation Health"
                                icon={<ArrowPathIcon className="h-4 w-4" />}
                                linkLabel="Manage policies →"
                                linkTo="/secrets/rotation"
                            >
                                <RotationCardContent rotation={rotation} isDark={isDark} />
                            </SectionCard>

                            {/* Card 3 — Access Health */}
                            <SectionCard
                                title="Access Health"
                                icon={<EyeIcon className="h-4 w-4" />}
                                linkLabel="View audit log →"
                                linkTo="/audit"
                            >
                                <AccessCardContent
                                    access={access}
                                    isDark={isDark}
                                    onFailedAuthClick={() => navigate('/audit?tab=audit&filter=failed')}
                                />
                            </SectionCard>

                            {/* Card 4 — Anomaly Alerts */}
                            <SectionCard
                                title="Anomaly Alerts"
                                icon={<ShieldCheckIcon className="h-4 w-4" />}
                                linkLabel={anomalies.count > 0 ? 'View anomalies →' : undefined}
                                linkTo="/audit?tab=anomalies"
                            >
                                <AnomalyCardContent anomalies={anomalies} isDark={isDark} />
                            </SectionCard>
                        </div>

                        {/* ── Footer note ───────────────────────────────────── */}
                        <p className="text-xs text-center" style={{ color: 'var(--text-muted)' }}>
                            Health score is computed from the first 500 secrets. Score updates every 2 minutes.
                        </p>
                    </>
                )}
            </div>
        </div>
    );
}
