import { formatDateTime } from '../../utils/datetime';
import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { complianceApi } from '../../services/compliance';
import { apiClient } from '../../services/client';
import { triggerBlobDownload } from '../../utils';

// LegalHoldBanner surfaces the deployment legal-hold state (A.5.34) and lets an
// admin place or lift it. Reads status from the shared posture query; mutations
// need system.write (a 403 surfaces as an inline error). Hidden until the posture
// loads (or on 403 — the panel above already shows the admin-only note).
const LegalHoldBanner: React.FC = () => {
    const queryClient = useQueryClient();
    const { data: p } = useQuery({
        queryKey: ['compliance', 'posture'],
        queryFn: () => complianceApi.getPosture(),
        staleTime: 60_000,
        retry: false,
    });
    const invalidate = () => queryClient.invalidateQueries({ queryKey: ['compliance', 'posture'] });
    const place = useMutation({
        mutationFn: (reason: string) => complianceApi.placeLegalHold(reason),
        onSuccess: invalidate,
    });
    const lift = useMutation({
        mutationFn: (reason: string) => complianceApi.liftLegalHold(reason),
        onSuccess: invalidate,
    });

    const [placing, setPlacing] = useState(false);
    const [lifting, setLifting] = useState(false);
    const [reason, setReason] = useState('');
    const [error, setError] = useState('');
    const onError = (err: any) =>
        setError(err?.response?.data?.error ?? err?.response?.data?.message ?? 'Action failed.');

    if (!p) return null;
    const active = p.legalHold.active;

    return (
        <div
            className="rounded-xl border mb-6 px-6 py-4"
            style={
                active
                    ? { borderColor: 'var(--error)', backgroundColor: 'var(--error-subtle)' }
                    : { borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }
            }
        >
            <div className="flex items-center gap-3">
                <div className="flex-1 min-w-0">
                    <p
                        className="text-sm font-semibold"
                        style={{ color: active ? 'var(--error)' : 'var(--text-primary)' }}
                    >
                        {active ? 'Legal hold active — purges are blocked' : 'No legal hold'}
                    </p>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                        {active
                            ? `Records are preserved (A.5.34). Reason: ${p.legalHold.reason || '—'}`
                            : 'Background purge/retention jobs run normally.'}
                    </p>
                </div>
                {(() => {
                    if (active && !lifting) {
                        return (
                            <button
                                type="button"
                                onClick={() => {
                                    setError('');
                                    setLifting(true);
                                }}
                                disabled={lift.isPending}
                                className="px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 shrink-0"
                                style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                            >
                                Lift hold
                            </button>
                        );
                    }
                    if (!placing && !active) {
                        return (
                            <button
                                type="button"
                                onClick={() => {
                                    setError('');
                                    setPlacing(true);
                                }}
                                className="px-3 py-1.5 rounded-lg text-xs font-medium shrink-0"
                                style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                            >
                                Place hold
                            </button>
                        );
                    }
                    return null;
                })()}
            </div>
            {lifting && active && (
                <div className="mt-3 flex items-center gap-2">
                    <input
                        value={reason}
                        onChange={(e) => setReason(e.target.value)}
                        placeholder="Reason for lifting (e.g. litigation closed — case INC-7)"
                        autoFocus
                        className="flex-1 rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                    <button
                        type="button"
                        onClick={() => {
                            if (!reason.trim()) return;
                            setError('');
                            lift.mutate(reason.trim(), {
                                onError,
                                onSuccess: () => {
                                    invalidate();
                                    setLifting(false);
                                    setReason('');
                                },
                            });
                        }}
                        disabled={lift.isPending || !reason.trim()}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 shrink-0"
                        style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                    >
                        Confirm lift
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            setLifting(false);
                            setReason('');
                        }}
                        className="px-2.5 py-1.5 rounded-lg text-xs shrink-0"
                        style={{ color: 'var(--text-muted)' }}
                    >
                        Cancel
                    </button>
                </div>
            )}
            {placing && !active && (
                <div className="mt-3 flex items-center gap-2">
                    <input
                        value={reason}
                        onChange={(e) => setReason(e.target.value)}
                        placeholder="Reason (e.g. litigation hold — case INC-7)"
                        autoFocus
                        className="flex-1 rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                    <button
                        type="button"
                        onClick={() => {
                            if (!reason.trim()) return;
                            setError('');
                            place.mutate(reason.trim(), {
                                onError,
                                onSuccess: () => {
                                    invalidate();
                                    setPlacing(false);
                                    setReason('');
                                },
                            });
                        }}
                        disabled={place.isPending || !reason.trim()}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 shrink-0"
                        style={{ backgroundColor: 'var(--error)', color: '#fff' }}
                    >
                        Confirm hold
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            setPlacing(false);
                            setReason('');
                        }}
                        className="px-2.5 py-1.5 rounded-lg text-xs shrink-0"
                        style={{ color: 'var(--text-muted)' }}
                    >
                        Cancel
                    </button>
                </div>
            )}
            {error && (
                <p className="text-xs mt-2" style={{ color: 'var(--error)' }}>
                    {error}
                </p>
            )}
        </div>
    );
};

interface SectionCardProps {
    title: string;
    children: React.ReactNode;
}

const Tile: React.FC<{ label: string; value: React.ReactNode; tone?: 'good' | 'warn' | 'bad' | undefined }> = ({
    label,
    value,
    tone,
}) => {
    let color = 'var(--text-primary)';
    if (tone === 'good') color = 'var(--success)';
    else if (tone === 'warn') color = 'var(--warning)';
    else if (tone === 'bad') color = 'var(--error)';
    return (
        <div
            className="rounded-lg border px-3 py-2.5"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-app)' }}
        >
            <div className="text-lg font-semibold" style={{ color }}>
                {value}
            </div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                {label}
            </div>
        </div>
    );
};

const posturePlaceholder = (): React.ReactElement => (
    <div
        className="rounded-xl border mb-6 p-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[1, 2, 3, 4].map((i) => (
                <div key={i} className="h-16 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-muted)' }} />
            ))}
        </div>
    </div>
);

const postureErrorMessage = (status: number | undefined): string => {
    if (status === 403) return 'The live controls-posture report is available to administrators (system.read).';
    return 'Controls posture is currently unavailable.';
};

const buildAnomalyTone = (highSeverityOpen: number, unacknowledged: number): 'bad' | 'warn' | 'good' => {
    if (highSeverityOpen > 0) return 'bad';
    if (unacknowledged > 0) return 'warn';
    return 'good';
};

const buildAnomalyValue = (unacknowledged: number, highSeverityOpen: number): string => {
    const suffix = highSeverityOpen > 0 ? ` (${highSeverityOpen} high)` : '';
    return `${unacknowledged}${suffix}`;
};

function countTone(n: number, aboveTone: 'warn' | 'bad'): 'good' | 'warn' | 'bad' {
    return n > 0 ? aboveTone : 'good';
}
function maybeCountTone(n: number, aboveTone: 'warn' | 'bad'): 'good' | 'warn' | 'bad' | undefined {
    return n > 0 ? aboveTone : undefined;
}
function boolTone(ok: boolean): 'good' | 'bad' {
    return ok ? 'good' : 'bad';
}

// PosturePanel surfaces the live controls-posture report (GET /compliance/posture).
// It needs system.read; non-admins get 403 and the panel shows a quiet note rather
// than failing the page.
const PosturePanel: React.FC = () => {
    const {
        data: p,
        isLoading,
        isError,
        error,
    } = useQuery({
        queryKey: ['compliance', 'posture'],
        queryFn: () => complianceApi.getPosture(),
        staleTime: 60_000,
        retry: false,
    });

    if (isLoading) return posturePlaceholder();
    if (isError || !p) {
        const status = (error as any)?.response?.status as number | undefined;
        return (
            <div
                className="rounded-xl border mb-6 px-6 py-4 text-sm"
                style={{
                    borderColor: 'var(--border)',
                    backgroundColor: 'var(--bg-surface)',
                    color: 'var(--text-muted)',
                }}
            >
                {postureErrorMessage(status)}
            </div>
        );
    }

    const ag = p.accessGovernance;
    const reviewed = ag.projects - ag.projectsNeverReviewed;
    const anomalyValue = buildAnomalyValue(p.anomalies.unacknowledged, p.anomalies.highSeverityOpen);
    const anomalyTone = buildAnomalyTone(p.anomalies.highSeverityOpen, p.anomalies.unacknowledged);
    return (
        <div
            className="rounded-xl border mb-8 overflow-hidden"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div
                className="px-6 py-4 border-b flex items-center justify-between"
                style={{ borderColor: 'var(--border)' }}
            >
                <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                    Controls posture
                </h2>
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    {p.generatedAt ? formatDateTime(p.generatedAt) : ''}
                </span>
            </div>
            <div className="px-6 py-5 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                <Tile
                    label="Audit chain verified (A.5.28)"
                    value={p.auditIntegrity.chainVerified ? 'Yes' : 'No'}
                    tone={boolTone(p.auditIntegrity.chainVerified)}
                />
                <Tile
                    label="On-box checkpointed"
                    value={p.auditIntegrity.checkpointed ? 'Yes' : 'No'}
                    tone={maybeCountTone(p.auditIntegrity.checkpointed ? 0 : 1, 'warn')}
                />
                <Tile
                    label="Second-factor coverage"
                    value={`${p.identity.secondFactorPercent}%`}
                    tone={p.identity.secondFactorPercent >= 80 ? 'good' : 'warn'}
                />
                <Tile label="Active users" value={p.identity.activeUsers} />
                <Tile
                    label="Projects reviewed (A.5.18)"
                    value={`${reviewed}/${ag.projects}`}
                    tone={countTone(ag.projectsNeverReviewed, 'warn')}
                />
                <Tile label="Open campaigns / pending" value={`${ag.openCampaigns} / ${ag.pendingItems}`} />
                <Tile
                    label="Dormant role grants"
                    value={ag.dormantRoleGrants}
                    tone={countTone(ag.dormantRoleGrants, 'warn')}
                />
                <Tile
                    label="SoD violations (A.5.3)"
                    value={ag.sodViolations}
                    tone={countTone(ag.sodViolations, 'bad')}
                />
                <Tile
                    label="Projects overdue for recert (A.5.18)"
                    value={ag.projectsOverdue}
                    tone={countTone(ag.projectsOverdue, 'warn')}
                />
                <Tile
                    label="Rotation overdue / due-soon (A.5.15)"
                    value={`${p.rotation.overdue} / ${p.rotation.dueSoon}`}
                    tone={countTone(p.rotation.overdue, 'warn')}
                />
                <Tile
                    label="Break-glass active / total"
                    value={`${p.emergencyAccess.activeActivations} / ${p.emergencyAccess.totalActivations}`}
                    tone={maybeCountTone(p.emergencyAccess.activeActivations, 'warn')}
                />
                <Tile
                    label="Restricted secrets (A.5.12)"
                    value={p.classification.restricted}
                    tone={maybeCountTone(p.classification.restricted, 'warn')}
                />
                <Tile
                    label="Unclassified secrets"
                    value={`${p.classification.unclassified} / ${p.classification.totalSecrets}`}
                    tone={countTone(p.classification.unclassified, 'warn')}
                />
                <Tile label="Open anomalies (NIS2)" value={anomalyValue} tone={anomalyTone} />
            </div>
            <div className="px-6 pb-5 pt-1">
                <h3
                    className="text-xs font-semibold uppercase tracking-widest mb-3"
                    style={{ color: 'var(--text-muted)' }}
                >
                    Data retention (A.5.33) — {p.retention.enabled ? 'enforced' : 'not configured'}
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <Tile label="Anomaly alerts" value={retentionWindow(p.retention.anomalyAlertsDays)} />
                    <Tile label="Closed access reviews" value={retentionWindow(p.retention.closedAccessReviewsDays)} />
                    <Tile label="Break-glass register" value={retentionWindow(p.retention.breakGlassDays)} />
                    <Tile
                        label="Resolved access requests"
                        value={retentionWindow(p.retention.resolvedAccessRequestsDays)}
                    />
                </div>
            </div>
        </div>
    );
};

// retentionWindow renders a retention window: a day count, or "Keep" when 0 (the
// record type is retained indefinitely).
const retentionWindow = (days: number): string => (days > 0 ? `${days}d` : 'Keep');

// DigestPanel surfaces the on-demand compliance digest (GET /compliance/digest) — the
// same human-readable summary otherwise broadcast to the notification channels — so an
// admin can read or copy a point-in-time report. Needs system.read; hidden on 403/error.
const DigestPanel: React.FC = () => {
    const { data, isError } = useQuery({
        queryKey: ['compliance', 'digest'],
        queryFn: () => complianceApi.getDigest(),
        staleTime: 60_000,
        retry: false,
    });
    const [copied, setCopied] = useState(false);

    if (isError || !data?.body) return null; // 403/unavailable — posture panel already notes admin-only

    const onCopy = () => {
        const text = `${data.title}\n\n${data.body}`;
        void navigator.clipboard?.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div
            className="rounded-xl border mb-8 overflow-hidden"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div
                className="px-6 py-4 border-b flex items-center justify-between gap-3"
                style={{ borderColor: 'var(--border)' }}
            >
                <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                    Compliance digest
                </h2>
                <button
                    type="button"
                    onClick={onCopy}
                    className="px-2.5 py-1 rounded-lg text-xs font-medium shrink-0"
                    style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                >
                    {copied ? 'Copied' : 'Copy'}
                </button>
            </div>
            <div className="px-6 py-5">
                <p className="text-sm font-medium mb-2" style={{ color: 'var(--text-primary)' }}>
                    {data.title}
                </p>
                <pre className="text-xs whitespace-pre-wrap font-sans" style={{ color: 'var(--text-secondary)' }}>
                    {data.body}
                </pre>
            </div>
        </div>
    );
};

// SoDViolationsSection lists the separation-of-duties violations (principals
// holding a forbidden permission pair). Needs system.read; hidden on 403/empty.
const SoDViolationsSection: React.FC = () => {
    const { data: violations = [], isError } = useQuery({
        queryKey: ['sod', 'violations'],
        queryFn: () => complianceApi.getSoDViolations(),
        staleTime: 60_000,
        retry: false,
    });
    if (isError || violations.length === 0) return null;
    return (
        <div
            className="rounded-xl border mb-8 overflow-hidden"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--error)' }}>
                    Separation-of-duties violations ({violations.length})
                </h2>
            </div>
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {violations.map((v) => (
                    <li key={`${v.username}:${v.policyName}`} className="px-6 py-3 flex items-center gap-3">
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                {v.email ? `${v.username} (${v.email})` : v.username}
                            </p>
                            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                {v.policyName}
                            </p>
                        </div>
                        <span
                            className="text-xs px-2 py-1 rounded-md shrink-0"
                            style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                        >
                            {v.permissionA} + {v.permissionB}
                        </span>
                    </li>
                ))}
            </ul>
        </div>
    );
};

const SectionCard: React.FC<SectionCardProps> = ({ title, children }) => (
    <div
        className="rounded-xl border overflow-hidden mb-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                {title}
            </h2>
        </div>
        <div className="px-6 py-5">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                {children}
            </p>
        </div>
    </div>
);

// ControlMatrixPanel renders the framework control matrix (GET /compliance/controls):
// each enforced control with its live status and ISO/SOC2/NIS2/DORA/ENS references.
// A framework selector tab bar filters the view to a single framework and shows
// a per-framework compliance score — the "compliance mapping reports" Q3 feature.
const NA_META = { label: 'N/A', color: 'var(--text-muted)', bg: 'var(--bg-muted)' };
const STATUS_META: Record<string, { label: string; color: string; bg: string }> = {
    pass: { label: 'Pass', color: 'var(--success)', bg: 'var(--success-subtle)' },
    gap: { label: 'Gap', color: 'var(--error)', bg: 'var(--error-subtle)' },
    not_configured: NA_META,
    // Added 2026-09-07 alongside the backend's ControlStatusPartiallyEvaluated:
    // a mix of evaluated/not-yet-evaluated members, distinct from a clean Pass.
    partially_evaluated: { label: 'Partial', color: 'var(--warning)', bg: 'var(--warning-subtle)' },
};

type FrameworkKey = 'all' | 'iso27001' | 'soc2' | 'nis2' | 'dora' | 'ens';

const FRAMEWORKS: { key: FrameworkKey; label: string; fullName: string; description: string }[] = [
    { key: 'all', label: 'All', fullName: 'All frameworks', description: '' },
    {
        key: 'iso27001',
        label: 'ISO 27001',
        fullName: 'ISO/IEC 27001:2022',
        description:
            'Information security management system standard. Annex A controls cover access management (A.8), cryptography (A.8.24), and operations security.',
    },
    {
        key: 'soc2',
        label: 'SOC 2',
        fullName: 'SOC 2 Type II',
        description:
            'AICPA trust service criteria. Security, Availability, Confidentiality, and Privacy principles relevant to secrets management.',
    },
    {
        key: 'nis2',
        label: 'NIS2',
        fullName: 'NIS2 Directive (EU 2022/2555)',
        description:
            'Article 21 mandates technical security measures including access controls, encryption, and audit logging for essential and important entities.',
    },
    {
        key: 'dora',
        label: 'DORA',
        fullName: 'Digital Operational Resilience Act (EU 2022/2554)',
        description:
            'Article 30 requires ICT risk management records, access logs, and cryptographic controls for financial entities and their ICT providers.',
    },
    {
        key: 'ens',
        label: 'ENS',
        fullName: 'Esquema Nacional de Seguridad',
        description:
            "Spain's mandatory security certification for public-sector ICT. Maps to op.acc, op.exp, mp.s, and mp.sw control families.",
    },
];

const ControlMatrixPanel: React.FC = () => {
    const { data: m, isError } = useQuery({
        queryKey: ['compliance', 'controls'],
        queryFn: () => complianceApi.getControls(),
        staleTime: 60_000,
        retry: false,
    });
    const [csvBusy, setCsvBusy] = useState(false);
    const [activeFramework, setActiveFramework] = useState<FrameworkKey>('all');

    if (isError || !m) return null;

    // Download the control matrix as a CSV for an auditor's spreadsheet (server #376).
    const onDownloadCsv = async () => {
        setCsvBusy(true);
        try {
            const res = await apiClient.get('/api/v1/compliance/controls.csv', { responseType: 'blob' });
            triggerBlobDownload(res.data as Blob, 'compliance-controls.csv');
        } finally {
            setCsvBusy(false);
        }
    };

    const refLine = (c: (typeof m.controls)[number]): string => {
        const parts: string[] = [];
        if (c.frameworks.iso27001.length) parts.push(`ISO ${c.frameworks.iso27001.join(', ')}`);
        if (c.frameworks.soc2.length) parts.push(`SOC2 ${c.frameworks.soc2.join(', ')}`);
        if (c.frameworks.nis2.length) parts.push(`NIS2 ${c.frameworks.nis2.join(', ')}`);
        if (c.frameworks.dora.length) parts.push(`DORA ${c.frameworks.dora.join(', ')}`);
        if (c.frameworks.ens.length) parts.push(`ENS ${c.frameworks.ens.join(', ')}`);
        return parts.join(' · ');
    };

    // Filter controls to the selected framework
    const visibleControls =
        activeFramework === 'all'
            ? m.controls
            : m.controls.filter(
                  (c) => (c.frameworks[activeFramework as Exclude<FrameworkKey, 'all'>] ?? []).length > 0
              );

    // Per-framework score
    const passCount = visibleControls.filter((c) => c.status === 'pass').length;
    const gapCount = visibleControls.filter((c) => c.status === 'gap').length;
    const scoreDenom = passCount + gapCount;
    const scorePercent = scoreDenom > 0 ? Math.round((passCount / scoreDenom) * 100) : 100;
    const activeFw = FRAMEWORKS.find((f) => f.key === activeFramework)!;
    let scoreColor = 'var(--error)';
    if (scorePercent >= 90) scoreColor = 'var(--success)';
    else if (scorePercent >= 70) scoreColor = 'var(--warning)';

    return (
        <div
            className="rounded-xl border mb-8 overflow-hidden"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            {/* Header */}
            <div
                className="px-6 py-4 border-b flex items-center justify-between"
                style={{ borderColor: 'var(--border)' }}
            >
                <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                    Compliance mapping reports
                </h2>
                <div className="flex items-center gap-3 shrink-0">
                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        {visibleControls.length} control{visibleControls.length !== 1 ? 's' : ''} · {passCount} pass ·{' '}
                        {gapCount} gap
                    </span>
                    <button
                        type="button"
                        onClick={onDownloadCsv}
                        disabled={csvBusy}
                        className="px-2.5 py-1 rounded-lg text-xs font-medium disabled:opacity-50"
                        style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                    >
                        {csvBusy ? 'Exporting…' : 'Download CSV'}
                    </button>
                </div>
            </div>

            {/* Framework tabs */}
            <div
                className="px-6 py-3 border-b flex items-center gap-1 overflow-x-auto"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-subtle)' }}
            >
                {FRAMEWORKS.map((fw) => (
                    <button
                        type="button"
                        key={fw.key}
                        onClick={() => setActiveFramework(fw.key)}
                        className={`px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-all duration-100 ${
                            activeFramework === fw.key
                                ? 'bg-surface text-base-primary border border-base shadow-xs'
                                : 'text-base-muted hover:text-base-secondary'
                        }`}
                    >
                        {fw.label}
                    </button>
                ))}
            </div>

            {/* Per-framework score card (shown when a specific framework is selected) */}
            {activeFramework !== 'all' && (
                <div
                    className="px-6 py-4 border-b"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-app)' }}
                >
                    <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                            <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                                {activeFw.fullName}
                            </p>
                            {activeFw.description && (
                                <p className="text-xs mt-1 leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                                    {activeFw.description}
                                </p>
                            )}
                        </div>
                        <div className="shrink-0 text-right">
                            <div className="text-2xl font-bold tabular-nums" style={{ color: scoreColor }}>
                                {scorePercent}%
                            </div>
                            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                                compliance score
                            </div>
                        </div>
                    </div>
                    {/* Progress bar */}
                    <div
                        className="mt-3 h-1.5 rounded-full overflow-hidden"
                        style={{ backgroundColor: 'var(--bg-muted)' }}
                    >
                        <div
                            className="h-full rounded-full transition-all duration-500"
                            style={{ width: `${scorePercent}%`, backgroundColor: scoreColor }}
                        />
                    </div>
                    {gapCount > 0 && (
                        <p className="text-xs mt-2" style={{ color: 'var(--error)' }}>
                            {gapCount} control{gapCount !== 1 ? 's' : ''} with gaps require remediation to achieve full{' '}
                            {activeFw.label} coverage.
                        </p>
                    )}
                </div>
            )}

            {/* Control list */}
            {visibleControls.length === 0 ? (
                <div className="px-6 py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                    No controls mapped to {activeFw.fullName} yet.
                </div>
            ) : (
                <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {visibleControls.map((c) => {
                        const s = STATUS_META[c.status] ?? NA_META;
                        return (
                            <li
                                key={c.id}
                                className="px-6 py-3 flex items-start gap-3"
                                style={{ borderColor: 'var(--border)' }}
                            >
                                <span
                                    className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium shrink-0 mt-0.5"
                                    style={{ color: s.color, backgroundColor: s.bg }}
                                >
                                    {s.label}
                                </span>
                                <div className="min-w-0">
                                    <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                                        {c.name}{' '}
                                        <span className="text-xs font-normal" style={{ color: 'var(--text-muted)' }}>
                                            · {c.area}
                                        </span>
                                    </div>
                                    <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                                        {c.detail}
                                    </div>
                                    <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                                        {refLine(c)}
                                    </div>
                                </div>
                            </li>
                        );
                    })}
                </ul>
            )}
        </div>
    );
};

// RiskRegisterPanel lists governed risk exceptions (GET /risk-exceptions) and lets
// an admin record or revoke one. List needs system.read; create/revoke need
// system.write (a 403 surfaces as an inline error / hidden controls).
const RISK_CATEGORIES = ['sod', 'mfa', 'rotation', 'dormant_access', 'classification', 'other'];

const RiskRegisterPanel: React.FC = () => {
    const queryClient = useQueryClient();
    const { data: exceptions, isError } = useQuery({
        queryKey: ['compliance', 'risk-exceptions'],
        queryFn: () => complianceApi.getRiskExceptions(),
        staleTime: 60_000,
        retry: false,
    });
    const invalidate = () => {
        queryClient.invalidateQueries({ queryKey: ['compliance', 'risk-exceptions'] });
        queryClient.invalidateQueries({ queryKey: ['compliance', 'posture'] });
    };
    const create = useMutation({ mutationFn: complianceApi.createRiskException, onSuccess: invalidate });
    const revoke = useMutation({
        mutationFn: (id: number) => complianceApi.revokeRiskException(id),
        onSuccess: invalidate,
    });

    const [adding, setAdding] = useState(false);
    const [form, setForm] = useState({ title: '', category: 'sod', reference: '', justification: '', expires: '' });
    const [error, setError] = useState('');
    const onErr = (e: any) => setError(e?.response?.data?.error ?? e?.response?.data?.message ?? 'Action failed.');

    if (isError || !exceptions) return null; // 403/unavailable — posture panel already notes admin-only

    const submit = () => {
        if (!form.title.trim() || !form.justification.trim() || !form.expires) return;
        setError('');
        create.mutate(
            {
                title: form.title.trim(),
                category: form.category,
                reference: form.reference.trim(),
                justification: form.justification.trim(),
                expiresAt: `${form.expires}T00:00:00Z`,
            },
            {
                onError: onErr,
                onSuccess: () => {
                    invalidate();
                    setAdding(false);
                    setForm({ title: '', category: 'sod', reference: '', justification: '', expires: '' });
                },
            }
        );
    };

    return (
        <div
            className="rounded-xl border mb-8 overflow-hidden"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div
                className="px-6 py-4 border-b flex items-center justify-between"
                style={{ borderColor: 'var(--border)' }}
            >
                <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                    Risk register (A.5.8) — {exceptions.length} active exception{exceptions.length === 1 ? '' : 's'}
                </h2>
                {!adding && (
                    <button
                        type="button"
                        onClick={() => {
                            setError('');
                            setAdding(true);
                        }}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium shrink-0"
                        style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                    >
                        Add exception
                    </button>
                )}
            </div>

            {adding && (
                <div
                    className="px-6 py-4 border-b grid grid-cols-1 sm:grid-cols-2 gap-2"
                    style={{ borderColor: 'var(--border)' }}
                >
                    <input
                        value={form.title}
                        onChange={(e) => setForm({ ...form, title: e.target.value })}
                        placeholder="Title (e.g. accept SoD during cutover)"
                        className="rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                    <select
                        value={form.category}
                        onChange={(e) => setForm({ ...form, category: e.target.value })}
                        className="rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    >
                        {RISK_CATEGORIES.map((c) => (
                            <option key={c} value={c}>
                                {c}
                            </option>
                        ))}
                    </select>
                    <input
                        value={form.reference}
                        onChange={(e) => setForm({ ...form, reference: e.target.value })}
                        placeholder="Reference (a user, an SoD pair, a secret)"
                        className="rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                    <input
                        type="date"
                        value={form.expires}
                        onChange={(e) => setForm({ ...form, expires: e.target.value })}
                        aria-label="Expires"
                        className="rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                    <input
                        value={form.justification}
                        onChange={(e) => setForm({ ...form, justification: e.target.value })}
                        placeholder="Justification (recorded for audit)"
                        className="sm:col-span-2 rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                    <div className="sm:col-span-2 flex items-center gap-2">
                        <button
                            type="button"
                            onClick={submit}
                            disabled={
                                create.isPending || !form.title.trim() || !form.justification.trim() || !form.expires
                            }
                            className="px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50"
                            style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                        >
                            Record exception
                        </button>
                        <button
                            type="button"
                            onClick={() => {
                                setAdding(false);
                                setError('');
                            }}
                            className="px-2.5 py-1.5 rounded-lg text-xs"
                            style={{ color: 'var(--text-muted)' }}
                        >
                            Cancel
                        </button>
                        {error && (
                            <span className="text-xs" style={{ color: 'var(--error)' }}>
                                {error}
                            </span>
                        )}
                    </div>
                </div>
            )}

            {exceptions.length === 0 ? (
                <div className="px-6 py-4 text-sm" style={{ color: 'var(--text-muted)' }}>
                    No active risk exceptions.
                </div>
            ) : (
                <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {exceptions.map((e) => (
                        <li
                            key={e.id}
                            className="px-6 py-3 flex items-start justify-between gap-3"
                            style={{ borderColor: 'var(--border)' }}
                        >
                            <div className="min-w-0">
                                <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                                    {e.title}{' '}
                                    <span className="text-xs font-normal" style={{ color: 'var(--text-muted)' }}>
                                        · {e.category}
                                        {e.reference ? ` · ${e.reference}` : ''}
                                    </span>
                                </div>
                                <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                                    {e.justification}
                                </div>
                                <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                                    Expires {e.expiresAt ? new Date(e.expiresAt).toLocaleDateString() : '—'}
                                </div>
                            </div>
                            <button
                                type="button"
                                onClick={() => revoke.mutate(e.id)}
                                disabled={revoke.isPending}
                                className="px-2.5 py-1 rounded-lg text-xs font-medium shrink-0 disabled:opacity-50"
                                style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                            >
                                Revoke
                            </button>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

export const CompliancePage: React.FC = () => (
    <div className="max-w-4xl mx-auto px-6 py-8">
        <div className="mb-8">
            <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                Compliance
            </h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                Your live controls posture, and how Keyorix supports your regulatory obligations.
            </p>
        </div>

        <LegalHoldBanner />
        <PosturePanel />
        <DigestPanel />
        <ControlMatrixPanel />
        <RiskRegisterPanel />
        <SoDViolationsSection />

        <SectionCard title="NIS2 Directive">
            Keyorix supports NIS2 Article 21 technical requirements — access controls, encryption of data at rest and in
            transit, and audit logging. Every secret access, rotation, and user action is logged with actor identity and
            timestamp. On-premise deployment means audit data stays on your infrastructure under your data retention
            policy. Use the NIS2 tab in the control matrix above for a live view of covered controls.
        </SectionCard>

        <SectionCard title="DORA">
            DORA Article 30 requires financial entities to maintain detailed ICT risk management records including
            access logs and cryptographic controls. Keyorix provides tamper-evident audit logs, envelope encryption with
            key rotation support, and PostgreSQL-backed storage designed for long-term operational continuity. Air-gap
            compatibility means no dependency on external cloud services for secret resolution. See the DORA tab in the
            control matrix above for the live coverage view.
        </SectionCard>

        <SectionCard title="ENS (Esquema Nacional de Seguridad)">
            ENS is Spain's mandatory security certification framework for public-sector ICT systems and their suppliers.
            Keyorix maps to the operational (op.acc, op.exp) and technical (mp.s, mp.sw) control families required for
            ENS Medium and High categories — covering identity and access management, audit traceability, and
            cryptographic key lifecycle. On-premise deployment keeps processing within your jurisdiction, satisfying ENS
            data localisation requirements without architectural concessions.
        </SectionCard>

        <SectionCard title="ISO 27001">
            Keyorix maps directly to ISO 27001 Annex A controls for access management (A.8), cryptography (A.8.24), and
            operations security. RBAC, AES-256-GCM encryption, and full audit trails are shipped by default — not
            add-ons. On-premise deployment supports your organisation's asset management and boundary control
            requirements. Use the ISO 27001 tab in the control matrix above for a live per-control status.
        </SectionCard>
    </div>
);
