import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { ExclamationTriangleIcon, LockClosedIcon } from '@heroicons/react/24/outline';
import { useQueryClient } from '@tanstack/react-query';
import {
    BREAK_GLASS_KEYS,
    useActivateBreakGlass,
    useBreakGlassActivations,
    useReviewBreakGlass,
    useRevokeBreakGlass,
} from '../../features/projects/breakGlass';
import { useProjectMembers } from '../../features/projects/api';
import { useCan } from '../../features/auth/useCan';
import { useAuth } from '../../features/auth/api';
import {
    BreakGlassActivation,
    BreakGlassRefusal,
    BreakGlassState,
    BreakGlassSettings,
    classifyBreakGlassError,
} from '../../services/breakGlass';
import { apiErrorMessage, MFA_ENROLMENT_URL } from '../../services/client';
import { Dialog } from '../../components/ui/Dialog';
import { Modal } from '../../components/ui/Modal';
import { Button } from '../../components/ui/Button';

interface ProjectBreakGlassTabProps {
    projectId: number;
}

// Lifetimes the picker can offer, as Go durations with their length. The server sends its
// ceiling (break_glass.max_ttl) with the list, and the picker offers only the entries within
// it (plus the ceiling itself). Against an older server that sends none, every entry is
// offered and a longer pick is shortened by the server; the expiry actually granted is what
// the list below shows. "Server default" sends no ttl at all.
const TTL_CANDIDATES: { value: string; seconds: number }[] = [
    { value: '15m', seconds: 15 * 60 },
    { value: '30m', seconds: 30 * 60 },
    { value: '1h', seconds: 60 * 60 },
    { value: '2h', seconds: 2 * 60 * 60 },
    { value: '4h', seconds: 4 * 60 * 60 },
    { value: '8h', seconds: 8 * 60 * 60 },
    { value: '24h', seconds: 24 * 60 * 60 },
];

// The server's bounds on a review note (internal/core/break_glass.go); it enforces them, this
// only keeps the button honest.
const REVIEW_NOTE_MIN = 10;
const REVIEW_NOTE_MAX = 2000;

const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? '' : 's'}`;

export const formatTtl = (seconds: number): string => {
    if (seconds % 3600 === 0) return plural(seconds / 3600, 'hour');
    if (seconds % 60 === 0) {
        const m = seconds / 60;
        return m >= 60 ? `${plural(Math.floor(m / 60), 'hour')} ${plural(m % 60, 'minute')}` : plural(m, 'minute');
    }
    return plural(seconds, 'second');
};

export const ttlChoices = (settings?: BreakGlassSettings): { value: string; label: string }[] => {
    const defaultLabel =
        settings && settings.defaultTtlSeconds > 0
            ? `Server default (${formatTtl(settings.defaultTtlSeconds)})`
            : 'Server default';
    const choices = [{ value: '', label: defaultLabel }];
    const max = settings?.maxTtlSeconds;
    const within = TTL_CANDIDATES.filter((c) => max === undefined || c.seconds <= max);
    within.forEach((c) => choices.push({ value: c.value, label: formatTtl(c.seconds) }));
    if (max !== undefined && !within.some((c) => c.seconds === max)) {
        choices.push({ value: `${max}s`, label: `${formatTtl(max)} (server maximum)` });
    }
    return choices;
};

// The server requires a justification of at least this many characters (trimmed). Mirrored
// only to explain the refusal early; the server is the authority.
const MIN_JUSTIFICATION = 10;

const useNow = (running: boolean, intervalMs = 1000): number => {
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        if (!running) return;
        setNow(Date.now());
        const t = setInterval(() => setNow(Date.now()), intervalMs);
        return () => clearInterval(t);
    }, [running, intervalMs]);
    return now;
};

export const formatRemaining = (ms: number): string => {
    const total = Math.max(0, Math.floor(ms / 1000));
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    const pad = (n: number) => String(n).padStart(2, '0');
    return h > 0 ? `${h}h ${pad(m)}m ${pad(s)}s` : `${m}m ${pad(s)}s`;
};

const expiryMs = (a: BreakGlassActivation): number => (a.expiresAt ? new Date(a.expiresAt).getTime() : NaN);

// What the page shows as the status. The server flips `active` to `expired` lazily, so an
// activation whose expiry has passed is shown as expired here without waiting for it.
const effectiveState = (a: BreakGlassActivation, now: number): BreakGlassActivation['state'] =>
    a.state === 'active' && expiryMs(a) <= now ? 'expired' : a.state;

const STATE_STYLE: Record<BreakGlassActivation['state'], { label: string; bg: string; fg: string }> = {
    active: { label: 'Active', bg: 'var(--warning-subtle)', fg: 'var(--warning)' },
    expired: { label: 'Expired', bg: 'var(--bg-muted)', fg: 'var(--text-muted)' },
    revoked: { label: 'Revoked', bg: 'var(--error-subtle)', fg: 'var(--error)' },
};

const formatTime = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '—');

const Notice: React.FC<{ tone: 'error' | 'warning' | 'info'; title: string; children?: React.ReactNode }> = ({
    tone,
    title,
    children,
}) => {
    const bg =
        tone === 'error' ? 'var(--error-subtle)' : tone === 'warning' ? 'var(--warning-subtle)' : 'var(--bg-subtle)';
    const fg = tone === 'error' ? 'var(--error)' : tone === 'warning' ? 'var(--warning)' : 'var(--text-secondary)';
    return (
        <div role="alert" className="rounded-lg px-4 py-3 text-sm" style={{ backgroundColor: bg, color: fg }}>
            <p className="font-medium">{title}</p>
            {children && <div className="mt-1">{children}</div>}
        </div>
    );
};

const RefusalNotice: React.FC<{ refusal: BreakGlassRefusal; fallback?: string }> = ({ refusal, fallback }) => {
    if (refusal === 'disabled') {
        return (
            <Notice tone="info" title="Break-glass is not enabled on this server">
                Emergency access is off by default. A server administrator turns it on with{' '}
                <code>break_glass.enabled</code> in the server configuration.
            </Notice>
        );
    }
    if (refusal === 'mfa') {
        return (
            <Notice tone="warning" title="This project requires multi-factor authentication">
                Enrol a second factor to use break-glass here.{' '}
                <Link to={MFA_ENROLMENT_URL} className="underline">
                    Set up MFA
                </Link>
            </Notice>
        );
    }
    if (refusal === 'forbidden') {
        return (
            <Notice tone="error" title="Not allowed">
                {fallback || 'The server refused this request. Break-glass is only open to members of the project.'}
            </Notice>
        );
    }
    return (
        <Notice tone="error" title="Something went wrong">
            {fallback || 'The request failed. Try again.'}
        </Notice>
    );
};

// ── Request form ─────────────────────────────────────────────────────────────

const RequestForm: React.FC<{
    projectId: number;
    settings?: BreakGlassSettings | undefined;
    onDisabled: () => void;
}> = ({ projectId, settings, onDisabled }) => {
    const activate = useActivateBreakGlass(projectId);
    const choices = ttlChoices(settings);
    const [justification, setJustification] = useState('');
    const [ttl, setTtl] = useState('');
    const [refusal, setRefusal] = useState<{ kind: BreakGlassRefusal; message: string } | null>(null);
    const [granted, setGranted] = useState<BreakGlassActivation | null>(null);

    const trimmed = justification.trim();
    const tooShort = trimmed.length < MIN_JUSTIFICATION;

    const submit = (e: React.FormEvent) => {
        e.preventDefault();
        if (tooShort) return;
        setRefusal(null);
        setGranted(null);
        activate.mutate(
            { justification: trimmed, ttl: ttl || undefined },
            {
                onSuccess: (a) => {
                    setGranted(a);
                    setJustification('');
                },
                onError: (err) => {
                    const kind = classifyBreakGlassError(err);
                    if (kind === 'disabled') onDisabled();
                    setRefusal({ kind, message: apiErrorMessage(err, 'Activation failed.') });
                },
            }
        );
    };

    return (
        <form
            onSubmit={submit}
            aria-label="Request emergency access"
            className="rounded-xl border p-4 space-y-3"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div>
                <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
                    Request emergency access
                </h2>
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                    Grants you a time-limited role on this project right away. The request is recorded in the audit log
                    with your justification, administrators are alerted, and access ends automatically.
                </p>
            </div>

            <div>
                <label htmlFor="bg-justification" className="block text-sm font-medium mb-1">
                    Justification
                </label>
                <textarea
                    id="bg-justification"
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                    rows={3}
                    required
                    placeholder="What is happening, and why do you need access now? (at least 10 characters)"
                    className="w-full rounded-lg border px-3 py-2 text-sm"
                    style={{
                        borderColor: 'var(--border)',
                        backgroundColor: 'var(--bg-surface)',
                        color: 'var(--text-primary)',
                    }}
                />
            </div>

            <div>
                <label htmlFor="bg-ttl" className="block text-sm font-medium mb-1">
                    How long
                </label>
                <select
                    id="bg-ttl"
                    value={ttl}
                    onChange={(e) => setTtl(e.target.value)}
                    className="rounded-lg border px-3 py-2 text-sm"
                    style={{
                        borderColor: 'var(--border)',
                        backgroundColor: 'var(--bg-surface)',
                        color: 'var(--text-primary)',
                    }}
                >
                    {choices.map((c) => (
                        <option key={c.value} value={c.value}>
                            {c.label}
                        </option>
                    ))}
                </select>
                <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                    {settings
                        ? `The server allows at most ${formatTtl(settings.maxTtlSeconds)}; the expiry you actually get is shown below.`
                        : 'The server caps the lifetime at its configured maximum; the expiry you actually get is shown below.'}
                </p>
            </div>

            {refusal && <RefusalNotice refusal={refusal.kind} fallback={refusal.message} />}
            {granted && (
                <Notice tone="warning" title="Emergency access is active">
                    Role {granted.roleName || 'granted'} until {formatTime(granted.expiresAt)}.
                    {granted.degraded && (
                        <>
                            {' '}
                            <strong data-testid="bg-granted-degraded">
                                The audit log is not accepting writes right now, so this grant was recorded as owed and
                                shortened; administrators have been alerted and it must be reviewed.
                            </strong>
                        </>
                    )}
                </Notice>
            )}

            <button
                type="submit"
                disabled={tooShort || activate.isPending}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg disabled:opacity-50"
                style={{ backgroundColor: 'var(--error)', color: 'white' }}
            >
                <ExclamationTriangleIcon className="h-4 w-4" />
                {activate.isPending ? 'Requesting…' : 'Request emergency access'}
            </button>
        </form>
    );
};

// ── Activations list ─────────────────────────────────────────────────────────

const Countdown: React.FC<{ activation: BreakGlassActivation; now: number }> = ({ activation, now }) => {
    if (effectiveState(activation, now) !== 'active') {
        return <span style={{ color: 'var(--text-muted)' }}>{formatTime(activation.expiresAt)}</span>;
    }
    return (
        <span>
            <span className="font-mono tabular-nums" data-testid={`bg-countdown-${activation.id}`}>
                {formatRemaining(expiryMs(activation) - now)}
            </span>{' '}
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                left
            </span>
        </span>
    );
};

const ActivationsTable: React.FC<{
    projectId: number;
    activations: BreakGlassActivation[];
    showWho: boolean;
    names: Map<number, string>;
    canRevoke: boolean;
    canReview: boolean;
}> = ({ projectId, activations, showWho, names, canRevoke, canReview }) => {
    const qc = useQueryClient();
    const { user } = useAuth();
    const revoke = useRevokeBreakGlass(projectId);
    const review = useReviewBreakGlass(projectId);
    const [target, setTarget] = useState<BreakGlassActivation | null>(null);
    const [reviewTarget, setReviewTarget] = useState<BreakGlassActivation | null>(null);
    const [reviewNote, setReviewNote] = useState('');
    const [reviewError, setReviewError] = useState<string | null>(null);
    const [error, setError] = useState<{ kind: BreakGlassRefusal; message: string } | null>(null);

    const anyActive = activations.some((a) => a.state === 'active');
    const now = useNow(anyActive);

    // The server flips an expired grant to `expired` lazily. When a countdown reaches zero,
    // ask once per activation for the server's view so the row settles on what is recorded.
    const refetched = useRef<Set<number>>(new Set());
    useEffect(() => {
        const lapsed = activations.filter(
            (a) => a.state === 'active' && expiryMs(a) <= now && !refetched.current.has(a.id)
        );
        if (lapsed.length === 0) return;
        lapsed.forEach((a) => refetched.current.add(a.id));
        void qc.invalidateQueries({ queryKey: BREAK_GLASS_KEYS.all });
    }, [activations, now, qc]);

    const who = (a: BreakGlassActivation) => names.get(a.userId) ?? `User #${a.userId}`;

    const confirmRevoke = () => {
        if (!target) return;
        setError(null);
        revoke.mutate(target.id, {
            onSuccess: () => setTarget(null),
            onError: (err) => {
                setTarget(null);
                setError({ kind: classifyBreakGlassError(err), message: apiErrorMessage(err, 'Revoke failed.') });
            },
        });
    };

    // Offered only where the server would accept it: a reviewer with roles.assign who is not the
    // requester, on an activation that has ended and has no review yet. The server enforces all
    // of it again (self-review 403, still-active 400, already-reviewed 400).
    const canReviewRow = (a: BreakGlassActivation, state: BreakGlassState) =>
        canReview && state !== 'active' && !a.reviewedBy && user?.id !== undefined && a.userId !== Number(user.id);

    const openReview = (a: BreakGlassActivation) => {
        setReviewNote('');
        setReviewError(null);
        review.reset();
        setReviewTarget(a);
    };

    const noteLength = reviewNote.trim().length;
    const noteValid = noteLength >= REVIEW_NOTE_MIN && noteLength <= REVIEW_NOTE_MAX;

    const submitReview = () => {
        if (!reviewTarget || !noteValid) return;
        setReviewError(null);
        review.mutate(
            { activationId: reviewTarget.id, note: reviewNote.trim() },
            {
                onSuccess: () => setReviewTarget(null),
                onError: (err) => setReviewError(apiErrorMessage(err, 'Review failed.')),
            }
        );
    };

    if (activations.length === 0) {
        return (
            <p className="text-sm py-6 text-center" style={{ color: 'var(--text-muted)' }}>
                No emergency access has been requested on this project.
            </p>
        );
    }

    return (
        <>
            {error && (
                <div className="mb-3">
                    <RefusalNotice
                        refusal={error.kind}
                        fallback={
                            error.kind === 'forbidden' ? 'You do not have permission to revoke access.' : error.message
                        }
                    />
                </div>
            )}
            <div className="overflow-x-auto rounded-xl border" style={{ borderColor: 'var(--border)' }}>
                <table className="w-full text-sm">
                    <thead>
                        <tr className="text-left text-xs" style={{ color: 'var(--text-muted)' }}>
                            {showWho && <th className="px-4 py-2 font-medium">Who</th>}
                            <th className="px-4 py-2 font-medium">Status</th>
                            <th className="px-4 py-2 font-medium">Justification</th>
                            <th className="px-4 py-2 font-medium">Requested</th>
                            <th className="px-4 py-2 font-medium">Expires</th>
                            {canRevoke && <th className="px-4 py-2" />}
                        </tr>
                    </thead>
                    <tbody>
                        {activations.map((a) => {
                            const state = effectiveState(a, now);
                            const style = STATE_STYLE[state];
                            return (
                                <tr
                                    key={a.id}
                                    data-testid={`bg-row-${a.id}`}
                                    className="border-t"
                                    style={{ borderColor: 'var(--border)' }}
                                >
                                    {showWho && <td className="px-4 py-2">{who(a)}</td>}
                                    <td className="px-4 py-2">
                                        <span
                                            className="px-2 py-0.5 rounded-full text-xs font-medium"
                                            style={{ backgroundColor: style.bg, color: style.fg }}
                                        >
                                            {style.label}
                                        </span>
                                        {a.reviewedBy !== undefined && (
                                            <span
                                                data-testid={`bg-reviewed-${a.id}`}
                                                title={a.reviewNote ? `Reviewed: ${a.reviewNote}` : 'Reviewed'}
                                                className="ml-1 px-2 py-0.5 rounded-full text-xs font-medium"
                                                style={{
                                                    backgroundColor: 'var(--accent-subtle)',
                                                    color: 'var(--accent-text)',
                                                }}
                                            >
                                                Reviewed
                                            </span>
                                        )}
                                        {a.degraded && (
                                            <span
                                                data-testid={`bg-degraded-${a.id}`}
                                                title={
                                                    a.auditSettledAt
                                                        ? 'Granted while the audit log refused writes; its audit records were written later. Review is mandatory.'
                                                        : 'Granted while the audit log refused writes; its audit records are still owed. Review is mandatory.'
                                                }
                                                className="ml-1 px-2 py-0.5 rounded-full text-xs font-medium"
                                                style={{ backgroundColor: 'var(--error)', color: 'white' }}
                                            >
                                                Degraded{a.auditSettledAt ? '' : ' · audit owed'}
                                            </span>
                                        )}
                                    </td>
                                    <td className="px-4 py-2 max-w-xs" style={{ overflowWrap: 'anywhere' }}>
                                        {a.justification}
                                    </td>
                                    <td className="px-4 py-2 whitespace-nowrap">{formatTime(a.createdAt)}</td>
                                    <td className="px-4 py-2 whitespace-nowrap">
                                        <Countdown activation={a} now={now} />
                                    </td>
                                    {canRevoke && (
                                        <td className="px-4 py-2 text-right">
                                            {state === 'active' && (
                                                <button
                                                    type="button"
                                                    onClick={() => setTarget(a)}
                                                    className="text-sm underline"
                                                    style={{ color: 'var(--error)' }}
                                                >
                                                    Revoke
                                                </button>
                                            )}
                                            {canReviewRow(a, state) && (
                                                <button
                                                    type="button"
                                                    data-testid={`bg-review-${a.id}`}
                                                    onClick={() => openReview(a)}
                                                    className="text-sm underline"
                                                    style={{ color: 'var(--accent-text)' }}
                                                >
                                                    Review
                                                </button>
                                            )}
                                        </td>
                                    )}
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>

            <Dialog
                isOpen={target !== null}
                onClose={() => setTarget(null)}
                title="Revoke emergency access?"
                message={
                    target
                        ? `${who(target)} will lose the ${target.roleName || 'emergency'} role on this project immediately. The activation stays in the record as revoked.`
                        : ''
                }
                type="danger"
                confirmText="Revoke"
                onConfirm={confirmRevoke}
                loading={revoke.isPending}
            />

            <Modal
                isOpen={reviewTarget !== null}
                onClose={() => setReviewTarget(null)}
                title="Review emergency access"
                size="md"
            >
                {reviewTarget && (
                    <div className="space-y-3">
                        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                            {who(reviewTarget)} used the {reviewTarget.roleName || 'emergency'} role on this project.
                            Record that you, as an independent reviewer, checked what was done with it. The review is
                            permanent and cannot be changed.
                        </p>
                        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                            Justification given: {reviewTarget.justification}
                        </p>
                        <label
                            htmlFor="bg-review-note"
                            className="block text-sm font-medium"
                            style={{ color: 'var(--text-primary)' }}
                        >
                            Review note
                        </label>
                        <textarea
                            id="bg-review-note"
                            value={reviewNote}
                            onChange={(e) => setReviewNote(e.target.value)}
                            rows={4}
                            maxLength={REVIEW_NOTE_MAX}
                            className="w-full px-3 py-2 rounded-md border text-sm"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                borderColor: 'var(--border-strong)',
                                color: 'var(--text-primary)',
                            }}
                            placeholder="What you checked and what you found"
                        />
                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            At least {REVIEW_NOTE_MIN} characters.
                        </p>
                        {reviewError && (
                            <p role="alert" className="text-sm" style={{ color: 'var(--error)' }}>
                                {reviewError}
                            </p>
                        )}
                        <div className="flex justify-end gap-2 pt-2">
                            <Button variant="secondary" onClick={() => setReviewTarget(null)}>
                                Cancel
                            </Button>
                            <Button
                                data-testid="bg-review-submit"
                                loading={review.isPending}
                                disabled={!noteValid}
                                onClick={submitReview}
                            >
                                Record review
                            </Button>
                        </div>
                    </div>
                )}
            </Modal>
        </>
    );
};

// The member directory is only worth asking for in the all-activations view, whose caller
// holds roles.read; a plain member sees only their own rows and needs no names.
const AllActivations: React.FC<{
    projectId: number;
    activations: BreakGlassActivation[];
    canRevoke: boolean;
    canReview: boolean;
}> = ({ projectId, activations, canRevoke, canReview }) => {
    const { data: members } = useProjectMembers(projectId);
    const names = new Map<number, string>();
    (members ?? []).forEach((m) => names.set(m.userId, m.displayName || m.username));
    return (
        <ActivationsTable
            projectId={projectId}
            activations={activations}
            showWho
            names={names}
            canRevoke={canRevoke}
            canReview={canReview}
        />
    );
};

// ── Tab ──────────────────────────────────────────────────────────────────────

/**
 * Break-glass tab (#3148): emergency, self-service, time-boxed access. Any project member can
 * request it; whoever holds roles.read sees every activation and, with roles.assign, can end
 * one early. The server decides all of it: this page shows what the server returns (scope
 * "project" vs "own") and what it refuses, and hides controls only as a courtesy.
 */
export const ProjectBreakGlassTab: React.FC<ProjectBreakGlassTabProps> = ({ projectId }) => {
    const can = useCan();
    const { data, isLoading, error } = useBreakGlassActivations(projectId);
    const [disabled, setDisabled] = useState(false);

    if (isLoading) {
        return (
            <div className="animate-pulse space-y-3" aria-busy="true">
                <div className="h-24 rounded-xl" style={{ backgroundColor: 'var(--bg-muted)' }} />
                <div className="h-16 rounded-xl" style={{ backgroundColor: 'var(--bg-muted)' }} />
            </div>
        );
    }

    if (error) {
        const kind = classifyBreakGlassError(error);
        return (
            <div className="space-y-3">
                <RefusalNotice
                    refusal={kind}
                    fallback={
                        kind === 'forbidden'
                            ? 'You do not have access to this project’s break-glass activations. Only members of the project can use or see them.'
                            : apiErrorMessage(error, 'Could not load break-glass activations.')
                    }
                />
            </div>
        );
    }

    const scope = data?.scope ?? 'own';
    const activations = data?.activations ?? [];
    const settings = data?.settings;
    // The server says up front whether the feature is on; a refusal on submit is the fallback
    // for an older server that does not send its limits.
    const off = disabled || settings?.enabled === false;

    return (
        <div className="space-y-6">
            {off ? (
                <RefusalNotice refusal="disabled" />
            ) : (
                <RequestForm projectId={projectId} settings={settings} onDisabled={() => setDisabled(true)} />
            )}

            <section aria-label="Activations">
                <h2
                    className="flex items-center gap-2 text-base font-semibold mb-2"
                    style={{ color: 'var(--text-primary)' }}
                >
                    <LockClosedIcon className="h-4 w-4" />
                    {scope === 'project' ? 'All activations on this project' : 'Your activations'}
                </h2>
                {scope === 'project' ? (
                    <AllActivations
                        projectId={projectId}
                        activations={activations}
                        canRevoke={can.manageMembers}
                        canReview={can.manageMembers}
                    />
                ) : (
                    <ActivationsTable
                        projectId={projectId}
                        activations={activations}
                        showWho={false}
                        names={new Map()}
                        canRevoke={false}
                        canReview={false}
                    />
                )}
            </section>
        </div>
    );
};
