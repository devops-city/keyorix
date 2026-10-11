import React, { SubmitEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    PlusIcon,
    ArrowPathIcon,
    ExclamationTriangleIcon,
    CheckCircleIcon,
    ClockIcon,
    PencilIcon,
    TrashIcon,
} from '@heroicons/react/24/outline';
import { Button } from '../../components/ui/Button';
import { Select } from '../../components/ui/Select';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import {
    useRotationPolicies,
    useRotationPolicyEvaluations,
    useCreateRotationPolicy,
    useUpdateRotationPolicy,
    useDeleteRotationPolicy,
} from '../../features/secrets/useRotationPolicies';
import { environmentsApi } from '../../services/environments';
import { projectsApi } from '../../services/projects';
import { RotationPolicy, RotationPolicyEvaluation, CreateRotationPolicyPayload } from '../../types';
import { apiErrorMessage } from '../../services/client';

// ── helpers ───────────────────────────────────────────────────────────────────

function formatDate(d: string): string {
    return new Intl.DateTimeFormat('en', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    }).format(new Date(d));
}

// ── constants ─────────────────────────────────────────────────────────────────

const INTERVAL_OPTIONS = [
    { value: '30', label: '30 days' },
    { value: '60', label: '60 days' },
    { value: '90', label: '90 days' },
    { value: '180', label: '180 days' },
    { value: '365', label: '365 days' },
];

const ALERT_DAYS_OPTIONS = [
    { value: '3', label: '3 days before' },
    { value: '7', label: '7 days before' },
    { value: '14', label: '14 days before' },
    { value: '30', label: '30 days before' },
];

const SCOPE_OPTIONS = [
    { value: 'environment', label: 'Environment' },
    { value: 'project', label: 'Project' },
];

// ── sub-components ────────────────────────────────────────────────────────────

const EvalStatusBadge: React.FC<{ ev: RotationPolicyEvaluation }> = ({ ev }) => {
    if (ev.is_overdue) {
        return (
            <span
                className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium"
                style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444' }}
            >
                Overdue
            </span>
        );
    }
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium"
            style={{ backgroundColor: 'rgba(245,158,11,0.12)', color: '#f59e0b' }}
        >
            Due soon
        </span>
    );
};

const ActivePill: React.FC<{ active: boolean }> = ({ active }) => (
    <span
        className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
        style={
            active
                ? { backgroundColor: 'rgba(16,185,129,0.12)', color: '#10b981' }
                : { backgroundColor: 'var(--bg-subtle)', color: 'var(--text-muted)' }
        }
    >
        {active ? 'Active' : 'Inactive'}
    </span>
);

// ── main page ─────────────────────────────────────────────────────────────────

export function RotationPoliciesPage() {
    // ── modal / form state ────────────────────────────────────────────────────
    const [showCreate, setShowCreate] = React.useState(false);
    const [editing, setEditing] = React.useState<RotationPolicy | null>(null);
    const [deleting, setDeleting] = React.useState<RotationPolicy | null>(null);

    const [fName, setFName] = React.useState('');
    const [fDesc, setFDesc] = React.useState('');
    const [fScope, setFScope] = React.useState<'project' | 'environment'>('environment');
    const [fEnvId, setFEnvId] = React.useState('');
    const [fProjId, setFProjId] = React.useState('');
    const [fInterval, setFInterval] = React.useState('90');
    const [fAlert, setFAlert] = React.useState('14');
    const [fNotify, setFNotify] = React.useState(false);
    const [fError, setFError] = React.useState('');

    // ── queries / mutations ───────────────────────────────────────────────────
    const { policies, isLoading, error, refetch } = useRotationPolicies();
    const { evaluations, isLoading: evalLoading } = useRotationPolicyEvaluations();
    const createMutation = useCreateRotationPolicy();
    const updateMutation = useUpdateRotationPolicy();
    const deleteMutation = useDeleteRotationPolicy();

    const { data: environments } = useQuery({
        queryKey: ['environments'],
        queryFn: environmentsApi.list,
        staleTime: 5 * 60 * 1000,
    });
    const { data: projects } = useQuery({
        queryKey: ['projects'],
        queryFn: () => projectsApi.list(),
        staleTime: 5 * 60 * 1000,
    });

    const envMap = React.useMemo(() => {
        const m: Record<number, string> = {};
        (environments ?? []).forEach((e) => {
            m[e.id] = e.name;
        });
        return m;
    }, [environments]);

    const projMap = React.useMemo(() => {
        const m: Record<number, string> = {};
        (projects ?? []).forEach((p) => {
            m[p.id] = p.name;
        });
        return m;
    }, [projects]);

    // ── evaluation buckets ────────────────────────────────────────────────────
    const overdueList = evaluations.filter((e) => e.is_overdue);
    const approachingList = evaluations.filter((e) => e.is_approaching && !e.is_overdue);
    const healthyCount = evaluations.filter((e) => !e.is_overdue && !e.is_approaching).length;
    const problemList = [...overdueList, ...approachingList];

    // ── form helpers ──────────────────────────────────────────────────────────
    function resetForm() {
        setFName('');
        setFDesc('');
        setFScope('environment');
        setFEnvId('');
        setFProjId('');
        setFInterval('90');
        setFAlert('14');
        setFNotify(false);
        setFError('');
    }

    function openCreate() {
        resetForm();
        setShowCreate(true);
    }

    function openEdit(p: RotationPolicy) {
        setFName(p.name);
        setFDesc(p.description ?? '');
        setFScope(p.scope);
        setFEnvId(p.environment_id ? String(p.environment_id) : '');
        setFProjId(p.project_id ? String(p.project_id) : '');
        setFInterval(String(p.interval_days));
        setFAlert(String(p.alert_days_before));
        setFNotify(p.notify_on_breach);
        setFError('');
        setEditing(p);
    }

    function closeModal() {
        setShowCreate(false);
        setEditing(null);
        resetForm();
    }

    function handleSubmit(e: SubmitEvent<HTMLFormElement>) {
        e.preventDefault();
        setFError('');

        if (!fName.trim()) {
            setFError('Name is required.');
            return;
        }
        if (fScope === 'environment' && !fEnvId) {
            setFError('Environment is required.');
            return;
        }
        if (fScope === 'project' && !fProjId) {
            setFError('Project is required.');
            return;
        }
        if (Number(fAlert) >= Number(fInterval)) {
            setFError('Alert days must be less than the rotation interval.');
            return;
        }

        const payload: CreateRotationPolicyPayload = {
            name: fName.trim(),
            description: fDesc.trim(),
            scope: fScope,
            environment_id: fScope === 'environment' ? Number(fEnvId) : null,
            project_id: fScope === 'project' ? Number(fProjId) : null,
            interval_days: Number(fInterval),
            alert_days_before: Number(fAlert),
            notify_on_breach: fNotify,
        };

        if (editing) {
            updateMutation.mutate(
                { id: editing.id, ...payload },
                {
                    onSuccess: closeModal,
                    onError: (err) => setFError(err instanceof Error ? err.message : 'Failed to update policy.'),
                }
            );
        } else {
            createMutation.mutate(payload, {
                onSuccess: closeModal,
                onError: (err) => setFError(err instanceof Error ? err.message : 'Failed to create policy.'),
            });
        }
    }

    const isSubmitting = createMutation.isPending || updateMutation.isPending;
    const isModalOpen = showCreate || editing !== null;

    // ── error state ───────────────────────────────────────────────────────────
    if (error) {
        return (
            <div className="p-6">
                <Alert
                    type="error"
                    title="Failed to load rotation policies"
                    message="There was an error loading your rotation policies. Please try again."
                >
                    <Button variant="outline" size="sm" onClick={() => refetch()}>
                        Retry
                    </Button>
                </Alert>
            </div>
        );
    }

    return (
        <div className="p-6 space-y-6">
            {/* ── Header ──────────────────────────────────────────────────── */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                        Rotation Policies
                    </h1>
                    <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Define how often secrets must be rotated per environment
                    </p>
                </div>
                <Button onClick={openCreate} className="flex items-center">
                    <PlusIcon className="h-4 w-4 mr-2" />
                    New Policy
                </Button>
            </div>

            {/* ── Evaluation panel ─────────────────────────────────────────── */}
            <div
                className="rounded-xl border"
                style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
            >
                <div className="flex items-center gap-2 px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
                    <ArrowPathIcon className="h-4 w-4" style={{ color: 'var(--text-muted)' }} />
                    <h2
                        className="text-sm font-semibold uppercase tracking-widest"
                        style={{ color: 'var(--text-primary)' }}
                    >
                        Rotation Status
                    </h2>
                </div>

                <div className="px-6 py-4 space-y-4">
                    {evalLoading ? (
                        <div className="py-4">
                            <Loading />
                        </div>
                    ) : (
                        <>
                            {/* Summary badges */}
                            <div className="flex flex-wrap gap-3">
                                <span
                                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium"
                                    style={{ backgroundColor: 'rgba(239,68,68,0.10)', color: '#ef4444' }}
                                >
                                    <ExclamationTriangleIcon className="h-4 w-4" />
                                    {overdueList.length} overdue
                                </span>
                                <span
                                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium"
                                    style={{ backgroundColor: 'rgba(245,158,11,0.10)', color: '#f59e0b' }}
                                >
                                    <ClockIcon className="h-4 w-4" />
                                    {approachingList.length} approaching breach
                                </span>
                                <span
                                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium"
                                    style={{ backgroundColor: 'rgba(16,185,129,0.10)', color: '#10b981' }}
                                >
                                    <CheckCircleIcon className="h-4 w-4" />
                                    {healthyCount} healthy
                                </span>
                            </div>

                            {/* Table or all-clear */}
                            {problemList.length === 0 ? (
                                <div className="flex items-center gap-2 py-2" style={{ color: '#10b981' }}>
                                    <CheckCircleIcon className="h-5 w-5 shrink-0" />
                                    <span className="text-sm font-medium">All secrets are within rotation policy</span>
                                </div>
                            ) : (
                                <div
                                    className="overflow-x-auto rounded-lg border"
                                    style={{ borderColor: 'var(--border)' }}
                                >
                                    <table className="min-w-full divide-y" style={{ borderColor: 'var(--border)' }}>
                                        <thead style={{ backgroundColor: 'var(--bg-subtle)' }}>
                                            <tr>
                                                {['Secret Name', 'Policy', 'Last Rotated', 'Status', 'Days'].map(
                                                    (h) => (
                                                        <th
                                                            key={h}
                                                            className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider"
                                                            style={{ color: 'var(--text-muted)' }}
                                                        >
                                                            {h}
                                                        </th>
                                                    )
                                                )}
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                                            {problemList.map((ev) => (
                                                <EvalRow key={`${ev.policy_id}-${ev.secret_id}`} ev={ev} />
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </>
                    )}
                </div>
            </div>

            {/* ── Policies table ───────────────────────────────────────────── */}
            {(() => {
                const policiesTableContent =
                    policies.length === 0 ? (
                        <div className="p-12 text-center">
                            <ArrowPathIcon className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--text-muted)' }} />
                            <h3 className="text-lg font-medium mb-2" style={{ color: 'var(--text-primary)' }}>
                                No rotation policies yet
                            </h3>
                            <p className="text-sm mb-6" style={{ color: 'var(--text-muted)' }}>
                                Create your first policy to start tracking secret rotation hygiene.
                            </p>
                            <Button onClick={openCreate} className="inline-flex items-center">
                                <PlusIcon className="h-4 w-4 mr-2" />
                                New Policy
                            </Button>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y" style={{ borderColor: 'var(--border)' }}>
                                <thead style={{ backgroundColor: 'var(--bg-subtle)' }}>
                                    <tr>
                                        {[
                                            'Name',
                                            'Scope',
                                            'Interval',
                                            'Alert Before',
                                            'Status',
                                            'Created By',
                                            'Actions',
                                        ].map((h, i) => (
                                            <th
                                                key={h}
                                                className={`px-6 py-3 text-xs font-medium uppercase tracking-wider ${i === 6 ? 'text-right' : 'text-left'}`}
                                                style={{ color: 'var(--text-muted)' }}
                                            >
                                                {h}
                                            </th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                                    {policies.map((policy) => (
                                        <PolicyRow
                                            key={policy.id}
                                            policy={policy}
                                            envMap={envMap}
                                            projMap={projMap}
                                            onEdit={openEdit}
                                            onDelete={setDeleting}
                                        />
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    );
                return (
                    <div
                        className="rounded-xl border"
                        style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                    >
                        {isLoading ? (
                            <div className="p-8">
                                <Loading />
                            </div>
                        ) : (
                            policiesTableContent
                        )}
                    </div>
                );
            })()}

            {/* ── Create / Edit modal ──────────────────────────────────────── */}
            <Modal
                isOpen={isModalOpen}
                onClose={closeModal}
                title={editing ? `Edit: ${editing.name}` : 'New Rotation Policy'}
                size="md"
            >
                <form onSubmit={handleSubmit} className="space-y-4">
                    {fError && <Alert type="error" title="Validation error" message={fError} />}

                    <div>
                        <label
                            htmlFor="policy-name-input"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Name <span style={{ color: '#ef4444' }}>*</span>
                        </label>
                        <input
                            id="policy-name-input"
                            type="text"
                            required
                            value={fName}
                            onChange={(e) => setFName(e.target.value)}
                            placeholder="e.g. Production secrets rotation"
                            className="w-full rounded-md border px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: 'var(--border)',
                            }}
                        />
                    </div>

                    <div>
                        <label
                            htmlFor="policy-description-input"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Description
                        </label>
                        <textarea
                            id="policy-description-input"
                            rows={2}
                            value={fDesc}
                            onChange={(e) => setFDesc(e.target.value)}
                            placeholder="Optional description…"
                            className="w-full rounded-md border px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-blue-500 resize-none"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: 'var(--border)',
                            }}
                        />
                    </div>

                    <div>
                        <label
                            htmlFor="policy-scope-select"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Scope <span style={{ color: '#ef4444' }}>*</span>
                        </label>
                        <Select
                            id="policy-scope-select"
                            value={fScope}
                            onChange={(e) => {
                                setFScope(e.target.value as 'project' | 'environment');
                                setFEnvId('');
                                setFProjId('');
                            }}
                            options={SCOPE_OPTIONS}
                        />
                    </div>

                    {fScope === 'environment' && (
                        <div>
                            <label
                                htmlFor="policy-environment-select"
                                className="block text-sm font-medium mb-1"
                                style={{ color: 'var(--text-secondary)' }}
                            >
                                Environment <span style={{ color: '#ef4444' }}>*</span>
                            </label>
                            <Select
                                id="policy-environment-select"
                                value={fEnvId}
                                onChange={(e) => setFEnvId(e.target.value)}
                                placeholder="Select environment…"
                                options={(environments ?? []).map((env) => ({
                                    value: String(env.id),
                                    label: env.name,
                                }))}
                            />
                        </div>
                    )}

                    {fScope === 'project' && (
                        <div>
                            <label
                                htmlFor="policy-project-select"
                                className="block text-sm font-medium mb-1"
                                style={{ color: 'var(--text-secondary)' }}
                            >
                                Project <span style={{ color: '#ef4444' }}>*</span>
                            </label>
                            <Select
                                id="policy-project-select"
                                value={fProjId}
                                onChange={(e) => setFProjId(e.target.value)}
                                placeholder="Select project…"
                                options={(projects ?? []).map((p) => ({
                                    value: String(p.id),
                                    label: p.name,
                                }))}
                            />
                        </div>
                    )}

                    <div>
                        <label
                            htmlFor="policy-interval-select"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Rotation interval
                        </label>
                        <Select
                            id="policy-interval-select"
                            value={fInterval}
                            onChange={(e) => setFInterval(e.target.value)}
                            options={INTERVAL_OPTIONS}
                        />
                    </div>

                    <div>
                        <label
                            htmlFor="policy-alert-select"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Alert before breach
                        </label>
                        <Select
                            id="policy-alert-select"
                            value={fAlert}
                            onChange={(e) => setFAlert(e.target.value)}
                            options={ALERT_DAYS_OPTIONS}
                        />
                    </div>

                    <div className="flex items-center gap-3">
                        <input
                            type="checkbox"
                            id="notify-on-breach"
                            checked={fNotify}
                            onChange={(e) => setFNotify(e.target.checked)}
                            className="h-4 w-4 rounded-sm text-blue-600 focus:ring-blue-500"
                            style={{ borderColor: 'var(--border)' }}
                        />
                        <label
                            htmlFor="notify-on-breach"
                            className="text-sm"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Notify on breach
                        </label>
                    </div>

                    <div
                        className="flex items-center justify-end gap-3 pt-4 border-t"
                        style={{ borderColor: 'var(--border)' }}
                    >
                        <Button type="button" variant="outline" onClick={closeModal} disabled={isSubmitting}>
                            Cancel
                        </Button>
                        <Button type="submit" disabled={isSubmitting}>
                            {(() => {
                                const idleLabel = editing ? 'Save Changes' : 'Create Policy';
                                const busyLabel = editing ? 'Saving…' : 'Creating…';
                                return isSubmitting ? busyLabel : idleLabel;
                            })()}
                        </Button>
                    </div>
                </form>
            </Modal>

            {/* ── Delete confirmation ──────────────────────────────────────── */}
            <Modal
                isOpen={deleting !== null}
                onClose={() => {
                    setDeleting(null);
                    deleteMutation.reset();
                }}
                title="Delete Policy"
                size="sm"
            >
                <div className="space-y-4">
                    {deleteMutation.isError && (
                        <Alert
                            type="error"
                            title="Failed to delete policy"
                            message={apiErrorMessage(deleteMutation.error, 'An unexpected error occurred')}
                        />
                    )}
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Are you sure you want to delete <span className="font-semibold">{deleting?.name}</span>? This
                        action cannot be undone.
                    </p>
                    <div
                        className="flex items-center justify-end gap-3 pt-4 border-t"
                        style={{ borderColor: 'var(--border)' }}
                    >
                        <Button
                            variant="outline"
                            onClick={() => {
                                setDeleting(null);
                                deleteMutation.reset();
                            }}
                            disabled={deleteMutation.isPending}
                        >
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={() => {
                                if (!deleting) return;
                                deleteMutation.mutate(deleting.id, {
                                    onSuccess: () => {
                                        setDeleting(null);
                                    },
                                });
                            }}
                            disabled={deleteMutation.isPending}
                        >
                            {deleteMutation.isPending ? 'Deleting…' : 'Delete'}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
}

// ── extracted row components (kept outside to avoid re-definition on renders) ─

const EvalRow: React.FC<{ ev: RotationPolicyEvaluation }> = ({ ev }) => (
    <tr className="hover:bg-subtle transition-colors">
        <td className="px-4 py-3 text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
            {ev.secret_name}
        </td>
        <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>
            {ev.policy_name}
        </td>
        <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>
            {ev.last_rotated_at ? formatDate(ev.last_rotated_at) : '—'}
        </td>
        <td className="px-4 py-3">
            <EvalStatusBadge ev={ev} />
        </td>
        <td className="px-4 py-3 text-sm tabular-nums" style={{ color: ev.is_overdue ? '#ef4444' : '#f59e0b' }}>
            {ev.days_overdue}d
        </td>
    </tr>
);

interface PolicyRowProps {
    policy: RotationPolicy;
    envMap: Record<number, string>;
    projMap: Record<number, string>;
    onEdit: (p: RotationPolicy) => void;
    onDelete: (p: RotationPolicy) => void;
}

const PolicyRow: React.FC<PolicyRowProps> = ({ policy, envMap, projMap, onEdit, onDelete }) => {
    const envName = policy.environment_id ? (envMap[policy.environment_id] ?? `#${policy.environment_id}`) : '—';
    const projName = policy.project_id ? (projMap[policy.project_id] ?? `#${policy.project_id}`) : '—';
    const scopeLabel = policy.scope === 'environment' ? `Environment: ${envName}` : `Project: ${projName}`;

    return (
        <tr className="hover:bg-subtle transition-colors">
            <td className="px-6 py-4">
                <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                    {policy.name}
                </span>
                {policy.description && (
                    <p className="text-xs mt-0.5 max-w-xs truncate" style={{ color: 'var(--text-muted)' }}>
                        {policy.description}
                    </p>
                )}
            </td>
            <td className="px-6 py-4 text-sm whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                {scopeLabel}
            </td>
            <td className="px-6 py-4 text-sm whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                Every {policy.interval_days} days
            </td>
            <td className="px-6 py-4 text-sm whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                {policy.alert_days_before} days before
            </td>
            <td className="px-6 py-4 whitespace-nowrap">
                <ActivePill active={policy.is_active} />
            </td>
            <td className="px-6 py-4 text-sm" style={{ color: 'var(--text-secondary)' }}>
                {policy.created_by}
            </td>
            <td className="px-6 py-4 whitespace-nowrap text-right">
                <div className="flex items-center justify-end gap-1">
                    <Button variant="ghost" size="sm" onClick={() => onEdit(policy)} title="Edit">
                        <PencilIcon className="h-4 w-4" />
                    </Button>
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onDelete(policy)}
                        title="Delete"
                        style={{ color: '#ef4444' }}
                    >
                        <TrashIcon className="h-4 w-4" />
                    </Button>
                </div>
            </td>
        </tr>
    );
};
