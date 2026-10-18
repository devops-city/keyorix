import React, { useState } from 'react';
import {
    CpuChipIcon,
    PlusIcon,
    PlayIcon,
    PauseIcon,
    NoSymbolIcon,
    ChevronRightIcon,
} from '@heroicons/react/24/outline';
import {
    MachineIdentity,
    MachineIdentityType,
    MACHINE_IDENTITY_TYPES,
    isStaleMachineIdentity,
    STALE_MACHINE_IDENTITY_DAYS,
} from '../../services/machineIdentities';
import { useAuth } from '../auth';
import { useConfirm } from '../../components/ui/useConfirm';
import {
    useMachineIdentities,
    useCreateMachineIdentity,
    useTransitionMachineIdentity,
    useClassifyMachineIdentity,
} from './api';
import { classificationMeta, CLASSIFICATION_LEVELS } from '../secrets/classification';
import { MachineTokensPanel } from './MachineTokensPanel';

const typeLabel: Record<MachineIdentityType, string> = {
    ci: 'CI',
    k8s: 'Kubernetes',
    service: 'Service',
    automation: 'Automation',
    other: 'Other',
};

const stateStyle = (state: string): React.CSSProperties => {
    switch (state) {
        case 'active':
            return { backgroundColor: 'var(--success-subtle, #dcfce7)', color: 'var(--success, #15803d)' };
        case 'pending':
            return { backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' };
        case 'suspended':
            return { backgroundColor: 'var(--warning-subtle, #fef9c3)', color: 'var(--warning, #a16207)' };
        case 'revoked':
        default:
            return { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' };
    }
};

/**
 * ADR-023 machine identities for the Members tab — the non-human half of the
 * Humans vs Machine Identities segmentation. Lists this project's machine
 * identities (CI/k8s/service/automation) with a 4-state lifecycle. Project
 * admins can create one and advance its state (activate/suspend/revoke); the
 * list is read-only for ordinary members. Machine-token authentication itself
 * is a deliberate backend follow-up, so these identities cannot yet sign in.
 */
export const MachineIdentitiesSection: React.FC<{ projectId: number }> = ({ projectId }) => {
    const { isAdmin } = useAuth();
    const { requestConfirm, confirmDialog } = useConfirm();
    const { data: identities = [], isLoading } = useMachineIdentities(projectId);
    const create = useCreateMachineIdentity(projectId);
    const transition = useTransitionMachineIdentity(projectId);
    const classify = useClassifyMachineIdentity(projectId);

    const [name, setName] = useState('');
    const [identityType, setIdentityType] = useState<MachineIdentityType>('ci');
    const [error, setError] = useState('');
    const [expanded, setExpanded] = useState<number | null>(null);

    const surface = (err: any, fallback: string) =>
        setError(err?.response?.data?.message ?? err?.response?.data?.error ?? fallback);

    const handleCreate = () => {
        if (!name.trim()) return;
        setError('');
        create.mutate(
            { name: name.trim(), identityType },
            {
                onSuccess: () => setName(''),
                onError: (err) => surface(err, 'Failed to create machine identity.'),
            }
        );
    };

    const act = async (m: MachineIdentity, action: 'activate' | 'suspend' | 'revoke') => {
        // Activating/reactivating is non-destructive; suspend and revoke break the
        // identity's access (revoke permanently), so both are confirmed first.
        if (action === 'suspend') {
            const ok = await requestConfirm({
                title: 'Suspend machine identity',
                message: `Suspend machine identity "${m.name}"? It will lose access until reactivated.`,
                confirmText: 'Suspend',
            });
            if (!ok) return;
        } else if (action === 'revoke') {
            const ok = await requestConfirm({
                title: 'Revoke machine identity',
                message: `Revoke machine identity "${m.name}"? This cannot be undone.`,
                confirmText: 'Revoke',
            });
            if (!ok) return;
        }
        setError('');
        transition.mutate(
            { machineId: m.id, action },
            { onError: (err) => surface(err, `Failed to ${action} machine identity.`) }
        );
    };

    const reclassify = (m: MachineIdentity, classification: string) => {
        if (classification === m.classification) return;
        setError('');
        classify.mutate(
            { machineId: m.id, classification },
            { onError: (err) => surface(err, 'Failed to update classification.') }
        );
    };

    const selectStyle: React.CSSProperties = {
        backgroundColor: 'var(--bg-app)',
        border: '1px solid var(--border)',
        color: 'var(--text-primary)',
    };

    const identitiesContent =
        identities.length === 0 ? (
            <div className="p-8 text-center">
                <CpuChipIcon className="h-9 w-9 mx-auto mb-2" style={{ color: 'var(--text-muted)' }} />
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                    No machine identities yet.
                </p>
            </div>
        ) : (
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {identities.map((m) => (
                    <li key={m.id}>
                        <div className="flex items-center gap-3 px-4 py-3">
                            <button
                                type="button"
                                onClick={() => setExpanded(expanded === m.id ? null : m.id)}
                                className="shrink-0"
                                aria-label={`Toggle tokens for ${m.name}`}
                            >
                                <ChevronRightIcon
                                    className="h-4 w-4 transition-transform"
                                    style={{
                                        color: 'var(--text-muted)',
                                        transform: expanded === m.id ? 'rotate(90deg)' : 'none',
                                    }}
                                />
                            </button>
                            <div
                                className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0"
                                style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-secondary)' }}
                            >
                                <CpuChipIcon className="h-4 w-4" />
                            </div>
                            <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                    {m.name}
                                </p>
                                <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                    {typeLabel[m.identityType] ?? m.identityType}
                                    {m.description ? ` · ${m.description}` : ''}
                                </p>
                            </div>
                            {isAdmin ? (
                                <select
                                    aria-label={`Classification for ${m.name}`}
                                    value={m.classification ?? ''}
                                    disabled={classify.isPending}
                                    onChange={(e) => reclassify(m, e.target.value)}
                                    className="rounded-lg px-2 py-1 text-xs outline-hidden shrink-0 disabled:opacity-50"
                                    style={selectStyle}
                                    title="Data classification (ISO 27001 A.5.12)"
                                >
                                    {CLASSIFICATION_LEVELS.map((level) => (
                                        <option key={level || 'unclassified'} value={level}>
                                            {classificationMeta(level).label}
                                        </option>
                                    ))}
                                </select>
                            ) : (
                                <span
                                    data-testid="mi-classification-badge"
                                    className={`px-2 py-0.5 rounded-full text-xs font-medium shrink-0 ${classificationMeta(m.classification ?? '').color}`}
                                    title="Data classification (ISO 27001 A.5.12)"
                                >
                                    {classificationMeta(m.classification ?? '').label}
                                </span>
                            )}
                            <span
                                className="px-2 py-0.5 rounded-full text-xs font-medium capitalize shrink-0"
                                style={stateStyle(m.state)}
                            >
                                {m.state}
                            </span>
                            {isStaleMachineIdentity(m) && (
                                <span
                                    data-testid="mi-stale-badge"
                                    className="px-2 py-0.5 rounded-full text-xs font-medium shrink-0 bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300"
                                    title={`Not seen in ${STALE_MACHINE_IDENTITY_DAYS}+ days — consider revoking`}
                                >
                                    Stale
                                </span>
                            )}
                            {isAdmin && m.state !== 'revoked' && (
                                <div className="flex items-center gap-1 shrink-0">
                                    {(m.state === 'pending' || m.state === 'suspended') && (
                                        <button
                                            type="button"
                                            onClick={() => act(m, 'activate')}
                                            disabled={transition.isPending}
                                            className="p-1.5 rounded-sm transition-colors disabled:opacity-50"
                                            style={{ color: 'var(--success, #15803d)' }}
                                            title={m.state === 'suspended' ? 'Reactivate' : 'Activate'}
                                        >
                                            <PlayIcon className="h-4 w-4" />
                                        </button>
                                    )}
                                    {m.state === 'active' && (
                                        <button
                                            type="button"
                                            onClick={() => act(m, 'suspend')}
                                            disabled={transition.isPending}
                                            className="p-1.5 rounded-sm transition-colors disabled:opacity-50"
                                            style={{ color: 'var(--warning, #a16207)' }}
                                            title="Suspend"
                                        >
                                            <PauseIcon className="h-4 w-4" />
                                        </button>
                                    )}
                                    <button
                                        type="button"
                                        onClick={() => act(m, 'revoke')}
                                        disabled={transition.isPending}
                                        className="p-1.5 rounded-sm transition-colors hover:bg-red-50 disabled:opacity-50"
                                        style={{ color: 'var(--error)' }}
                                        title="Revoke"
                                    >
                                        <NoSymbolIcon className="h-4 w-4" />
                                    </button>
                                </div>
                            )}
                        </div>
                        {expanded === m.id && (
                            <MachineTokensPanel projectId={projectId} machineId={m.id} canManage={isAdmin} />
                        )}
                    </li>
                ))}
            </ul>
        );

    return (
        <div className="mt-6">
            <h3 className="text-sm font-semibold mb-0.5" style={{ color: 'var(--text-primary)' }}>
                Machine identities
            </h3>
            <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
                Non-human members — CI runners, Kubernetes workloads, services, and automation.
            </p>

            {error && (
                <div
                    className="rounded-lg px-3 py-2 text-sm mb-2"
                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                >
                    {error}
                </div>
            )}

            {/* Create row (admins only — create needs roles.assign at project scope). */}
            {isAdmin && (
                <div
                    className="rounded-lg border p-3 mb-3 flex flex-wrap items-center gap-2"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                >
                    <input
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                        placeholder="Machine identity name…"
                        className="flex-1 min-w-[12rem] rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={selectStyle}
                    />
                    <select
                        value={identityType}
                        onChange={(e) => setIdentityType(e.target.value as MachineIdentityType)}
                        className="rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={selectStyle}
                    >
                        {MACHINE_IDENTITY_TYPES.map((t) => (
                            <option key={t} value={t}>
                                {typeLabel[t]}
                            </option>
                        ))}
                    </select>
                    <button
                        type="button"
                        onClick={handleCreate}
                        disabled={!name.trim() || create.isPending}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50"
                        style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                    >
                        <PlusIcon className="h-4 w-4" />
                        Add
                    </button>
                </div>
            )}

            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                {isLoading ? (
                    <div className="p-6 space-y-3">
                        {[1, 2].map((i) => (
                            <div key={i} className="flex items-center gap-3 animate-pulse">
                                <div className="h-8 w-8 rounded-lg" style={{ backgroundColor: 'var(--bg-muted)' }} />
                                <div className="flex-1">
                                    <div
                                        className="h-3 w-32 rounded-sm mb-1.5"
                                        style={{ backgroundColor: 'var(--bg-muted)' }}
                                    />
                                    <div
                                        className="h-2.5 w-48 rounded-sm"
                                        style={{ backgroundColor: 'var(--bg-muted)' }}
                                    />
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    identitiesContent
                )}
            </div>
            {confirmDialog}
        </div>
    );
};
