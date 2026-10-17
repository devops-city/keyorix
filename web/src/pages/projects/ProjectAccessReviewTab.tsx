import React, { useState } from 'react';
import { ShieldCheckIcon, CheckIcon, NoSymbolIcon } from '@heroicons/react/24/outline';
import { useAccessReview, useAttestAccessReview, useRevokeAccessReview } from '../../features/projects/api';
import { AccessReviewEntry, AccessReviewDecision } from '../../services/projects';
import { ProjectAccessReviewCampaigns, lastUsedInfo } from './ProjectAccessReviewCampaigns';

interface ProjectAccessReviewTabProps {
    projectId: number;
}

// A stable key for one access-review entry (entries have no server id).
const entryKey = (e: AccessReviewEntry) =>
    `${e.source}:${e.principalId}:${e.roleId ?? 0}:${e.secretId ?? 0}:${e.environmentId ?? 0}`;

const decisionFor = (e: AccessReviewEntry): AccessReviewDecision => ({
    source: e.source,
    principalType: e.principalType,
    principalId: e.principalId,
    roleId: e.roleId,
    environmentId: e.environmentId,
    secretId: e.secretId,
});

const SOURCE_LABEL: Record<string, string> = {
    role: 'Role',
    owner: 'Owner',
    direct_share: 'Direct share',
    group_share: 'Group share',
};

const sourceDetail = (e: AccessReviewEntry): string => {
    if (e.source === 'role') {
        const scope = e.environmentId ? `env ${e.environmentId}` : 'project-wide';
        return `Role: ${e.roleName || '—'} (${scope})`;
    }
    return e.secretName ? `Secret: ${e.secretName}` : '—';
};

/**
 * Access Review tab (ISO 27001 A.5.18 / SOC 2 CC6.2–6.3). Lists every grant of
 * access to this project's secrets — role-based standing access plus per-secret
 * ownership and shares — and lets an admin recertify each: attest (reviewed and
 * kept) or revoke (remove the grant). Ownership can't be revoked here.
 */
export const ProjectAccessReviewTab: React.FC<ProjectAccessReviewTabProps> = ({ projectId }) => {
    const { data: entries = [], isLoading, isError } = useAccessReview(projectId);
    const attest = useAttestAccessReview(projectId);
    const revoke = useRevokeAccessReview(projectId);

    const [attestedKeys, setAttestedKeys] = useState<Set<string>>(new Set());
    const [confirmKey, setConfirmKey] = useState<string | null>(null);
    const [error, setError] = useState('');

    const onError = (err: any) =>
        setError(err?.response?.data?.error ?? err?.response?.data?.message ?? 'Action failed.');

    const handleAttest = (e: AccessReviewEntry) => {
        setError('');
        const key = entryKey(e);
        attest.mutate(decisionFor(e), {
            onSuccess: () => setAttestedKeys((prev) => new Set(prev).add(key)),
            onError,
        });
    };

    const handleRevoke = (e: AccessReviewEntry) => {
        setError('');
        revoke.mutate(decisionFor(e), {
            onSuccess: () => setConfirmKey(null),
            onError,
        });
    };

    const emptyOrList =
        entries.length === 0 ? (
            <div className="p-10 text-center">
                <ShieldCheckIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                    No one has access to this project&rsquo;s secrets.
                </p>
            </div>
        ) : (
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {entries.map((e) => {
                    const key = entryKey(e);
                    const attested = attestedKeys.has(key);
                    const confirming = confirmKey === key;
                    const principal =
                        e.principalType === 'user' && e.email ? `${e.principalName} (${e.email})` : e.principalName;
                    const revocable = e.source !== 'owner';
                    return (
                        <li key={key} className="flex items-center gap-3 px-4 py-3">
                            <span
                                className="px-2 py-0.5 rounded-full text-xs font-medium shrink-0"
                                style={{ backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' }}
                            >
                                {SOURCE_LABEL[e.source] ?? e.source}
                            </span>
                            <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                    {principal || `${e.principalType} ${e.principalId}`}
                                </p>
                                <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                    {sourceDetail(e)}
                                </p>
                            </div>
                            {e.principalType === 'user' &&
                                (() => {
                                    const { label, dormant } = lastUsedInfo(e);
                                    return (
                                        <span
                                            className="text-xs shrink-0 px-2 py-1 rounded-md hidden sm:inline"
                                            style={{
                                                backgroundColor: dormant ? 'var(--warning-subtle)' : 'var(--bg-muted)',
                                                color: dormant ? 'var(--warning)' : 'var(--text-muted)',
                                            }}
                                            title={
                                                dormant
                                                    ? 'Dormant — review whether this standing access is still needed'
                                                    : `Last secret access in this project${e.activityWindowDays ? ` (last ${e.activityWindowDays} days)` : ''}`
                                            }
                                        >
                                            {label}
                                        </span>
                                    );
                                })()}
                            <span
                                className="text-xs shrink-0 px-2 py-1 rounded-md"
                                style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-secondary)' }}
                                title="Access level"
                            >
                                {e.accessLevel || '—'}
                            </span>

                            {/* Recertification actions */}
                            <div className="flex items-center gap-2 shrink-0">
                                {attested ? (
                                    <span
                                        className="inline-flex items-center gap-1 text-xs"
                                        style={{ color: 'var(--success)' }}
                                    >
                                        <CheckIcon className="h-3.5 w-3.5" />
                                        Attested
                                    </span>
                                ) : (
                                    <button
                                        type="button"
                                        onClick={() => handleAttest(e)}
                                        disabled={attest.isPending}
                                        className="px-2.5 py-1 rounded-lg text-xs font-medium disabled:opacity-50"
                                        style={{
                                            border: '1px solid var(--border)',
                                            color: 'var(--text-secondary)',
                                        }}
                                        title="Certify this access was reviewed and kept"
                                    >
                                        Attest
                                    </button>
                                )}
                                {revocable &&
                                    (confirming ? (
                                        <span className="inline-flex items-center gap-1">
                                            <button
                                                type="button"
                                                onClick={() => handleRevoke(e)}
                                                disabled={revoke.isPending}
                                                className="px-2.5 py-1 rounded-lg text-xs font-medium disabled:opacity-50"
                                                style={{ backgroundColor: 'var(--error)', color: '#fff' }}
                                            >
                                                Confirm
                                            </button>
                                            <button
                                                type="button"
                                                onClick={() => setConfirmKey(null)}
                                                className="px-2 py-1 rounded-lg text-xs"
                                                style={{ color: 'var(--text-muted)' }}
                                            >
                                                Cancel
                                            </button>
                                        </span>
                                    ) : (
                                        <button
                                            type="button"
                                            onClick={() => setConfirmKey(key)}
                                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium"
                                            style={{
                                                backgroundColor: 'var(--error-subtle)',
                                                color: 'var(--error)',
                                            }}
                                            title="Remove this access"
                                        >
                                            <NoSymbolIcon className="h-3.5 w-3.5" />
                                            Revoke
                                        </button>
                                    ))}
                            </div>
                        </li>
                    );
                })}
            </ul>
        );

    const errorOrContent = isError ? (
        <div className="p-6 text-center">
            <p className="text-sm" style={{ color: 'var(--error)' }}>
                Failed to load the access review.
            </p>
        </div>
    ) : (
        emptyOrList
    );

    return (
        <div>
            <div className="mb-4">
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                    Access Review
                </h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    Who can reach this project&rsquo;s secrets, and how (ISO 27001 A.5.18). Attest a grant to certify it
                    was reviewed and kept, or revoke it to remove the access. Both are audited.
                </p>
            </div>

            {error && (
                <div
                    className="rounded-lg px-3 py-2 text-sm mb-3"
                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                >
                    {error}
                </div>
            )}

            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                {isLoading ? (
                    <div className="p-6 space-y-3">
                        {[1, 2, 3].map((i) => (
                            <div key={i} className="flex items-center gap-3 animate-pulse">
                                <div className="h-8 w-8 rounded-full" style={{ backgroundColor: 'var(--bg-muted)' }} />
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
                    errorOrContent
                )}
            </div>

            <ProjectAccessReviewCampaigns projectId={projectId} />
        </div>
    );
};
