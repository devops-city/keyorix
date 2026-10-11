import React, { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
    EyeIcon,
    EyeSlashIcon,
    DocumentDuplicateIcon,
    PencilIcon,
    ShareIcon,
    TrashIcon,
    ClockIcon,
    TagIcon,
    MapPinIcon,
    UserIcon,
    KeyIcon,
    ArrowPathIcon,
    ShieldExclamationIcon,
    ShieldCheckIcon,
} from '@heroicons/react/24/outline';
import {
    useSecretVersions,
    useSecretValue,
    useRotateSecret,
    useSecretRisk,
    useClassifySecret,
    useRollbackSecret,
    useSecretAccessors,
    useSecretAccessLog,
    useSecretAuditTrail,
    useSecretTags,
    useSetSecretTags,
    useSecretDescription,
    useSetSecretDescription,
    useCopySecret,
    useSuspendSecret,
    useResumeSecret,
} from './api';
import { TransferOwnership } from './TransferOwnership';
import { SecretDependenciesSection } from './SecretDependenciesSection';
import { CertificatePanel } from './CertificatePanel';
import { CLASSIFICATION_LEVELS, classificationMeta } from './classification';
import { RiskBand, Secret } from '../../types';
import { copyToClipboard } from '../../utils';
import { queryKeys } from '../../lib/queryClient';
import { useAutoClearOnIdle } from '../../hooks/useAutoClearOnIdle';
import { Button } from '../../components/ui/Button';
import { Spinner, Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { apiErrorMessage } from '../../services/client';
import { useCan, type Can } from '../auth/useCan';
import { Textarea } from '../../components/ui/Textarea';
import { parseServerDate } from '../../utils';
import { eventLabel, accessActionLabel } from '../../utils/eventLabels';
import { formatDateTime } from '../../utils/datetime';

const relativeFromNow = (d: string | Date): string => {
    const days = Math.floor((Date.now() - parseServerDate(d).getTime()) / 86_400_000);
    if (days <= 0) return 'today';
    if (days === 1) return 'yesterday';
    if (days < 30) return `${days} days ago`;
    const months = Math.floor(days / 30);
    if (months < 12) return `${months} month${months === 1 ? '' : 's'} ago`;
    const years = Math.floor(days / 365);
    return `${years} year${years === 1 ? '' : 's'} ago`;
};

// Inside a secret's own history the "secret." prefix is noise for events nobody curated a label for.
const auditEventLabel = (eventType: string): string => eventLabel(eventType, 'secret.');

const RISK_BAND_STYLE: Record<RiskBand, { label: string; color: string }> = {
    low: { label: 'Low risk', color: '#10b981' },
    medium: { label: 'Medium risk', color: '#f59e0b' },
    high: { label: 'High risk', color: '#ef4444' },
};

const factorColor = (score: number): string => {
    const mediumOrLow = score >= 34 ? '#f59e0b' : '#10b981';
    return score >= 67 ? '#ef4444' : mediumOrLow;
};

const formatSecretValue = (value: string, type: string): string => {
    if (type === 'json') {
        try {
            return JSON.stringify(JSON.parse(value), null, 2);
        } catch {
            return value;
        }
    }
    return value;
};

const TYPE_COLORS: Record<string, string> = {
    text: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
    password: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
    api_key: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
    certificate: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
    json: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
};

const getTypeColor = (type: string): string => TYPE_COLORS[type] ?? TYPE_COLORS['text']!;

const PERMISSION_COLORS: Record<string, string> = {
    owner: 'bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300',
    write: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
};
const DEFAULT_PERMISSION_COLOR = 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300';
const getPermissionColor = (permission: string): string => PERMISSION_COLORS[permission] ?? DEFAULT_PERMISSION_COLOR;

function computeLatestVersion(versions: VersionItem[] | undefined): VersionItem | null {
    if (!versions || versions.length === 0) return null;
    return versions.reduce((a, b) => (a.VersionNumber >= b.VersionNumber ? a : b), versions[0]!);
}

function buildSecretValueDisplay(
    showValue: boolean,
    isLoading: boolean,
    secretValue: string | null,
    secretType: string
): React.ReactNode {
    if (!showValue) {
        return (
            <div className="bg-gray-50 dark:bg-gray-700 rounded-md p-4 text-center">
                <div className="text-gray-400 dark:text-gray-500 mb-2">
                    <EyeSlashIcon className="h-8 w-8 mx-auto" />
                </div>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                    Secret value is hidden for security. Click &ldquo;Reveal&rdquo; to view.
                </p>
            </div>
        );
    }
    if (isLoading) {
        return (
            <div className="bg-gray-50 dark:bg-gray-700 rounded-md p-4">
                <Loading />
            </div>
        );
    }
    if (!secretValue) return null;
    return (
        <div className="bg-gray-50 dark:bg-gray-700 rounded-md p-4">
            {secretType === 'json' ? (
                <pre className="text-sm font-mono text-gray-900 dark:text-white whitespace-pre-wrap overflow-x-auto">
                    {formatSecretValue(secretValue, secretType)}
                </pre>
            ) : (
                <div className="text-sm font-mono text-gray-900 dark:text-white break-all">{secretValue}</div>
            )}
        </div>
    );
}

// ─── Section components ─────────────────────────────────────────────────────

type VersionItem = NonNullable<ReturnType<typeof useSecretVersions>['data']>[number];
type Accessor = NonNullable<ReturnType<typeof useSecretAccessors>['data']>[number];
type AccessLogEntry = NonNullable<ReturnType<typeof useSecretAccessLog>['data']>[number];
type AuditEntry = NonNullable<ReturnType<typeof useSecretAuditTrail>['data']>[number];
type RiskData = NonNullable<ReturnType<typeof useSecretRisk>['data']>;

interface SecretDetailHeaderProps {
    secret: Secret;
    classification: string;
    suspended: boolean;
    classifyPending: boolean;
    onClassify: (level: string) => void;
    onEdit?: ((secret: Secret) => void) | undefined;
    onShare?: ((secret: Secret) => void) | undefined;
    onRotateClick: () => void;
    onCopy: () => void;
    copyPending: boolean;
    onToggleSuspend: () => void;
    suspendTogglePending: boolean;
    onDelete?: ((secret: Secret) => void) | undefined;
    can: Can;
}

const SecretDetailHeader: React.FC<SecretDetailHeaderProps> = ({
    secret,
    classification,
    suspended,
    classifyPending,
    onClassify,
    onEdit,
    onShare,
    onRotateClick,
    onCopy,
    copyPending,
    onToggleSuspend,
    suspendTogglePending,
    onDelete,
    can,
}) => (
    <div data-testid="secret-header" className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">{secret.name}</h2>
                <span
                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getTypeColor(secret.type)}`}
                >
                    {secret.type}
                </span>
                <span
                    data-testid="classification-badge"
                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${classificationMeta(classification).color}`}
                    title="Data classification (ISO 27001 A.5.12)"
                >
                    <ShieldCheckIcon className="h-3.5 w-3.5 mr-1" />
                    {classificationMeta(classification).label}
                </span>
                {suspended && (
                    <span
                        data-testid="suspended-badge"
                        className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300"
                        title="Value reads are blocked while suspended"
                    >
                        Suspended
                    </span>
                )}
            </div>

            <div
                data-testid="secret-meta"
                className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-gray-500 dark:text-gray-400"
            >
                <div className="flex items-center">
                    <MapPinIcon className="h-4 w-4 mr-1" />
                    {secret.environment || 'No environment'}
                </div>
                <div className="flex items-center">
                    <UserIcon className="h-4 w-4 mr-1" />
                    {secret.owner}
                </div>
                <div className="flex items-center">
                    <ClockIcon className="h-4 w-4 mr-1" />
                    {formatDateTime(secret.lastModified)}
                </div>
                <div className="flex items-center">
                    <ArrowPathIcon className="h-4 w-4 mr-1" />
                    {secret.lastRotatedAt ? `Rotated ${relativeFromNow(secret.lastRotatedAt)}` : 'Never rotated'}
                </div>
                <label className="flex items-center">
                    <span className="sr-only">Classification</span>
                    <ShieldCheckIcon className="h-4 w-4 mr-1" />
                    <select
                        aria-label="Classification"
                        value={classification}
                        disabled={classifyPending || !can.writeSecrets}
                        title={can.writeSecrets ? undefined : 'You do not have permission to change the classification'}
                        onChange={(e) => onClassify(e.target.value)}
                        className="bg-transparent text-sm text-gray-500 dark:text-gray-400 border-0 focus:ring-0 cursor-pointer disabled:opacity-50"
                    >
                        {CLASSIFICATION_LEVELS.map((level) => (
                            <option key={level || 'unclassified'} value={level}>
                                {classificationMeta(level).label}
                            </option>
                        ))}
                    </select>
                </label>
            </div>
            {can.deleteSecrets && (
                <div className="mt-2">
                    <TransferOwnership secretId={secret.id} currentOwner={secret.owner} />
                </div>
            )}
        </div>

        <div data-testid="secret-actions" className="flex flex-wrap items-center gap-2">
            {can.writeSecrets && (
                <>
                    <Button variant="outline" size="sm" onClick={() => onEdit?.(secret)}>
                        <PencilIcon className="h-4 w-4 mr-2" />
                        Edit
                    </Button>
                    <Button variant="outline" size="sm" onClick={onRotateClick}>
                        <ArrowPathIcon className="h-4 w-4 mr-2" />
                        Rotate
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => onShare?.(secret)}>
                        <ShareIcon className="h-4 w-4 mr-2" />
                        Share
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={onCopy}
                        disabled={copyPending}
                        title="Copy this secret into another environment (same project)"
                    >
                        <DocumentDuplicateIcon className="h-4 w-4 mr-2" />
                        Copy
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={onToggleSuspend}
                        disabled={suspendTogglePending}
                        className={suspended ? '' : 'text-amber-600 hover:text-amber-700'}
                    >
                        {suspended ? 'Resume' : 'Suspend'}
                    </Button>
                </>
            )}
            {can.deleteSecrets && (
                <Button
                    variant="outline"
                    size="sm"
                    onClick={() => onDelete?.(secret)}
                    className="text-red-600 hover:text-red-700"
                >
                    <TrashIcon className="h-4 w-4 mr-2" />
                    Delete
                </Button>
            )}
        </div>
    </div>
);

interface SecretValuePanelProps {
    showValue: boolean;
    isLoading: boolean;
    error: unknown;
    secretValueDisplay: React.ReactNode;
    copySuccess: boolean;
    secretValue: string | null;
    onToggleValue: () => void;
    onCopyValue: (value: string) => void;
}

const SecretValuePanel: React.FC<SecretValuePanelProps> = ({
    showValue,
    isLoading,
    error,
    secretValueDisplay,
    copySuccess,
    secretValue,
    onToggleValue,
    onCopyValue,
}) => {
    const revealButtonContent = showValue ? (
        <>
            <EyeSlashIcon className="h-4 w-4 mr-2" />
            Hide
        </>
    ) : (
        <>
            <EyeIcon className="h-4 w-4 mr-2" />
            Reveal
        </>
    );
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                    <KeyIcon className="h-5 w-5 mr-2" />
                    Secret Value
                </h3>
                <div className="flex items-center space-x-2">
                    <Button variant="outline" size="sm" onClick={onToggleValue} disabled={showValue && isLoading}>
                        {showValue && isLoading ? <Spinner size="sm" /> : revealButtonContent}
                    </Button>

                    {showValue && secretValue && (
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => onCopyValue(secretValue)}
                            className={copySuccess ? 'text-green-600' : ''}
                        >
                            <DocumentDuplicateIcon className="h-4 w-4 mr-2" />
                            {copySuccess ? 'Copied!' : 'Copy'}
                        </Button>
                    )}
                </div>
            </div>

            {!!error && (
                <Alert
                    type="error"
                    title="Failed to load secret value"
                    message={apiErrorMessage(error, 'There was an error loading the secret value. Please try again.')}
                />
            )}

            {secretValueDisplay}

            {copySuccess && (
                <div className="mt-2">
                    <Alert type="success" title="Copied to clipboard" message="Secret value copied to clipboard." />
                </div>
            )}
        </div>
    );
};

interface VersionHistoryPanelProps {
    versions: VersionItem[] | undefined;
    latestVersion: VersionItem | null;
    rollbackMutation: ReturnType<typeof useRollbackSecret>;
    onRollback: (version: number) => void;
    canRollback: boolean;
}

const VersionHistoryPanel: React.FC<VersionHistoryPanelProps> = ({
    versions,
    latestVersion,
    rollbackMutation,
    onRollback,
    canRollback,
}) => {
    if (!versions || versions.length <= 1 || !latestVersion) return null;
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Version History</h3>
            {rollbackMutation.isError && (
                <Alert
                    type="error"
                    title="Rollback failed"
                    message={
                        rollbackMutation.error instanceof Error
                            ? rollbackMutation.error.message
                            : 'An unexpected error occurred'
                    }
                />
            )}
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {[...versions]
                    .sort((a, b) => b.VersionNumber - a.VersionNumber)
                    .map((v) => (
                        <div key={v.VersionNumber} className="flex items-center justify-between py-2.5">
                            <div className="flex items-center gap-2 text-sm">
                                <span className="font-medium text-gray-900 dark:text-white tabular-nums">
                                    v{v.VersionNumber}
                                </span>
                                {v.VersionNumber === latestVersion.VersionNumber && (
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300">
                                        current
                                    </span>
                                )}
                                <span className="text-gray-500 dark:text-gray-400">{formatDateTime(v.CreatedAt)}</span>
                            </div>
                            {canRollback && v.VersionNumber !== latestVersion.VersionNumber && (
                                <Button
                                    variant="outline"
                                    size="sm"
                                    disabled={rollbackMutation.isPending}
                                    onClick={() => onRollback(v.VersionNumber)}
                                >
                                    {rollbackMutation.isPending ? 'Rolling back…' : 'Roll back'}
                                </Button>
                            )}
                        </div>
                    ))}
            </div>
        </div>
    );
};

interface AccessorsPanelProps {
    accessors: Accessor[] | undefined;
}

const AccessorsPanel: React.FC<AccessorsPanelProps> = ({ accessors }) => {
    if (!accessors || accessors.length === 0) return null;
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Who can access</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
                Users who can read this secret (admins with a role grant are not listed).
            </p>
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {accessors.map((a) => (
                    <div key={a.user_id} className="flex items-center justify-between py-2.5 text-sm">
                        <div className="flex items-center gap-2">
                            <UserIcon className="h-4 w-4 text-gray-400" />
                            <span className="font-medium text-gray-900 dark:text-white">{a.username}</span>
                            <span className="text-xs text-gray-500 dark:text-gray-400">{a.source}</span>
                        </div>
                        <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${getPermissionColor(a.permission)}`}
                        >
                            {a.permission}
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
};

interface RecentAccessPanelProps {
    accessLog: AccessLogEntry[] | undefined;
}

const RecentAccessPanel: React.FC<RecentAccessPanelProps> = ({ accessLog }) => {
    if (!accessLog || accessLog.length === 0) return null;
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Recent access</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">Reads of this secret in the last 30 days.</p>
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {accessLog.slice(0, 25).map((e) => (
                    <div
                        key={`${e.accessed_by}-${e.access_time}-${e.action}`}
                        className="flex items-center justify-between py-2 text-sm"
                    >
                        <div className="flex items-center gap-2 min-w-0">
                            <UserIcon className="h-4 w-4 text-gray-400 shrink-0" />
                            <span className="font-medium text-gray-900 dark:text-white">
                                {e.accessed_by || 'unknown'}
                            </span>
                            <span className="text-xs text-gray-500 dark:text-gray-400 truncate">
                                {accessActionLabel(e.action)}
                                {e.ip_address ? ` · ${e.ip_address}` : ''}
                            </span>
                        </div>
                        <span
                            className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap"
                            title={formatDateTime(e.access_time, { seconds: true })}
                        >
                            {relativeFromNow(e.access_time)}
                        </span>
                    </div>
                ))}
            </div>
            {accessLog.length > 25 && (
                <p className="text-xs text-gray-400 mt-3">Showing the 25 most recent of {accessLog.length}.</p>
            )}
        </div>
    );
};

interface DescriptionPanelProps {
    description: string;
    descDraft: string | null;
    setDescDraft: (v: string | null) => void;
    mutation: ReturnType<typeof useSetSecretDescription>;
    readOnly: boolean;
}

const DescriptionPanel: React.FC<DescriptionPanelProps> = ({
    description,
    descDraft,
    setDescDraft,
    mutation,
    readOnly,
}) => (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Description</h3>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
            A free-text note — what this secret is for, its upstream, who to contact.
        </p>
        <textarea
            value={descDraft ?? description}
            onChange={(e) => setDescDraft(e.target.value)}
            disabled={mutation.isPending}
            readOnly={readOnly}
            rows={3}
            maxLength={1024}
            placeholder="No description."
            className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-white disabled:opacity-50"
        />
        {descDraft !== null && descDraft !== description && (
            <div className="mt-2 flex justify-end gap-2">
                <button
                    type="button"
                    onClick={() => setDescDraft(null)}
                    disabled={mutation.isPending}
                    className="px-3 py-1 text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 disabled:opacity-50"
                >
                    Cancel
                </button>
                <button
                    type="button"
                    onClick={() => mutation.mutate(descDraft, { onSuccess: () => setDescDraft(null) })}
                    disabled={mutation.isPending}
                    className="px-3 py-1 rounded-md text-sm font-medium text-white disabled:opacity-50"
                    style={{ backgroundColor: 'var(--accent, #2563eb)' }}
                >
                    {mutation.isPending ? 'Saving…' : 'Save'}
                </button>
            </div>
        )}
    </div>
);

interface TagsEditPanelProps {
    secretTags: string[];
    tagDraft: string;
    setTagDraft: (v: string) => void;
    onTagKeyDown: (e: React.KeyboardEvent<HTMLInputElement>) => void;
    mutation: ReturnType<typeof useSetSecretTags>;
    readOnly: boolean;
}

const TagsEditPanel: React.FC<TagsEditPanelProps> = ({
    secretTags,
    tagDraft,
    setTagDraft,
    onTagKeyDown,
    mutation,
    readOnly,
}) => (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Tags</h3>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
            Free-form labels for organizing and filtering secrets.
        </p>
        <div className="flex flex-wrap items-center gap-2">
            {secretTags.map((t) => (
                <span
                    key={t}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200"
                >
                    {t}
                    {!readOnly && (
                        <button
                            type="button"
                            aria-label={`Remove tag ${t}`}
                            disabled={mutation.isPending}
                            onClick={() => mutation.mutate(secretTags.filter((x) => x !== t))}
                            className="text-gray-400 hover:text-red-500 disabled:opacity-50"
                        >
                            ×
                        </button>
                    )}
                </span>
            ))}
            {secretTags.length === 0 && <span className="text-xs text-gray-400">No tags yet.</span>}
        </div>
        {!readOnly && (
            <input
                value={tagDraft}
                onChange={(e) => setTagDraft(e.target.value)}
                onKeyDown={onTagKeyDown}
                disabled={mutation.isPending}
                placeholder="Add a tag and press Enter…"
                className="mt-3 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-3 py-1.5 text-sm text-gray-900 dark:text-white disabled:opacity-50"
            />
        )}
    </div>
);

interface AuditTrailPanelProps {
    auditTrail: AuditEntry[] | undefined;
}

const AuditTrailPanel: React.FC<AuditTrailPanelProps> = ({ auditTrail }) => {
    if (!auditTrail || auditTrail.length === 0) return null;
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">History</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
                Lifecycle events for this secret — created, rotated, suspended, shared, and more.
            </p>
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {auditTrail.map((e) => (
                    <div key={e.id} className="flex items-center justify-between py-2 text-sm">
                        <div className="flex items-center gap-2 min-w-0">
                            <ClockIcon className="h-4 w-4 text-gray-400 shrink-0" />
                            <span className="font-medium text-gray-900 dark:text-white">
                                {auditEventLabel(e.event_type)}
                            </span>
                            {e.description && (
                                <span className="text-xs text-gray-500 dark:text-gray-400 truncate">
                                    {e.description}
                                </span>
                            )}
                            {e.actor_type === 'machine_identity' && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300">
                                    machine
                                </span>
                            )}
                        </div>
                        <span
                            className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap"
                            title={formatDateTime(e.timestamp, { seconds: true })}
                        >
                            {relativeFromNow(e.timestamp)}
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
};

interface RiskScorePanelProps {
    risk: RiskData | undefined;
}

const RiskScorePanel: React.FC<RiskScorePanelProps> = ({ risk }) => {
    if (!risk) return null;
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                    <ShieldExclamationIcon className="h-5 w-5 mr-2" />
                    Risk Score
                </h3>
                <div className="flex items-center gap-3">
                    <span
                        className="text-2xl font-bold tabular-nums"
                        style={{ color: RISK_BAND_STYLE[risk.band].color }}
                    >
                        {risk.score}
                        <span className="text-sm font-normal text-gray-400"> / 100</span>
                    </span>
                    <span
                        className="px-2.5 py-1 rounded-full text-xs font-semibold"
                        style={{
                            color: RISK_BAND_STYLE[risk.band].color,
                            backgroundColor: `${RISK_BAND_STYLE[risk.band].color}1a`,
                        }}
                    >
                        {RISK_BAND_STYLE[risk.band].label}
                    </span>
                </div>
            </div>
            <div className="space-y-3">
                {risk.factors.map((f) => (
                    <div key={f.key} className="space-y-1">
                        <div className="flex items-center justify-between text-sm">
                            <span className="text-gray-700 dark:text-gray-300">
                                {f.label}
                                <span className="text-gray-400 dark:text-gray-500 ml-2">
                                    {Math.round(f.weight * 100)}%
                                </span>
                            </span>
                            <span className="text-xs text-gray-500 dark:text-gray-400">{f.detail}</span>
                        </div>
                        <div className="h-1.5 rounded-full overflow-hidden bg-gray-100 dark:bg-gray-700">
                            <div
                                className="h-full rounded-full transition-all duration-700"
                                style={{ width: `${f.score}%`, backgroundColor: factorColor(f.score) }}
                            />
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

interface StaticTagsPanelProps {
    tags: string[];
}

const StaticTagsPanel: React.FC<StaticTagsPanelProps> = ({ tags }) => {
    if (tags.length === 0) return null;
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4 flex items-center">
                <TagIcon className="h-5 w-5 mr-2" />
                Tags
            </h3>
            <div className="flex flex-wrap gap-2">
                {tags.map((tag) => (
                    <span
                        key={tag}
                        className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                    >
                        {tag}
                    </span>
                ))}
            </div>
        </div>
    );
};

interface MetadataPanelProps {
    metadata: Record<string, any>;
}

const MetadataPanel: React.FC<MetadataPanelProps> = ({ metadata }) => {
    if (Object.keys(metadata).length === 0) return null;
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Metadata</h3>
            <div className="space-y-3">
                {Object.entries(metadata).map(([key, value]) => (
                    <div key={key} className="flex items-start">
                        <div className="w-1/3 text-sm font-medium text-gray-500 dark:text-gray-400">{key}</div>
                        <div className="w-2/3 text-sm text-gray-900 dark:text-white">{value}</div>
                    </div>
                ))}
            </div>
        </div>
    );
};

interface SharingInfoPanelProps {
    secret: Secret;
    onShare?: ((secret: Secret) => void) | undefined;
    canShare: boolean;
}

const SharingInfoPanel: React.FC<SharingInfoPanelProps> = ({ secret, onShare, canShare }) => {
    if (!secret.isShared) return null;
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4 flex items-center">
                <ShareIcon className="h-5 w-5 mr-2" />
                Sharing
            </h3>
            <div className="flex items-center justify-between">
                <div>
                    <p className="text-sm text-gray-900 dark:text-white">
                        This secret is shared with <span className="font-medium">{secret.shareCount}</span> recipients
                    </p>
                    {canShare && (
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                            Click "Share" to manage sharing permissions
                        </p>
                    )}
                </div>
                {canShare && (
                    <Button variant="outline" size="sm" onClick={() => onShare?.(secret)}>
                        Manage Shares
                    </Button>
                )}
            </div>
        </div>
    );
};

interface PermissionsPanelProps {
    permissions: string[];
}

const PermissionsPanel: React.FC<PermissionsPanelProps> = ({ permissions }) => {
    if (permissions.length === 0) return null;
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Permissions</h3>
            <div className="flex flex-wrap gap-2">
                {permissions.map((permission) => (
                    <span
                        key={permission}
                        className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                    >
                        {permission}
                    </span>
                ))}
            </div>
        </div>
    );
};

interface RotateSecretModalProps {
    isOpen: boolean;
    secretName: string;
    rotateValue: string;
    setRotateValue: (v: string) => void;
    onClose: () => void;
    onRotate: () => void;
    mutation: ReturnType<typeof useRotateSecret>;
}

const RotateSecretModal: React.FC<RotateSecretModalProps> = ({
    isOpen,
    secretName,
    rotateValue,
    setRotateValue,
    onClose,
    onRotate,
    mutation,
}) => (
    <Modal isOpen={isOpen} onClose={onClose} title={`Rotate ${secretName}`} size="md">
        <div className="space-y-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">
                Enter the new value for this secret. Rotating stores a new version (the previous value is kept in
                history) and records the rotation timestamp.
            </p>

            <Textarea
                label="New value"
                value={rotateValue}
                onChange={(e) => setRotateValue(e.target.value)}
                placeholder="New secret value"
                rows={4}
                autoComplete="off"
                disabled={mutation.isPending}
            />

            {mutation.isError && (
                <Alert
                    type="error"
                    title="Rotation failed"
                    message={apiErrorMessage(mutation.error, 'The secret could not be rotated.')}
                />
            )}

            <div className="flex items-center justify-end space-x-3 pt-2">
                <Button variant="outline" onClick={onClose} disabled={mutation.isPending}>
                    Cancel
                </Button>
                <Button variant="default" onClick={onRotate} disabled={!rotateValue.trim() || mutation.isPending}>
                    {mutation.isPending ? (
                        <>
                            <Spinner size="sm" />
                            <span className="ml-2">Rotating…</span>
                        </>
                    ) : (
                        <>
                            <ArrowPathIcon className="h-4 w-4 mr-2" />
                            Rotate secret
                        </>
                    )}
                </Button>
            </div>
        </div>
    </Modal>
);

// ─── Main component ─────────────────────────────────────────────────────────

interface SecretDetailViewProps {
    secret: Secret;
    onEdit?: (secret: Secret) => void;
    onShare?: (secret: Secret) => void;
    onDelete?: (secret: Secret) => void;
    onClose?: () => void;
}

export const SecretDetailView: React.FC<SecretDetailViewProps> = ({ secret, onEdit, onShare, onDelete, onClose }) => {
    const can = useCan();
    const [showValue, setShowValue] = useState(false);
    const [copySuccess, setCopySuccess] = useState(false);
    const [showRotate, setShowRotate] = useState(false);
    const [rotateValue, setRotateValue] = useState('');

    // `secret` is the snapshot the list handed over when this view opened, so
    // it never learns about a rotation or rollback done in here. Remember the
    // moment locally so the header stops saying "Never rotated" (#2977).
    const [rotatedHereAt, setRotatedHereAt] = useState<string | null>(null);
    const headerSecret = rotatedHereAt ? { ...secret, lastRotatedAt: rotatedHereAt } : secret;

    const [classification, setClassification] = useState<string>(secret.classification ?? '');
    const [status, setStatus] = useState<string>(secret.status ?? 'active');
    const suspendMutation = useSuspendSecret(secret.id);
    const resumeMutation = useResumeSecret(secret.id);
    const copyMutation = useCopySecret(secret.id);
    const [copyMsg, setCopyMsg] = useState('');

    const handleCopy = () => {
        const envInput = window.prompt('Copy to which environment? Enter the target environment ID (same project):');
        const envId = Number(envInput);
        if (!envInput || !Number.isInteger(envId) || envId <= 0) return;
        const name = window.prompt('Name for the copy (leave blank to keep the same name):') || undefined;
        setCopyMsg('');
        copyMutation.mutate(
            { environmentId: envId, ...(name ? { name } : {}) },
            {
                onSuccess: () => setCopyMsg(`Copied to environment ${envId}.`),
                onError: (err: any) =>
                    setCopyMsg(err?.response?.data?.message ?? err?.response?.data?.error ?? 'Copy failed.'),
            }
        );
    };
    const suspended = status === 'suspended';
    const handleToggleSuspend = () => {
        if (suspended) {
            resumeMutation.mutate(undefined, { onSuccess: () => setStatus('active') });
        } else {
            if (!window.confirm('Suspend this secret? Value reads will be blocked until you resume it.')) return;
            suspendMutation.mutate(undefined, { onSuccess: () => setStatus('suspended') });
        }
    };

    const { data: versions } = useSecretVersions(secret.id, showValue);
    // #2450: the actual plaintext comes from a separate endpoint
    // (GET /secrets/{id}?include_value=true) -- GET .../versions never carries
    // a value field at all (see secretsApi.getValue's doc comment).
    const { data: secretValue = null, isLoading, error } = useSecretValue(secret.id, showValue);
    const queryClient = useQueryClient();
    // Revealed plaintext otherwise lingers in the React Query cache for the
    // default gcTime after the value is hidden or the view is closed —
    // evict it explicitly rather than relying on that timeout.
    useEffect(() => {
        if (!showValue) {
            queryClient.removeQueries({ queryKey: queryKeys.secrets.versions(secret.id) });
            queryClient.removeQueries({ queryKey: queryKeys.secrets.value(secret.id) });
        }
    }, [showValue, secret.id, queryClient]);
    useEffect(() => {
        return () => {
            queryClient.removeQueries({ queryKey: queryKeys.secrets.versions(secret.id) });
            queryClient.removeQueries({ queryKey: queryKeys.secrets.value(secret.id) });
        };
    }, [secret.id, queryClient]);
    // G28: revealed plaintext otherwise stays rendered in the DOM indefinitely —
    // until now, only an explicit "Hide" click or navigating away re-masked it.
    // Auto-clear on idle, tab backgrounding, or window blur too.
    useAutoClearOnIdle(() => setShowValue(false), showValue);
    const rotateMutation = useRotateSecret(secret.id);
    const rollbackMutation = useRollbackSecret(secret.id);
    const { data: accessors } = useSecretAccessors(secret.id);
    const { data: accessLog } = useSecretAccessLog(secret.id);
    const { data: auditTrail } = useSecretAuditTrail(secret.id);
    const { data: secretTags = [] } = useSecretTags(secret.id);
    const setTags = useSetSecretTags(secret.id);
    const [tagDraft, setTagDraft] = useState('');
    const { data: description = '' } = useSecretDescription(secret.id);
    const setDescription = useSetSecretDescription(secret.id);
    const [descDraft, setDescDraft] = useState<string | null>(null);
    const { data: risk } = useSecretRisk(secret.id);
    const classifyMutation = useClassifySecret(secret.id);

    const handleRollback = (version: number) => {
        if (!window.confirm(`Roll back to version ${version}? Its value will be re-instated as a new version.`)) return;
        rollbackMutation.mutate(version, {
            onSuccess: () => {
                setShowValue(false);
                setRotatedHereAt(new Date().toISOString());
            },
        });
    };

    // Optimistically reflect the new level; revert if the server rejects it.
    const handleClassify = (level: string) => {
        const previous = classification;
        if (level === previous) return;
        setClassification(level);
        classifyMutation.mutate(level, {
            onError: () => setClassification(previous),
        });
    };

    const closeRotate = () => {
        setShowRotate(false);
        setRotateValue('');
        rotateMutation.reset();
    };

    const handleRotate = () => {
        if (!rotateValue.trim()) return;
        rotateMutation.mutate(rotateValue, {
            onSuccess: () => {
                setShowValue(false); // force a re-reveal so the new version is fetched
                setRotatedHereAt(new Date().toISOString());
                closeRotate();
            },
        });
    };

    const latestVersion = computeLatestVersion(versions);

    const handleCopyValue = async (value: string): Promise<void> => {
        try {
            await copyToClipboard(value);
            setCopySuccess(true);
            setTimeout(() => setCopySuccess(false), 2000);
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
        }
    };

    const handleToggleValue = () => {
        setShowValue(!showValue);
    };

    const secretValueDisplay = buildSecretValueDisplay(showValue, isLoading, secretValue, secret.type);

    const handleTagKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key !== 'Enter') return;
        const t = tagDraft.trim().toLowerCase();
        if (!t || secretTags.includes(t)) {
            setTagDraft('');
            return;
        }
        setTags.mutate([...secretTags, t], { onSuccess: () => setTagDraft('') });
    };

    return (
        <div className="space-y-6">
            <SecretDetailHeader
                secret={headerSecret}
                classification={classification}
                suspended={suspended}
                classifyPending={classifyMutation.isPending}
                onClassify={handleClassify}
                onEdit={onEdit}
                onShare={onShare}
                onRotateClick={() => setShowRotate(true)}
                onCopy={handleCopy}
                copyPending={copyMutation.isPending}
                onToggleSuspend={handleToggleSuspend}
                suspendTogglePending={suspendMutation.isPending || resumeMutation.isPending}
                onDelete={onDelete}
                can={can}
            />

            {copyMsg && (
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    {copyMsg}
                </p>
            )}

            <SecretValuePanel
                showValue={showValue}
                isLoading={isLoading}
                error={error}
                secretValueDisplay={secretValueDisplay}
                copySuccess={copySuccess}
                secretValue={secretValue}
                onToggleValue={handleToggleValue}
                onCopyValue={handleCopyValue}
            />

            {/* Certificate metadata (ADR-054) — for certificate-typed secrets */}
            {secret.type === 'certificate' && <CertificatePanel secretId={secret.id} />}

            <VersionHistoryPanel
                versions={versions}
                latestVersion={latestVersion}
                rollbackMutation={rollbackMutation}
                onRollback={handleRollback}
                canRollback={can.writeSecrets}
            />

            <AccessorsPanel accessors={accessors} />

            <RecentAccessPanel accessLog={accessLog} />

            <DescriptionPanel
                description={description}
                descDraft={descDraft}
                setDescDraft={setDescDraft}
                mutation={setDescription}
                readOnly={!can.writeSecrets}
            />

            <TagsEditPanel
                secretTags={secretTags}
                tagDraft={tagDraft}
                setTagDraft={setTagDraft}
                onTagKeyDown={handleTagKeyDown}
                mutation={setTags}
                readOnly={!can.writeSecrets}
            />

            <AuditTrailPanel auditTrail={auditTrail} />

            <RiskScorePanel risk={risk} />

            {/* Dependency graph (ADR-052) */}
            <SecretDependenciesSection secret={secret} />

            <StaticTagsPanel tags={secret.tags} />

            <MetadataPanel metadata={secret.metadata} />

            <SharingInfoPanel secret={secret} onShare={onShare} canShare={can.writeSecrets} />

            <PermissionsPanel permissions={secret.permissions} />

            <div className="flex items-center justify-end space-x-3 pt-6 border-t border-gray-200 dark:border-gray-700">
                <Button variant="outline" onClick={onClose}>
                    Close
                </Button>
            </div>

            <RotateSecretModal
                isOpen={showRotate}
                secretName={secret.name}
                rotateValue={rotateValue}
                setRotateValue={setRotateValue}
                onClose={closeRotate}
                onRotate={handleRotate}
                mutation={rotateMutation}
            />
        </div>
    );
};
