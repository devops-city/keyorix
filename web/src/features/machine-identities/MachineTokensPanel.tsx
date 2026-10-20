import React, { useState } from 'react';
import { KeyIcon, NoSymbolIcon } from '@heroicons/react/24/outline';
import { Button } from '../../components/ui/Button';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { useConfirm } from '../../components/ui/useConfirm';
import { IssuedMachineToken } from '../../services/machineIdentities';
import { classificationMeta, CLASSIFICATION_LEVELS } from '../secrets/classification';
import { useMachineTokens, useIssueMachineToken, useRevokeMachineToken, useClassifyMachineToken } from './api';
import { useAutoClearOnIdle } from '../../hooks/useAutoClearOnIdle';
import { copyToClipboard } from '../../utils';

/**
 * Machine-token credentials for one machine identity (ADR-030): issue an opaque
 * bearer token (shown ONCE), list issued tokens with their data-classification,
 * reclassify, and revoke. Issue/revoke/classify need roles.assign at the project
 * scope (server-enforced); the list renders read-only for ordinary members.
 */
export const MachineTokensPanel: React.FC<{
    projectId: number;
    machineId: number;
    canManage: boolean;
}> = ({ projectId, machineId, canManage }) => {
    const { data: tokens = [], isLoading } = useMachineTokens(projectId, machineId);
    const issue = useIssueMachineToken(projectId, machineId);
    const revoke = useRevokeMachineToken(projectId, machineId);
    const { requestConfirm, confirmDialog } = useConfirm();
    const classify = useClassifyMachineToken(projectId, machineId);

    const [issued, setIssued] = useState<IssuedMachineToken | null>(null);
    const [error, setError] = useState('');
    const [name, setName] = useState('');
    const [copied, setCopied] = useState(false);

    // G28: the token otherwise stays rendered in the modal indefinitely until the
    // user explicitly clicks Done/Close — auto-clear it on idle, tab
    // backgrounding, or window blur too.
    useAutoClearOnIdle(() => setIssued(null), issued !== null);

    const surface = (err: any, fallback: string) =>
        setError(err?.response?.data?.message ?? err?.response?.data?.error ?? fallback);

    const handleIssue = () => {
        if (!name.trim()) return;
        setError('');
        issue.mutate(
            { name: name.trim() },
            {
                onSuccess: (t) => {
                    setIssued(t);
                    setName('');
                },
                onError: (err) => surface(err, 'Failed to issue token.'),
            }
        );
    };

    const copy = async () => {
        if (!issued) return;
        await copyToClipboard(issued.token);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const selectStyle: React.CSSProperties = {
        backgroundColor: 'var(--bg-app)',
        border: '1px solid var(--border)',
        color: 'var(--text-primary)',
    };

    const tokenList =
        tokens.length === 0 ? (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                No tokens issued yet.
            </p>
        ) : (
            <ul className="space-y-1">
                {tokens.map((t) => (
                    <li key={t.id} className="flex items-center gap-2 text-xs">
                        <span className="font-mono shrink-0" style={{ color: 'var(--text-muted)' }}>
                            {t.prefix}…
                        </span>
                        <span className="truncate" style={{ color: 'var(--text-primary)' }}>
                            {t.name || '(unnamed)'}
                        </span>
                        {t.revoked && (
                            <span
                                className="px-2 py-0.5 rounded-full font-medium shrink-0"
                                style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }}
                            >
                                revoked
                            </span>
                        )}
                        <span className="ml-auto flex items-center gap-2 shrink-0">
                            {canManage ? (
                                <select
                                    aria-label={`Classification for token ${t.prefix}`}
                                    value={t.classification ?? ''}
                                    disabled={classify.isPending}
                                    onChange={(e) => {
                                        if (e.target.value === (t.classification ?? '')) return;
                                        setError('');
                                        classify.mutate(
                                            { tokenId: t.id, classification: e.target.value },
                                            { onError: (err) => surface(err, 'Failed to update classification.') }
                                        );
                                    }}
                                    className="rounded-lg px-2 py-0.5 text-xs outline-hidden disabled:opacity-50"
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
                                    data-testid="mt-classification-badge"
                                    className={`px-2 py-0.5 rounded-full font-medium ${classificationMeta(t.classification ?? '').color}`}
                                    title="Data classification (ISO 27001 A.5.12)"
                                >
                                    {classificationMeta(t.classification ?? '').label}
                                </span>
                            )}
                            {canManage && !t.revoked && (
                                <button
                                    type="button"
                                    onClick={async () => {
                                        const ok = await requestConfirm({
                                            title: 'Revoke token',
                                            message: `Revoke token "${t.name || t.prefix}"? Any client using it will lose access immediately.`,
                                            confirmText: 'Revoke',
                                        });
                                        if (!ok) return;
                                        setError('');
                                        revoke.mutate(t.id, {
                                            onError: (err) => surface(err, 'Failed to revoke token.'),
                                        });
                                    }}
                                    disabled={revoke.isPending}
                                    className="p-1 rounded-sm disabled:opacity-50"
                                    style={{ color: 'var(--error)' }}
                                    title="Revoke token"
                                >
                                    <NoSymbolIcon className="h-4 w-4" />
                                </button>
                            )}
                        </span>
                    </li>
                ))}
            </ul>
        );

    return (
        <div className="px-4 py-3" style={{ backgroundColor: 'var(--bg-app)' }}>
            {error && <Alert type="error" message={error} className="mb-2" />}

            {canManage && (
                <div className="flex items-center gap-2 mb-3">
                    <input
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleIssue()}
                        placeholder="Token name…"
                        className="flex-1 min-w-[10rem] rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={selectStyle}
                    />
                    <Button size="sm" onClick={handleIssue} disabled={!name.trim() || issue.isPending}>
                        <KeyIcon className="size-4" />
                        Issue token
                    </Button>
                </div>
            )}

            {isLoading ? (
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    Loading tokens…
                </p>
            ) : (
                tokenList
            )}

            {/* The raw token is shown ONCE — never retrievable again. */}
            <Modal isOpen={!!issued} onClose={() => setIssued(null)} title="Machine token issued" size="md">
                <div className="space-y-3">
                    <Alert
                        type="warning"
                        message="Copy this now — the token is shown once and cannot be retrieved again."
                    />
                    {issued && (
                        <div className="flex items-stretch gap-2">
                            <code
                                className="flex-1 min-w-0 px-3 py-2 text-xs font-mono break-all rounded-lg border"
                                style={{
                                    borderColor: 'var(--border)',
                                    backgroundColor: 'var(--bg-app)',
                                    color: 'var(--text-primary)',
                                }}
                            >
                                {issued.token}
                            </code>
                            <Button variant="outline" onClick={copy} className="shrink-0">
                                {copied ? 'Copied' : 'Copy'}
                            </Button>
                        </div>
                    )}
                    <div className="flex justify-end">
                        <Button variant="secondary" onClick={() => setIssued(null)}>
                            Done
                        </Button>
                    </div>
                </div>
            </Modal>
            {confirmDialog}
        </div>
    );
};
