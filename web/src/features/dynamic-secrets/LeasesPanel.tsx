import { formatDateTime } from '../../utils/datetime';
import React, { useState } from 'react';
import { KeyIcon, NoSymbolIcon } from '@heroicons/react/24/outline';
import { Button } from '../../components/ui/Button';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { IssuedCredential } from '../../services/dynamicSecrets';
import { useDynamicLeases, useIssueLease, useRevokeLease, useRevokeAllLeases } from './api';
import { useAutoClearOnIdle } from '../../hooks/useAutoClearOnIdle';
import { copyToClipboard } from '../../utils';

const leaseStatusStyle = (status: string): React.CSSProperties => {
    switch (status) {
        case 'active':
            return { backgroundColor: 'var(--success-subtle, #dcfce7)', color: 'var(--success, #15803d)' };
        case 'expired':
            return { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' };
        case 'revoke_failed':
            return { backgroundColor: 'var(--error-subtle)', color: 'var(--error)' };
        case 'revoked':
        default:
            return { backgroundColor: 'var(--warning-subtle, #fef9c3)', color: 'var(--warning, #a16207)' };
    }
};

// fieldLabel humanizes a cloud-credential field key, e.g. access_key_id → "Access key id".
const fieldLabel = (key: string): string => {
    const s = key.replaceAll('_', ' ');
    return s.charAt(0).toUpperCase() + s.slice(1);
};

const CopyRow: React.FC<{ label: string; value: string }> = ({ label, value }) => {
    const [copied, setCopied] = useState(false);
    const copy = async () => {
        await copyToClipboard(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };
    return (
        <div className="flex items-stretch gap-2">
            <div className="flex-1 min-w-0">
                <p className="text-xs mb-0.5" style={{ color: 'var(--text-muted)' }}>
                    {label}
                </p>
                <code
                    className="block px-3 py-2 text-xs font-mono break-all rounded-lg border"
                    style={{
                        borderColor: 'var(--border)',
                        backgroundColor: 'var(--bg-app)',
                        color: 'var(--text-primary)',
                    }}
                >
                    {value}
                </code>
            </div>
            <Button variant="outline" onClick={copy} className="shrink-0 self-end">
                {copied ? 'Copied' : 'Copy'}
            </Button>
        </div>
    );
};

/**
 * Lease management for one dynamic-secret config (ADR-035): issue a short-lived
 * credential (shown ONCE), list issued leases, revoke one, or revoke them all (the
 * incident kill switch). Issue/revoke require secrets.write at the config's scope
 * (the server enforces it); the panel still renders the lease list read-only.
 */
export const LeasesPanel: React.FC<{ configId: number; canManage: boolean }> = ({ configId, canManage }) => {
    const { data: leases = [], isLoading } = useDynamicLeases(configId);
    const issue = useIssueLease(configId);
    const revoke = useRevokeLease(configId);
    const revokeAll = useRevokeAllLeases(configId);

    const [credential, setCredential] = useState<IssuedCredential | null>(null);
    const [error, setError] = useState('');
    // Surfaces the outcome of a "Revoke all" call — distinct from `error`, which
    // is for the mutation itself failing outright (network/authz). A revoke-all
    // call can succeed at the HTTP layer while some individual leases still fail
    // to revoke upstream (see revokeAll's {revoked, failed} response below); that
    // partial failure must not look identical to a full success.
    const [revokeAllNotice, setRevokeAllNotice] = useState<{ type: 'success' | 'warning'; message: string } | null>(
        null
    );

    // G28: the credential (often a plaintext password) otherwise stays rendered
    // in the modal indefinitely until the user explicitly clicks Done/Close —
    // auto-clear it on idle, tab backgrounding, or window blur too.
    useAutoClearOnIdle(() => setCredential(null), credential !== null);

    const surface = (err: any, fallback: string) =>
        setError(err?.response?.data?.message ?? err?.response?.data?.error ?? fallback);

    const handleIssue = () => {
        setError('');
        setRevokeAllNotice(null);
        issue.mutate(undefined, {
            onSuccess: (cred) => setCredential(cred),
            onError: (err) => surface(err, 'Failed to issue credential.'),
        });
    };

    const activeCount = leases.filter((l) => l.status === 'active').length;

    const leasesContent =
        leases.length === 0 ? (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                No leases issued yet.
            </p>
        ) : (
            <ul className="space-y-1">
                {leases.map((l) => (
                    <li key={l.leaseId} className="flex items-center gap-2 text-xs">
                        <span
                            className="px-2 py-0.5 rounded-full font-medium capitalize shrink-0"
                            style={leaseStatusStyle(l.status)}
                        >
                            {l.status.replaceAll('_', ' ')}
                        </span>
                        <span className="font-mono truncate" style={{ color: 'var(--text-primary)' }}>
                            {l.roleName || l.leaseId}
                        </span>
                        {l.expiresAt && (
                            <span style={{ color: 'var(--text-muted)' }}>· expires {formatDateTime(l.expiresAt)}</span>
                        )}
                        {/* A failed revoke means the credential is STILL LIVE upstream (see
                            CountActiveLeases/ListExpiredActiveLeases treating revoke_failed as
                            active) — surface why it failed so the operator isn't left guessing. */}
                        {l.status === 'revoke_failed' && l.revokeError && (
                            <span className="truncate" style={{ color: 'var(--error)' }} title={l.revokeError}>
                                {l.revokeError}
                            </span>
                        )}
                        {canManage && (l.status === 'active' || l.status === 'revoke_failed') && (
                            <button
                                type="button"
                                onClick={() => {
                                    const confirmMessage =
                                        l.status === 'revoke_failed'
                                            ? 'Retry revoking this lease? The credential is still live upstream until this succeeds.'
                                            : 'Revoke this lease? The credential will stop working immediately.';
                                    if (!window.confirm(confirmMessage)) return;
                                    setError('');
                                    setRevokeAllNotice(null);
                                    revoke.mutate(l.leaseId, {
                                        onError: (err) => surface(err, 'Failed to revoke lease.'),
                                    });
                                }}
                                disabled={revoke.isPending}
                                className="ml-auto p-1 rounded-sm disabled:opacity-50 shrink-0"
                                style={{ color: 'var(--error)' }}
                                title={l.status === 'revoke_failed' ? 'Retry revoke' : 'Revoke lease'}
                            >
                                <NoSymbolIcon className="h-4 w-4" />
                            </button>
                        )}
                    </li>
                ))}
            </ul>
        );

    return (
        <div className="px-4 py-3" style={{ backgroundColor: 'var(--bg-app)' }}>
            {error && <Alert type="error" message={error} className="mb-2" />}
            {revokeAllNotice && (
                <Alert
                    type={revokeAllNotice.type}
                    message={revokeAllNotice.message}
                    dismissible
                    onDismiss={() => setRevokeAllNotice(null)}
                    className="mb-2"
                />
            )}

            {canManage && (
                <div className="flex items-center gap-2 mb-3">
                    <Button size="sm" onClick={handleIssue} disabled={issue.isPending}>
                        <KeyIcon className="size-4" />
                        Issue credential
                    </Button>
                    {activeCount > 0 && (
                        <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => {
                                if (
                                    !window.confirm(
                                        `Revoke all ${activeCount} active lease(s)? Every issued credential will stop working immediately.`
                                    )
                                )
                                    return;
                                setError('');
                                setRevokeAllNotice(null);
                                revokeAll.mutate(undefined, {
                                    onSuccess: ({ revoked, failed }) => {
                                        if (failed > 0) {
                                            setRevokeAllNotice({
                                                type: 'warning',
                                                message: `Revoked ${revoked} of ${revoked + failed} lease(s) — ${failed} failed. Check the lease list below and retry the failed one(s).`,
                                            });
                                        } else {
                                            setRevokeAllNotice({
                                                type: 'success',
                                                message: `Revoked ${revoked} lease(s).`,
                                            });
                                        }
                                    },
                                    onError: (err) => surface(err, 'Failed to revoke leases.'),
                                });
                            }}
                            disabled={revokeAll.isPending}
                        >
                            Revoke all ({activeCount})
                        </Button>
                    )}
                </div>
            )}

            {isLoading ? (
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    Loading leases…
                </p>
            ) : (
                leasesContent
            )}

            {/* The issued credential is shown ONCE — it is never retrievable again. */}
            <Modal isOpen={!!credential} onClose={() => setCredential(null)} title="Credential issued" size="md">
                <div className="space-y-3">
                    <Alert
                        type="warning"
                        message="Copy these now — the password is shown once and cannot be retrieved again. The credential auto-revokes at expiry."
                    />
                    {credential && (
                        <>
                            {/* Database backends → username/password; cloud-IAM backends → fields. */}
                            {credential.username && <CopyRow label="Username" value={credential.username} />}
                            {credential.password && <CopyRow label="Password" value={credential.password} />}
                            {credential.fields &&
                                Object.keys(credential.fields)
                                    .filter((k) => k !== 'expiration')
                                    .sort((a, b) => a.localeCompare(b))
                                    .map((k) => (
                                        <CopyRow key={k} label={fieldLabel(k)} value={credential.fields![k] ?? ''} />
                                    ))}
                            {credential.expiresAt && (
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                    Expires {formatDateTime(credential.expiresAt)}
                                </p>
                            )}
                        </>
                    )}
                    <div className="flex justify-end">
                        <Button variant="secondary" onClick={() => setCredential(null)}>
                            Done
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
