import React, { useEffect, useState } from 'react';
import { Button } from '../../components/ui/Button';
import { Spinner } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { apiErrorMessage } from '../../services/client';
import { SuspendAuditRefusal, isSuspendAuditRefusal } from './SuspendAuditRefusal';

interface SuspendSecretModalProps {
    isOpen: boolean;
    secretName: string;
    pending: boolean;
    error?: unknown;
    onClose: () => void;
    // clearSyncedCopies is the person's choice for THIS suspension only.
    onConfirm: (clearSyncedCopies: boolean) => void;
}

// SuspendSecretModal confirms a suspension and offers the one extra choice a compromise
// response needs: also clear the copies synced to Kubernetes clusters (the operator and
// k8s-sync empty them on their next sync, whatever each resource's own onSuspend says).
// The choice starts unchecked on every open and is never remembered; resuming removes it
// and the next sync restores the copies. Keyorix does not know which clusters hold copies,
// so the dialog offers the option without listing them.
export const SuspendSecretModal: React.FC<SuspendSecretModalProps> = ({
    isOpen,
    secretName,
    pending,
    error,
    onClose,
    onConfirm,
}) => {
    const [clearCopies, setClearCopies] = useState(false);

    // A fresh decision every time the dialog opens.
    useEffect(() => {
        if (isOpen) setClearCopies(false);
    }, [isOpen]);

    return (
        <Modal isOpen={isOpen} onClose={onClose} title={`Suspend ${secretName}`} size="md">
            <div className="space-y-4">
                <p className="text-sm text-gray-500 dark:text-gray-400">
                    Value reads will be blocked until you resume the secret. Its versions, shares and audit trail are
                    kept.
                </p>

                <div className="flex items-start">
                    <input
                        id="suspend-clear-synced-copies"
                        type="checkbox"
                        className="mt-1 h-4 w-4 rounded-sm"
                        checked={clearCopies}
                        onChange={(e) => setClearCopies(e.target.checked)}
                        disabled={pending}
                        data-testid="suspend-clear-synced-copies"
                    />
                    <label htmlFor="suspend-clear-synced-copies" className="ml-2 text-sm text-base-secondary">
                        Also clear copies synced to Kubernetes clusters
                        <span className="block text-xs text-gray-500 dark:text-gray-400">
                            The operator and keyorix-k8s-sync empty the keys they manage in the Kubernetes Secrets on
                            their next sync, for this suspension only. They never delete a Secret or touch one they do
                            not own. Resuming restores the copies.
                        </span>
                    </label>
                </div>

                <Alert
                    type={clearCopies ? 'warning' : 'info'}
                    title="Rotate the secret if it may be compromised"
                    message="Suspending blocks reads from Keyorix, but a copy already in a cluster, a log or a build is still valid until the secret is rotated at its source."
                />

                <SuspendAuditRefusal
                    error={error}
                    pending={pending}
                    actionLabel="Suspend without clearing synced copies"
                    onPlainSuspend={() => {
                        setClearCopies(false);
                        onConfirm(false);
                    }}
                />
                {error && !isSuspendAuditRefusal(error) ? (
                    <Alert
                        type="error"
                        title="Suspend failed"
                        message={apiErrorMessage(error, 'The secret could not be suspended.')}
                    />
                ) : null}

                <div className="flex items-center justify-end space-x-3 pt-2">
                    <Button variant="outline" onClick={onClose} disabled={pending}>
                        Cancel
                    </Button>
                    <Button variant="default" onClick={() => onConfirm(clearCopies)} disabled={pending}>
                        {pending ? (
                            <>
                                <Spinner size="sm" />
                                <span className="ml-2">Suspending…</span>
                            </>
                        ) : (
                            'Suspend secret'
                        )}
                    </Button>
                </div>
            </div>
        </Modal>
    );
};
