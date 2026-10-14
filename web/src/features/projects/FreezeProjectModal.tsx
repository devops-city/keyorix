import React, { useEffect, useState } from 'react';
import { Button } from '../../components/ui/Button';
import { Spinner } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { apiErrorMessage } from '../../services/client';

interface FreezeProjectModalProps {
    isOpen: boolean;
    pending: boolean;
    error?: unknown;
    onClose: () => void;
    // clearSyncedCopies is the person's choice for THIS freeze only.
    onConfirm: (clearSyncedCopies: boolean) => void;
}

// FreezeProjectModal confirms a project-wide freeze and offers the one extra choice a
// compromise response needs: also clear the copies of every affected secret synced to
// Kubernetes clusters (the operator and k8s-sync empty them on their next sync, whatever
// each resource's own onSuspend says). Same choice, same wording and same permission as
// the single-secret SuspendSecretModal. It starts unchecked on every open and is never
// remembered; resuming removes it and the next sync restores the copies.
export const FreezeProjectModal: React.FC<FreezeProjectModalProps> = ({
    isOpen,
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
        <Modal isOpen={isOpen} onClose={onClose} title="Freeze all secrets in this project" size="md">
            <div className="space-y-4">
                <p className="text-sm text-gray-500 dark:text-gray-400">
                    Value reads of every secret in this project that you can manage will be blocked until you resume
                    them. Versions, shares and audit trail are kept.
                </p>

                <div className="flex items-start">
                    <input
                        id="freeze-clear-synced-copies"
                        type="checkbox"
                        className="mt-1 h-4 w-4 rounded-sm"
                        checked={clearCopies}
                        onChange={(e) => setClearCopies(e.target.checked)}
                        disabled={pending}
                        data-testid="freeze-clear-synced-copies"
                    />
                    <label htmlFor="freeze-clear-synced-copies" className="ml-2 text-sm text-base-secondary">
                        Also clear copies synced to Kubernetes clusters
                        <span className="block text-xs text-gray-500 dark:text-gray-400">
                            For every secret frozen now, the operator and keyorix-k8s-sync empty the keys they manage in
                            the Kubernetes Secrets on their next sync, for this freeze only. They never delete a Secret
                            or touch one they do not own. Resuming restores the copies.
                        </span>
                    </label>
                </div>

                <Alert
                    type={clearCopies ? 'warning' : 'info'}
                    title="Rotate the secrets if they may be compromised"
                    message="Freezing blocks reads from Keyorix, but a copy already in a cluster, a log or a build is still valid until each secret is rotated at its source."
                />

                {error ? (
                    <Alert
                        type="error"
                        title="Freeze failed"
                        message={apiErrorMessage(error, 'The project could not be frozen.')}
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
                                <span className="ml-2">Freezing…</span>
                            </>
                        ) : (
                            'Freeze all secrets'
                        )}
                    </Button>
                </div>
            </div>
        </Modal>
    );
};
