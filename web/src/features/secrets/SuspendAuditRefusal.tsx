import React from 'react';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';
import { SUSPEND_AUDIT_UNAVAILABLE, apiErrorCode, apiErrorMessage } from '../../services/client';

interface SuspendAuditRefusalProps {
    error?: unknown;
    pending: boolean;
    // Names the action, e.g. "Suspend without clearing synced copies".
    actionLabel: string;
    // Re-submits the same request without clearing the synced copies.
    onPlainSuspend: () => void;
}

// isSuspendAuditRefusal reports whether a failed suspend/freeze was refused because the
// audit log could not record a clear-synced-copies request (SuspendAuditUnavailable).
export const isSuspendAuditRefusal = (error: unknown): boolean => apiErrorCode(error) === SUSPEND_AUDIT_UNAVAILABLE;

// SuspendAuditRefusal is what the suspend and freeze dialogs show instead of a generic
// failure when the server refuses a clear-synced-copies request for want of the audit log.
// Nothing was changed, so the person can still cut access right now: one click re-submits
// the request as a plain suspend. Clearing the copies needs the audit log back.
export const SuspendAuditRefusal: React.FC<SuspendAuditRefusalProps> = ({
    error,
    pending,
    actionLabel,
    onPlainSuspend,
}) => {
    if (!isSuspendAuditRefusal(error)) return null;
    return (
        <div className="space-y-3" data-testid="suspend-audit-refusal">
            <Alert
                type="warning"
                title="Clearing synced copies needs the audit log"
                message={apiErrorMessage(error, 'The audit log could not record this suspension.')}
            />
            <Button
                variant="outline"
                onClick={onPlainSuspend}
                disabled={pending}
                data-testid="suspend-without-clearing"
            >
                {actionLabel}
            </Button>
        </div>
    );
};
