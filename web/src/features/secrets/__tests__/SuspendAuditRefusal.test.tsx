import { describe, it, expect, vi } from 'vitest';
import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from 'axios';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { SuspendSecretModal } from '../SuspendSecretModal';
import { FreezeProjectModal } from '../../projects/FreezeProjectModal';
import { apiErrorCode } from '../../../services/client';

// SUSPEND-HINT-1: a clear-synced-copies suspend refused because the audit log cannot record
// it answers 500 with the stable code SuspendAuditUnavailable. The dialog must say what to
// do now and put the plain suspend one click away.

const REFUSAL_MESSAGE =
    'The audit log could not record this suspension, so clearing synced copies was refused. Retry, or suspend without clearing synced copies to cut access immediately; clearing needs the audit log back.';

const apiError = (status: number, body: Record<string, unknown>) =>
    new AxiosError('Request failed', 'ERR_BAD_RESPONSE', undefined, undefined, {
        status,
        statusText: '',
        data: body,
        headers: {},
        config: { headers: new AxiosHeaders() } as InternalAxiosRequestConfig,
    });

const auditRefusal = () =>
    apiError(500, { success: false, code: 500, error: 'SuspendAuditUnavailable', message: REFUSAL_MESSAGE });

describe('apiErrorCode', () => {
    it('reads the stable code from the error envelope', () => {
        expect(apiErrorCode(auditRefusal())).toBe('SuspendAuditUnavailable');
    });
    it('is undefined for failures without one', () => {
        expect(apiErrorCode(new Error('boom'))).toBeUndefined();
        expect(apiErrorCode(apiError(500, { message: 'x' }))).toBeUndefined();
        expect(apiErrorCode(undefined)).toBeUndefined();
    });
});

describe('SuspendSecretModal audit refusal', () => {
    const base = { isOpen: true, secretName: 'db-password', pending: false, onClose: vi.fn() };

    it('shows the server hint and a plain-suspend action that re-submits without clearing', () => {
        const onConfirm = vi.fn();
        render(<SuspendSecretModal {...base} error={auditRefusal()} onConfirm={onConfirm} />);

        expect(screen.getByText(REFUSAL_MESSAGE)).toBeInTheDocument();
        expect(screen.queryByText('Suspend failed')).not.toBeInTheDocument();

        fireEvent.click(screen.getByTestId('suspend-without-clearing'));
        expect(onConfirm).toHaveBeenCalledTimes(1);
        expect(onConfirm).toHaveBeenCalledWith(false);
    });

    it('unchecks the clear-copies choice when the plain suspend is chosen', () => {
        render(<SuspendSecretModal {...base} error={auditRefusal()} onConfirm={vi.fn()} />);
        const box = screen.getByTestId('suspend-clear-synced-copies') as HTMLInputElement;
        fireEvent.click(box);
        expect(box.checked).toBe(true);
        fireEvent.click(screen.getByTestId('suspend-without-clearing'));
        expect(box.checked).toBe(false);
    });

    it('disables the plain-suspend action while a request is pending', () => {
        render(<SuspendSecretModal {...base} pending error={auditRefusal()} onConfirm={vi.fn()} />);
        expect(screen.getByTestId('suspend-without-clearing')).toBeDisabled();
    });

    it('keeps the generic failure for any other error and offers no plain-suspend shortcut', () => {
        render(
            <SuspendSecretModal
                {...base}
                error={apiError(500, { error: 'InternalError', message: 'Failed to suspend secret' })}
                onConfirm={vi.fn()}
            />
        );
        expect(screen.getByText('Suspend failed')).toBeInTheDocument();
        expect(screen.getByText('Failed to suspend secret')).toBeInTheDocument();
        expect(screen.queryByTestId('suspend-without-clearing')).not.toBeInTheDocument();
    });

    it('shows no refusal when there is no error', () => {
        render(<SuspendSecretModal {...base} onConfirm={vi.fn()} />);
        expect(screen.queryByTestId('suspend-audit-refusal')).not.toBeInTheDocument();
    });
});

describe('FreezeProjectModal audit refusal', () => {
    it('offers the plain freeze one click away', () => {
        const onConfirm = vi.fn();
        render(
            <FreezeProjectModal isOpen pending={false} onClose={vi.fn()} error={auditRefusal()} onConfirm={onConfirm} />
        );
        expect(screen.getByText(REFUSAL_MESSAGE)).toBeInTheDocument();
        expect(screen.queryByText('Freeze failed')).not.toBeInTheDocument();
        fireEvent.click(screen.getByTestId('suspend-without-clearing'));
        expect(onConfirm).toHaveBeenCalledWith(false);
    });
});
