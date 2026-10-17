import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { render, screen } from '@testing-library/react';
import { AxiosError } from 'axios';
import { SuspendSecretModal } from '../SuspendSecretModal';

// A clear-synced-copies suspend refused because its audit event cannot be recorded
// answers 500 with the next step in `message` (server/http/handlers/secrets_suspend.go).
// The dialog must show the server's text, so the responder learns that a plain suspend
// still cuts access now.
describe('SuspendSecretModal refusal', () => {
    it('shows the server message, including how to cut access now', () => {
        const message =
            'The audit event for this request could not be recorded; the secret was not suspended. Retry, or suspend without clearing to cut access now';
        const refusal = new AxiosError('Request failed with status code 500');
        refusal.response = { status: 500, data: { error: 'InternalError', message } } as AxiosError['response'];

        render(
            <SuspendSecretModal
                isOpen
                secretName="db-password"
                pending={false}
                error={refusal}
                onClose={vi.fn()}
                onConfirm={vi.fn()}
            />
        );

        expect(screen.getByText(message)).toBeInTheDocument();
    });
});
