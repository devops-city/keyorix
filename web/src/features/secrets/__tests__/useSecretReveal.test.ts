import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { AxiosError, AxiosHeaders } from 'axios';
import { useSecretReveal } from '../useSecretReveal';
import { Secret } from '../../../types';

const { getValueMock, copyToClipboardMock } = vi.hoisted(() => ({
    getValueMock: vi.fn(),
    copyToClipboardMock: vi.fn(),
}));

vi.mock('../../../services/secrets', () => ({
    secretsApi: {
        getValue: getValueMock,
    },
}));

// Partial: the real apiErrorMessage (services/client) needs the real getEnvConfig.
vi.mock('../../../utils', async (importOriginal) => ({
    ...(await importOriginal<typeof import('../../../utils')>()),
    copyToClipboard: copyToClipboardMock,
}));

const makeSecret = (overrides: Partial<Secret> = {}): Secret => ({
    id: 1,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-06-14T00:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
    ...overrides,
});

describe('useSecretReveal', () => {
    beforeEach(() => {
        // resetAllMocks (not clearAllMocks) so a mockResolvedValue/mockRejectedValue set in
        // one test can't leak its implementation into the next.
        vi.resetAllMocks();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    // #2450: this hook used to call secretsApi.getVersions and atob()-decode
    // EncryptedValue off the first entry -- a field the real API never
    // returns (it's version metadata only). Fixed to call secretsApi.getValue
    // (GET /secrets/{id}?include_value=true), the endpoint that actually
    // returns a plaintext value.
    it('copies the plaintext value and clears copiedSecretId after 2s', async () => {
        vi.useFakeTimers();
        const secret = makeSecret({ id: 42 });
        getValueMock.mockResolvedValue('super-secret-value');
        copyToClipboardMock.mockResolvedValue(undefined);

        const { result } = renderHook(() => useSecretReveal());

        await act(async () => {
            await result.current.handleCopySecretValue(secret);
        });

        expect(getValueMock).toHaveBeenCalledWith(42);
        expect(copyToClipboardMock).toHaveBeenCalledWith('super-secret-value');
        expect(result.current.copyingSecretId).toBeNull();
        expect(result.current.copiedSecretId).toBe(42);
        expect(result.current.copyErrorId).toBeNull();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });

        expect(result.current.copiedSecretId).toBeNull();
    });

    it('sets copyErrorId (not copiedSecretId) when getValue rejects, and clears after 6s', async () => {
        vi.useFakeTimers();
        const secret = makeSecret({ id: 7 });
        getValueMock.mockRejectedValue(new Error('Forbidden'));

        const { result } = renderHook(() => useSecretReveal());

        await act(async () => {
            await result.current.handleCopySecretValue(secret);
        });

        expect(copyToClipboardMock).not.toHaveBeenCalled();
        expect(result.current.copyErrorId).toBe(7);
        expect(result.current.copiedSecretId).toBeNull();
        expect(result.current.copyingSecretId).toBeNull();

        // ERRMAP-1: the error stays up long enough to read its reason in the tooltip.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });
        expect(result.current.copyErrorId).toBe(7);

        await act(async () => {
            await vi.advanceTimersByTimeAsync(4000);
        });

        expect(result.current.copyErrorId).toBeNull();
        expect(result.current.copyError).toBeNull();
    });

    // ERRMAP-1: a value read the secret's own state refuses (409 SecretExpired /
    // SecretSuspended / SecretMaxReadsExhausted, 403 SecretAccessOutsideSchedule)
    // must say why, not just turn the button red.
    it('keeps the server reason when the read is refused', async () => {
        const secret = makeSecret({ id: 5 });
        const refusal = new AxiosError('Request failed with status code 409', 'ERR_BAD_REQUEST', undefined, undefined, {
            status: 409,
            statusText: 'Conflict',
            headers: {},
            config: { headers: new AxiosHeaders() },
            data: {
                success: false,
                code: 409,
                error: 'SecretExpired',
                message: 'secret has expired; its value can no longer be read',
            },
        });
        getValueMock.mockRejectedValue(refusal);

        const { result } = renderHook(() => useSecretReveal());

        await act(async () => {
            await result.current.handleCopySecretValue(secret);
        });

        expect(copyToClipboardMock).not.toHaveBeenCalled();
        expect(result.current.copyErrorId).toBe(5);
        expect(result.current.copyError).toBe('secret has expired; its value can no longer be read');
    });

    it('sets copyErrorId when copyToClipboard rejects', async () => {
        const secret = makeSecret({ id: 9 });
        getValueMock.mockResolvedValue('value');
        copyToClipboardMock.mockRejectedValue(new Error('clipboard denied'));

        const { result } = renderHook(() => useSecretReveal());

        await act(async () => {
            await result.current.handleCopySecretValue(secret);
        });

        expect(result.current.copyErrorId).toBe(9);
        expect(result.current.copiedSecretId).toBeNull();
    });

    it('sets copyingSecretId synchronously while the request is in flight', async () => {
        const secret = makeSecret({ id: 11 });
        let resolveValue: (value: string) => void = () => {};
        getValueMock.mockReturnValue(
            new Promise((resolve) => {
                resolveValue = resolve;
            })
        );
        copyToClipboardMock.mockResolvedValue(undefined);

        const { result } = renderHook(() => useSecretReveal());

        // Sonar flags this as a redundant act() call, but it isn't: handleCopySecretValue
        // sets copyingSecretId synchronously before its first await, and without this
        // wrapper React 18's act-environment defers that flush past the assertion below
        // (verified: removing the wrapper makes the next expect() read null, not 11).
        act(() => {
            // NOSONAR: not redundant, see comment above
            void result.current.handleCopySecretValue(secret);
        });

        expect(result.current.copyingSecretId).toBe(11);

        resolveValue('value');

        await waitFor(() => expect(result.current.copyingSecretId).toBeNull());
        expect(result.current.copiedSecretId).toBe(11);
    });
});
