import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError } from 'axios';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { sharingApi, buildUpdateShareBody } from '../sharing';
import type { ShareRecord } from '../../types';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

function ok<T>(data: T) {
    return { data: { data } };
}

const share: ShareRecord = {
    id: 1,
    secretId: 42,
    recipientType: 'user',
    recipientId: 7,
    recipientName: 'alice',
    permission: 'read',
    createdAt: '2026-06-01T00:00:00.000Z',
    createdBy: 'bob',
};

beforeEach(() => vi.clearAllMocks());

// buildUpdateShareBody sends only the requested change so a permission-only edit
// never disturbs the share's existing expiry (the server preserves it).
describe('buildUpdateShareBody', () => {
    it('sends only the permission when neither expiry field is set (preserve)', () => {
        expect(buildUpdateShareBody({ permission: 'write' })).toEqual({ permission: 'write' });
    });

    it('sends clear_expiry to make a share permanent', () => {
        expect(buildUpdateShareBody({ permission: 'read', clearExpiry: true })).toEqual({
            permission: 'read',
            clear_expiry: true,
        });
    });

    it('sends expires_at to set/extend the expiry', () => {
        const iso = '2026-07-01T00:00:00.000Z';
        expect(buildUpdateShareBody({ permission: 'read', expiresAt: iso })).toEqual({
            permission: 'read',
            expires_at: iso,
        });
    });

    it('prefers clear over a stale expiresAt when both somehow arrive', () => {
        const body = buildUpdateShareBody({
            permission: 'read',
            clearExpiry: true,
            expiresAt: '2026-07-01T00:00:00.000Z',
        });
        expect(body.clear_expiry).toBe(true);
        // both keys may be present; the server treats clear_expiry as authoritative.
        expect(body.permission).toBe('read');
    });
});

// ── sharingApi.list ────────────────────────────────────────────────────────────

describe('sharingApi.list', () => {
    it('sends the given filters as query params and returns the paginated payload', async () => {
        const page = { data: [share], total: 1, page: 1, pageSize: 20, totalPages: 1 };
        mock.get.mockResolvedValueOnce(ok(page));
        const params = { page: 1, pageSize: 20, secretId: 42, recipientType: 'user' as const };
        const result = await sharingApi.list(params);
        expect(mock.get).toHaveBeenCalledWith('/api/v1/shares', { params });
        expect(result).toEqual(page);
    });

    it('calls with undefined params when none are given', async () => {
        const page = { data: [], total: 0, page: 1, pageSize: 20, totalPages: 0 };
        mock.get.mockResolvedValueOnce(ok(page));
        await sharingApi.list();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/shares', { params: undefined });
    });
});

// ── sharingApi.get ─────────────────────────────────────────────────────────────

describe('sharingApi.get', () => {
    it('fetches a single share by id', async () => {
        mock.get.mockResolvedValueOnce(ok(share));
        await expect(sharingApi.get(1)).resolves.toEqual(share);
        expect(mock.get).toHaveBeenCalledWith('/api/v1/shares/1');
    });
});

// ── sharingApi.create ──────────────────────────────────────────────────────────

describe('sharingApi.create', () => {
    it('posts to the per-secret share endpoint with a user recipient and no expiry', async () => {
        mock.post.mockResolvedValueOnce(ok(share));
        const result = await sharingApi.create({
            secretId: 42,
            recipientType: 'user',
            recipientId: 7,
            permission: 'read',
        });
        expect(mock.post).toHaveBeenCalledWith('/api/v1/secrets/42/share', {
            recipient_id: 7,
            is_group: false,
            permission: 'read',
        });
        expect(result).toEqual(share);
    });

    it('sets is_group true for a group recipient and includes expires_at when provided', async () => {
        mock.post.mockResolvedValueOnce(ok(share));
        await sharingApi.create({
            secretId: 42,
            recipientType: 'group',
            recipientId: 9,
            permission: 'write',
            expiresAt: '2026-08-01T00:00:00.000Z',
        });
        expect(mock.post).toHaveBeenCalledWith('/api/v1/secrets/42/share', {
            recipient_id: 9,
            is_group: true,
            permission: 'write',
            expires_at: '2026-08-01T00:00:00.000Z',
        });
    });
});

// ── sharingApi.update ──────────────────────────────────────────────────────────

describe('sharingApi.update', () => {
    it('puts the built body to the share endpoint and returns the updated share', async () => {
        const updated = { ...share, permission: 'write' as const };
        mock.put.mockResolvedValueOnce(ok(updated));
        const result = await sharingApi.update(1, { permission: 'write' });
        expect(mock.put).toHaveBeenCalledWith('/api/v1/shares/1', { permission: 'write' });
        expect(result).toEqual(updated);
    });

    it('forwards clearExpiry/expiresAt through buildUpdateShareBody', async () => {
        mock.put.mockResolvedValueOnce(ok(share));
        await sharingApi.update(1, { permission: 'read', clearExpiry: true });
        expect(mock.put).toHaveBeenCalledWith('/api/v1/shares/1', { permission: 'read', clear_expiry: true });
    });
});

// ── sharingApi.delete ──────────────────────────────────────────────────────────

describe('sharingApi.delete', () => {
    it('calls DELETE on the share endpoint', async () => {
        mock.delete.mockResolvedValueOnce({});
        await sharingApi.delete(1);
        expect(mock.delete).toHaveBeenCalledWith('/api/v1/shares/1');
    });
});

// ── sharingApi.selfRemove ──────────────────────────────────────────────────────

describe('sharingApi.selfRemove', () => {
    it('posts to the self-remove endpoint', async () => {
        mock.post.mockResolvedValueOnce({});
        await sharingApi.selfRemove(1);
        expect(mock.post).toHaveBeenCalledWith('/api/v1/shares/1/self-remove');
    });
});

// SHARE-3: the Sharing Management page lists GET /shares for a caller with global
// secrets.read and falls back to the owner-scoped GET /shares/owned when that route's
// permission gate refuses them. The profile cannot tell the two apart (its
// permissions are merged across scopes), so the server decides.
describe('sharingApi.listForManagement', () => {
    const page = { data: [share], total: 1, page: 1, pageSize: 20, totalPages: 1 };
    const refusal = (error: string, message: string) =>
        new AxiosError('Request failed with status code 403', 'ERR_BAD_REQUEST', undefined, undefined, {
            status: 403,
            statusText: 'Forbidden',
            headers: {},
            config: {} as never,
            data: { error, message, code: 403 },
        });

    it('uses GET /shares (scope "all") when the caller may list it', async () => {
        mock.get.mockResolvedValueOnce(ok(page));
        const out = await sharingApi.listForManagement({ page: 2, pageSize: 10 });
        expect(out).toEqual({ ...page, scope: 'all' });
        expect(mock.get).toHaveBeenCalledTimes(1);
        expect(mock.get).toHaveBeenCalledWith('/api/v1/shares', { params: { page: 2, pageSize: 10 } });
    });

    it('falls back to GET /shares/owned (scope "owned") on the permission gate refusal', async () => {
        mock.get.mockRejectedValueOnce(refusal('Forbidden', 'Insufficient permissions'));
        mock.get.mockResolvedValueOnce(ok(page));
        const out = await sharingApi.listForManagement({ recipientType: 'user' });
        expect(out).toEqual({ ...page, scope: 'owned' });
        expect(mock.get).toHaveBeenLastCalledWith('/api/v1/shares/owned', { params: { recipientType: 'user' } });
    });

    it('does not fall back on a project-MFA refusal (that is not a permission answer)', async () => {
        const mfa = refusal('ProjectMFARequired', 'This project requires MFA');
        mock.get.mockRejectedValueOnce(mfa);
        await expect(sharingApi.listForManagement()).rejects.toBe(mfa);
        expect(mock.get).toHaveBeenCalledTimes(1);
    });

    it('surfaces the owner-scoped list refusal itself', async () => {
        const denied = refusal('Forbidden', 'You can only list the shares you created');
        mock.get.mockRejectedValueOnce(refusal('Forbidden', 'Insufficient permissions'));
        mock.get.mockRejectedValueOnce(denied);
        await expect(sharingApi.listForManagement()).rejects.toBe(denied);
    });
});
