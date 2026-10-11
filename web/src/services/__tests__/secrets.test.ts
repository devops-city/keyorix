import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the shared axios instance before importing the service under test.
vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        patch: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { secretsApi } from '../secrets';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    patch: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

describe('secretsApi.list', () => {
    it('maps last_rotated_at → lastRotatedAt (null when never rotated)', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secrets: [
                        { id: 1, name: 'rotated-key', type: 'api_key', last_rotated_at: '2026-05-01T00:00:00Z' },
                        { id: 2, name: 'never-key', type: 'password' },
                    ],
                    total: 2,
                    page: 1,
                    page_size: 20,
                    total_pages: 1,
                },
            },
        });

        const out = await secretsApi.list();

        expect(out.data).toHaveLength(2);
        expect(out.data[0]).toMatchObject({ id: 1, name: 'rotated-key', lastRotatedAt: '2026-05-01T00:00:00Z' });
        expect(out.data[1].lastRotatedAt).toBeNull();
    });

    it('calls the LIST endpoint with no params object when called with no args', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });

        await secretsApi.list();

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets', { params: undefined });
    });

    it('forwards the params object to apiClient.get verbatim (no filtering/renaming)', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });

        const params = {
            search: 'db-password',
            type: 'password',
            project_id: 4,
            environment_id: 9,
            tags: ['prod', 'critical'],
        };
        await secretsApi.list(params);

        // list() passes the whole params object straight through to axios's `params`
        // option — there is no conditional-inclusion logic here (unlike mostAccessed/
        // unused below, which build their query object field-by-field).
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets', { params });
    });

    it('falls back to namespace/zone/environment defaults and normalizes classification/status', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secrets: [{ id: 3, name: 'bare', type: 'text' }],
                },
            },
        });

        const out = await secretsApi.list();

        expect(out.data[0]).toMatchObject({
            namespace: 'default',
            zone: '',
            environment: 'production',
            classification: '',
            status: 'active',
            owner: '',
            shareCount: 0,
            isShared: false,
            tags: [],
            permissions: [],
            metadata: {},
            Expiration: null,
        });
    });

    it('prefers namespace_name/zone_name/environment_name over the short field names', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secrets: [
                        {
                            id: 4,
                            name: 'scoped',
                            type: 'text',
                            namespace_name: 'team-a',
                            namespace: 'ignored',
                            zone_name: 'us-east',
                            zone: 'ignored',
                            environment_name: 'staging',
                            environment: 'ignored',
                            classification: 'confidential',
                            status: 'suspended',
                        },
                    ],
                },
            },
        });

        const out = await secretsApi.list();

        expect(out.data[0]).toMatchObject({
            namespace: 'team-a',
            zone: 'us-east',
            environment: 'staging',
            classification: 'confidential',
            status: 'suspended',
        });
    });

    it('defaults total/page/totalPages and pageSize (from params.pageSize) when the envelope omits them', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: null } } });

        const out = await secretsApi.list({ pageSize: 50 });

        expect(out.data).toEqual([]);
        expect(out.total).toBe(0);
        expect(out.page).toBe(1);
        expect(out.totalPages).toBe(1);
        expect(out.pageSize).toBe(50);
    });

    it('falls back to pageSize 20 when neither the envelope nor params supply one', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });

        const out = await secretsApi.list();

        expect(out.pageSize).toBe(20);
    });
});

describe('secretsApi.get', () => {
    it('GETs the secret by id and unwraps data.data', async () => {
        mocked.get.mockResolvedValue({ data: { data: { id: 5, name: 'x' }, message: 'ok', success: true } });

        const out = await secretsApi.get(5);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/5');
        expect(out).toEqual({ id: 5, name: 'x' });
    });
});

describe('secretsApi.create', () => {
    it('POSTs the form data to the CREATE endpoint and returns the created secret', async () => {
        mocked.post.mockResolvedValue({ data: { data: { id: 6, name: 'new-secret' } } });

        const payload = { name: 'new-secret', value: 'v', type: 'text', environment: 'production' };
        const out = await secretsApi.create(payload);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets', payload);
        expect(out).toEqual({ id: 6, name: 'new-secret' });
    });
});

describe('secretsApi.update', () => {
    it('PUTs partial form data to the UPDATE endpoint and returns the updated secret', async () => {
        mocked.put.mockResolvedValue({ data: { data: { id: 7, name: 'renamed' } } });

        const out = await secretsApi.update(7, { name: 'renamed' });

        expect(mocked.put).toHaveBeenCalledWith('/api/v1/secrets/7', { name: 'renamed' });
        expect(out).toEqual({ id: 7, name: 'renamed' });
    });
});

describe('secretsApi.delete', () => {
    it('DELETEs the secret by id and returns nothing', async () => {
        mocked.delete.mockResolvedValue({ data: {} });

        const out = await secretsApi.delete(8);

        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/secrets/8');
        expect(out).toBeUndefined();
    });
});

describe('secretsApi.getVersions', () => {
    // #2450: the real GET .../versions response NEVER carries a value field --
    // internal/storage/models.SecretVersion.EncryptedValue is tagged `json:"-"`
    // server-side, so it can never appear here. This mock used to fabricate an
    // EncryptedValue field that the real API cannot produce, which is exactly
    // how the #2450 regression went undetected: the test modeled a response
    // shape the real system never sends. Metadata only, matching reality.
    it('returns versions with index 0 as the latest (metadata only, no value)', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    versions: [
                        { VersionNumber: 3, CreatedAt: '2026-06-01T00:00:00Z', ReadCount: 0 },
                        { VersionNumber: 2, CreatedAt: '2026-05-01T00:00:00Z', ReadCount: 2 },
                    ],
                },
            },
        });

        const out = await secretsApi.getVersions(9);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/9/versions');
        expect(out).toHaveLength(2);
        expect(out[0]).toEqual({ VersionNumber: 3, CreatedAt: '2026-06-01T00:00:00Z', ReadCount: 0 });
        expect(out[0]).not.toHaveProperty('EncryptedValue');
    });

    it('defaults to an empty array when versions is missing', async () => {
        mocked.get.mockResolvedValue({ data: { data: {} } });

        const out = await secretsApi.getVersions(9);

        expect(out).toEqual([]);
    });
});

// #2450: getValue is the ONLY endpoint that actually returns a secret's
// plaintext -- GET /secrets/{id}?include_value=true.
describe('secretsApi.getValue', () => {
    it('GETs the secret with include_value=true and returns the plaintext value', async () => {
        mocked.get.mockResolvedValue({
            data: { data: { secret: { id: 9, name: 'db-password' }, value: 'sup3r-secret' } },
        });

        const out = await secretsApi.getValue(9);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/9', { params: { include_value: true } });
        expect(out).toBe('sup3r-secret');
    });
});

describe('secretsApi.rotate', () => {
    it('POSTs the new value to the rotate endpoint', async () => {
        mocked.post.mockResolvedValue({ data: { data: { ID: 1 }, message: 'Secret rotated successfully' } });

        await secretsApi.rotate(1, 'new-secret-value');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/rotate', { new_value: 'new-secret-value' });
    });
});

describe('secretsApi.rollback', () => {
    it('POSTs the target version number to the rollback endpoint', async () => {
        mocked.post.mockResolvedValue({ data: { message: 'Secret rolled back' } });

        const out = await secretsApi.rollback(1, 2);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/rollback', { version: 2 });
        expect(out).toEqual({ message: 'Secret rolled back' });
    });
});

describe('secretsApi.transferOwnership', () => {
    it('POSTs the new owner id to the transfer-ownership endpoint', async () => {
        mocked.post.mockResolvedValue({ data: { message: 'Ownership transferred' } });

        const out = await secretsApi.transferOwnership(1, 42);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/transfer-ownership', { new_owner_id: 42 });
        expect(out).toEqual({ message: 'Ownership transferred' });
    });
});

describe('secretsApi.suspend', () => {
    it('POSTs {reason} when a reason is given', async () => {
        mocked.post.mockResolvedValue({ data: { message: 'Suspended' } });

        await secretsApi.suspend(1, 'incident-142');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/suspend', { reason: 'incident-142' });
    });

    it('POSTs an empty body when no reason is given', async () => {
        mocked.post.mockResolvedValue({ data: { message: 'Suspended' } });

        await secretsApi.suspend(1);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/suspend', {});
    });

    // reason is checked against undefined (not truthiness), so an explicitly-passed
    // empty string ('') is sent as `{ reason: '' }` rather than being dropped like an
    // omitted reason — distinguishing "clear the reason to empty" from "no reason".
    it('POSTs {reason: ""} when reason is explicitly an empty string', async () => {
        mocked.post.mockResolvedValue({ data: { message: 'Suspended' } });

        await secretsApi.suspend(1, '');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/suspend', { reason: '' });
    });
});

describe('secretsApi.resume', () => {
    it('POSTs an empty body to the resume endpoint', async () => {
        mocked.post.mockResolvedValue({ data: { message: 'Resumed' } });

        const out = await secretsApi.resume(1);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/resume', {});
        expect(out).toEqual({ message: 'Resumed' });
    });
});

describe('secretsApi.accessList', () => {
    it('GETs and unwraps data.accessors', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    accessors: [{ user_id: 1, username: 'alice', permission: 'owner', source: 'owner' }],
                },
            },
        });

        const out = await secretsApi.accessList(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1/access');
        expect(out).toEqual({
            accessors: [{ user_id: 1, username: 'alice', permission: 'owner', source: 'owner' }],
            degraded: false,
            degradedReasons: [],
        });
    });

    it('passes the degraded flag and its reasons through', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    accessors: [],
                    degraded: true,
                    degraded_reasons: ['secret_acls: the caller lacks secrets.manage on the secret'],
                },
            },
        });

        const out = await secretsApi.accessList(1);

        expect(out).toEqual({
            accessors: [],
            degraded: true,
            degradedReasons: ['secret_acls: the caller lacks secrets.manage on the secret'],
        });
    });

    it('defaults to an empty, non-degraded report when data is missing', async () => {
        mocked.get.mockResolvedValue({ data: {} });

        const out = await secretsApi.accessList(1);

        expect(out).toEqual({ accessors: [], degraded: false, degradedReasons: [] });
    });
});

describe('secretsApi.accessLog', () => {
    it('defaults days to 30 and unwraps data.access_log', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    access_log: [
                        {
                            AccessedBy: 'alice',
                            AccessTime: '2026-06-01T00:00:00Z',
                            Action: 'read',
                            IPAddress: '10.0.0.1',
                        },
                    ],
                },
            },
        });

        const out = await secretsApi.accessLog(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1/access-log', { params: { days: 30 } });
        expect(out).toHaveLength(1);
        expect(out[0]).toMatchObject({ AccessedBy: 'alice', Action: 'read' });
    });

    it('passes a custom days window through', async () => {
        mocked.get.mockResolvedValue({ data: { data: { access_log: [] } } });

        await secretsApi.accessLog(1, 7);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1/access-log', { params: { days: 7 } });
    });

    it('defaults to an empty array when data is missing', async () => {
        mocked.get.mockResolvedValue({ data: {} });

        const out = await secretsApi.accessLog(1);

        expect(out).toEqual([]);
    });
});

describe('secretsApi.auditTrail', () => {
    it('defaults limit to 50 and unwraps data.audit', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    audit: [
                        {
                            id: 1,
                            event_type: 'created',
                            timestamp: '2026-06-01T00:00:00Z',
                            actor_type: 'user',
                            description: 'Secret created',
                            success: true,
                        },
                    ],
                },
            },
        });

        const out = await secretsApi.auditTrail(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1/audit', { params: { limit: 50 } });
        expect(out).toHaveLength(1);
        expect(out[0]).toMatchObject({ event_type: 'created', success: true });
    });

    it('passes a custom limit through', async () => {
        mocked.get.mockResolvedValue({ data: { data: { audit: [] } } });

        await secretsApi.auditTrail(1, 10);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1/audit', { params: { limit: 10 } });
    });

    it('defaults to an empty array when data is missing', async () => {
        mocked.get.mockResolvedValue({ data: {} });

        const out = await secretsApi.auditTrail(1);

        expect(out).toEqual([]);
    });
});

describe('secretsApi.description', () => {
    it('reads the description field', async () => {
        mocked.get.mockResolvedValue({ data: { data: { description: 'prod db password' } } });

        const out = await secretsApi.description(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1');
        expect(out).toBe('prod db password');
    });

    it('defaults to an empty string when data is not present', async () => {
        mocked.get.mockResolvedValue({ data: {} });

        const out = await secretsApi.description(1);

        expect(out).toBe('');
    });
});

describe('secretsApi.setDescription', () => {
    it('PATCHes the description', async () => {
        mocked.patch.mockResolvedValue({ data: {} });

        await secretsApi.setDescription(1, 'updated note');

        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/secrets/1/description', { description: 'updated note' });
    });

    it('PATCHes an empty string to clear the description', async () => {
        mocked.patch.mockResolvedValue({ data: {} });

        await secretsApi.setDescription(1, '');

        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/secrets/1/description', { description: '' });
    });
});

describe('secretsApi.policy', () => {
    it('GETs and unwraps the active policy', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    name: { enabled: true, pattern: '^[a-z-]+$', max_length: 64 },
                    value: { enabled: true, min_length: 12, reject_common: true },
                },
            },
        });

        const out = await secretsApi.policy();

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/policy');
        expect(out).toMatchObject({
            name: { enabled: true, max_length: 64 },
            value: { enabled: true, min_length: 12 },
        });
    });

    it('falls back to an all-disabled policy when data is missing', async () => {
        mocked.get.mockResolvedValue({ data: {} });

        const out = await secretsApi.policy();

        expect(out).toEqual({ name: { enabled: false }, value: { enabled: false } });
    });
});

describe('secretsApi.copy', () => {
    it('POSTs environment_id only when no name override is given', async () => {
        mocked.post.mockResolvedValue({ data: { data: { id: 20, name: 'copied' } } });

        const out = await secretsApi.copy(1, 3);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/copy', { environment_id: 3 });
        expect(out).toEqual({ id: 20, name: 'copied' });
    });

    it('includes name when a rename is given', async () => {
        mocked.post.mockResolvedValue({ data: { data: { id: 21, name: 'renamed-copy' } } });

        await secretsApi.copy(1, 3, 'renamed-copy');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/copy', {
            environment_id: 3,
            name: 'renamed-copy',
        });
    });
});

describe('secretsApi.tags', () => {
    it('GETs and unwraps data.tags', async () => {
        mocked.get.mockResolvedValue({ data: { data: { tags: ['prod', 'db'] } } });

        const out = await secretsApi.tags(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1/tags');
        expect(out).toEqual(['prod', 'db']);
    });

    it('defaults to an empty array when data is missing', async () => {
        mocked.get.mockResolvedValue({ data: {} });

        const out = await secretsApi.tags(1);

        expect(out).toEqual([]);
    });
});

describe('secretsApi.setTags', () => {
    it('PUTs the tags and returns the server-normalized set', async () => {
        // The server may normalize tags (e.g. lowercase/dedupe); assert the return
        // value comes from the response, not an echo of the input.
        mocked.put.mockResolvedValue({ data: { data: { tags: ['prod', 'db'] } } });

        const out = await secretsApi.setTags(1, ['Prod', 'DB', 'Prod']);

        expect(mocked.put).toHaveBeenCalledWith('/api/v1/secrets/1/tags', { tags: ['Prod', 'DB', 'Prod'] });
        expect(out).toEqual(['prod', 'db']);
    });

    it('defaults to an empty array when data is missing', async () => {
        mocked.put.mockResolvedValue({ data: {} });

        const out = await secretsApi.setTags(1, []);

        expect(out).toEqual([]);
    });
});

describe('secretsApi usage analytics', () => {
    it('mostAccessed unwraps {data:{secrets}} and passes window/limit params', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secrets: [{ secret_id: 1, secret_name: 'hot', read_count: 9, last_read: '2026-06-01T00:00:00Z' }],
                    days: 60,
                },
            },
        });

        const out = await secretsApi.mostAccessed({ days: 60, limit: 5 });

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/usage/most-accessed', {
            params: { days: 60, limit: 5 },
        });
        expect(out).toHaveLength(1);
        expect(out[0]).toMatchObject({ secret_id: 1, read_count: 9 });
    });

    it('mostAccessed includes project_id when projectId is given', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });

        await secretsApi.mostAccessed({ projectId: 4 });

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/usage/most-accessed', {
            params: { project_id: 4 },
        });
    });

    it('mostAccessed sends an empty params object when no args are given', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });

        await secretsApi.mostAccessed();

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/usage/most-accessed', { params: {} });
    });

    // Each param is gated against undefined (not truthiness), so an explicitly-passed
    // 0 is distinguishable from "not provided" and is included in the query string.
    it('includes an explicit days: 0 and limit: 0 in the query', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });

        await secretsApi.mostAccessed({ days: 0, limit: 0 });

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/usage/most-accessed', {
            params: { days: 0, limit: 0 },
        });
    });

    it('mostAccessed defaults to an empty array when the payload has no secrets key', async () => {
        mocked.get.mockResolvedValue({ data: { data: {} } });

        const out = await secretsApi.mostAccessed({ days: 30 });

        expect(out).toEqual([]);
    });

    it('unused unwraps secrets and defaults to an empty array', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: null, days: 30 } } });

        const out = await secretsApi.unused({ days: 30 });

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/usage/unused', { params: { days: 30 } });
        expect(out).toEqual([]);
    });

    it('unused includes project_id when projectId is given', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });

        await secretsApi.unused({ projectId: 2 });

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/usage/unused', { params: { project_id: 2 } });
    });

    it('unused includes an explicit days: 0 in the query', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });

        await secretsApi.unused({ days: 0 });

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/usage/unused', { params: { days: 0 } });
    });
});

describe('secretsApi.risk', () => {
    it('fetches and unwraps the per-secret risk score', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secret_id: 7,
                    secret_name: 'k',
                    score: 72,
                    band: 'high',
                    factors: [{ key: 'expiry', label: 'Expiry', score: 100, weight: 0.3, detail: 'Expired' }],
                },
            },
        });

        const out = await secretsApi.risk(7);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/7/risk');
        expect(out).toMatchObject({ secret_id: 7, score: 72, band: 'high' });
        expect(out.factors).toHaveLength(1);
    });
});

describe('secretsApi.classify', () => {
    it('PATCHes the classification', async () => {
        mocked.patch.mockResolvedValue({ data: {} });

        await secretsApi.classify(1, 'confidential');

        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/secrets/1/classification', {
            classification: 'confidential',
        });
    });

    it('PATCHes an empty string to clear the classification', async () => {
        mocked.patch.mockResolvedValue({ data: {} });

        await secretsApi.classify(1, '');

        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/secrets/1/classification', { classification: '' });
    });
});

describe('secretsApi.setAutoRotate', () => {
    it('PATCHes the full auto-rotate payload (with defaults filled)', async () => {
        mocked.patch.mockResolvedValue({ data: { message: 'ok' } });
        await secretsApi.setAutoRotate(7, { enabled: true });
        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/secrets/7/auto-rotate', {
            enabled: true,
            length: 0,
            charset: '',
            backend: '',
            ref: '',
        });
    });

    it('passes a backend + ref + generator spec through', async () => {
        mocked.patch.mockResolvedValue({ data: { message: 'ok' } });
        await secretsApi.setAutoRotate(9, {
            enabled: true,
            length: 24,
            charset: 'hex',
            backend: 'prod-pg',
            ref: 'app_svc',
        });
        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/secrets/9/auto-rotate', {
            enabled: true,
            length: 24,
            charset: 'hex',
            backend: 'prod-pg',
            ref: 'app_svc',
        });
    });
});

describe('secretsApi.dependencies', () => {
    it('GETs and unwraps the dependency graph edges', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secret_id: 1,
                    depends_on: [{ id: 10, secret_id: 2, secret_name: 'db-root', note: 'shared cred' }],
                    dependents: [],
                },
            },
        });

        const out = await secretsApi.dependencies(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1/dependencies');
        expect(out.depends_on).toHaveLength(1);
        expect(out.dependents).toEqual([]);
    });
});

describe('secretsApi.addDependency', () => {
    it('POSTs depends_on_id with a note', async () => {
        mocked.post.mockResolvedValue({ data: {} });

        await secretsApi.addDependency(1, 2, 'shared cred');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/dependencies', {
            depends_on_id: 2,
            note: 'shared cred',
        });
    });

    it('defaults note to an empty string when omitted', async () => {
        mocked.post.mockResolvedValue({ data: {} });

        await secretsApi.addDependency(1, 2);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/dependencies', {
            depends_on_id: 2,
            note: '',
        });
    });
});

describe('secretsApi.removeDependency', () => {
    it('DELETEs the dependency edge by id', async () => {
        mocked.delete.mockResolvedValue({ data: {} });

        await secretsApi.removeDependency(1, 10);

        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/secrets/1/dependencies/10');
    });
});

describe('secretsApi.certificate', () => {
    it('GETs and unwraps the certificate metadata', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secret_id: 1,
                    secret_name: 'tls-cert',
                    subject: 'CN=example.com',
                    issuer: 'CN=Example CA',
                    serial_number: '01',
                    not_before: '2026-01-01T00:00:00Z',
                    not_after: '2027-01-01T00:00:00Z',
                    days_until_expiry: 150,
                    is_expired: false,
                    is_ca: false,
                    self_signed: false,
                    signature_algorithm: 'SHA256-RSA',
                    public_key_algorithm: 'RSA',
                },
            },
        });

        const out = await secretsApi.certificate(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1/certificate');
        expect(out).toMatchObject({ secret_name: 'tls-cert', is_expired: false, days_until_expiry: 150 });
    });
});

describe('secretsApi.impact', () => {
    it('GETs and unwraps the blast-radius of rotating a secret', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secret_id: 1,
                    secret_name: 'db-root',
                    affected: [{ secret_id: 2, secret_name: 'app-conn-string', depth: 1 }],
                },
            },
        });

        const out = await secretsApi.impact(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/1/impact');
        expect(out.affected).toHaveLength(1);
        expect(out.affected[0]).toMatchObject({ secret_id: 2, depth: 1 });
    });
});
