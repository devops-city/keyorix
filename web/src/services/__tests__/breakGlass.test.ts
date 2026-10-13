import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';

const { getMock, postMock } = vi.hoisted(() => ({ getMock: vi.fn(), postMock: vi.fn() }));
vi.mock('../client', () => ({ apiClient: { get: getMock, post: postMock } }));

import { breakGlassApi, classifyBreakGlassError } from '../breakGlass';

const refusal = (status: number, data: unknown) =>
    new AxiosError('Request failed', 'ERR_BAD_REQUEST', undefined, undefined, {
        status,
        statusText: '',
        data,
        headers: {},
        config: { headers: new AxiosHeaders() },
    });

beforeEach(() => vi.clearAllMocks());

describe('breakGlassApi', () => {
    it('maps the wire list, including the admin-only fields when present', async () => {
        getMock.mockResolvedValue({
            data: {
                data: {
                    scope: 'project',
                    count: 1,
                    activations: [
                        {
                            id: 4,
                            user_id: 9,
                            role_name: 'project_developer',
                            justification: 'why',
                            state: 'revoked',
                            expires_at: '2026-10-13T12:00:00Z',
                            created_at: '2026-10-13T10:00:00Z',
                            revoked_by: 2,
                            revoked_at: '2026-10-13T10:30:00Z',
                        },
                    ],
                },
            },
        });
        const list = await breakGlassApi.list(5);
        expect(getMock).toHaveBeenCalledWith('/api/v1/projects/5/break-glass');
        expect(list.scope).toBe('project');
        expect(list.activations[0]).toMatchObject({ id: 4, userId: 9, state: 'revoked', revokedBy: 2 });
    });

    it('treats anything but an explicit "project" scope as the caller’s own view', async () => {
        getMock.mockResolvedValue({ data: { data: { activations: [] } } });
        expect((await breakGlassApi.list(5)).scope).toBe('own');
    });

    it('posts the justification and only sends ttl when one is chosen', async () => {
        postMock.mockResolvedValue({ data: { data: { activation: { id: 1, state: 'active' } } } });
        await breakGlassApi.activate(5, 'because', '2h');
        expect(postMock).toHaveBeenLastCalledWith('/api/v1/projects/5/break-glass', {
            justification: 'because',
            ttl: '2h',
        });
        await breakGlassApi.activate(5, 'because');
        expect(postMock).toHaveBeenLastCalledWith('/api/v1/projects/5/break-glass', { justification: 'because' });
    });

    it('revokes via the activation’s revoke route', async () => {
        postMock.mockResolvedValue({ data: {} });
        await breakGlassApi.revoke(5, 12);
        expect(postMock).toHaveBeenCalledWith('/api/v1/projects/5/break-glass/12/revoke');
    });
});

describe('classifyBreakGlassError', () => {
    it('recognises the three 403 shapes the server produces', () => {
        expect(classifyBreakGlassError(refusal(403, { error: 'ProjectMFARequired', message: 'x' }))).toBe('mfa');
        expect(
            classifyBreakGlassError(
                refusal(403, {
                    error: 'Error',
                    message: 'permission denied: break-glass is not enabled on this server; set ...',
                })
            )
        ).toBe('disabled');
        expect(classifyBreakGlassError(refusal(403, { error: 'Forbidden', message: 'Insufficient permissions' }))).toBe(
            'forbidden'
        );
        expect(classifyBreakGlassError(refusal(403, undefined))).toBe('forbidden');
    });

    it('does not mistake other statuses or non-HTTP errors for a refusal', () => {
        expect(classifyBreakGlassError(refusal(500, { error: 'ProjectMFARequired' }))).toBe('other');
        expect(classifyBreakGlassError(refusal(400, { message: 'break-glass is not enabled' }))).toBe('other');
        expect(classifyBreakGlassError(new Error('boom'))).toBe('other');
    });
});
