import { isAxiosError } from 'axios';
import { apiClient } from './client';
import type { components } from '../types/api-generated';

// Break-glass (emergency access), ADR-112 / #3148. The server enforces everything: whether
// the feature is on, project membership, the TTL ceiling, the MFA policy, who may list all
// activations (roles.read) and who may revoke (roles.assign). This layer only shapes the
// wire format and names the refusals so the page can say what happened.

export type BreakGlassState = 'active' | 'expired' | 'revoked';

export interface BreakGlassActivation {
    id: number;
    userId: number;
    roleName: string;
    justification: string;
    state: BreakGlassState;
    expiresAt?: string | undefined;
    createdAt?: string | undefined;
    // Admin-view fields: the server omits them from a member's own view.
    revokedBy?: number | undefined;
    revokedAt?: string | undefined;
    reviewedBy?: number | undefined;
    reviewedAt?: string | undefined;
    reviewNote?: string | undefined;
}

/** "project": every activation of the project (caller holds roles.read). "own": only the caller's. */
export type BreakGlassScope = 'project' | 'own';

export interface BreakGlassList {
    activations: BreakGlassActivation[];
    scope: BreakGlassScope;
}

type WireActivation = components['schemas']['BreakGlassActivation'] & {
    revoked_by?: number;
    revoked_at?: string;
    reviewed_by?: number;
    reviewed_at?: string;
    review_note?: string;
};

const normalize = (a: WireActivation): BreakGlassActivation => ({
    id: a.id ?? 0,
    userId: a.user_id ?? 0,
    roleName: a.role_name ?? '',
    justification: a.justification ?? '',
    state: a.state ?? 'active',
    expiresAt: a.expires_at,
    createdAt: a.created_at,
    revokedBy: a.revoked_by,
    revokedAt: a.revoked_at,
    reviewedBy: a.reviewed_by,
    reviewedAt: a.reviewed_at,
    reviewNote: a.review_note,
});

export const breakGlassApi = {
    async list(projectId: number): Promise<BreakGlassList> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/break-glass`);
        const data = response.data?.data ?? response.data ?? {};
        return {
            activations: ((data.activations ?? []) as WireActivation[]).map(normalize),
            // Fail closed on the view: anything but an explicit "project" is the caller's own.
            scope: data.scope === 'project' ? 'project' : 'own',
        };
    },

    // ttl is a Go duration ("2h"); omitted means the server's default. The server caps it at
    // its configured maximum and the returned activation carries the expiry actually granted.
    async activate(projectId: number, justification: string, ttl?: string): Promise<BreakGlassActivation> {
        const response = await apiClient.post(`/api/v1/projects/${projectId}/break-glass`, {
            justification,
            ...(ttl ? { ttl } : {}),
        });
        const data = response.data?.data ?? response.data ?? {};
        return normalize(data.activation as WireActivation);
    },

    async revoke(projectId: number, activationId: number): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/break-glass/${activationId}/revoke`);
    },
};

export type BreakGlassRefusal =
    /** break_glass.enabled is false on this server. */
    | 'disabled'
    /** The project requires a second factor and this session has none. */
    | 'mfa'
    /** Any other 403: not a member, restricted token, no right to the admin view. */
    | 'forbidden'
    | 'other';

// The server has no distinct error code for "disabled": it answers 403 with error "Error" and
// a message that says so (internal/core/break_glass.go errBreakGlassDisabled). The MFA
// refusal does have its own code, ProjectMFARequired. Anything else 403 is a plain refusal.
const DISABLED_MESSAGE = /break-glass is not enabled/i;

export const classifyBreakGlassError = (error: unknown): BreakGlassRefusal => {
    if (!isAxiosError(error) || error.response?.status !== 403) return 'other';
    const data = error.response.data as { error?: string; message?: string } | undefined;
    if (data?.error === 'ProjectMFARequired') return 'mfa';
    if (data?.message && DISABLED_MESSAGE.test(data.message)) return 'disabled';
    return 'forbidden';
};
