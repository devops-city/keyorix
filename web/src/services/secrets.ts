import { apiClient } from './client';
import {
    ApiResponse,
    PaginatedResponse,
    Secret,
    SecretFormData,
    SecretUsageStat,
    UnusedSecretStat,
    SecretRiskScore,
    SecretAccessor,
    SecretAccessLogEntry,
    SecretAuditEntry,
    SecretPolicy,
} from '../types';
import { API_ENDPOINTS } from '../constants';

// Secret dependency graph (ADR-052). An edge means the focal secret and the linked
// secret are related such that rotating one affects the other.
export interface DependencyEdge {
    id: number; // the edge id (for removal)
    secret_id: number; // the other secret in the edge
    secret_name: string;
    note?: string;
}

export interface SecretDependencies {
    secret_id: number;
    depends_on: DependencyEdge[]; // secrets this one depends on
    dependents: DependencyEdge[]; // secrets that depend on this one
}

export interface ImpactedSecret {
    secret_id: number;
    secret_name: string;
    depth: number; // hop distance from the rotated secret
}

export interface SecretImpact {
    secret_id: number;
    secret_name: string;
    affected: ImpactedSecret[]; // transitive dependents (blast radius)
}

// Public X.509 metadata of a certificate-valued secret (ADR-054). Never includes the
// certificate value or any private key.
export interface CertificateInfo {
    secret_id: number;
    secret_name: string;
    subject: string;
    issuer: string;
    serial_number: string;
    not_before: string;
    not_after: string;
    days_until_expiry: number;
    is_expired: boolean;
    is_ca: boolean;
    self_signed: boolean;
    dns_names?: string[];
    signature_algorithm: string;
    public_key_algorithm: string;
}

export const secretsApi = {
    async list(params?: {
        page?: number;
        pageSize?: number;
        search?: string;
        type?: string;
        classification?: string;
        namespace?: string;
        zone?: string;
        environment?: string;
        environment_id?: number;
        project_id?: number;
        tags?: string[];
    }): Promise<PaginatedResponse<Secret>> {
        const response = await apiClient.get(API_ENDPOINTS.SECRETS.LIST, { params });
        const { secrets, total, page, page_size, total_pages } = response.data.data;
        const mappedSecrets: Secret[] = (secrets ?? []).map((s: any) => ({
            id: s.id,
            name: s.name,
            type: s.type,
            // The Share dialog searches recipients in the secret's project (SHARE-2).
            projectId: s.project_id ?? undefined,
            isShared: s.is_shared ?? false,
            shareCount: s.share_count ?? 0,
            lastModified: s.updated_at ?? s.created_at ?? '',
            owner: s.created_by ?? '',
            namespace: s.namespace_name ?? s.namespace ?? 'default',
            zone: s.zone_name ?? s.zone ?? '',
            environment: s.environment_name ?? s.environment ?? 'production',
            tags: [],
            permissions: [],
            metadata: {},
            Expiration: s.expiration ?? null,
            lastRotatedAt: s.last_rotated_at ?? null,
            classification: s.classification ?? '',
            status: s.status ?? 'active',
        }));
        return {
            data: mappedSecrets,
            total: total ?? 0,
            page: page ?? 1,
            pageSize: page_size ?? params?.pageSize ?? 20,
            totalPages: total_pages ?? 1,
        };
    },

    async get(id: number): Promise<Secret> {
        const response = await apiClient.get<ApiResponse<Secret>>(API_ENDPOINTS.SECRETS.GET(id));
        return response.data.data;
    },

    // getValue fetches the secret's CURRENT plaintext value -- GET
    // /secrets/{id}?include_value=true (server/http/handlers/secrets_crud.go).
    // This is the only endpoint that actually returns a value: GET .../versions
    // (getVersions, below) never does -- internal/storage/models.SecretVersion's
    // EncryptedValue field is tagged `json:"-"` server-side, so it can never
    // appear in that response. #2450 was exactly this: callers decoding
    // `versions[0].EncryptedValue` as base64 were always decoding `undefined`.
    async getValue(id: number): Promise<string> {
        const response = await apiClient.get<ApiResponse<{ secret: Secret; value: string }>>(
            API_ENDPOINTS.SECRETS.GET(id),
            { params: { include_value: true } }
        );
        return response.data.data.value;
    },

    async create(data: any): Promise<Secret> {
        const response = await apiClient.post<ApiResponse<Secret>>(API_ENDPOINTS.SECRETS.CREATE, data);
        return response.data.data;
    },

    async update(id: number, data: Partial<SecretFormData>): Promise<Secret> {
        const response = await apiClient.put<ApiResponse<Secret>>(API_ENDPOINTS.SECRETS.UPDATE(id), data);
        return response.data.data;
    },

    async delete(id: number): Promise<void> {
        await apiClient.delete(API_ENDPOINTS.SECRETS.DELETE(id));
    },

    // getVersions returns version METADATA only (number, created-at, read count)
    // -- never a value. See getValue (above) for the current plaintext.
    async getVersions(id: number): Promise<{ VersionNumber: number; CreatedAt: string }[]> {
        const response = await apiClient.get(API_ENDPOINTS.SECRETS.VERSIONS(id));
        return response.data.data.versions ?? [];
    },

    async rotate(id: number, newValue: string) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/rotate`, { new_value: newValue });
        return response.data;
    },

    // rollback restores the secret to a prior version's value as a new version.
    async rollback(id: number, version: number) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/rollback`, { version });
        return response.data;
    },

    // transferOwnership hands the secret to another user (the new owner). The server
    // requires the caller to be the current owner (or the owner to be gone).
    async transferOwnership(id: number, newOwnerId: number) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/transfer-ownership`, { new_owner_id: newOwnerId });
        return response.data;
    },

    // suspend freezes value reads of the secret (incident response); resume restores.
    async suspend(id: number, reason?: string) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/suspend`, reason !== undefined ? { reason } : {});
        return response.data;
    },
    async resume(id: number) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/resume`, {});
        return response.data;
    },

    // accessList returns the users who can read the secret (owner + direct + group
    // shares, members expanded) — GET /secrets/{id}/access.
    async accessList(id: number): Promise<SecretAccessor[]> {
        const response = await apiClient.get(`/api/v1/secrets/${id}/access`);
        return response.data.data?.accessors ?? [];
    },

    // accessLog returns the secret's recent reads (who/when/from where) —
    // GET /secrets/{id}/access-log?days=N.
    async accessLog(id: number, days = 30): Promise<SecretAccessLogEntry[]> {
        const response = await apiClient.get(`/api/v1/secrets/${id}/access-log`, { params: { days } });
        return response.data.data?.access_log ?? [];
    },

    // auditTrail returns the secret's lifecycle events (created/rotated/suspended/
    // shared/…) newest-first — GET /secrets/{id}/audit?limit=N. Never a value.
    async auditTrail(id: number, limit = 50): Promise<SecretAuditEntry[]> {
        const response = await apiClient.get(`/api/v1/secrets/${id}/audit`, { params: { limit } });
        return response.data.data?.audit ?? [];
    },

    // description reads the secret's free-text note.
    async description(id: number): Promise<string> {
        const response = await apiClient.get(API_ENDPOINTS.SECRETS.GET(id));
        const s = response.data.data ?? {};
        return s.description ?? '';
    },

    // setDescription sets/clears the note — PATCH /secrets/{id}/description.
    async setDescription(id: number, description: string): Promise<void> {
        await apiClient.patch(`/api/v1/secrets/${id}/description`, { description });
    },

    // policy returns the active create-time secret policies (naming + value), so the
    // create form can show conventions and pre-validate — GET /secrets/policy.
    async policy(): Promise<SecretPolicy> {
        const response = await apiClient.get('/api/v1/secrets/policy');
        return response.data.data ?? { name: { enabled: false }, value: { enabled: false } };
    },

    // copy promotes a secret's value + metadata into another environment of the
    // same project — POST /secrets/{id}/copy. Returns the created secret.
    async copy(id: number, environmentId: number, name?: string): Promise<any> {
        const body: Record<string, unknown> = { environment_id: environmentId };
        if (name) body.name = name;
        const response = await apiClient.post(`/api/v1/secrets/${id}/copy`, body);
        return response.data.data;
    },

    // tags returns the secret's tags — GET /secrets/{id}/tags.
    async tags(id: number): Promise<string[]> {
        const response = await apiClient.get(`/api/v1/secrets/${id}/tags`);
        return response.data.data?.tags ?? [];
    },

    // setTags replaces the secret's tag set — PUT /secrets/{id}/tags. Returns the
    // stored (server-normalized) tags.
    async setTags(id: number, tags: string[]): Promise<string[]> {
        const response = await apiClient.put(`/api/v1/secrets/${id}/tags`, { tags });
        return response.data.data?.tags ?? [];
    },

    async mostAccessed(params?: { days?: number; limit?: number; projectId?: number }): Promise<SecretUsageStat[]> {
        const query: Record<string, unknown> = {};
        if (params?.days !== undefined) query.days = params.days;
        if (params?.limit !== undefined) query.limit = params.limit;
        if (params?.projectId) query.project_id = params.projectId;
        const response = await apiClient.get('/api/v1/secrets/usage/most-accessed', { params: query });
        return (response.data.data?.secrets ?? []) as SecretUsageStat[];
    },

    async unused(params?: { days?: number; projectId?: number }): Promise<UnusedSecretStat[]> {
        const query: Record<string, unknown> = {};
        if (params?.days !== undefined) query.days = params.days;
        if (params?.projectId) query.project_id = params.projectId;
        const response = await apiClient.get('/api/v1/secrets/usage/unused', { params: query });
        return (response.data.data?.secrets ?? []) as UnusedSecretStat[];
    },

    async risk(id: number): Promise<SecretRiskScore> {
        const response = await apiClient.get<ApiResponse<SecretRiskScore>>(`/api/v1/secrets/${id}/risk`);
        return response.data.data;
    },

    // classify sets (or clears, with '') the secret's data-classification label
    // (ISO 27001 A.5.12) via PATCH /secrets/{id}/classification.
    async classify(id: number, classification: string): Promise<void> {
        await apiClient.patch(API_ENDPOINTS.SECRETS.CLASSIFY(id), { classification });
    },

    // setAutoRotate configures automated rotation (ADR-046/047) via
    // PATCH /secrets/{id}/auto-rotate: enable/disable, the generated-value shape
    // (length/charset), and an optional backend + ref to rotate an upstream credential.
    async setAutoRotate(
        id: number,
        opts: { enabled: boolean; length?: number; charset?: string; backend?: string; ref?: string }
    ): Promise<void> {
        await apiClient.patch(`/api/v1/secrets/${id}/auto-rotate`, {
            enabled: opts.enabled,
            length: opts.length ?? 0,
            charset: opts.charset ?? '',
            backend: opts.backend ?? '',
            ref: opts.ref ?? '',
        });
    },

    // --- secret dependency graph (ADR-052) ---

    // dependencies returns the secret's direct dependencies and dependents.
    async dependencies(id: number): Promise<SecretDependencies> {
        const response = await apiClient.get<ApiResponse<SecretDependencies>>(`/api/v1/secrets/${id}/dependencies`);
        return response.data.data;
    },

    // addDependency declares that this secret depends on dependsOnId.
    async addDependency(id: number, dependsOnId: number, note?: string): Promise<void> {
        await apiClient.post(`/api/v1/secrets/${id}/dependencies`, { depends_on_id: dependsOnId, note: note ?? '' });
    },

    // removeDependency deletes one dependency edge by its id.
    async removeDependency(id: number, edgeId: number): Promise<void> {
        await apiClient.delete(`/api/v1/secrets/${id}/dependencies/${edgeId}`);
    },

    // impact returns the blast radius of rotating this secret (transitive dependents).
    // certificate returns the public X.509 metadata of a certificate-valued secret.
    async certificate(id: number): Promise<CertificateInfo> {
        const response = await apiClient.get<ApiResponse<CertificateInfo>>(`/api/v1/secrets/${id}/certificate`);
        return response.data.data;
    },

    async impact(id: number): Promise<SecretImpact> {
        const response = await apiClient.get<ApiResponse<SecretImpact>>(`/api/v1/secrets/${id}/impact`);
        return response.data.data;
    },
};
