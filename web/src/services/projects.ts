import { apiClient } from './client';
import type { operations } from '../types/api-generated';

export interface Project {
    id: number;
    name: string;
    description?: string;
    secretCount?: number;
    environmentCount?: number;
    lastActivity?: string;
    createdAt?: string;
    updatedAt?: string;
    deleted?: boolean;
    // ADR-037: blocks interactive access to this project for sessions without
    // a second factor. Toggling requires roles.assign (stricter than the
    // secrets.write gate on name/description).
    requireMfa?: boolean;
}

export interface ProjectEnvironment {
    id: number;
    name: string;
    projectId: number;
    deleted?: boolean;
}

// Generated from openapi.yaml's createProject/updateProject requestBody
// schemas (see package.json's generate:api-types) rather than hand-written,
// so a required field the spec adds (or drops) is a TypeScript compile
// error here, not a runtime 400 discovered later -- see
// src/types/api-contract-checks.ts for the regression this guards against.
export type CreateProjectPayload = operations['createProject']['requestBody']['content']['application/json'];
export type UpdateProjectPayload = operations['updateProject']['requestBody']['content']['application/json'];

export interface ProjectMember {
    userId: number;
    username: string;
    displayName: string;
    email: string;
    roleId: number;
    roleName: string;
}

// Access review / recertification (ISO 27001 A.5.18). One grant of access to a
// project's secrets; `source` says which mechanism conferred it.
export interface AccessReviewEntry {
    principalType: 'user' | 'group';
    principalId: number;
    principalName: string;
    email: string;
    source: 'role' | 'owner' | 'direct_share' | 'group_share';
    roleId: number;
    roleName: string;
    accessLevel: string;
    environmentId: number;
    secretId: number;
    secretName: string;
    // The user principal's most recent secret access in the project within the last
    // activityWindowDays days (the recertification period); absent = no recorded
    // activity in that window (dormant standing access). Groups never carry it.
    lastUsedAt?: string;
    // The report-level look-back of lastUsedAt, copied onto each entry.
    activityWindowDays?: number;
}

// A recertification decision identifying one entry to attest (keep) or revoke.
export interface AccessReviewDecision {
    source: string;
    principalType?: string;
    principalId: number;
    roleId?: number;
    environmentId?: number;
    secretId?: number;
}

const normalizeAccessReviewEntry = (e: any): AccessReviewEntry => ({
    principalType: e.principal_type ?? e.principalType,
    principalId: e.principal_id ?? e.principalId ?? 0,
    principalName: e.principal_name ?? e.principalName ?? '',
    email: e.email ?? '',
    source: e.source,
    roleId: e.role_id ?? e.roleId ?? 0,
    roleName: e.role_name ?? e.roleName ?? '',
    accessLevel: e.access_level ?? e.accessLevel ?? '',
    environmentId: e.environment_id ?? e.environmentId ?? 0,
    secretId: e.secret_id ?? e.secretId ?? 0,
    secretName: e.secret_name ?? e.secretName ?? '',
    lastUsedAt: e.last_used_at ?? e.lastUsedAt ?? undefined,
});

// Access-review campaigns (periodic recertification cycles, A.5.18).
export interface AccessReviewCampaign {
    id: number;
    projectId: number;
    name: string;
    state: 'open' | 'closed';
    createdAt: string;
    closedAt?: string;
    // Look-back of the items' lastUsedAt, fixed when the campaign was opened; 0 = opened
    // before the window existed (the whole audit history).
    activityWindowDays?: number;
}

export interface CampaignProgress {
    total: number;
    pending: number;
    attested: number;
    revoked: number;
}

export interface CampaignSummary {
    campaign: AccessReviewCampaign;
    progress: CampaignProgress;
}

export interface AccessReviewItem {
    id: number;
    principalType: 'user' | 'group';
    principalId: number;
    principalName: string;
    email: string;
    source: string;
    roleName: string;
    accessLevel: string;
    secretName: string;
    lastUsedAt?: string;
    decision: 'pending' | 'attested' | 'revoked';
}

export interface CampaignDetail {
    campaign: AccessReviewCampaign;
    items: AccessReviewItem[];
    progress: CampaignProgress;
}

const normalizeCampaign = (c: any): AccessReviewCampaign => ({
    id: c.id ?? c.ID ?? 0,
    projectId: c.project_id ?? c.projectId ?? 0,
    name: c.name ?? c.Name ?? '',
    state: c.state ?? c.State ?? 'open',
    createdAt: c.created_at ?? c.createdAt ?? '',
    closedAt: c.closed_at ?? c.closedAt ?? undefined,
    activityWindowDays: c.activity_window_days ?? c.activityWindowDays ?? undefined,
});

const normalizeProgress = (p: any): CampaignProgress => ({
    total: p?.total ?? 0,
    pending: p?.pending ?? 0,
    attested: p?.attested ?? 0,
    revoked: p?.revoked ?? 0,
});

const normalizeItem = (i: any): AccessReviewItem => ({
    id: i.id ?? i.ID ?? 0,
    principalType: i.principal_type ?? i.principalType,
    principalId: i.principal_id ?? i.principalId ?? 0,
    principalName: i.principal_name ?? i.principalName ?? '',
    email: i.email ?? '',
    source: i.source,
    roleName: i.role_name ?? i.roleName ?? '',
    accessLevel: i.access_level ?? i.accessLevel ?? '',
    secretName: i.secret_name ?? i.secretName ?? '',
    lastUsedAt: i.last_used_at ?? i.lastUsedAt ?? undefined,
    decision: i.decision ?? 'pending',
});

const toDecisionBody = (d: AccessReviewDecision) => ({
    source: d.source,
    principal_type: d.principalType,
    principal_id: d.principalId,
    role_id: d.roleId,
    environment_id: d.environmentId,
    secret_id: d.secretId,
});

// Cross-environment drift detection (M2). A key is consistent, present in some
// environments but not others, or present everywhere with diverging settings.
export type DriftStatus = 'missing_in_some' | 'metadata_drift';

export interface DriftEnvironment {
    id: number;
    name: string;
}

export interface DriftKey {
    name: string;
    presentIn: number[];
    missingFrom: number[];
    status: DriftStatus;
    driftFields: string[];
}

export interface DriftSummary {
    environmentCount: number;
    totalKeys: number;
    consistentKeys: number;
    missingInSome: number;
    metadataDrift: number;
}

export interface ProjectDrift {
    projectId: number;
    environments: DriftEnvironment[];
    driftedKeys: DriftKey[];
    summary: DriftSummary;
}

const normalizeDrift = (d: any): ProjectDrift => ({
    projectId: d.project_id ?? d.projectId ?? 0,
    environments: (d.environments ?? []).map((e: any) => ({ id: e.id ?? e.ID, name: e.name ?? e.Name })),
    driftedKeys: (d.drifted_keys ?? d.driftedKeys ?? []).map((k: any) => ({
        name: k.name ?? '',
        presentIn: k.present_in ?? k.presentIn ?? [],
        missingFrom: k.missing_from ?? k.missingFrom ?? [],
        status: k.status,
        driftFields: k.drift_fields ?? k.driftFields ?? [],
    })),
    summary: {
        environmentCount: d.summary?.environment_count ?? 0,
        totalKeys: d.summary?.total_keys ?? 0,
        consistentKeys: d.summary?.consistent_keys ?? 0,
        missingInSome: d.summary?.missing_in_some ?? 0,
        metadataDrift: d.summary?.metadata_drift ?? 0,
    },
});

// Automated rotation planning (ADR-053). The project's overdue/due-soon secrets,
// batched into dependency-respecting waves and prioritised by urgency.
export interface PlannedRotation {
    secretId: number;
    secretName: string;
    status: string; // overdue | due_soon
    daysOverdue: number; // positive = overdue, negative = days remaining
    riskScore: number;
    riskBand: string; // low | medium | high
    urgency: number;
    autoRotate: boolean;
    afterSecretIds: number[];
    reasons: string[];
}

export interface RotationWave {
    index: number;
    secrets: PlannedRotation[];
}

export interface RotationPlan {
    projectId: number;
    totalSecrets: number;
    overdueCount: number;
    dueSoonCount: number;
    waves: RotationWave[];
}

const normalizeRotationPlan = (d: any): RotationPlan => ({
    projectId: d.project_id ?? d.projectId ?? 0,
    totalSecrets: d.total_secrets ?? 0,
    overdueCount: d.overdue_count ?? 0,
    dueSoonCount: d.due_soon_count ?? 0,
    waves: (d.waves ?? []).map((w: any) => ({
        index: w.index ?? 0,
        secrets: (w.secrets ?? []).map((s: any) => ({
            secretId: s.secret_id ?? 0,
            secretName: s.secret_name ?? '',
            status: s.status ?? '',
            daysOverdue: s.days_overdue ?? 0,
            riskScore: s.risk_score ?? 0,
            riskBand: s.risk_band ?? '',
            urgency: s.urgency ?? 0,
            autoRotate: s.auto_rotate ?? false,
            afterSecretIds: s.after_secret_ids ?? [],
            reasons: s.reasons ?? [],
        })),
    })),
});

// ADR-021 project roles offered in the Members tab.
export const PROJECT_ROLES = ['project_admin', 'project_developer', 'project_viewer', 'project_auditor'] as const;

const normalizeMember = (m: any): ProjectMember => ({
    userId: m.user_id ?? m.userId,
    username: m.username ?? '',
    displayName: m.display_name ?? m.displayName ?? '',
    email: m.email ?? '',
    roleId: m.role_id ?? m.roleId ?? 0,
    roleName: m.role_name ?? m.roleName ?? '',
});

const normalize = (p: any): Project => ({
    id: p.id,
    name: p.name,
    description: p.description ?? '',
    secretCount: p.secret_count ?? 0,
    environmentCount: p.environment_count ?? 0,
    lastActivity: p.last_activity ?? p.updated_at ?? '',
    createdAt: p.created_at ?? '',
    updatedAt: p.updated_at ?? '',
    deleted: p.deleted ?? false,
    requireMfa: p.require_mfa ?? false,
});

const normalizeEnv = (e: any): ProjectEnvironment => ({
    id: e.id,
    name: e.name,
    projectId: e.project_id,
    deleted: Boolean(e.deleted_at),
});

export const projectsApi = {
    async list(includeDeleted = false): Promise<Project[]> {
        const response = await apiClient.get(`/api/v1/projects${includeDeleted ? '?include_deleted=true' : ''}`);
        const projects = response.data.data?.projects ?? response.data.projects ?? [];
        return projects.map(normalize);
    },

    async restore(projectId: number): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/restore`);
    },

    async restoreEnvironment(projectId: number, environmentId: number): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/environments/${environmentId}/restore`);
    },

    async get(id: number): Promise<Project> {
        const response = await apiClient.get(`/api/v1/projects/${id}`);
        const p = response.data.data ?? response.data;
        return normalize(p);
    },

    async create(payload: CreateProjectPayload): Promise<Project> {
        const response = await apiClient.post('/api/v1/projects', payload);
        const p = response.data.data ?? response.data;
        return normalize(p);
    },

    async update(id: number, payload: UpdateProjectPayload): Promise<Project> {
        const response = await apiClient.put(`/api/v1/projects/${id}`, payload);
        const p = response.data.data ?? response.data;
        return normalize(p);
    },

    async delete(projectId: number): Promise<void> {
        await apiClient.delete(`/api/v1/projects/${projectId}`);
    },

    async listEnvironments(projectId: number, includeDeleted = false): Promise<ProjectEnvironment[]> {
        const response = await apiClient.get(
            `/api/v1/projects/${projectId}/environments${includeDeleted ? '?include_deleted=true' : ''}`
        );
        const envs = response.data.data?.environments ?? response.data.environments ?? [];
        return envs.map(normalizeEnv);
    },

    async listMembers(projectId: number): Promise<ProjectMember[]> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/members`);
        const members = response.data.data?.members ?? response.data.members ?? [];
        return members.map(normalizeMember);
    },

    async addMember(projectId: number, userId: number, role: string): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/members`, { user_id: userId, role });
    },

    async updateMemberRole(projectId: number, userId: number, role: string): Promise<void> {
        await apiClient.put(`/api/v1/projects/${projectId}/members/${userId}`, { role });
    },

    async removeMember(projectId: number, userId: number): Promise<void> {
        await apiClient.delete(`/api/v1/projects/${projectId}/members/${userId}`);
    },

    async drift(projectId: number): Promise<ProjectDrift> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/drift`);
        return normalizeDrift(response.data.data ?? response.data);
    },

    async rotationPlan(projectId: number): Promise<RotationPlan> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/rotation-plan`);
        return normalizeRotationPlan(response.data.data ?? response.data);
    },

    async accessReview(projectId: number): Promise<AccessReviewEntry[]> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/access-review`);
        const entries = response.data.data?.entries ?? response.data.entries ?? [];
        const windowDays = response.data.data?.activity_window_days ?? response.data.activity_window_days ?? undefined;
        return entries.map((e: any) => ({ ...normalizeAccessReviewEntry(e), activityWindowDays: windowDays }));
    },

    async attestAccessReview(projectId: number, decision: AccessReviewDecision): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/access-review/attest`, toDecisionBody(decision));
    },

    async revokeAccessReview(projectId: number, decision: AccessReviewDecision): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/access-review/revoke`, toDecisionBody(decision));
    },

    async listCampaigns(projectId: number): Promise<CampaignSummary[]> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/access-review/campaigns`);
        const campaigns = response.data.data?.campaigns ?? response.data.campaigns ?? [];
        return campaigns.map((c: any) => ({
            campaign: normalizeCampaign(c.campaign ?? c),
            progress: normalizeProgress(c.progress),
        }));
    },

    async openCampaign(projectId: number, name: string): Promise<CampaignSummary> {
        const response = await apiClient.post(`/api/v1/projects/${projectId}/access-review/campaigns`, { name });
        const d = response.data.data ?? response.data;
        return { campaign: normalizeCampaign(d.campaign), progress: normalizeProgress(d.progress) };
    },

    async getCampaign(projectId: number, campaignId: number): Promise<CampaignDetail> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/access-review/campaigns/${campaignId}`);
        const d = response.data.data ?? response.data;
        return {
            campaign: normalizeCampaign(d.campaign),
            items: (d.items ?? []).map(normalizeItem),
            progress: normalizeProgress(d.progress),
        };
    },

    async decideCampaignItem(
        projectId: number,
        campaignId: number,
        itemId: number,
        action: 'attest' | 'revoke',
        reason?: string
    ): Promise<void> {
        await apiClient.post(
            `/api/v1/projects/${projectId}/access-review/campaigns/${campaignId}/items/${itemId}/decide`,
            { action, reason: reason ?? '' }
        );
    },

    async closeCampaign(projectId: number, campaignId: number, force: boolean): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/access-review/campaigns/${campaignId}/close`, { force });
    },
};
