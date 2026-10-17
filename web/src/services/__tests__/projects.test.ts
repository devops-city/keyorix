import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { projectsApi, PROJECT_ROLES } from '../projects';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

describe('PROJECT_ROLES', () => {
    it('lists the ADR-021 project roles offered in the Members tab', () => {
        expect(PROJECT_ROLES).toEqual(['project_admin', 'project_developer', 'project_viewer', 'project_auditor']);
    });
});

describe('projectsApi.list', () => {
    it('fetches without include_deleted by default and normalizes the snake_case wire fields', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: {
                    projects: [
                        {
                            id: 1,
                            name: 'alpha',
                            description: 'desc',
                            secret_count: 3,
                            environment_count: 2,
                            created_at: '2024-01-01',
                            updated_at: '2024-01-02',
                            require_mfa: true,
                        },
                    ],
                },
            },
        });

        const result = await projectsApi.list();

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects');
        expect(result).toEqual([
            {
                id: 1,
                name: 'alpha',
                description: 'desc',
                secretCount: 3,
                environmentCount: 2,
                lastActivity: '2024-01-02', // falls back to updated_at when last_activity is absent
                createdAt: '2024-01-01',
                updatedAt: '2024-01-02',
                deleted: false,
                requireMfa: true,
            },
        ]);
    });

    it('appends include_deleted=true when requested', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: { projects: [] } } });

        await projectsApi.list(true);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects?include_deleted=true');
    });

    it('falls back to bare data.projects when data.data is absent, defaulting untouched fields', async () => {
        mocked.get.mockResolvedValueOnce({ data: { projects: [{ id: 5, name: 'bravo' }] } });

        const result = await projectsApi.list();

        expect(result).toEqual([
            {
                id: 5,
                name: 'bravo',
                description: '',
                secretCount: 0,
                environmentCount: 0,
                lastActivity: '',
                createdAt: '',
                updatedAt: '',
                deleted: false,
                requireMfa: false,
            },
        ]);
    });

    it('returns [] when neither the wrapped nor bare shape is present', async () => {
        mocked.get.mockResolvedValueOnce({ data: {} });

        await expect(projectsApi.list()).resolves.toEqual([]);
    });

    it('prefers last_activity over the updated_at fallback when both are present', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: { projects: [{ id: 1, name: 'x', last_activity: '2024-05-01', updated_at: '2024-01-02' }] } },
        });

        const result = await projectsApi.list();

        expect(result[0].lastActivity).toBe('2024-05-01');
    });
});

describe('projectsApi.restore', () => {
    it('posts to the project restore endpoint', async () => {
        mocked.post.mockResolvedValueOnce({});

        await projectsApi.restore(7);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/7/restore');
    });
});

describe('projectsApi.restoreEnvironment', () => {
    it('posts to the nested environment restore endpoint', async () => {
        mocked.post.mockResolvedValueOnce({});

        await projectsApi.restoreEnvironment(7, 3);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/7/environments/3/restore');
    });
});

describe('projectsApi.get', () => {
    it('unwraps data.data and normalizes the snake_case wire fields', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: { id: 9, name: 'gamma', require_mfa: false } },
        });

        const result = await projectsApi.get(9);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/9');
        expect(result.id).toBe(9);
        expect(result.name).toBe('gamma');
        expect(result.requireMfa).toBe(false);
    });

    it('falls back to bare data when data.data is absent', async () => {
        mocked.get.mockResolvedValueOnce({ data: { id: 2, name: 'delta' } });

        const result = await projectsApi.get(2);

        expect(result).toEqual({
            id: 2,
            name: 'delta',
            description: '',
            secretCount: 0,
            environmentCount: 0,
            lastActivity: '',
            createdAt: '',
            updatedAt: '',
            deleted: false,
            requireMfa: false,
        });
    });
});

describe('projectsApi.create', () => {
    it('posts the payload and normalizes the created project from data.data', async () => {
        mocked.post.mockResolvedValueOnce({ data: { data: { id: 11, name: 'epsilon' } } });
        const payload = { name: 'epsilon', description: 'new project' };

        const result = await projectsApi.create(payload);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects', payload);
        expect(result.id).toBe(11);
        expect(result.name).toBe('epsilon');
    });

    it('falls back to bare data when data.data is absent', async () => {
        mocked.post.mockResolvedValueOnce({ data: { id: 12, name: 'zeta' } });

        const result = await projectsApi.create({ name: 'zeta' });

        expect(result.id).toBe(12);
        expect(result.name).toBe('zeta');
    });
});

describe('projectsApi.delete', () => {
    it('deletes the project by id', async () => {
        mocked.delete.mockResolvedValueOnce({});

        await projectsApi.delete(4);

        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/projects/4');
    });
});

describe('projectsApi.listEnvironments', () => {
    it('fetches without include_deleted by default and normalizes the snake_case wire fields', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: {
                    environments: [
                        { id: 1, name: 'production', project_id: 9, deleted_at: null },
                        { id: 2, name: 'staging', project_id: 9, deleted_at: '2024-01-01' },
                    ],
                },
            },
        });

        const result = await projectsApi.listEnvironments(9);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/9/environments');
        expect(result).toEqual([
            { id: 1, name: 'production', projectId: 9, deleted: false },
            { id: 2, name: 'staging', projectId: 9, deleted: true },
        ]);
    });

    it('appends include_deleted=true when requested', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: { environments: [] } } });

        await projectsApi.listEnvironments(9, true);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/9/environments?include_deleted=true');
    });

    it('falls back to bare data.environments and normalizes snake_case fields', async () => {
        mocked.get.mockResolvedValueOnce({ data: { environments: [{ id: 3, name: 'dev', project_id: 9 }] } });

        const result = await projectsApi.listEnvironments(9);

        expect(result).toEqual([{ id: 3, name: 'dev', projectId: 9, deleted: false }]);
    });

    it('returns [] when neither the wrapped nor bare shape is present', async () => {
        mocked.get.mockResolvedValueOnce({ data: {} });

        await expect(projectsApi.listEnvironments(9)).resolves.toEqual([]);
    });
});

describe('projectsApi.listMembers', () => {
    it('normalizes Go snake_case member fields', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: {
                    members: [
                        {
                            user_id: 1,
                            username: 'alice',
                            display_name: 'Alice A',
                            email: 'alice@example.com',
                            role_id: 2,
                            role_name: 'project_admin',
                        },
                    ],
                },
            },
        });

        const result = await projectsApi.listMembers(9);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/9/members');
        expect(result).toEqual([
            {
                userId: 1,
                username: 'alice',
                displayName: 'Alice A',
                email: 'alice@example.com',
                roleId: 2,
                roleName: 'project_admin',
            },
        ]);
    });

    it('returns [] when members is missing', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: {} } });

        await expect(projectsApi.listMembers(9)).resolves.toEqual([]);
    });

    it('defaults every member field on a sparse row', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: { members: [{}] } } });

        const result = await projectsApi.listMembers(9);

        expect(result).toEqual([
            { userId: undefined, username: '', displayName: '', email: '', roleId: 0, roleName: '' },
        ]);
    });
});

describe('projectsApi.addMember', () => {
    it('posts user_id and role', async () => {
        mocked.post.mockResolvedValueOnce({});

        await projectsApi.addMember(9, 5, 'project_viewer');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/9/members', { user_id: 5, role: 'project_viewer' });
    });
});

describe('projectsApi.updateMemberRole', () => {
    it('puts the new role', async () => {
        mocked.put.mockResolvedValueOnce({});

        await projectsApi.updateMemberRole(9, 5, 'project_admin');

        expect(mocked.put).toHaveBeenCalledWith('/api/v1/projects/9/members/5', { role: 'project_admin' });
    });
});

describe('projectsApi.removeMember', () => {
    it('deletes the membership', async () => {
        mocked.delete.mockResolvedValueOnce({});

        await projectsApi.removeMember(9, 5);

        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/projects/9/members/5');
    });
});

describe('projectsApi.rotationPlan', () => {
    it('unwraps {data} and normalizes snake_case rotation plan (ADR-053)', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: {
                    project_id: 1,
                    total_secrets: 10,
                    overdue_count: 2,
                    due_soon_count: 3,
                    waves: [
                        {
                            index: 0,
                            secrets: [
                                {
                                    secret_id: 100,
                                    secret_name: 'API_KEY',
                                    status: 'overdue',
                                    days_overdue: 5,
                                    risk_score: 80,
                                    risk_band: 'high',
                                    urgency: 9,
                                    auto_rotate: true,
                                    after_secret_ids: [101],
                                    reasons: ['overdue by 5 days'],
                                },
                            ],
                        },
                    ],
                },
            },
        });

        const plan = await projectsApi.rotationPlan(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/1/rotation-plan');
        expect(plan).toEqual({
            projectId: 1,
            totalSecrets: 10,
            overdueCount: 2,
            dueSoonCount: 3,
            waves: [
                {
                    index: 0,
                    secrets: [
                        {
                            secretId: 100,
                            secretName: 'API_KEY',
                            status: 'overdue',
                            daysOverdue: 5,
                            riskScore: 80,
                            riskBand: 'high',
                            urgency: 9,
                            autoRotate: true,
                            afterSecretIds: [101],
                            reasons: ['overdue by 5 days'],
                        },
                    ],
                },
            ],
        });
    });

    it('defaults missing fields safely', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: { project_id: 2 } } });

        const plan = await projectsApi.rotationPlan(2);

        expect(plan).toEqual({
            projectId: 2,
            totalSecrets: 0,
            overdueCount: 0,
            dueSoonCount: 0,
            waves: [],
        });
    });

    it('defaults projectId to 0 and wave index/secrets fields when a wave/secret is sparse', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: { waves: [{ secrets: [{}] }] } },
        });

        const plan = await projectsApi.rotationPlan(9);

        expect(plan.projectId).toBe(0);
        expect(plan.waves).toEqual([
            {
                index: 0,
                secrets: [
                    {
                        secretId: 0,
                        secretName: '',
                        status: '',
                        daysOverdue: 0,
                        riskScore: 0,
                        riskBand: '',
                        urgency: 0,
                        autoRotate: false,
                        afterSecretIds: [],
                        reasons: [],
                    },
                ],
            },
        ]);
    });

    it('defaults a wave to [] secrets when the wave omits the secrets key', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: { project_id: 3, waves: [{ index: 1 }] } },
        });

        const plan = await projectsApi.rotationPlan(3);

        expect(plan.waves).toEqual([{ index: 1, secrets: [] }]);
    });

    it('falls back to bare response.data when data.data is absent', async () => {
        mocked.get.mockResolvedValueOnce({ data: { project_id: 4 } });

        const plan = await projectsApi.rotationPlan(4);

        expect(plan.projectId).toBe(4);
    });
});

describe('projectsApi.accessReview', () => {
    it('normalizes snake_case entries (ISO 27001 A.5.18)', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: {
                    entries: [
                        {
                            principal_type: 'user',
                            principal_id: 3,
                            principal_name: 'bob',
                            email: 'bob@example.com',
                            source: 'role',
                            role_id: 1,
                            role_name: 'project_viewer',
                            access_level: 'read',
                            environment_id: 2,
                            secret_id: 55,
                            secret_name: 'DB_PASSWORD',
                            last_used_at: '2024-06-01',
                        },
                    ],
                },
            },
        });

        const result = await projectsApi.accessReview(9);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/9/access-review');
        expect(result).toEqual([
            {
                principalType: 'user',
                principalId: 3,
                principalName: 'bob',
                email: 'bob@example.com',
                source: 'role',
                roleId: 1,
                roleName: 'project_viewer',
                accessLevel: 'read',
                environmentId: 2,
                secretId: 55,
                secretName: 'DB_PASSWORD',
                lastUsedAt: '2024-06-01',
            },
        ]);
    });

    it('copies the report-level look-back window onto every entry (RECERT-BOUND-1)', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: { activity_window_days: 45, entries: [{ source: 'role' }, { source: 'owner' }] } },
        });

        const result = await projectsApi.accessReview(9);

        expect(result.map((e) => e.activityWindowDays)).toEqual([45, 45]);
    });

    it('returns [] when entries is missing', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: {} } });

        await expect(projectsApi.accessReview(9)).resolves.toEqual([]);
    });

    it('defaults every field on a sparse access-review entry', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: { entries: [{ source: 'owner' }] } } });

        const result = await projectsApi.accessReview(9);

        expect(result).toEqual([
            {
                principalType: undefined,
                principalId: 0,
                principalName: '',
                email: '',
                source: 'owner',
                roleId: 0,
                roleName: '',
                accessLevel: '',
                environmentId: 0,
                secretId: 0,
                secretName: '',
                lastUsedAt: undefined,
            },
        ]);
    });
});

describe('projectsApi.attestAccessReview', () => {
    it('posts the decision converted to snake_case', async () => {
        mocked.post.mockResolvedValueOnce({});

        await projectsApi.attestAccessReview(9, {
            source: 'role',
            principalType: 'user',
            principalId: 3,
            roleId: 1,
            environmentId: 2,
            secretId: 55,
        });

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/9/access-review/attest', {
            source: 'role',
            principal_type: 'user',
            principal_id: 3,
            role_id: 1,
            environment_id: 2,
            secret_id: 55,
        });
    });
});

describe('projectsApi.revokeAccessReview', () => {
    it('posts the decision converted to snake_case, omitting fields the caller left unset', async () => {
        mocked.post.mockResolvedValueOnce({});

        await projectsApi.revokeAccessReview(9, {
            source: 'direct_share',
            principalId: 4,
        });

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/9/access-review/revoke', {
            source: 'direct_share',
            principal_type: undefined,
            principal_id: 4,
            role_id: undefined,
            environment_id: undefined,
            secret_id: undefined,
        });
    });
});

describe('projectsApi.listCampaigns', () => {
    it('normalizes campaign + progress pairs', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: {
                    campaigns: [
                        {
                            campaign: {
                                id: 1,
                                project_id: 9,
                                name: 'Q1 review',
                                state: 'open',
                                created_at: '2024-01-01',
                            },
                            progress: { total: 10, pending: 4, attested: 5, revoked: 1 },
                        },
                    ],
                },
            },
        });

        const result = await projectsApi.listCampaigns(9);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/9/access-review/campaigns');
        expect(result).toEqual([
            {
                campaign: {
                    id: 1,
                    projectId: 9,
                    name: 'Q1 review',
                    state: 'open',
                    createdAt: '2024-01-01',
                    closedAt: undefined,
                },
                progress: { total: 10, pending: 4, attested: 5, revoked: 1 },
            },
        ]);
    });

    it('returns [] when campaigns is missing', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: {} } });

        await expect(projectsApi.listCampaigns(9)).resolves.toEqual([]);
    });

    it('falls back to normalizing the row itself when it is not wrapped under a campaign key', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: {
                    campaigns: [{ id: 1, name: 'Q1 review', progress: { total: 1 } }],
                },
            },
        });

        const result = await projectsApi.listCampaigns(9);

        expect(result[0].campaign.id).toBe(1);
        expect(result[0].campaign.name).toBe('Q1 review');
    });

    it('defaults the campaign id to 0 when neither id nor ID is present', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: { campaigns: [{ campaign: { name: 'unnamed' }, progress: {} }] } },
        });

        const result = await projectsApi.listCampaigns(9);

        expect(result[0].campaign.id).toBe(0);
    });
});

describe('projectsApi.openCampaign', () => {
    it('posts the campaign name and normalizes the created campaign + progress', async () => {
        mocked.post.mockResolvedValueOnce({
            data: {
                data: {
                    campaign: { id: 2, project_id: 9, name: 'Q2 review', state: 'open', created_at: '2024-04-01' },
                    progress: { total: 0, pending: 0, attested: 0, revoked: 0 },
                },
            },
        });

        const result = await projectsApi.openCampaign(9, 'Q2 review');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/9/access-review/campaigns', { name: 'Q2 review' });
        expect(result.campaign.id).toBe(2);
        expect(result.campaign.name).toBe('Q2 review');
        expect(result.progress).toEqual({ total: 0, pending: 0, attested: 0, revoked: 0 });
    });

    it('falls back to bare response.data when data.data is absent', async () => {
        mocked.post.mockResolvedValueOnce({
            data: { campaign: { id: 3, name: 'bare' }, progress: { total: 0 } },
        });

        const result = await projectsApi.openCampaign(9, 'bare');

        expect(result.campaign.id).toBe(3);
    });
});

describe('projectsApi.getCampaign', () => {
    it('normalizes campaign, items, and progress', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: {
                    campaign: {
                        id: 2,
                        project_id: 9,
                        name: 'Q2 review',
                        state: 'closed',
                        created_at: '2024-04-01',
                        closed_at: '2024-05-01',
                    },
                    items: [
                        {
                            id: 7,
                            principal_type: 'group',
                            principal_id: 3,
                            principal_name: 'eng-team',
                            email: '',
                            source: 'group_share',
                            role_name: 'project_developer',
                            access_level: 'write',
                            secret_name: 'API_KEY',
                            last_used_at: '2024-04-15',
                            decision: 'attested',
                        },
                    ],
                    progress: { total: 1, pending: 0, attested: 1, revoked: 0 },
                },
            },
        });

        const result = await projectsApi.getCampaign(9, 2);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/9/access-review/campaigns/2');
        expect(result.campaign.closedAt).toBe('2024-05-01');
        expect(result.items).toEqual([
            {
                id: 7,
                principalType: 'group',
                principalId: 3,
                principalName: 'eng-team',
                email: '',
                source: 'group_share',
                roleName: 'project_developer',
                accessLevel: 'write',
                secretName: 'API_KEY',
                lastUsedAt: '2024-04-15',
                decision: 'attested',
            },
        ]);
        expect(result.progress.attested).toBe(1);
    });

    it('defaults items to [] when missing', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: { campaign: { id: 3 }, progress: {} } } });

        const result = await projectsApi.getCampaign(9, 3);

        expect(result.items).toEqual([]);
    });

    it('defaults every item field on a sparse row', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: { campaign: { id: 3 }, items: [{}], progress: {} } },
        });

        const result = await projectsApi.getCampaign(9, 3);

        expect(result.items).toEqual([
            {
                id: 0,
                principalType: undefined,
                principalId: 0,
                principalName: '',
                email: '',
                source: undefined,
                roleName: '',
                accessLevel: '',
                secretName: '',
                lastUsedAt: undefined,
                decision: 'pending',
            },
        ]);
    });

    it('falls back to bare response.data when data.data is absent', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { campaign: { id: 4, name: 'bare' }, items: [], progress: {} },
        });

        const result = await projectsApi.getCampaign(9, 4);

        expect(result.campaign.id).toBe(4);
    });
});

describe('projectsApi.decideCampaignItem', () => {
    it('posts the action with a reason', async () => {
        mocked.post.mockResolvedValueOnce({});

        await projectsApi.decideCampaignItem(9, 2, 7, 'attest', 'looks fine');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/9/access-review/campaigns/2/items/7/decide', {
            action: 'attest',
            reason: 'looks fine',
        });
    });

    it('defaults reason to an empty string when omitted', async () => {
        mocked.post.mockResolvedValueOnce({});

        await projectsApi.decideCampaignItem(9, 2, 7, 'revoke');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/9/access-review/campaigns/2/items/7/decide', {
            action: 'revoke',
            reason: '',
        });
    });
});

describe('projectsApi.closeCampaign', () => {
    it('posts the force flag', async () => {
        mocked.post.mockResolvedValueOnce({});

        await projectsApi.closeCampaign(9, 2, true);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/9/access-review/campaigns/2/close', { force: true });
    });
});
