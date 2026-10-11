import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, User, Recipient } from '../types';
import { API_ENDPOINTS } from '../constants';

// SetupLinkResult mirrors the backend ADR-028 credential-delivery outcome. In
// out-of-band mode `link_for_admin` is set for the admin to relay; in SMTP mode the
// link is sent and `delivered` is true.
export interface SetupLinkResult {
    email: string;
    channel: string; // smtp | out_of_band | log
    delivered: boolean;
    link_for_admin?: string;
}

// CreateUserResult is the POST /users response. The setup-link path nests the created
// user under `user` and the delivery outcome under `setup_link`; the classic path
// returns the user fields directly. Callers only read `setup_link`, so the rest stays
// loose.
// OneTimePasswordResult mirrors the backend ADR-028 Part E artifact: the
// generated password is returned once (under `one_time_password`) for the admin
// to relay out-of-band — never emailed, never stored in clear.
export interface OneTimePasswordResult {
    email: string;
    one_time_password: string;
    // UTC RFC 3339 instant after which login with it is refused like a wrong password.
    expires_at?: string;
}

export interface CreateUserResult {
    setup_link?: SetupLinkResult;
    one_time_password?: OneTimePasswordResult;
    [key: string]: any;
}

// AccountState mirrors the ADR-025 lifecycle states on the user DTO.
export type AccountState = 'active' | 'pending_first_login' | 'password_reset_required' | 'suspended';

// AdminUser is the admin-facing user row (snake_case from the Go DTO), including
// the ADR-025 account state and the per-user project tallies the backend now merges.
export interface AdminUser {
    id: number;
    username: string;
    email: string;
    display_name: string;
    active: boolean;
    account_state: AccountState;
    created_at: string;
    updated_at: string;
    last_login_at: string | null;
    deleted_at: string | null;
    project_count?: number;
    active_project_count?: number;
    // Present (RFC3339) only while a per-account login lockout is ACTIVE (ADR-040).
    login_locked_until?: string | null;
}

// UserMembership is one row of a user's project-assignments view: one entry per
// project the user holds a live project-scoped role grant in.
//
// #2781: the server used to answer this from the ADR-022 onboarding journal, which
// nothing the UI writes, so this list was empty for every user and the detail page
// read "Not a member of any project" while the project's own Members tab listed
// them. It now answers from the role grants — the same definition
// GET /api/v1/projects/{id}/members reports.
export interface UserMembership {
    project_id: number;
    project_name: string;
    // The highest-privilege role held at this project's scope; `roles` has all of
    // them (a direct grant plus a group-inherited one can coexist).
    role: string;
    roles: string[];
    state: string;
    // True when the membership comes only from a group grant — the project's own
    // Members tab has no row to remove for it.
    via_group: boolean;
    // True when the project has been soft-deleted. The grant survives a soft-delete
    // (a restore reinstates it), so the row is shown rather than hidden — but it is
    // not counted by the per-user project tallies on the admin Users list, and it
    // used to come back with an empty project_name.
    project_deleted: boolean;
}

// ProjectAssignment is one project-scoped role grant applied atomically at
// create time (ADR-028 atomic POST /users). `project_id` keys the grant; the
// optional `project_name` is carried by the UI for display and is ignored by the
// backend.
export interface ProjectAssignment {
    project_id: number;
    role: string;
    project_name?: string;
}

// SYSTEM_ROLES are the install-wide roles (ADR-021) offered as the optional
// system-role override on the Global-Admin create dialog. Omitting the override
// lets the backend apply its system_viewer baseline.
export const SYSTEM_ROLES = ['system_admin', 'system_auditor', 'system_viewer'] as const;

export const usersApi = {
    async list(params?: { page?: number; pageSize?: number; search?: string }): Promise<PaginatedResponse<User>> {
        const response = await apiClient.get<ApiResponse<PaginatedResponse<User>>>(API_ENDPOINTS.USERS.LIST, {
            params,
        });
        return response.data.data;
    },

    async get(id: number): Promise<User> {
        const response = await apiClient.get<ApiResponse<User>>(API_ENDPOINTS.USERS.GET(id));
        return response.data.data;
    },

    async search(query: string): Promise<Recipient[]> {
        const response = await apiClient.get(API_ENDPOINTS.USERS.SEARCH, { params: { q: query } });
        const users = response.data.data?.users ?? [];
        return users.map((u: any) => ({
            id: u.id,
            name: u.username,
            type: 'user' as const,
            email: u.email,
        }));
    },

    async create(body: {
        username: string;
        email: string;
        display_name: string;
        // Optional when deliver_setup_link is set: the user sets their own password
        // via the setup link (ADR-028) instead of the admin choosing one.
        password?: string;
        deliver_setup_link?: boolean;
        // ADR-028 Part E: server generates a strong one-time password, returned
        // once for out-of-band relay. Mutually exclusive with the other two.
        generate_one_time_password?: boolean;
        // ADR-028 atomic provisioning (admin-set-password path only): an optional
        // system-role override and a set of project-scoped role assignments, applied
        // with the create in one transaction. Rejected by the backend alongside
        // deliver_setup_link / generate_one_time_password.
        role?: string;
        project_assignments?: ProjectAssignment[];
    }): Promise<CreateUserResult> {
        const response = await apiClient.post('/api/v1/users', body);
        return response.data?.data ?? response.data;
    },

    async update(id: number, body: object): Promise<any> {
        const response = await apiClient.put(`/api/v1/users/${id}`, body);
        return response.data;
    },

    async delete(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/users/${id}`);
    },

    async restore(id: number): Promise<void> {
        await apiClient.post(`/api/v1/users/${id}/restore`);
    },

    // ── ADR-025 account lifecycle (admin actions, gated by users.write) ──────

    async suspend(id: number): Promise<void> {
        await apiClient.post(`/api/v1/users/${id}/suspend`);
    },

    async reactivate(id: number): Promise<void> {
        await apiClient.post(`/api/v1/users/${id}/reactivate`);
    },

    // Clear an active per-account login lockout (ADR-040). Does not change account_state.
    async unlock(id: number): Promise<void> {
        await apiClient.post(`/api/v1/users/${id}/unlock`);
    },

    async requirePasswordReset(id: number): Promise<void> {
        await apiClient.post(`/api/v1/users/${id}/require-password-reset`);
    },

    // Force-logout: revoke all of the user's active sessions (admin force-logout
    // for suspected session/token theft). Does not change account_state.
    async revokeSessions(id: number): Promise<void> {
        await apiClient.post(`/api/v1/users/${id}/revoke-sessions`);
    },

    // Reissue + re-deliver a setup link (ADR-028). Returns the delivery outcome,
    // including the link itself for out-of-band relay.
    async resendSetupLink(id: number): Promise<SetupLinkResult> {
        const response = await apiClient.post(`/api/v1/users/${id}/resend-setup-link`);
        return response.data?.data ?? response.data;
    },

    // Per-user project assignments for the detail page. See UserMembership for what
    // "membership" means here and why (#2781).
    async getMemberships(id: number): Promise<UserMembership[]> {
        const response = await apiClient.get(`/api/v1/users/${id}/memberships`);
        const rows = response.data.data?.memberships ?? response.data.memberships ?? [];
        return rows.map((m: any) => {
            const role = m.role ?? m.Role ?? '';
            return {
                project_id: m.project_id ?? m.ProjectID ?? 0,
                project_name: m.project_name ?? m.ProjectName ?? '',
                role,
                // Fall back to [role] rather than [] so a row always names at least
                // the role it reports — an empty list would read as "no role".
                roles: m.roles ?? m.Roles ?? (role ? [role] : []),
                state: m.state ?? m.State ?? '',
                via_group: m.via_group ?? m.ViaGroup ?? false,
                project_deleted: m.project_deleted ?? m.ProjectDeleted ?? false,
            };
        });
    },

    // Accounts stuck in a restricted state past the window (ADR-025).
    async getStale(params?: { state?: string; days?: number }): Promise<AdminUser[]> {
        const response = await apiClient.get('/api/v1/users/stale', { params });
        return response.data.data?.users ?? response.data.users ?? [];
    },
};
