import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, ShareRecord, ShareFormData } from '../types';
import { API_ENDPOINTS } from '../constants';

// buildUpdateShareBody maps the edit-share form into the PUT /shares/{id} payload.
// Only the requested change is sent: clear_expiry to make a share permanent, or
// expires_at to set/extend/shorten it; sending neither preserves the current expiry.
export const buildUpdateShareBody = (data: {
    permission: 'read' | 'write';
    expiresAt?: string;
    clearExpiry?: boolean;
}): { permission: 'read' | 'write'; clear_expiry?: boolean; expires_at?: string } => ({
    permission: data.permission,
    ...(data.clearExpiry ? { clear_expiry: true } : {}),
    ...(data.expiresAt ? { expires_at: data.expiresAt } : {}),
});

// ShareRecipient is one row of GET /projects/{id}/share-recipients: an active member
// of the project the caller can share with. email is present only when the caller may
// already read the project's member emails (users.read at the project).
export interface ShareRecipient {
    id: number;
    username: string;
    display_name: string;
    email?: string;
}

export interface ShareRecipientPage {
    recipients: ShareRecipient[];
    total: number;
    page: number;
    page_size: number;
}

export const sharingApi = {
    // searchRecipients looks recipients up among the secret's project members
    // (SHARE-2). Unlike GET /users it needs no global permission, so a project-only
    // admin can find who to share with.
    async searchRecipients(
        projectId: number,
        params: { q: string; page?: number; pageSize?: number }
    ): Promise<ShareRecipientPage> {
        const response = await apiClient.get<ApiResponse<ShareRecipientPage>>(
            API_ENDPOINTS.SHARING.RECIPIENTS(projectId),
            {
                params: {
                    q: params.q,
                    ...(params.page ? { page: params.page } : {}),
                    ...(params.pageSize ? { page_size: params.pageSize } : {}),
                },
            }
        );
        return response.data.data;
    },

    async list(params?: {
        page?: number;
        pageSize?: number;
        secretId?: number;
        recipientType?: 'user' | 'group';
    }): Promise<PaginatedResponse<ShareRecord>> {
        const response = await apiClient.get<ApiResponse<PaginatedResponse<ShareRecord>>>(API_ENDPOINTS.SHARING.LIST, {
            params,
        });
        return response.data.data;
    },

    async get(id: number): Promise<ShareRecord> {
        const response = await apiClient.get<ApiResponse<ShareRecord>>(API_ENDPOINTS.SHARING.GET(id));
        return response.data.data;
    },

    async create(data: ShareFormData & { secretId: number }): Promise<ShareRecord> {
        const response = await apiClient.post<ApiResponse<ShareRecord>>(API_ENDPOINTS.SHARING.CREATE(data.secretId), {
            recipient_id: data.recipientId,
            is_group: data.recipientType === 'group',
            permission: data.permission,
            // Only send expires_at for a time-bound share; omit it for a permanent one.
            ...(data.expiresAt ? { expires_at: data.expiresAt } : {}),
        });
        return response.data.data;
    },

    // update changes a share's permission and, optionally, its time-bound expiry:
    // expiresAt (ISO) sets/extends/shortens it; clearExpiry makes it permanent; sending
    // neither preserves the current expiry. The server validates a future expiry.
    async update(
        id: number,
        data: { permission: 'read' | 'write'; expiresAt?: string; clearExpiry?: boolean }
    ): Promise<ShareRecord> {
        const response = await apiClient.put<ApiResponse<ShareRecord>>(
            API_ENDPOINTS.SHARING.UPDATE(id),
            buildUpdateShareBody(data)
        );
        return response.data.data;
    },

    async delete(id: number): Promise<void> {
        await apiClient.delete(API_ENDPOINTS.SHARING.DELETE(id));
    },

    async selfRemove(id: number): Promise<void> {
        await apiClient.post(API_ENDPOINTS.SHARING.SELF_REMOVE(id));
    },
};
