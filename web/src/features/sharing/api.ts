import { useQuery, useMutation, keepPreviousData } from '@tanstack/react-query';
import { sharingApi } from '../../services/sharing';
import { usersApi } from '../../services/users';
import { queryKeys, invalidateQueries } from '../../lib/queryClient';
import { ShareFormData } from '../../types';

export const useShares = (params?: {
    page?: number;
    pageSize?: number;
    secretId?: number;
    recipientType?: 'user' | 'group';
}) => {
    return useQuery({
        queryKey: queryKeys.sharing.list(params),
        queryFn: () => sharingApi.list(params),
        placeholderData: keepPreviousData,
    });
};

export const useDeleteShare = () => {
    return useMutation({
        mutationFn: (shareId: number) => sharingApi.delete(shareId),
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};

export const useBulkDeleteShares = () => {
    return useMutation({
        mutationFn: async (shareIds: number[]) => {
            await Promise.all(shareIds.map((id) => sharingApi.delete(id)));
            return shareIds;
        },
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};

// useUpdateShare changes a share's permission and/or its time-bound expiry.
export const useUpdateShare = () => {
    return useMutation({
        mutationFn: ({
            id,
            permission,
            expiresAt,
            clearExpiry,
        }: {
            id: number;
            permission: 'read' | 'write';
            expiresAt?: string;
            clearExpiry?: boolean;
        }) =>
            sharingApi.update(id, {
                permission,
                ...(expiresAt ? { expiresAt } : {}),
                ...(clearExpiry ? { clearExpiry } : {}),
            }),
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};

export const useCreateShare = () => {
    return useMutation({
        mutationFn: (data: ShareFormData & { secretId: number }) => sharingApi.create(data),
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};

// Plain async function — called imperatively inside form submit handlers.
// Lives here so components don't import directly from services/.
export const searchRecipients = (query: string) => usersApi.search(query);

// searchShareRecipients lists the active members of the secret's project the caller
// can share with (GET /projects/{id}/share-recipients, SHARE-2). It needs secrets.write
// in that project, not the global users.read GET /users needs.
export const searchShareRecipients = (projectId: number, query: string, pageSize = 8) =>
    sharingApi.searchRecipients(projectId, { q: query, pageSize });

// Composite mutation: share with the identity already verified in the UI
// (recipientId, captured when the caller picked a specific user from the
// autocomplete dropdown), falling back to a fresh username search only when
// no id was supplied. Resolving by username string at submit time would let
// a username reassigned/renamed between selection and submit silently
// redirect the share to a different account than the one the sharer picked.
export const useShareSecret = (secretId: number) => {
    return useMutation({
        mutationFn: async ({
            username,
            recipientId,
            permission,
            expiresAt,
        }: {
            username: string;
            recipientId?: number;
            permission: 'read' | 'write';
            expiresAt?: string;
        }) => {
            let recipient: { id: number; type: 'user' | 'group' };
            if (recipientId != null) {
                recipient = { id: recipientId, type: 'user' };
            } else {
                const results = await usersApi.search(username.trim());
                const match = results.find((r) => r.name.toLowerCase() === username.trim().toLowerCase());
                if (!match) throw new Error(`User "${username}" not found.`);
                recipient = match;
            }
            return sharingApi.create({
                secretId,
                recipientType: recipient.type,
                recipientId: recipient.id,
                permission,
                ...(expiresAt ? { expiresAt } : {}),
            });
        },
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};
