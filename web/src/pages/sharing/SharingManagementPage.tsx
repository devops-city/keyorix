import { formatDateTime } from '../../utils/datetime';
import { apiErrorMessage } from '../../services/client';
import React, { useState } from 'react';
import {
    ShareIcon,
    UserIcon,
    UserGroupIcon,
    PencilIcon,
    TrashIcon,
    EyeIcon,
    MagnifyingGlassIcon,
} from '@heroicons/react/24/outline';
import {
    useShares,
    useDeleteShare,
    useBulkDeleteShares,
    useUpdateShare,
    expiresAtFromPreset,
} from '../../features/sharing';
import { useUIStore } from '../../store/uiStore';
import { ShareRecord, PaginationState } from '../../types';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Select } from '../../components/ui/Select';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { Dialog } from '../../components/ui/Dialog';

const ITEMS_PER_PAGE = 20;

const RECIPIENT_TYPE_OPTIONS = [
    { value: 'all', label: 'All Types' },
    { value: 'user', label: 'Users' },
    { value: 'group', label: 'Groups' },
];

const PERMISSION_OPTIONS = [
    { value: 'all', label: 'All Permissions' },
    { value: 'read', label: 'Read Only' },
    { value: 'write', label: 'Read & Write' },
];

// Expiry actions offered when editing an existing share.
const EDIT_EXPIRY_OPTIONS = [
    { value: 'keep', label: 'Keep current' },
    { value: 'clear', label: 'No expiry (permanent)' },
    { value: '1h', label: 'In 1 hour' },
    { value: '24h', label: 'In 24 hours' },
    { value: '7d', label: 'In 7 days' },
    { value: '30d', label: 'In 30 days' },
];

// shareExpiry renders a time-bound share's expiry as a coloured badge: permanent
// (no expiry), expired (in the past), or a short "in 3d / 5h / 12m" countdown.
export const shareExpiry = (
    expiresAt: string | undefined,
    now: number = Date.now()
): { label: string; className: string } => {
    if (!expiresAt) {
        return { label: 'Permanent', className: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300' };
    }
    const ms = new Date(expiresAt).getTime() - now;
    if (Number.isNaN(ms)) {
        return { label: 'Permanent', className: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300' };
    }
    if (ms <= 0) {
        return { label: 'Expired', className: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' };
    }
    const mins = Math.floor(ms / 60000);
    let rel: string;
    if (mins < 60) rel = `${Math.max(mins, 1)}m`;
    else if (mins < 60 * 24) rel = `${Math.floor(mins / 60)}h`;
    else rel = `${Math.floor(mins / (60 * 24))}d`;
    return { label: `in ${rel}`, className: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300' };
};

export const SharingManagementPage: React.FC = () => {
    const { openModal, closeModal, activeModal, modalData } = useUIStore();
    const updateShare = useUpdateShare();
    // Edit-share form: the chosen permission and an expiry action (keep current,
    // clear to permanent, or a new duration).
    const editShare = modalData?.share as ShareRecord | undefined;
    const [editPermission, setEditPermission] = useState<'read' | 'write'>('read');
    const [editExpiry, setEditExpiry] = useState('keep');
    React.useEffect(() => {
        if (activeModal === 'edit-share' && editShare) {
            setEditPermission(editShare.permission);
            setEditExpiry('keep');
            updateShare.reset();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [activeModal, editShare?.id]);
    const [selectedItems, setSelectedItems] = useState<Set<number>>(new Set());
    const [bulkActionMode, setBulkActionMode] = useState(false);
    const toggleSelectedItem = (id: number) =>
        setSelectedItems((prev) => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    const clearSelectedItems = () => setSelectedItems(new Set());

    // State for filters and pagination
    const [filters, setFilters] = useState({
        search: '',
        recipientType: 'all',
        permission: 'all',
        secretId: undefined as number | undefined,
    });

    const [pagination, setPagination] = useState<PaginationState>({
        page: 1,
        pageSize: ITEMS_PER_PAGE,
        total: 0,
        totalPages: 0,
    });

    const { data, isLoading, error, refetch } = useShares({
        page: pagination.page,
        pageSize: pagination.pageSize,
        ...(filters.secretId !== undefined ? { secretId: filters.secretId } : {}),
        ...(filters.recipientType !== 'all' ? { recipientType: filters.recipientType as 'user' | 'group' } : {}),
    });

    // Update pagination when data changes
    React.useEffect(() => {
        if (data) {
            setPagination((prev) => ({
                ...prev,
                total: data.total,
                totalPages: data.totalPages,
            }));
        }
    }, [data]);

    const deleteMutation = useDeleteShare();
    const bulkDeleteMutation = useBulkDeleteShares();

    // Handle filter changes
    const handleFilterChange = (key: string, value: any) => {
        setFilters((prev) => ({ ...prev, [key]: value }));
        setPagination((prev) => ({ ...prev, page: 1 })); // Reset to first page
    };

    // Handle search with debouncing
    const [searchInput, setSearchInput] = useState(filters.search);
    React.useEffect(() => {
        const timer = setTimeout(() => {
            handleFilterChange('search', searchInput);
        }, 300);
        return () => clearTimeout(timer);
    }, [searchInput]);

    // Handle pagination
    const handlePageChange = (page: number) => {
        setPagination((prev) => ({ ...prev, page }));
    };

    // Handle individual share actions
    const handleViewSecret = (share: ShareRecord) => {
        openModal('view-secret', { secretId: share.secretId });
    };

    const handleEditShare = (share: ShareRecord) => {
        openModal('edit-share', { share });
    };

    const handleSubmitEditShare = () => {
        if (!editShare) return;
        const args: { id: number; permission: 'read' | 'write'; expiresAt?: string; clearExpiry?: boolean } = {
            id: editShare.id,
            permission: editPermission,
        };
        if (editExpiry === 'clear') {
            args.clearExpiry = true;
        } else if (editExpiry !== 'keep') {
            const iso = expiresAtFromPreset(editExpiry);
            if (iso) args.expiresAt = iso;
        }
        updateShare.mutate(args, {
            onSuccess: () => {
                closeModal();
                refetch();
            },
        });
    };

    const handleDeleteShare = (share: ShareRecord) => {
        openModal('confirm-delete', {
            title: 'Delete Share',
            message: `Are you sure you want to revoke access for "${share.recipientName}"?`,
            onConfirm: () =>
                deleteMutation.mutate(share.id, {
                    onSuccess: () => {
                        closeModal();
                    },
                }),
        });
    };

    const handleBulkDelete = () => {
        if (selectedItems.size === 0) return;

        openModal('confirm-delete', {
            title: 'Delete Multiple Shares',
            message: `Are you sure you want to revoke ${selectedItems.size} share(s)?`,
            onConfirm: () =>
                bulkDeleteMutation.mutate(Array.from(selectedItems) as number[], {
                    onSuccess: () => {
                        clearSelectedItems();
                        setBulkActionMode(false);
                        closeModal();
                    },
                }),
        });
    };

    // Filter shares based on search
    const filteredShares = React.useMemo(() => {
        if (!data?.data) return [];

        let result = [...data.data];

        // Apply client-side search filter
        if (filters.search) {
            const searchLower = filters.search.toLowerCase();
            result = result.filter(
                (share) =>
                    share.recipientName.toLowerCase().includes(searchLower) ||
                    share.createdBy.toLowerCase().includes(searchLower)
            );
        }

        // Apply permission filter
        if (filters.permission !== 'all') {
            result = result.filter((share) => share.permission === filters.permission);
        }

        return result;
    }, [data?.data, filters.search, filters.permission]);

    if (error) {
        return (
            <div className="p-6">
                <Alert
                    type="error"
                    title="Failed to load shares"
                    message={apiErrorMessage(
                        error,
                        'There was an error loading the sharing information. Please try again.'
                    )}
                >
                    <Button variant="outline" size="sm" onClick={() => refetch()}>
                        Retry
                    </Button>
                </Alert>
            </div>
        );
    }

    const sharesContent =
        filteredShares.length === 0 ? (
            <div className="p-8 text-center">
                <div className="text-base-muted dark:text-base-muted mb-4">
                    <ShareIcon className="h-12 w-12 mx-auto" />
                </div>
                <h3 className="text-lg font-medium text-base-primary dark:text-white mb-2">No shares found</h3>
                <p className="text-base-muted dark:text-base-muted">
                    {filters.search || filters.recipientType !== 'all' || filters.permission !== 'all'
                        ? 'Try adjusting your filters.'
                        : 'No secrets have been shared yet.'}
                </p>
            </div>
        ) : (
            <div className="overflow-hidden">
                <table className="min-w-full divide-y divide-base dark:divide-gray-700">
                    <thead className="bg-subtle dark:bg-gray-900">
                        <tr>
                            {bulkActionMode && (
                                <th className="px-6 py-3 text-left">
                                    <input
                                        type="checkbox"
                                        className="rounded-sm border-gray-300 text-blue-600 focus:ring-blue-500"
                                        checked={
                                            filteredShares.length > 0 &&
                                            filteredShares.every((s) => selectedItems.has(s.id))
                                        }
                                        onChange={(e) => {
                                            if (e.target.checked) {
                                                filteredShares.forEach((s) => toggleSelectedItem(s.id));
                                            } else {
                                                clearSelectedItems();
                                            }
                                        }}
                                    />
                                </th>
                            )}
                            <th className="px-6 py-3 text-left text-xs font-medium text-base-muted dark:text-base-muted uppercase tracking-wider">
                                Secret
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-base-muted dark:text-base-muted uppercase tracking-wider">
                                Recipient
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-base-muted dark:text-base-muted uppercase tracking-wider">
                                Permission
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-base-muted dark:text-base-muted uppercase tracking-wider">
                                Shared By
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-base-muted dark:text-base-muted uppercase tracking-wider">
                                Created
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-base-muted dark:text-base-muted uppercase tracking-wider">
                                Expires
                            </th>
                            <th className="px-6 py-3 text-right text-xs font-medium text-base-muted dark:text-base-muted uppercase tracking-wider">
                                Actions
                            </th>
                        </tr>
                    </thead>
                    <tbody className="bg-surface dark:bg-gray-800 divide-y divide-base dark:divide-gray-700">
                        {filteredShares.map((share) => (
                            <tr key={share.id} className="hover:bg-subtle dark:hover:bg-gray-700">
                                {bulkActionMode && (
                                    <td className="px-6 py-4">
                                        <input
                                            type="checkbox"
                                            className="rounded-sm border-gray-300 text-blue-600 focus:ring-blue-500"
                                            checked={selectedItems.has(share.id)}
                                            onChange={() => toggleSelectedItem(share.id)}
                                        />
                                    </td>
                                )}
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm font-medium text-base-primary dark:text-white">
                                        Secret #{share.secretId}
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="flex items-center">
                                        <div className="shrink-0 mr-3">
                                            {share.recipientType === 'user' ? (
                                                <UserIcon className="h-5 w-5 text-base-muted" />
                                            ) : (
                                                <UserGroupIcon className="h-5 w-5 text-base-muted" />
                                            )}
                                        </div>
                                        <div>
                                            <div className="text-sm font-medium text-base-primary dark:text-white">
                                                {share.recipientName}
                                            </div>
                                            <div className="text-xs text-base-muted dark:text-base-muted">
                                                {share.recipientType}
                                            </div>
                                        </div>
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span
                                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                            share.permission === 'write'
                                                ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                                                : 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                                        }`}
                                    >
                                        {share.permission === 'write' ? 'Read & Write' : 'Read Only'}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted dark:text-base-muted">
                                    {share.createdBy}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted dark:text-base-muted">
                                    <div>{formatDateTime(share.createdAt)}</div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    {(() => {
                                        const e = shareExpiry(share.expiresAt);
                                        return (
                                            <span
                                                className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${e.className}`}
                                                title={share.expiresAt ?? 'No expiry'}
                                            >
                                                {e.label}
                                            </span>
                                        );
                                    })()}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <div className="flex items-center justify-end space-x-2">
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => handleViewSecret(share)}
                                            title="View secret"
                                        >
                                            <EyeIcon className="h-4 w-4" />
                                        </Button>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => handleEditShare(share)}
                                            title="Edit permissions"
                                        >
                                            <PencilIcon className="h-4 w-4" />
                                        </Button>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => handleDeleteShare(share)}
                                            title="Revoke access"
                                            className="text-red-600 hover:text-red-700"
                                        >
                                            <TrashIcon className="h-4 w-4" />
                                        </Button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>

                {/* Pagination */}
                {pagination.totalPages > 1 && (
                    <div className="bg-surface dark:bg-gray-800 px-4 py-3 border-t border-base dark:border-gray-700 sm:px-6">
                        <div className="flex items-center justify-between">
                            <div className="flex-1 flex justify-between sm:hidden">
                                <Button
                                    variant="outline"
                                    onClick={() => handlePageChange(pagination.page - 1)}
                                    disabled={pagination.page === 1}
                                >
                                    Previous
                                </Button>
                                <Button
                                    variant="outline"
                                    onClick={() => handlePageChange(pagination.page + 1)}
                                    disabled={pagination.page === pagination.totalPages}
                                >
                                    Next
                                </Button>
                            </div>
                            <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                                <div>
                                    <p className="text-sm text-base-secondary dark:text-base-muted">
                                        Showing{' '}
                                        <span className="font-medium">
                                            {(pagination.page - 1) * pagination.pageSize + 1}
                                        </span>{' '}
                                        to{' '}
                                        <span className="font-medium">
                                            {Math.min(pagination.page * pagination.pageSize, pagination.total)}
                                        </span>{' '}
                                        of <span className="font-medium">{pagination.total}</span> results
                                    </p>
                                </div>
                                <div>
                                    <nav className="relative z-0 inline-flex rounded-md shadow-xs -space-x-px">
                                        <Button
                                            variant="outline"
                                            onClick={() => handlePageChange(pagination.page - 1)}
                                            disabled={pagination.page === 1}
                                            className="rounded-l-md"
                                        >
                                            Previous
                                        </Button>
                                        {Array.from({ length: Math.min(5, pagination.totalPages) }, (_, i) => {
                                            const page = i + 1;
                                            return (
                                                <Button
                                                    key={page}
                                                    variant={pagination.page === page ? 'default' : 'outline'}
                                                    onClick={() => handlePageChange(page)}
                                                    className="rounded-none"
                                                >
                                                    {page}
                                                </Button>
                                            );
                                        })}
                                        <Button
                                            variant="outline"
                                            onClick={() => handlePageChange(pagination.page + 1)}
                                            disabled={pagination.page === pagination.totalPages}
                                            className="rounded-r-md"
                                        >
                                            Next
                                        </Button>
                                    </nav>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        );

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-semibold text-base-primary dark:text-white">Sharing Management</h1>
                    <p className="mt-1 text-sm text-base-muted dark:text-base-muted">
                        Manage secret sharing permissions and access
                    </p>
                </div>
                <div className="flex items-center space-x-3">
                    {bulkActionMode && (
                        <div className="flex items-center space-x-2">
                            <span className="text-sm text-base-muted dark:text-base-muted">
                                {selectedItems.size} selected
                            </span>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={handleBulkDelete}
                                disabled={selectedItems.size === 0}
                                className="text-red-600 hover:text-red-700"
                            >
                                <TrashIcon className="h-4 w-4 mr-1" />
                                Revoke
                            </Button>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => {
                                    setBulkActionMode(false);
                                    clearSelectedItems();
                                }}
                            >
                                Cancel
                            </Button>
                        </div>
                    )}
                    <Button variant="outline" size="sm" onClick={() => setBulkActionMode(!bulkActionMode)}>
                        Select
                    </Button>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-surface dark:bg-gray-800 rounded-lg border border-base dark:border-gray-700 p-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {/* Search */}
                    <div className="lg:col-span-2">
                        <Input
                            type="text"
                            placeholder="Search recipients or creators..."
                            value={searchInput}
                            onChange={(e) => setSearchInput(e.target.value)}
                            icon={MagnifyingGlassIcon}
                        />
                    </div>

                    {/* Recipient Type Filter */}
                    <div>
                        <Select
                            value={filters.recipientType}
                            onChange={(e) => handleFilterChange('recipientType', e.target.value)}
                            options={RECIPIENT_TYPE_OPTIONS}
                            placeholder="Recipient Type"
                        />
                    </div>

                    {/* Permission Filter */}
                    <div>
                        <Select
                            value={filters.permission}
                            onChange={(e) => handleFilterChange('permission', e.target.value)}
                            options={PERMISSION_OPTIONS}
                            placeholder="Permission"
                        />
                    </div>
                </div>

                {/* Active Filters */}
                {(filters.search || filters.recipientType !== 'all' || filters.permission !== 'all') && (
                    <div className="mt-4 flex items-center space-x-2">
                        <span className="text-sm text-base-muted dark:text-base-muted">Active filters:</span>
                        {filters.search && (
                            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                Search: {filters.search}
                            </span>
                        )}
                        {filters.recipientType !== 'all' && (
                            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                                Type: {filters.recipientType}
                            </span>
                        )}
                        {filters.permission !== 'all' && (
                            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
                                Permission: {filters.permission}
                            </span>
                        )}
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                                setFilters({
                                    search: '',
                                    recipientType: 'all',
                                    permission: 'all',
                                    secretId: undefined,
                                });
                                setSearchInput('');
                            }}
                            className="text-xs"
                        >
                            Clear all
                        </Button>
                    </div>
                )}
            </div>

            {/* Shares List */}
            <div className="bg-surface dark:bg-gray-800 rounded-lg border border-base dark:border-gray-700">
                {isLoading ? (
                    <div className="p-8">
                        <Loading />
                    </div>
                ) : (
                    sharesContent
                )}
            </div>

            <Modal
                isOpen={activeModal === 'edit-share'}
                onClose={closeModal}
                title={editShare ? `Edit share — ${editShare.recipientName}` : 'Edit share'}
                size="sm"
            >
                <div className="space-y-4">
                    {updateShare.isError && (
                        <Alert
                            type="error"
                            title="Error"
                            message={
                                updateShare.error instanceof Error
                                    ? updateShare.error.message
                                    : 'Failed to update share.'
                            }
                        />
                    )}
                    <div>
                        <label
                            htmlFor="edit-permission-select"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Permission
                        </label>
                        <Select
                            id="edit-permission-select"
                            value={editPermission}
                            onChange={(e) => setEditPermission(e.target.value as 'read' | 'write')}
                            options={[
                                { value: 'read', label: 'Read Only' },
                                { value: 'write', label: 'Read & Write' },
                            ]}
                            disabled={updateShare.isPending}
                        />
                    </div>
                    <div>
                        <label
                            htmlFor="edit-expiry-select"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Access expires
                        </label>
                        <Select
                            id="edit-expiry-select"
                            value={editExpiry}
                            onChange={(e) => setEditExpiry(e.target.value)}
                            options={EDIT_EXPIRY_OPTIONS}
                            disabled={updateShare.isPending}
                        />
                        {editShare?.expiresAt && editExpiry === 'keep' && (
                            <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                                Currently expires {formatDateTime(editShare.expiresAt)}.
                            </p>
                        )}
                    </div>
                    <div
                        className="flex items-center justify-end space-x-3 pt-4 border-t"
                        style={{ borderColor: 'var(--border)' }}
                    >
                        <Button variant="outline" onClick={closeModal} disabled={updateShare.isPending}>
                            Cancel
                        </Button>
                        <Button onClick={handleSubmitEditShare} disabled={updateShare.isPending}>
                            {updateShare.isPending ? 'Saving…' : 'Save'}
                        </Button>
                    </div>
                </div>
            </Modal>

            <Dialog
                isOpen={activeModal === 'confirm-delete'}
                onClose={closeModal}
                title={modalData?.title ?? ''}
                message={modalData?.message ?? ''}
                onConfirm={modalData?.onConfirm}
                type="danger"
                confirmText="Revoke"
                loading={deleteMutation.isPending || bulkDeleteMutation.isPending}
            />
        </div>
    );
};
