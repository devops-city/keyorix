import { useCan } from '../../features/auth/useCan';
import React from 'react';
import { useSearchParams } from 'react-router';
import {
    MagnifyingGlassIcon,
    PlusIcon,
    FunnelIcon,
    ChevronLeftIcon,
    ChevronRightIcon,
    ShareIcon,
    TrashIcon,
} from '@heroicons/react/24/outline';
import { SecretPolicy, SecretType } from '../../types';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Select } from '../../components/ui/Select';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { apiErrorMessage } from '../../services/client';
import {
    SecretDetailView,
    useSecretsList,
    useSecretReveal,
    SecretTableRow,
    useBulkClassifySecrets,
    useSetAutoRotate,
    useSecretPolicy,
} from '../../features/secrets';
import { ShareSecretModal } from '../../features/sharing';
import { useProjects, useProjectEnvironments } from '../../features/projects';
import { isPatternSafe, testPatternSafely } from '../../utils/safeRegex';
import { generateSecret } from '../../utils';
import { SECRET_TYPES } from '../../features/secrets/listConstants';
const SORT_OPTIONS = [
    { value: 'name_asc', label: 'Name (A-Z)' },
    { value: 'name_desc', label: 'Name (Z-A)' },
    { value: 'modified_desc', label: 'Recently Modified' },
    { value: 'modified_asc', label: 'Oldest Modified' },
    { value: 'type_asc', label: 'Type (A-Z)' },
    { value: 'type_desc', label: 'Type (Z-A)' },
    { value: 'created_desc', label: 'Recently Created' },
    { value: 'created_asc', label: 'Oldest Created' },
    { value: 'expiry_asc', label: 'Expiring Soonest' },
    { value: 'expiry_desc', label: 'Expiring Latest' },
];
const PAGE_SIZE_OPTIONS = [
    { value: '10', label: '10 per page' },
    { value: '20', label: '20 per page' },
    { value: '50', label: '50 per page' },
    { value: '100', label: '100 per page' },
];

// secretNameError returns a client-side validation message, or '' when ok.
// The server re-validates regardless — this just gives faster feedback.
function secretNameError(namePolicy: SecretPolicy['name'] | undefined, name: string): string {
    if (!namePolicy?.enabled) return '';
    if (namePolicy.max_length && name.length > namePolicy.max_length) {
        return `Name exceeds the ${namePolicy.max_length}-character maximum.`;
    }
    if (namePolicy.pattern) {
        // testPatternSafely refuses to run patterns that look like
        // catastrophic-backtracking shapes (or oversized input) -- see
        // src/utils/safeRegex.ts for why a same-thread timeout can't
        // substitute for that check.
        const result = testPatternSafely(namePolicy.pattern, name);
        if (!result.skipped && !result.matches) {
            return `Name must match the pattern ${namePolicy.pattern}.`;
        }
    }
    return '';
}

function filterSecretsForDisplay(secrets: any[], urlFilter: string | null): any[] {
    if (urlFilter === 'expiring') {
        return secrets.filter((s: any) => s.Expiration != null);
    }
    return secrets;
}

type ModalDefaults = {
    editName: string;
    editType: SecretType;
    rotateValue: string;
    arEnabled: boolean;
    arLength: string;
    arCharset: string;
    arBackend: string;
    arRef: string;
};

function buildModalDefaults(activeModal: string | null, secret: any): Partial<ModalDefaults> {
    if (activeModal === 'edit-secret' && secret) {
        return { editName: secret.name, editType: secret.type as SecretType, rotateValue: '' };
    }
    if (activeModal === 'rotate-secret') {
        return { rotateValue: generateSecret() };
    }
    if (activeModal === 'auto-rotate') {
        return { arEnabled: true, arLength: '', arCharset: '', arBackend: '', arRef: '' };
    }
    return {};
}

type ModalDefaultSetters = {
    setEditName: (v: string) => void;
    setEditType: (v: SecretType) => void;
    setRotateValue: (v: string) => void;
    setArEnabled: (v: boolean) => void;
    setArLength: (v: string) => void;
    setArCharset: (v: string) => void;
    setArBackend: (v: string) => void;
    setArRef: (v: string) => void;
    setEditValue: (v: string) => void;
};

function applyModalDefaults(activeModal: string | null, secret: any, setters: ModalDefaultSetters): void {
    const defaults = buildModalDefaults(activeModal, secret ?? null);
    if (defaults.editName !== undefined) setters.setEditName(defaults.editName);
    if (defaults.editType !== undefined) setters.setEditType(defaults.editType);
    if (defaults.rotateValue !== undefined) setters.setRotateValue(defaults.rotateValue);
    if (defaults.arEnabled !== undefined) setters.setArEnabled(defaults.arEnabled);
    if (defaults.arLength !== undefined) setters.setArLength(defaults.arLength);
    if (defaults.arCharset !== undefined) setters.setArCharset(defaults.arCharset);
    if (defaults.arBackend !== undefined) setters.setArBackend(defaults.arBackend);
    if (defaults.arRef !== undefined) setters.setArRef(defaults.arRef);
    if (activeModal === 'edit-secret' && secret) setters.setEditValue('');
}

function resolveValidEnvId(envs: { id: number }[], currentEnvId: number): number | null {
    const stillValid = envs.some((e) => e.id === currentEnvId);
    if (stillValid) return null;
    return envs[0]?.id ?? 0;
}

function resolveNameHint(policy: SecretPolicy['name'] | undefined): string {
    if (!policy?.enabled) return '';
    return [
        policy.pattern ? `must match ${policy.pattern}` : '',
        policy.max_length ? `max ${policy.max_length} chars` : '',
    ]
        .filter(Boolean)
        .join('; ');
}

function checkNamePatternUnsafe(policy: SecretPolicy['name'] | undefined): boolean {
    return !!policy?.enabled && !!policy.pattern && !isPatternSafe(policy.pattern);
}

// ─── Section components ─────────────────────────────────────────────────────

type ListState = ReturnType<typeof useSecretsList>;

interface SecretsPageHeaderProps {
    selectedItems: Set<number>;
    bulkClassifyPending: boolean;
    onBulkClassify: (level: string) => void;
    onBulkDelete: () => void;
    onClearSelection: () => void;
    onCreateClick: () => void;
}

const SecretsPageHeader: React.FC<SecretsPageHeaderProps> = ({
    selectedItems,
    bulkClassifyPending,
    onBulkClassify,
    onBulkDelete,
    onClearSelection,
    onCreateClick,
}) => {
    const can = useCan();
    return (
        <div className="flex items-center justify-between">
            <div>
                <h1 className="text-2xl font-semibold text-base-primary ">Secrets</h1>
                <p className="mt-1 text-sm text-base-muted ">Manage your secrets and access controls</p>
            </div>
            <div className="flex items-center space-x-3">
                {selectedItems.size > 0 && (
                    <div className="flex items-center space-x-2">
                        <span className="text-sm text-base-muted">{selectedItems.size} selected</span>
                        <Select
                            aria-label="Classify selected"
                            value=""
                            disabled={bulkClassifyPending || !can.writeSecrets}
                            onChange={(e) => {
                                const level = e.target.value;
                                if (!level) return;
                                onBulkClassify(level);
                            }}
                            options={[
                                { value: '', label: 'Classify as…' },
                                { value: 'public', label: 'Public' },
                                { value: 'internal', label: 'Internal' },
                                { value: 'confidential', label: 'Confidential' },
                                { value: 'restricted', label: 'Restricted' },
                                { value: 'unclassified', label: 'Unclassified' },
                            ]}
                        />
                        <Button
                            variant="outline"
                            size="sm"
                            disabled
                            title="Share each secret individually — bulk sharing is not supported"
                        >
                            <ShareIcon className="h-4 w-4 mr-1" />
                            Share
                        </Button>
                        {can.deleteSecrets && (
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={onBulkDelete}
                                disabled={selectedItems.size === 0}
                                className="text-red-600 hover:text-red-700"
                            >
                                <TrashIcon className="h-4 w-4 mr-1" />
                                Delete
                            </Button>
                        )}
                        <Button variant="ghost" size="sm" onClick={onClearSelection}>
                            Clear
                        </Button>
                    </div>
                )}
                {can.writeSecrets && (
                    <Button data-testid="create-secret-button" onClick={onCreateClick} className="flex items-center">
                        <PlusIcon className="h-4 w-4 mr-2" />
                        New Secret
                    </Button>
                )}
            </div>
        </div>
    );
};

interface SecretsFilterBarProps {
    searchInput: string;
    onSearchChange: (v: string) => void;
    filters: ListState['filters'];
    onFilterChange: ListState['handleFilterChange'];
    environments: ListState['environments'];
    sortBy: string;
    onSortChange: (v: string) => void;
    pageSize: number;
    onPageSizeChange: (v: number) => void;
    showAdvancedFilters: boolean;
    onToggleAdvanced: () => void;
    hasActiveFilters: boolean;
    onClearFilters: () => void;
    isFetching: boolean;
}

const SecretsFilterBar: React.FC<SecretsFilterBarProps> = ({
    searchInput,
    onSearchChange,
    filters,
    onFilterChange,
    environments,
    sortBy,
    onSortChange,
    pageSize,
    onPageSizeChange,
    showAdvancedFilters,
    onToggleAdvanced,
    hasActiveFilters,
    onClearFilters,
    isFetching,
}) => (
    <div className="bg-surface rounded-lg border border-base  p-4">
        <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
                <div className="lg:col-span-2">
                    <Input
                        type="text"
                        placeholder="Search by name, type, or tags..."
                        value={searchInput}
                        onChange={(e) => onSearchChange(e.target.value)}
                        icon={MagnifyingGlassIcon}
                    />
                </div>
                <Select
                    value={filters.type}
                    onChange={(e) => onFilterChange('type', e.target.value)}
                    options={SECRET_TYPES}
                />
                <Select
                    value={filters.classification || 'all'}
                    onChange={(e) => onFilterChange('classification', e.target.value === 'all' ? '' : e.target.value)}
                    options={[
                        { value: 'all', label: 'All Classifications' },
                        { value: 'unclassified', label: 'Unclassified' },
                        { value: 'public', label: 'Public' },
                        { value: 'internal', label: 'Internal' },
                        { value: 'confidential', label: 'Confidential' },
                        { value: 'restricted', label: 'Restricted' },
                    ]}
                />
                <Select
                    value={filters.environment || 'all'}
                    onChange={(e) => onFilterChange('environment', e.target.value === 'all' ? '' : e.target.value)}
                    options={[
                        { value: 'all', label: 'All Environments' },
                        // `environments` is the GLOBAL, cross-project list (useSecretsList's
                        // query key is `['environments']`, no project scope), and this
                        // filter is itself name-based (onFilterChange('environment', name)
                        // filters this page's already-cross-project secrets list by
                        // environment NAME, not by one specific environment row's id) --
                        // so every project's own "development"/"staging"/"production" rows
                        // collapse to the SAME filter value. Deduping by name before
                        // mapping to options is required, not cosmetic: Select (components/
                        // ui/Select.tsx) keys each <option> by `option.value`, so two (or,
                        // with more than two projects, three-plus) environment rows sharing
                        // a name previously produced duplicate React keys ("Encountered two
                        // children with the same key, `development`") -- found live by
                        // SESSION-I's web/e2e/real/pages.spec.ts running against a real
                        // backend with more than one project, which every existing mocked
                        // spec (web/e2e/*.spec.ts) never exercises with more than one.
                        ...Array.from(new Set(environments.map((e) => e.name))).map((name) => ({
                            value: name,
                            label: name.charAt(0).toUpperCase() + name.slice(1),
                        })),
                    ]}
                />
                <Select
                    value={sortBy}
                    onChange={(e) => onSortChange(e.target.value)}
                    options={SORT_OPTIONS}
                    placeholder="Sort by"
                />
                <Select
                    value={String(pageSize)}
                    onChange={(e) => onPageSizeChange(Number(e.target.value))}
                    options={PAGE_SIZE_OPTIONS}
                />
                <Button variant="outline" onClick={onToggleAdvanced} className="w-full">
                    <FunnelIcon className="h-4 w-4 mr-2" />
                    {showAdvancedFilters ? 'Hide' : 'More'} Filters
                </Button>
            </div>
            {showAdvancedFilters && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pt-4 border-t border-base ">
                    {/* Project filter — Phase 3: replace with project selector dropdown */}
                </div>
            )}
            {/* Tag filter hidden — tags not yet implemented on secrets */}
            {hasActiveFilters && (
                <div className="flex items-center justify-end pt-4 border-t border-base ">
                    <Button variant="ghost" size="sm" onClick={onClearFilters} className="text-xs">
                        Clear all
                    </Button>
                </div>
            )}
            {isFetching && (
                <div className="flex items-center justify-center py-2">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                    <span className="ml-2 text-sm text-base-muted ">Updating results...</span>
                </div>
            )}
        </div>
    </div>
);

const ExpiringFilterBanner: React.FC = () => (
    <div
        className="flex items-center justify-between px-4 py-2.5 rounded-lg border"
        style={{
            backgroundColor: 'rgba(217,119,6,0.06)',
            borderColor: 'rgba(217,119,6,0.30)',
            color: '#92400e',
        }}
    >
        <span className="text-sm font-medium" style={{ color: 'inherit' }}>
            Showing secrets with expiration set
        </span>
        <button
            type="button"
            onClick={() => window.history.replaceState({}, '', window.location.pathname)}
            className="text-sm font-medium underline underline-offset-2 hover:opacity-75 transition-opacity ml-4"
            style={{ color: 'inherit' }}
        >
            ✕ Clear filter
        </button>
    </div>
);

interface SecretsTableProps {
    isLoading: boolean;
    displayedSecrets: any[];
    hasActiveFilters: boolean;
    onCreateClick: () => void;
    selectedItems: Set<number>;
    toggleSelectedItem: (id: number) => void;
    clearSelectedItems: () => void;
    onView: (secret: any) => void;
    onEdit: (secret: any) => void;
    onDelete: (secret: any) => void;
    onShare: (secret: any) => void;
    onRotate: (secret: any) => void;
    onAutoRotate: (secret: any) => void;
    reveal: ReturnType<typeof useSecretReveal>;
    pagination: ListState['pagination'];
    onPageChange: (page: number) => void;
}

const SecretsTable: React.FC<SecretsTableProps> = ({
    isLoading,
    displayedSecrets,
    hasActiveFilters,
    onCreateClick,
    selectedItems,
    toggleSelectedItem,
    clearSelectedItems,
    onView,
    onEdit,
    onDelete,
    onShare,
    onRotate,
    onAutoRotate,
    reveal,
    pagination,
    onPageChange,
}) => {
    const canCreate = useCan().writeSecrets;
    if (isLoading) {
        return (
            <div className="p-8">
                <Loading />
            </div>
        );
    }
    if (displayedSecrets.length === 0) {
        return (
            <div className="p-8 text-center">
                <FunnelIcon className="h-12 w-12 mx-auto text-base-muted  mb-4" />
                <h3 className="text-lg font-medium text-base-primary  mb-2">No secrets found</h3>
                <p className="text-base-muted  mb-4">
                    {hasActiveFilters
                        ? 'Try adjusting your filters or search terms.'
                        : canCreate
                          ? 'Get started by creating your first secret.'
                          : 'There are no secrets here that you can see.'}
                </p>
                {!hasActiveFilters && canCreate && (
                    <Button data-testid="create-secret-button" onClick={onCreateClick}>
                        <PlusIcon className="h-4 w-4 mr-2" />
                        Create Secret
                    </Button>
                )}
            </div>
        );
    }
    return (
        <div className="overflow-x-auto">
            <table data-testid="secrets-table" className="min-w-full divide-y divide-base dark:divide-gray-700">
                <thead className="bg-subtle dark:bg-gray-900">
                    <tr>
                        <th className="px-4 py-3 text-left w-10">
                            <input
                                type="checkbox"
                                className="rounded-sm border-gray-300 text-blue-600 focus:ring-blue-500"
                                checked={
                                    displayedSecrets.length > 0 &&
                                    displayedSecrets.every((s) => selectedItems.has(s.id))
                                }
                                onChange={(e) => {
                                    if (e.target.checked) displayedSecrets.forEach((s) => toggleSelectedItem(s.id));
                                    else clearSelectedItems();
                                }}
                            />
                        </th>
                        {['Name', 'Type', 'Classification', 'Environment', 'Sharing', 'Modified'].map((h) => (
                            <th
                                key={h}
                                className="px-6 py-3 text-left text-xs font-medium text-base-muted  uppercase tracking-wider"
                            >
                                {h}
                            </th>
                        ))}
                        <th className="px-6 py-3 text-right text-xs font-medium text-base-muted  uppercase tracking-wider min-w-[180px]">
                            Actions
                        </th>
                    </tr>
                </thead>
                <tbody className="bg-surface divide-y divide-base dark:divide-gray-700">
                    {displayedSecrets.map((secret) => (
                        <SecretTableRow
                            key={secret.id}
                            secret={secret}
                            isSelected={selectedItems.has(secret.id)}
                            onToggleSelect={toggleSelectedItem}
                            onView={onView}
                            onEdit={onEdit}
                            onDelete={onDelete}
                            onShare={onShare}
                            onRotate={onRotate}
                            onAutoRotate={onAutoRotate}
                            onCopy={reveal.handleCopySecretValue}
                            copyingId={reveal.copyingSecretId}
                            copiedId={reveal.copiedSecretId}
                            copyErrorId={reveal.copyErrorId}
                            copyError={reveal.copyError}
                        />
                    ))}
                </tbody>
            </table>

            {pagination.totalPages > 1 && (
                <div className="px-4 py-3 border-t border-base  flex items-center justify-between">
                    <p className="text-sm text-base-secondary dark:text-base-muted">
                        Showing <span className="font-medium">{(pagination.page - 1) * pagination.pageSize + 1}</span>{' '}
                        to{' '}
                        <span className="font-medium">
                            {Math.min(pagination.page * pagination.pageSize, pagination.total)}
                        </span>{' '}
                        of <span className="font-medium">{pagination.total}</span> results
                    </p>
                    <div className="flex items-center space-x-2">
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => onPageChange(pagination.page - 1)}
                            disabled={pagination.page === 1}
                        >
                            <ChevronLeftIcon className="h-4 w-4" />
                        </Button>
                        <span className="text-sm text-base-secondary dark:text-base-muted">
                            Page {pagination.page} of {pagination.totalPages}
                        </span>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => onPageChange(pagination.page + 1)}
                            disabled={pagination.page === pagination.totalPages}
                        >
                            <ChevronRightIcon className="h-4 w-4" />
                        </Button>
                    </div>
                </div>
            )}
        </div>
    );
};

interface ViewSecretModalProps {
    secret: any;
    onClose: () => void;
    onEdit: (secret: any) => void;
    onShare: (secret: any) => void;
    onDelete: (secret: any) => void;
}

const ViewSecretModal: React.FC<ViewSecretModalProps> = ({ secret, onClose, onEdit, onShare, onDelete }) => (
    <Modal isOpen={secret !== null} onClose={onClose} size="xl">
        {secret && (
            <SecretDetailView
                secret={secret}
                onClose={onClose}
                onEdit={(s) => {
                    onClose();
                    onEdit(s);
                }}
                onShare={(s) => {
                    onClose();
                    onShare(s);
                }}
                onDelete={(s) => {
                    onClose();
                    onDelete(s);
                }}
            />
        )}
    </Modal>
);

interface EditSecretModalProps {
    isOpen: boolean;
    secret: any;
    onClose: () => void;
    editName: string;
    setEditName: (v: string) => void;
    editType: SecretType;
    setEditType: (v: SecretType) => void;
    editValue: string;
    setEditValue: (v: string) => void;
    mutation: ListState['editMutation'];
}

const EditSecretModal: React.FC<EditSecretModalProps> = ({
    isOpen,
    secret,
    onClose,
    editName,
    setEditName,
    editType,
    setEditType,
    editValue,
    setEditValue,
    mutation,
}) => (
    <Modal isOpen={isOpen} onClose={onClose} title={`Edit Secret: ${secret?.name ?? ''}`} size="md">
        <form
            onSubmit={(e) => {
                e.preventDefault();
                if (!secret) return;
                mutation.mutate({ id: secret.id, name: editName, type: editType, value: editValue });
            }}
            className="space-y-4"
        >
            {mutation.isError && (
                <Alert
                    type="error"
                    title="Failed to update secret"
                    message={apiErrorMessage(mutation.error, 'An unexpected error occurred')}
                />
            )}
            <div>
                <label
                    htmlFor="edit-secret-name"
                    className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1"
                >
                    Name
                </label>
                <input
                    id="edit-secret-name"
                    type="text"
                    required
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-surface  px-3 py-2 text-sm text-base-primary  focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                />
            </div>
            <div>
                <label
                    htmlFor="edit-secret-type"
                    className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1"
                >
                    Type
                </label>
                <Select
                    id="edit-secret-type"
                    value={editType}
                    onChange={(e) => setEditType(e.target.value as SecretType)}
                    options={SECRET_TYPES.filter((t) => t.value !== 'all') as { value: SecretType; label: string }[]}
                />
            </div>
            <div>
                <div className="flex items-center justify-between mb-1">
                    <label htmlFor="edit-secret-value" className="block text-sm font-medium text-base-secondary">
                        New Value
                    </label>
                    <button
                        type="button"
                        onClick={() => setEditValue(generateSecret())}
                        className="text-xs font-medium transition-colors"
                        style={{ color: 'var(--accent-text)' }}
                    >
                        ↻ Generate
                    </button>
                </div>
                <input
                    id="edit-secret-value"
                    type="text"
                    value={editValue}
                    onChange={(e) => setEditValue(e.target.value)}
                    placeholder="Leave blank to keep existing value"
                    className="w-full rounded-md border px-3 py-2 text-sm font-mono focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                    style={{
                        backgroundColor: 'var(--bg-app)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border-strong)',
                    }}
                />
                <p className="mt-1 text-xs text-base-muted">Leave blank to keep the existing value.</p>
            </div>
            <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base ">
                <Button type="button" variant="outline" onClick={onClose} disabled={mutation.isPending}>
                    Cancel
                </Button>
                <Button type="submit" disabled={mutation.isPending}>
                    {mutation.isPending ? 'Saving…' : 'Save Changes'}
                </Button>
            </div>
        </form>
    </Modal>
);

interface DeleteSecretModalProps {
    isOpen: boolean;
    secret: any;
    onClose: () => void;
    mutation: ListState['deleteMutation'];
}

const DeleteSecretModal: React.FC<DeleteSecretModalProps> = ({ isOpen, secret, onClose, mutation }) => (
    <Modal isOpen={isOpen} onClose={onClose} title="Delete Secret" size="sm">
        <div className="space-y-4">
            {mutation.isError && (
                <Alert
                    type="error"
                    title="Failed to delete secret"
                    message={apiErrorMessage(mutation.error, 'An unexpected error occurred')}
                />
            )}
            <p className="text-sm text-base-secondary dark:text-base-muted">
                Are you sure you want to delete <span className="font-semibold">{secret?.name}</span>? The secret will
                be soft-deleted and can be restored within 30 days.
            </p>
            <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base ">
                <Button variant="outline" onClick={onClose} disabled={mutation.isPending}>
                    Cancel
                </Button>
                <Button
                    variant="destructive"
                    onClick={() => secret && mutation.mutate(secret.id)}
                    disabled={mutation.isPending}
                >
                    {mutation.isPending ? 'Deleting…' : 'Delete'}
                </Button>
            </div>
        </div>
    </Modal>
);

interface CreateSecretModalProps {
    isOpen: boolean;
    onClose: () => void;
    onSubmit: (e: React.SubmitEvent<HTMLFormElement>) => void;
    createName: string;
    setCreateName: (v: string) => void;
    createValue: string;
    setCreateValue: (v: string) => void;
    createType: SecretType;
    setCreateType: (v: SecretType) => void;
    createError: string;
    createProjectId: number;
    setCreateProjectId: (v: number) => void;
    createEnvId: number;
    setCreateEnvId: (v: number) => void;
    createProjects: ReturnType<typeof useProjects>['data'];
    createEnvironments: ReturnType<typeof useProjectEnvironments>['data'];
    nameHint: string;
    namePatternUnsafe: boolean;
    mutation: ListState['createMutation'];
}

const CreateSecretModal: React.FC<CreateSecretModalProps> = ({
    isOpen,
    onClose,
    onSubmit,
    createName,
    setCreateName,
    createValue,
    setCreateValue,
    createType,
    setCreateType,
    createError,
    createProjectId,
    setCreateProjectId,
    createEnvId,
    setCreateEnvId,
    createProjects,
    createEnvironments,
    nameHint,
    namePatternUnsafe,
    mutation,
}) => (
    <Modal isOpen={isOpen} onClose={onClose} title="Create New Secret" size="md">
        <form onSubmit={onSubmit} className="space-y-4">
            {createError && <Alert type="error" title="Failed to create secret" message={createError} />}
            <div>
                <label
                    htmlFor="create-secret-name"
                    className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1"
                >
                    Name <span className="text-red-500">*</span>
                </label>
                <input
                    id="create-secret-name"
                    type="text"
                    required
                    value={createName}
                    onChange={(e) => setCreateName(e.target.value)}
                    className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-surface  px-3 py-2 text-sm text-base-primary  focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                />
                {nameHint && <p className="mt-1 text-xs text-base-muted">Naming policy: {nameHint}.</p>}
                {namePatternUnsafe && (
                    <p className="mt-1 text-xs text-amber-600">
                        This naming pattern can&apos;t be safely checked in your browser and won&apos;t be validated
                        here; the server will still enforce it when you submit.
                    </p>
                )}
            </div>
            <div>
                <div className="flex items-center justify-between mb-1">
                    <label htmlFor="create-secret-value" className="block text-sm font-medium text-base-secondary">
                        Value <span className="text-red-500">*</span>
                    </label>
                    <button
                        type="button"
                        onClick={() => setCreateValue(generateSecret())}
                        className="text-xs font-medium transition-colors"
                        style={{ color: 'var(--accent-text)' }}
                    >
                        ↻ Generate
                    </button>
                </div>
                <textarea
                    id="create-secret-value"
                    required
                    rows={3}
                    value={createValue}
                    onChange={(e) => setCreateValue(e.target.value)}
                    className="w-full rounded-md border px-3 py-2 text-sm font-mono focus:outline-hidden focus:ring-2 focus:ring-blue-500 resize-none"
                    style={{
                        backgroundColor: 'var(--bg-app)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border-strong)',
                    }}
                />
            </div>
            <div>
                <label
                    htmlFor="create-secret-type"
                    className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1"
                >
                    Type
                </label>
                <Select
                    id="create-secret-type"
                    value={createType}
                    onChange={(e) => setCreateType(e.target.value as SecretType)}
                    options={[
                        { value: 'text', label: 'Generic' },
                        { value: 'password', label: 'Password' },
                        { value: 'api_key', label: 'API Key' },
                        { value: 'certificate', label: 'Certificate' },
                        { value: 'json', label: 'JSON' },
                    ]}
                />
            </div>
            <div className="grid grid-cols-2 gap-3">
                <div>
                    <label
                        htmlFor="create-secret-project"
                        className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1"
                    >
                        Project <span className="text-red-500">*</span>
                    </label>
                    <Select
                        id="create-secret-project"
                        value={String(createProjectId)}
                        onChange={(e) => setCreateProjectId(Number(e.target.value))}
                        options={(createProjects ?? []).map((p) => ({ value: String(p.id), label: p.name }))}
                    />
                </div>
                <div>
                    <label
                        htmlFor="create-secret-environment"
                        className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1"
                    >
                        Environment <span className="text-red-500">*</span>
                    </label>
                    <Select
                        id="create-secret-environment"
                        value={String(createEnvId)}
                        onChange={(e) => setCreateEnvId(Number(e.target.value))}
                        options={(createEnvironments ?? []).map((env) => ({
                            value: String(env.id),
                            label: env.name,
                        }))}
                    />
                </div>
            </div>
            <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base ">
                <Button type="button" variant="outline" onClick={onClose} disabled={mutation.isPending}>
                    Cancel
                </Button>
                <Button data-testid="create-secret-submit" type="submit" disabled={mutation.isPending}>
                    {mutation.isPending ? 'Creating…' : 'Create Secret'}
                </Button>
            </div>
        </form>
    </Modal>
);

interface RotateSecretModalProps {
    isOpen: boolean;
    secret: any;
    onClose: () => void;
    rotateValue: string;
    setRotateValue: (v: string) => void;
    mutation: ListState['rotateMutation'];
}

const RotateSecretModal: React.FC<RotateSecretModalProps> = ({
    isOpen,
    secret,
    onClose,
    rotateValue,
    setRotateValue,
    mutation,
}) => (
    <Modal isOpen={isOpen} onClose={onClose} title={`Rotate Secret: ${secret?.name ?? ''}`} size="sm">
        <form
            onSubmit={(e) => {
                e.preventDefault();
                if (!secret) return;
                mutation.mutate({ id: secret.id, newValue: rotateValue });
            }}
            className="space-y-4"
        >
            {mutation.isError && (
                <Alert type="error" title="Failed to rotate secret" message={apiErrorMessage(mutation.error)} />
            )}
            <p className="text-sm text-base-muted">
                A new random value has been generated. Edit it or regenerate, then click Rotate to create a new version.
            </p>
            <div>
                <div className="flex items-center justify-between mb-1">
                    <label htmlFor="rotate-secret-value" className="block text-sm font-medium text-base-secondary">
                        New Value
                    </label>
                    <button
                        type="button"
                        onClick={() => setRotateValue(generateSecret())}
                        className="text-xs font-medium transition-colors"
                        style={{ color: 'var(--accent-text)' }}
                    >
                        ↻ Regenerate
                    </button>
                </div>
                <input
                    id="rotate-secret-value"
                    type="text"
                    value={rotateValue}
                    onChange={(e) => setRotateValue(e.target.value)}
                    className="w-full rounded-md border px-3 py-2 text-sm font-mono focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                    style={{
                        backgroundColor: 'var(--bg-app)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border-strong)',
                    }}
                />
            </div>
            <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base">
                <Button type="button" variant="outline" onClick={onClose} disabled={mutation.isPending}>
                    Cancel
                </Button>
                <Button type="submit" disabled={mutation.isPending || !rotateValue.trim()}>
                    {mutation.isPending ? 'Rotating…' : 'Rotate'}
                </Button>
            </div>
        </form>
    </Modal>
);

interface AutoRotateModalProps {
    isOpen: boolean;
    secret: any;
    onClose: () => void;
    onSubmit: (e: React.SubmitEvent<HTMLFormElement>) => void;
    arEnabled: boolean;
    setArEnabled: (v: boolean) => void;
    arLength: string;
    setArLength: (v: string) => void;
    arCharset: string;
    setArCharset: (v: string) => void;
    arBackend: string;
    setArBackend: (v: string) => void;
    arRef: string;
    setArRef: (v: string) => void;
    backendRefMismatch: boolean;
    mutation: ReturnType<typeof useSetAutoRotate>;
}

const AutoRotateModal: React.FC<AutoRotateModalProps> = ({
    isOpen,
    secret,
    onClose,
    onSubmit,
    arEnabled,
    setArEnabled,
    arLength,
    setArLength,
    arCharset,
    setArCharset,
    arBackend,
    setArBackend,
    arRef,
    setArRef,
    backendRefMismatch,
    mutation,
}) => (
    <Modal isOpen={isOpen} onClose={onClose} title={`Automated Rotation: ${secret?.name ?? ''}`} size="md">
        <form onSubmit={onSubmit} className="space-y-4">
            {mutation.isError && (
                <Alert
                    type="error"
                    title="Failed to update auto-rotation"
                    message={apiErrorMessage(mutation.error, 'An unexpected error occurred')}
                />
            )}
            <p className="text-sm text-base-muted">
                When enabled, Keyorix regenerates this secret on its rotation-policy schedule. Enable only for values
                Keyorix owns — or set a backend to rotate the upstream credential in place.
            </p>
            <label className="flex items-center gap-2 text-sm text-base-secondary">
                <input
                    type="checkbox"
                    checked={arEnabled}
                    onChange={(e) => setArEnabled(e.target.checked)}
                    aria-label="Enable auto-rotation"
                />{' '}
                Enable automated rotation
            </label>
            <div className="grid grid-cols-2 gap-3">
                <Input
                    label="Value length"
                    type="number"
                    placeholder="default 32"
                    value={arLength}
                    onChange={(e) => setArLength(e.target.value)}
                />
                <div>
                    <label htmlFor="auto-rotate-charset" className="block text-sm font-medium text-base-secondary mb-1">
                        Charset
                    </label>
                    <Select
                        id="auto-rotate-charset"
                        value={arCharset}
                        onChange={(e) => setArCharset(e.target.value)}
                        options={[
                            { value: '', label: 'Alphanumeric (default)' },
                            { value: 'lower_alphanumeric', label: 'Lowercase + digits' },
                            { value: 'hex', label: 'Hex' },
                            { value: 'alphanumeric_symbols', label: 'Alphanumeric + symbols' },
                        ]}
                    />
                </div>
            </div>
            <div className="pt-2 border-t border-base">
                <p className="text-xs text-base-muted mb-2">
                    Optional — rotate an upstream credential (e.g. a DB role or cloud key) via a configured backend.
                </p>
                <div className="grid grid-cols-2 gap-3">
                    <Input
                        label="Backend"
                        placeholder="e.g. prod-postgres"
                        value={arBackend}
                        onChange={(e) => setArBackend(e.target.value)}
                    />
                    <Input
                        label="Upstream ref"
                        placeholder="e.g. app_svc"
                        value={arRef}
                        onChange={(e) => setArRef(e.target.value)}
                    />
                </div>
                {backendRefMismatch && (
                    <p className="text-xs text-red-600 mt-1">Backend and ref must be set together.</p>
                )}
            </div>
            <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base">
                <Button type="button" variant="outline" onClick={onClose} disabled={mutation.isPending}>
                    Cancel
                </Button>
                <Button type="submit" disabled={mutation.isPending || backendRefMismatch}>
                    {mutation.isPending ? 'Saving…' : 'Save'}
                </Button>
            </div>
        </form>
    </Modal>
);

interface BulkDeleteSecretsModalProps {
    isOpen: boolean;
    secretIds: number[] | undefined;
    onClose: () => void;
    mutation: ListState['bulkDeleteMutation'];
}

const BulkDeleteSecretsModal: React.FC<BulkDeleteSecretsModalProps> = ({ isOpen, secretIds, onClose, mutation }) => (
    <Modal isOpen={isOpen} onClose={onClose} title="Delete Selected Secrets" size="sm">
        <div className="space-y-4">
            <p className="text-sm text-base-secondary dark:text-base-muted">
                Are you sure you want to delete <span className="font-semibold">{secretIds?.length}</span> secret(s)?
                They will be soft-deleted and can be restored within 30 days.
            </p>
            <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base ">
                <Button variant="outline" onClick={onClose} disabled={mutation.isPending}>
                    Cancel
                </Button>
                <Button
                    variant="destructive"
                    onClick={() => secretIds && mutation.mutate(secretIds)}
                    disabled={mutation.isPending}
                >
                    {mutation.isPending ? 'Deleting…' : `Delete ${secretIds?.length ?? ''} Secret(s)`}
                </Button>
            </div>
        </div>
    </Modal>
);

// ─── Main Page ───────────────────────────────────────────────────────────────

export const SecretsListPage: React.FC = () => {
    const list = useSecretsList();
    const bulkClassify = useBulkClassifySecrets();
    const reveal = useSecretReveal();
    const [searchParams] = useSearchParams();

    // Apply URL-driven sort on mount (e.g. ?sort=expiry_asc from dashboard)
    React.useEffect(() => {
        const sort = searchParams.get('sort');
        if (sort && sort !== list.sortBy) {
            list.setSortBy(sort);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
    const urlFilter = searchParams.get('filter'); // 'expiring' | null
    const displayedSecrets = filterSecretsForDisplay(list.secrets, urlFilter);
    const [viewingSecret, setViewingSecret] = React.useState<any>(null);
    const [createName, setCreateName] = React.useState('');
    const [createValue, setCreateValue] = React.useState('');
    const [createType, setCreateType] = React.useState<SecretType>('text');
    const [createError, setCreateError] = React.useState('');
    // Target project/environment for a new secret. The All-Secrets create form is
    // not scoped to a project, so the user must pick one — previously this was
    // hardcoded to project 1 / env 1, which errored or misfiled on any other DB.
    const [createProjectId, setCreateProjectId] = React.useState(0);
    const [createEnvId, setCreateEnvId] = React.useState(0);
    const { data: createProjects } = useProjects();

    // Active secret-name policy, for a create-time hint + client-side pre-validation.
    const { data: secretPolicy } = useSecretPolicy();
    const namePolicy = secretPolicy?.name;
    const nameHint = resolveNameHint(namePolicy);
    // The naming-policy pattern is admin-configured but untrusted from the
    // browser's perspective -- a catastrophic-backtracking shape (e.g.
    // `(a+)+$`) would hang this tab. When the pattern looks unsafe, skip the
    // live client-side check (the server still enforces it on submit) and
    // say so.
    const namePatternUnsafe = checkNamePatternUnsafe(namePolicy);
    const { data: createEnvironments } = useProjectEnvironments(createProjectId);
    // Default the project to the first available once projects load.
    React.useEffect(() => {
        const first = createProjects?.[0];
        if (createProjectId === 0 && first) {
            setCreateProjectId(first.id);
        }
    }, [createProjects, createProjectId]);
    // When the project changes (or its environments load), keep the selected
    // environment valid — default to the first env of the chosen project.
    React.useEffect(() => {
        if (!createEnvironments) return;
        const nextEnvId = resolveValidEnvId(createEnvironments, createEnvId);
        if (nextEnvId !== null) setCreateEnvId(nextEnvId);
    }, [createEnvironments, createEnvId]);
    const [editName, setEditName] = React.useState('');
    const [editType, setEditType] = React.useState<SecretType>('text');
    const [editValue, setEditValue] = React.useState('');
    const [rotateValue, setRotateValue] = React.useState('');

    // Automated-rotation modal form (ADR-046/047).
    const [arEnabled, setArEnabled] = React.useState(true);
    const [arLength, setArLength] = React.useState('');
    const [arCharset, setArCharset] = React.useState('');
    const [arBackend, setArBackend] = React.useState('');
    const [arRef, setArRef] = React.useState('');
    const autoRotate = useSetAutoRotate(list.modalData?.secret?.id ?? 0);
    const backendRefMismatch = (arBackend === '') !== (arRef === '');

    React.useEffect(() => {
        applyModalDefaults(list.activeModal, list.modalData?.secret ?? null, {
            setEditName,
            setEditType,
            setRotateValue,
            setArEnabled,
            setArLength,
            setArCharset,
            setArBackend,
            setArRef,
            setEditValue,
        });
    }, [list.activeModal, list.modalData]);

    const handleRotate = (secret: any) => {
        list.openModal('rotate-secret', { secret });
    };

    const handleAutoRotate = (secret: any) => {
        list.openModal('auto-rotate', { secret });
    };

    const submitAutoRotate = (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (backendRefMismatch) return; // both-or-neither (UI guard)
        autoRotate.mutate(
            {
                enabled: arEnabled,
                length: arLength ? Number(arLength) : 0,
                charset: arCharset,
                backend: arBackend.trim(),
                ref: arRef.trim(),
            },
            { onSuccess: () => list.closeModal() }
        );
    };

    const resetCreateForm = () => {
        setCreateName('');
        setCreateValue('');
        setCreateType('text');
        setCreateError('');
    };

    const handleCloseCreateModal = () => {
        list.closeModal();
        resetCreateForm();
    };

    const handleCreateSubmit = (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        setCreateError('');
        if (!createProjectId || !createEnvId) {
            setCreateError('Select a project and environment for the new secret.');
            return;
        }
        const nameErr = secretNameError(namePolicy, createName);
        if (nameErr) {
            setCreateError(nameErr);
            return;
        }
        list.createMutation.mutate(
            {
                name: createName,
                value: createValue,
                type: createType,
                project_id: createProjectId,
                environment_id: createEnvId,
            } as any,
            {
                onSuccess: resetCreateForm,
                onError: (err) => setCreateError(apiErrorMessage(err)),
            }
        );
    };

    const handleBulkClassify = (level: string) => {
        const ids = Array.from(list.selectedItems);
        bulkClassify.mutate(
            { ids, classification: level === 'unclassified' ? '' : level },
            { onSuccess: () => list.clearSelectedItems() }
        );
    };

    if (list.error) {
        return (
            <div className="p-6">
                <Alert
                    type="error"
                    title="Failed to load secrets"
                    message={apiErrorMessage(list.error, 'There was an error loading your secrets. Please try again.')}
                >
                    <Button variant="outline" size="sm" onClick={() => list.refetch()}>
                        Retry
                    </Button>
                </Alert>
            </div>
        );
    }

    return (
        <div className="p-6 space-y-6">
            <SecretsPageHeader
                selectedItems={list.selectedItems}
                bulkClassifyPending={bulkClassify.isPending}
                onBulkClassify={handleBulkClassify}
                onBulkDelete={() =>
                    list.openModal('bulk-delete-secrets', { secretIds: Array.from(list.selectedItems) })
                }
                onClearSelection={list.clearSelectedItems}
                onCreateClick={() => list.openModal('create-secret')}
            />

            <SecretsFilterBar
                searchInput={list.searchInput}
                onSearchChange={list.setSearchInput}
                filters={list.filters}
                onFilterChange={list.handleFilterChange}
                environments={list.environments}
                sortBy={list.sortBy}
                onSortChange={list.setSortBy}
                pageSize={list.pagination.pageSize}
                onPageSizeChange={list.handlePageSizeChange}
                showAdvancedFilters={list.showAdvancedFilters}
                onToggleAdvanced={() => list.setShowAdvancedFilters(!list.showAdvancedFilters)}
                hasActiveFilters={list.hasActiveFilters}
                onClearFilters={list.handleClearFilters}
                isFetching={list.isFetching}
            />

            {urlFilter === 'expiring' && <ExpiringFilterBanner />}

            <div className="bg-surface rounded-lg border border-base ">
                <SecretsTable
                    isLoading={list.isLoading}
                    displayedSecrets={displayedSecrets}
                    hasActiveFilters={list.hasActiveFilters}
                    onCreateClick={() => list.openModal('create-secret')}
                    selectedItems={list.selectedItems}
                    toggleSelectedItem={list.toggleSelectedItem}
                    clearSelectedItems={list.clearSelectedItems}
                    onView={setViewingSecret}
                    onEdit={(s) => list.openModal('edit-secret', { secret: s })}
                    onDelete={(s) => list.openModal('delete-secret', { secret: s })}
                    onShare={(s) => list.openModal('share-secret', { secret: s })}
                    onRotate={handleRotate}
                    onAutoRotate={handleAutoRotate}
                    reveal={reveal}
                    pagination={list.pagination}
                    onPageChange={list.handlePageChange}
                />
            </div>

            <ViewSecretModal
                secret={viewingSecret}
                onClose={() => setViewingSecret(null)}
                onEdit={(s) => list.openModal('edit-secret', { secret: s })}
                onShare={(s) => list.openModal('share-secret', { secret: s })}
                onDelete={(s) => list.openModal('delete-secret', { secret: s })}
            />

            <EditSecretModal
                isOpen={list.activeModal === 'edit-secret'}
                secret={list.modalData?.secret}
                onClose={list.closeModal}
                editName={editName}
                setEditName={setEditName}
                editType={editType}
                setEditType={setEditType}
                editValue={editValue}
                setEditValue={setEditValue}
                mutation={list.editMutation}
            />

            <DeleteSecretModal
                isOpen={list.activeModal === 'delete-secret'}
                secret={list.modalData?.secret}
                onClose={list.closeModal}
                mutation={list.deleteMutation}
            />

            <CreateSecretModal
                isOpen={list.activeModal === 'create-secret'}
                onClose={handleCloseCreateModal}
                onSubmit={handleCreateSubmit}
                createName={createName}
                setCreateName={setCreateName}
                createValue={createValue}
                setCreateValue={setCreateValue}
                createType={createType}
                setCreateType={setCreateType}
                createError={createError}
                createProjectId={createProjectId}
                setCreateProjectId={setCreateProjectId}
                createEnvId={createEnvId}
                setCreateEnvId={setCreateEnvId}
                createProjects={createProjects}
                createEnvironments={createEnvironments}
                nameHint={nameHint}
                namePatternUnsafe={namePatternUnsafe}
                mutation={list.createMutation}
            />

            {list.activeModal === 'share-secret' && list.modalData?.secret && (
                <ShareSecretModal
                    secret={list.modalData.secret}
                    isOpen
                    onClose={list.closeModal}
                    // Refresh only: the dialog shows its "Shared!" confirmation and closes
                    // itself shortly after. Closing it here unmounted it before the
                    // confirmation could render.
                    onSuccess={() => list.refetch()}
                />
            )}

            <RotateSecretModal
                isOpen={list.activeModal === 'rotate-secret'}
                secret={list.modalData?.secret}
                onClose={list.closeModal}
                rotateValue={rotateValue}
                setRotateValue={setRotateValue}
                mutation={list.rotateMutation}
            />

            <AutoRotateModal
                isOpen={list.activeModal === 'auto-rotate'}
                secret={list.modalData?.secret}
                onClose={list.closeModal}
                onSubmit={submitAutoRotate}
                arEnabled={arEnabled}
                setArEnabled={setArEnabled}
                arLength={arLength}
                setArLength={setArLength}
                arCharset={arCharset}
                setArCharset={setArCharset}
                arBackend={arBackend}
                setArBackend={setArBackend}
                arRef={arRef}
                setArRef={setArRef}
                backendRefMismatch={backendRefMismatch}
                mutation={autoRotate}
            />

            <BulkDeleteSecretsModal
                isOpen={list.activeModal === 'bulk-delete-secrets'}
                secretIds={list.modalData?.secretIds}
                onClose={list.closeModal}
                mutation={list.bulkDeleteMutation}
            />
        </div>
    );
};
