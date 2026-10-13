import { useCan } from '../../features/auth/useCan';
import React from 'react';
import { useSearchParams } from 'react-router';
import {
    PlusIcon,
    MagnifyingGlassIcon,
    ChevronLeftIcon,
    ChevronRightIcon,
    FunnelIcon,
    ArrowsRightLeftIcon,
    ArrowPathIcon,
} from '@heroicons/react/24/outline';
import { SecretType } from '../../types';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Select } from '../../components/ui/Select';
import { Loading } from '../../components/ui/Loading';
import { SecretTableRow, SecretDetailView, useSecretReveal } from '../../features/secrets';
import { useProjectSecrets } from '../../features/secrets/useProjectSecrets';
import { ShareSecretModal } from '../../features/sharing';
import { EnvironmentPills } from '../../features/projects/EnvironmentPills';
import { useProjectEnvironments } from '../../features/projects/api';
import { useDefaultEnvironment } from '../../features/projects/useDefaultEnvironment';
import { generateSecret } from '../../utils';
import { SECRET_TYPES } from '../../features/secrets/listConstants';
import { SecretsDriftPanel } from './SecretsDriftPanel';
import { SecretsRotationPlanPanel } from './SecretsRotationPlanPanel';
import { apiErrorMessage } from '../../services/client';

const PAGE_SIZE_OPTIONS = [
    { value: '10', label: '10 / page' },
    { value: '20', label: '20 / page' },
    { value: '50', label: '50 / page' },
];

type ProjectSecretsList = ReturnType<typeof useProjectSecrets>;
type RevealState = ReturnType<typeof useSecretReveal>;

// ─── Section components ─────────────────────────────────────────────────────

interface SecretsToolbarProps {
    list: ProjectSecretsList;
    selectedItems: Set<number>;
    clearSelected: () => void;
    onOpenDrift: () => void;
    onOpenRotationPlan: () => void;
}

const SecretsToolbar: React.FC<SecretsToolbarProps> = ({
    list,
    selectedItems,
    clearSelected,
    onOpenDrift,
    onOpenRotationPlan,
}) => {
    const can = useCan();
    return (
        <div className="flex flex-wrap items-center gap-3 mb-4">
            {/* Search */}
            <div className="relative flex-1 min-w-[200px]">
                <MagnifyingGlassIcon
                    className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4"
                    style={{ color: 'var(--text-muted)' }}
                />
                <input
                    type="text"
                    value={list.search}
                    onChange={(e) => list.setSearch(e.target.value)}
                    placeholder="Search secrets…"
                    className="w-full pl-9 pr-4 py-2 rounded-lg text-sm outline-hidden"
                    style={{
                        backgroundColor: 'var(--bg-surface)',
                        border: '1px solid var(--border)',
                        color: 'var(--text-primary)',
                    }}
                />
            </div>

            {/* Type filter */}
            <div className="w-36">
                <Select
                    value={list.typeFilter}
                    onChange={(e) => list.setTypeFilter(e.target.value as SecretType | 'all')}
                    options={SECRET_TYPES}
                />
            </div>

            {/* Page size */}
            <div className="w-28">
                <Select
                    value={String(list.pagination.pageSize)}
                    onChange={(e) => list.handlePageSizeChange(Number(e.target.value))}
                    options={PAGE_SIZE_OPTIONS}
                />
            </div>

            {/* Bulk actions */}
            {selectedItems.size > 0 && (
                <div className="flex items-center gap-2">
                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        {selectedItems.size} selected
                    </span>
                    <Button variant="ghost" size="sm" onClick={clearSelected}>
                        Clear
                    </Button>
                </div>
            )}

            {/* Drift & rotation reports (ADR-020: sub-actions of the Secrets mode, not their own tabs) */}
            <Button variant="outline" size="sm" onClick={onOpenDrift} className="flex items-center">
                <ArrowsRightLeftIcon className="h-4 w-4 mr-1" />
                Check Drift
            </Button>
            <Button variant="outline" size="sm" onClick={onOpenRotationPlan} className="flex items-center">
                <ArrowPathIcon className="h-4 w-4 mr-1" />
                Rotation Plan
            </Button>

            {/* New Secret */}
            {can.writeSecrets && (
                <Button onClick={() => list.openModal('create-secret')} className="flex items-center ml-auto">
                    <PlusIcon className="h-4 w-4 mr-1" />
                    New Secret
                </Button>
            )}
        </div>
    );
};

interface SecretsTableContentProps {
    list: ProjectSecretsList;
    activeEnvName: string;
    selectedItems: Set<number>;
    toggleSelected: (id: number) => void;
    clearSelected: () => void;
    onView: (secret: any) => void;
    reveal: RevealState;
}

const SecretsTableContent: React.FC<SecretsTableContentProps> = ({
    list,
    activeEnvName,
    selectedItems,
    toggleSelected,
    clearSelected,
    onView,
    reveal,
}) => {
    const canCreate = useCan().writeSecrets;
    if (list.isLoading) {
        return (
            <div className="p-8">
                <Loading />
            </div>
        );
    }

    if (list.secrets.length === 0) {
        return (
            <div className="p-10 text-center">
                <FunnelIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
                <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                    {list.search || list.typeFilter !== 'all'
                        ? 'No secrets match your filters'
                        : `No secrets in ${activeEnvName}`}
                </p>
                {!(list.search || list.typeFilter !== 'all') && canCreate && (
                    <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                        Create your first secret in this environment.
                    </p>
                )}
                {!(list.search || list.typeFilter !== 'all') && canCreate && (
                    <Button onClick={() => list.openModal('create-secret')}>
                        <PlusIcon className="h-4 w-4 mr-1" />
                        New Secret
                    </Button>
                )}
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y" style={{ borderColor: 'var(--border)' }}>
                <thead style={{ backgroundColor: 'var(--bg-subtle)' }}>
                    <tr>
                        <th className="px-4 py-3 text-left w-10">
                            <input
                                type="checkbox"
                                className="rounded-sm border-gray-300 text-blue-600"
                                checked={list.secrets.length > 0 && list.secrets.every((s) => selectedItems.has(s.id))}
                                onChange={(e) => {
                                    if (e.target.checked) list.secrets.forEach((s) => toggleSelected(s.id));
                                    else clearSelected();
                                }}
                            />
                        </th>
                        {['Name', 'Type', 'Classification', 'Environment', 'Sharing', 'Modified'].map((h) => (
                            <th
                                key={h}
                                className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                {h}
                            </th>
                        ))}
                        <th
                            className="px-6 py-3 text-right text-xs font-medium uppercase tracking-wider min-w-[180px]"
                            style={{ color: 'var(--text-muted)' }}
                        >
                            Actions
                        </th>
                    </tr>
                </thead>
                <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {list.secrets.map((secret) => (
                        <SecretTableRow
                            key={secret.id}
                            secret={secret}
                            isSelected={selectedItems.has(secret.id)}
                            onToggleSelect={toggleSelected}
                            onView={onView}
                            onEdit={(s) => list.openModal('edit-secret', { secret: s })}
                            onDelete={(s) => list.openModal('delete-secret', { secret: s })}
                            onShare={(s) => list.openModal('share-secret', { secret: s })}
                            onRotate={(s) => list.openModal('rotate-secret', { secret: s })}
                            onCopy={reveal.handleCopySecretValue}
                            copyingId={reveal.copyingSecretId}
                            copiedId={reveal.copiedSecretId}
                            copyErrorId={reveal.copyErrorId}
                            copyError={reveal.copyError}
                        />
                    ))}
                </tbody>
            </table>

            {/* Pagination */}
            {list.pagination.totalPages > 1 && (
                <div
                    className="px-4 py-3 border-t flex items-center justify-between"
                    style={{ borderColor: 'var(--border)' }}
                >
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        {(list.pagination.page - 1) * list.pagination.pageSize + 1}–
                        {Math.min(list.pagination.page * list.pagination.pageSize, list.pagination.total)} of{' '}
                        {list.pagination.total}
                    </p>
                    <div className="flex items-center gap-2">
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => list.handlePageChange(list.pagination.page - 1)}
                            disabled={list.pagination.page === 1}
                        >
                            <ChevronLeftIcon className="h-4 w-4" />
                        </Button>
                        <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
                            {list.pagination.page} / {list.pagination.totalPages}
                        </span>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => list.handlePageChange(list.pagination.page + 1)}
                            disabled={list.pagination.page === list.pagination.totalPages}
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
    viewingSecret: any;
    setViewingSecret: (secret: any) => void;
    list: ProjectSecretsList;
}

const ViewSecretModal: React.FC<ViewSecretModalProps> = ({ viewingSecret, setViewingSecret, list }) => (
    <Modal isOpen={viewingSecret !== null} onClose={() => setViewingSecret(null)} size="xl">
        {viewingSecret && (
            <SecretDetailView
                secret={viewingSecret}
                onClose={() => setViewingSecret(null)}
                onEdit={(s) => {
                    setViewingSecret(null);
                    list.openModal('edit-secret', { secret: s });
                }}
                onShare={(s) => {
                    setViewingSecret(null);
                    list.openModal('share-secret', { secret: s });
                }}
                onDelete={(s) => {
                    setViewingSecret(null);
                    list.openModal('delete-secret', { secret: s });
                }}
            />
        )}
    </Modal>
);

interface CreateSecretModalProps {
    list: ProjectSecretsList;
    activeEnvName: string;
    createName: string;
    setCreateName: (v: string) => void;
    createValue: string;
    setCreateValue: (v: string) => void;
    createType: SecretType;
    setCreateType: (v: SecretType) => void;
    onSubmit: () => void;
    onCancel: () => void;
}

const CreateSecretModal: React.FC<CreateSecretModalProps> = ({
    list,
    activeEnvName,
    createName,
    setCreateName,
    createValue,
    setCreateValue,
    createType,
    setCreateType,
    onSubmit,
    onCancel,
}) => (
    <Modal isOpen={list.activeModal === 'create-secret'} onClose={onCancel} title="New Secret" size="md">
        <form
            onSubmit={(e) => {
                e.preventDefault();
                onSubmit();
            }}
            className="space-y-4"
        >
            {list.createMutation.isError && (
                <Alert
                    type="error"
                    title="Failed to create secret"
                    message={apiErrorMessage(list.createMutation.error, 'Unexpected error')}
                />
            )}

            {/* Context badge */}
            <div
                className="flex items-center gap-2 text-xs px-3 py-2 rounded-lg"
                style={{ backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' }}
            >
                <span className="font-medium">Environment:</span>
                <span>{activeEnvName.charAt(0).toUpperCase() + activeEnvName.slice(1)}</span>
            </div>

            <div>
                <label
                    htmlFor="create-secret-name"
                    className="block text-sm font-medium mb-1"
                    style={{ color: 'var(--text-secondary)' }}
                >
                    Name <span style={{ color: 'var(--error)' }}>*</span>
                </label>
                <input
                    id="create-secret-name"
                    type="text"
                    required
                    value={createName}
                    onChange={(e) => setCreateName(e.target.value)}
                    autoFocus
                    className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden focus:ring-2 focus:ring-blue-500"
                    style={{
                        backgroundColor: 'var(--bg-app)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border)',
                    }}
                />
            </div>

            <div>
                <div className="flex items-center justify-between mb-1">
                    <label
                        htmlFor="create-secret-value"
                        className="block text-sm font-medium"
                        style={{ color: 'var(--text-secondary)' }}
                    >
                        Value <span style={{ color: 'var(--error)' }}>*</span>
                    </label>
                    <button
                        type="button"
                        onClick={() => setCreateValue(generateSecret())}
                        className="text-xs font-medium"
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
                    className="w-full rounded-lg border px-3 py-2 text-sm font-mono outline-hidden resize-none focus:ring-2 focus:ring-blue-500"
                    style={{
                        backgroundColor: 'var(--bg-app)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border)',
                    }}
                />
            </div>

            <div>
                <label
                    htmlFor="create-secret-type"
                    className="block text-sm font-medium mb-1"
                    style={{ color: 'var(--text-secondary)' }}
                >
                    Type
                </label>
                <Select
                    id="create-secret-type"
                    value={createType}
                    onChange={(e) => setCreateType(e.target.value as SecretType)}
                    options={SECRET_TYPES.filter((t) => t.value !== 'all') as { value: SecretType; label: string }[]}
                />
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
                <Button type="button" variant="outline" onClick={onCancel} disabled={list.createMutation.isPending}>
                    Cancel
                </Button>
                <Button
                    type="submit"
                    disabled={list.createMutation.isPending || !createName.trim() || !createValue.trim()}
                >
                    {list.createMutation.isPending ? 'Creating…' : 'Create Secret'}
                </Button>
            </div>
        </form>
    </Modal>
);

interface EditSecretModalProps {
    list: ProjectSecretsList;
    editName: string;
    setEditName: (v: string) => void;
    editType: SecretType;
    setEditType: (v: SecretType) => void;
    editValue: string;
    setEditValue: (v: string) => void;
}

const EditSecretModal: React.FC<EditSecretModalProps> = ({
    list,
    editName,
    setEditName,
    editType,
    setEditType,
    editValue,
    setEditValue,
}) => (
    <Modal
        isOpen={list.activeModal === 'edit-secret'}
        onClose={list.closeModal}
        title={`Edit Secret: ${list.modalData?.secret?.name ?? ''}`}
        size="md"
    >
        <form
            onSubmit={(e) => {
                e.preventDefault();
                if (!list.modalData?.secret) return;
                list.editMutation.mutate({
                    id: list.modalData.secret.id,
                    name: editName,
                    type: editType,
                    value: editValue,
                });
            }}
            className="space-y-4"
        >
            {list.editMutation.isError && (
                <Alert
                    type="error"
                    title="Failed to update secret"
                    message={apiErrorMessage(list.editMutation.error, 'Unexpected error')}
                />
            )}
            <div>
                <label
                    htmlFor="edit-secret-name"
                    className="block text-sm font-medium mb-1"
                    style={{ color: 'var(--text-secondary)' }}
                >
                    Name
                </label>
                <input
                    id="edit-secret-name"
                    type="text"
                    required
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden"
                    style={{
                        backgroundColor: 'var(--bg-app)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border)',
                    }}
                />
            </div>
            <div>
                <label
                    htmlFor="edit-secret-type"
                    className="block text-sm font-medium mb-1"
                    style={{ color: 'var(--text-secondary)' }}
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
                    <label
                        htmlFor="edit-secret-value"
                        className="block text-sm font-medium"
                        style={{ color: 'var(--text-secondary)' }}
                    >
                        New Value
                    </label>
                    <button
                        type="button"
                        onClick={() => setEditValue(generateSecret())}
                        className="text-xs font-medium"
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
                    placeholder="Leave blank to keep existing"
                    className="w-full rounded-lg border px-3 py-2 text-sm font-mono outline-hidden"
                    style={{
                        backgroundColor: 'var(--bg-app)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border)',
                    }}
                />
            </div>
            <div className="flex justify-end gap-2 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
                <Button
                    type="button"
                    variant="outline"
                    onClick={list.closeModal}
                    disabled={list.editMutation.isPending}
                >
                    Cancel
                </Button>
                <Button type="submit" disabled={list.editMutation.isPending}>
                    {list.editMutation.isPending ? 'Saving…' : 'Save Changes'}
                </Button>
            </div>
        </form>
    </Modal>
);

interface DeleteSecretModalProps {
    list: ProjectSecretsList;
}

const DeleteSecretModal: React.FC<DeleteSecretModalProps> = ({ list }) => (
    <Modal isOpen={list.activeModal === 'delete-secret'} onClose={list.closeModal} title="Delete Secret" size="sm">
        <div className="space-y-4">
            {list.deleteMutation.isError && (
                <Alert
                    type="error"
                    title="Failed to delete secret"
                    message={apiErrorMessage(list.deleteMutation.error, 'Unexpected error')}
                />
            )}
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                Delete <span className="font-semibold">{list.modalData?.secret?.name}</span>? It can be restored within
                30 days.
            </p>
            <div className="flex justify-end gap-2 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
                <Button variant="outline" onClick={list.closeModal} disabled={list.deleteMutation.isPending}>
                    Cancel
                </Button>
                <Button
                    variant="destructive"
                    onClick={() => list.modalData?.secret && list.deleteMutation.mutate(list.modalData.secret.id)}
                    disabled={list.deleteMutation.isPending}
                >
                    {list.deleteMutation.isPending ? 'Deleting…' : 'Delete'}
                </Button>
            </div>
        </div>
    </Modal>
);

interface RotateSecretModalProps {
    list: ProjectSecretsList;
    rotateValue: string;
    setRotateValue: (v: string) => void;
}

const RotateSecretModal: React.FC<RotateSecretModalProps> = ({ list, rotateValue, setRotateValue }) => (
    <Modal
        isOpen={list.activeModal === 'rotate-secret'}
        onClose={list.closeModal}
        title={`Rotate: ${list.modalData?.secret?.name ?? ''}`}
        size="sm"
    >
        <form
            onSubmit={(e) => {
                e.preventDefault();
                if (!list.modalData?.secret) return;
                list.rotateMutation.mutate({ id: list.modalData.secret.id, newValue: rotateValue });
            }}
            className="space-y-4"
        >
            {list.rotateMutation.isError && (
                <Alert
                    type="error"
                    title="Failed to rotate secret"
                    message={apiErrorMessage(list.rotateMutation.error, 'Unexpected error')}
                />
            )}
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                A new random value has been generated. Edit or regenerate, then click Rotate.
            </p>
            <div>
                <div className="flex items-center justify-between mb-1">
                    <label
                        htmlFor="rotate-secret-value"
                        className="block text-sm font-medium"
                        style={{ color: 'var(--text-secondary)' }}
                    >
                        New Value
                    </label>
                    <button
                        type="button"
                        onClick={() => setRotateValue(generateSecret())}
                        className="text-xs font-medium"
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
                    className="w-full rounded-lg border px-3 py-2 text-sm font-mono outline-hidden"
                    style={{
                        backgroundColor: 'var(--bg-app)',
                        color: 'var(--text-primary)',
                        borderColor: 'var(--border)',
                    }}
                />
            </div>
            <div className="flex justify-end gap-2 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
                <Button
                    type="button"
                    variant="outline"
                    onClick={list.closeModal}
                    disabled={list.rotateMutation.isPending}
                >
                    Cancel
                </Button>
                <Button type="submit" disabled={list.rotateMutation.isPending || !rotateValue.trim()}>
                    {list.rotateMutation.isPending ? 'Rotating…' : 'Rotate'}
                </Button>
            </div>
        </form>
    </Modal>
);

// ─── Main component ─────────────────────────────────────────────────────────

interface ProjectSecretsTabProps {
    projectId: number;
}

export const ProjectSecretsTab: React.FC<ProjectSecretsTabProps> = ({ projectId }) => {
    const [searchParams, setSearchParams] = useSearchParams();
    const reveal = useSecretReveal();

    // ── Environment selection ─────────────────────────────────────────────
    const { data: environments = [], isLoading: envsLoading } = useProjectEnvironments(projectId);

    // With no ?env=, open on an environment that actually has secrets (production
    // first); the production-or-first rule is only the fallback while counts load or
    // when none can be read. See useDefaultEnvironment.
    const { name: preferredEnvName } = useDefaultEnvironment(projectId, environments, !searchParams.get('env'));
    const fallbackEnvName = React.useMemo(() => {
        if (environments.length === 0) return 'production';
        const prod = environments.find((e) => e.name.toLowerCase() === 'production');
        return prod?.name ?? environments[0]?.name ?? 'production';
    }, [environments]);
    const defaultEnvName = preferredEnvName ?? fallbackEnvName;

    const activeEnvName = searchParams.get('env') ?? defaultEnvName;

    // Set the default env in the URL once it is decided (counts loaded) and no param is set
    React.useEffect(() => {
        if (environments.length > 0 && preferredEnvName && !searchParams.get('env')) {
            setSearchParams(
                (prev) => {
                    prev.set('env', preferredEnvName);
                    return prev;
                },
                { replace: true }
            );
        }
    }, [environments, preferredEnvName, searchParams, setSearchParams]);

    const activeEnv = environments.find((e) => e.name === activeEnvName) ?? null;
    const activeEnvId = activeEnv?.id ?? null;

    const handleEnvChange = (envName: string) => {
        setSearchParams(
            (prev) => {
                prev.set('env', envName);
                return prev;
            },
            { replace: true }
        );
    };

    // ── Secrets data ──────────────────────────────────────────────────────
    const list = useProjectSecrets({ projectId, environmentId: activeEnvId });

    // ── Local modal state (create / edit / rotate) ────────────────────────
    const [viewingSecret, setViewingSecret] = React.useState<any>(null);
    const [createName, setCreateName] = React.useState('');
    const [createValue, setCreateValue] = React.useState('');
    const [createType, setCreateType] = React.useState<SecretType>('text');
    const [editName, setEditName] = React.useState('');
    const [editType, setEditType] = React.useState<SecretType>('text');
    const [editValue, setEditValue] = React.useState('');
    const [rotateValue, setRotateValue] = React.useState('');
    const [driftOpen, setDriftOpen] = React.useState(false);
    const [rotationPlanOpen, setRotationPlanOpen] = React.useState(false);

    React.useEffect(() => {
        if (list.activeModal === 'edit-secret' && list.modalData?.secret) {
            setEditName(list.modalData.secret.name);
            setEditType(list.modalData.secret.type as SecretType);
            setEditValue('');
        }
        if (list.activeModal === 'rotate-secret') {
            setRotateValue(generateSecret());
        }
    }, [list.activeModal, list.modalData]);

    const resetCreate = () => {
        setCreateName('');
        setCreateValue('');
        setCreateType('text');
    };

    const handleCreate = () => {
        if (!createName.trim() || !createValue.trim()) return;
        list.createMutation.mutate(
            {
                name: createName.trim(),
                value: createValue,
                type: createType,
                project_id: projectId,
                ...(activeEnvId ? { environment_id: activeEnvId } : {}),
            },
            { onSuccess: resetCreate }
        );
    };

    // ── Selected items (bulk delete) ─────────────────────────────────────
    const [selectedItems, setSelectedItems] = React.useState<Set<number>>(new Set());
    const toggleSelected = (id: number) =>
        setSelectedItems((prev) => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    const clearSelected = () => setSelectedItems(new Set());

    if (list.error) {
        return (
            <Alert
                type="error"
                title="Failed to load secrets"
                message={apiErrorMessage(list.error, 'There was an error loading secrets for this project.')}
            >
                <Button variant="outline" size="sm" onClick={() => list.refetch()}>
                    Retry
                </Button>
            </Alert>
        );
    }

    return (
        <div>
            {/* Environment pills */}
            <EnvironmentPills
                environments={environments}
                activeEnvName={activeEnvName}
                onChange={handleEnvChange}
                isLoading={envsLoading}
            />

            {/* Toolbar */}
            <SecretsToolbar
                list={list}
                selectedItems={selectedItems}
                clearSelected={clearSelected}
                onOpenDrift={() => setDriftOpen(true)}
                onOpenRotationPlan={() => setRotationPlanOpen(true)}
            />

            {/* Table */}
            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                <SecretsTableContent
                    list={list}
                    activeEnvName={activeEnvName}
                    selectedItems={selectedItems}
                    toggleSelected={toggleSelected}
                    clearSelected={clearSelected}
                    onView={setViewingSecret}
                    reveal={reveal}
                />
            </div>

            {/* Fetching indicator */}
            {list.isFetching && !list.isLoading && (
                <div className="flex items-center gap-2 mt-2 text-xs" style={{ color: 'var(--text-muted)' }}>
                    <div className="animate-spin rounded-full h-3 w-3 border-b border-blue-500" />
                    Updating…
                </div>
            )}

            {/* ── Modals ── */}

            <ViewSecretModal viewingSecret={viewingSecret} setViewingSecret={setViewingSecret} list={list} />

            <CreateSecretModal
                list={list}
                activeEnvName={activeEnvName}
                createName={createName}
                setCreateName={setCreateName}
                createValue={createValue}
                setCreateValue={setCreateValue}
                createType={createType}
                setCreateType={setCreateType}
                onSubmit={handleCreate}
                onCancel={() => {
                    list.closeModal();
                    resetCreate();
                }}
            />

            <EditSecretModal
                list={list}
                editName={editName}
                setEditName={setEditName}
                editType={editType}
                setEditType={setEditType}
                editValue={editValue}
                setEditValue={setEditValue}
            />

            <DeleteSecretModal list={list} />

            {/* Share */}
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

            <RotateSecretModal list={list} rotateValue={rotateValue} setRotateValue={setRotateValue} />

            {/* Drift report */}
            <Modal isOpen={driftOpen} onClose={() => setDriftOpen(false)} size="xl">
                <SecretsDriftPanel projectId={projectId} />
            </Modal>

            {/* Rotation plan */}
            <Modal isOpen={rotationPlanOpen} onClose={() => setRotationPlanOpen(false)} size="xl">
                <SecretsRotationPlanPanel projectId={projectId} />
            </Modal>
        </div>
    );
};
