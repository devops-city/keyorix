import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import { render, screen, fireEvent, within, act } from '../../../test/test-utils';
import { SecretsListPage } from '../SecretsListPage';

const {
    createMutate,
    editMutate,
    deleteMutate,
    rotateMutate,
    bulkDeleteMutate,
    bulkClassifyMutate,
    autoRotateMutate,
    refetchMock,
    setSearchInputMock,
    handleFilterChangeMock,
    setSortByMock,
    handlePageChangeMock,
    handlePageSizeChangeMock,
    setShowAdvancedFiltersMock,
    handleClearFiltersMock,
} = vi.hoisted(() => ({
    createMutate: vi.fn(),
    editMutate: vi.fn(),
    deleteMutate: vi.fn(),
    rotateMutate: vi.fn(),
    bulkDeleteMutate: vi.fn(),
    bulkClassifyMutate: vi.fn(),
    autoRotateMutate: vi.fn(),
    refetchMock: vi.fn(),
    setSearchInputMock: vi.fn(),
    handleFilterChangeMock: vi.fn(),
    setSortByMock: vi.fn(),
    handlePageChangeMock: vi.fn(),
    handlePageSizeChangeMock: vi.fn(),
    setShowAdvancedFiltersMock: vi.fn(),
    handleClearFiltersMock: vi.fn(),
}));

const listState = vi.hoisted(() => ({
    secrets: [] as any[],
    isLoading: false,
    error: null as unknown,
    isFetching: false,
    searchInput: '',
    filters: { search: '', type: 'all', classification: '', environment: '', tags: [] as string[] },
    environments: [
        { id: 1, name: 'production' },
        { id: 2, name: 'staging' },
    ] as any[],
    sortBy: 'modified_desc',
    pagination: { page: 1, pageSize: 20, total: 0, totalPages: 1 },
    showAdvancedFilters: false,
    hasActiveFilters: false,
    createMutation: { isPending: false, isError: false, error: null as unknown },
    editMutation: { isPending: false, isError: false, error: null as unknown },
    deleteMutation: { isPending: false, isError: false, error: null as unknown },
    rotateMutation: { isPending: false, isError: false, error: null as unknown },
    bulkDeleteMutation: { isPending: false, isError: false, error: null as unknown },
}));

const bulkClassifyState = vi.hoisted(() => ({ isPending: false }));
const autoRotateState = vi.hoisted(() => ({ isPending: false, isError: false, error: null as unknown }));
const secretPolicyState = vi.hoisted(() => ({ data: undefined as any }));
const createProjectsState = vi.hoisted(() => ({ data: [] as any[] }));
const createEnvironmentsState = vi.hoisted(() => ({ data: [] as any[] }));

vi.mock('../../../features/secrets', () => ({
    useSecretsList: () => {
        const [activeModal, setActiveModalState] = React.useState<string | null>(null);
        const [modalData, setModalData] = React.useState<any>(null);
        const [selectedItems, setSelectedItems] = React.useState<Set<number>>(new Set());
        const openModal = (id: string, data: any = null) => {
            setActiveModalState(id);
            setModalData(data);
        };
        const closeModal = () => {
            setActiveModalState(null);
            setModalData(null);
        };
        const toggleSelectedItem = (id: number) =>
            setSelectedItems((prev) => {
                const next = new Set(prev);
                if (next.has(id)) next.delete(id);
                else next.add(id);
                return next;
            });
        const clearSelectedItems = () => setSelectedItems(new Set());
        return {
            secrets: listState.secrets,
            isLoading: listState.isLoading,
            error: listState.error,
            refetch: refetchMock,
            isFetching: listState.isFetching,
            searchInput: listState.searchInput,
            setSearchInput: setSearchInputMock,
            filters: listState.filters,
            handleFilterChange: handleFilterChangeMock,
            environments: listState.environments,
            sortBy: listState.sortBy,
            setSortBy: setSortByMock,
            pagination: listState.pagination,
            handlePageChange: handlePageChangeMock,
            handlePageSizeChange: handlePageSizeChangeMock,
            showAdvancedFilters: listState.showAdvancedFilters,
            setShowAdvancedFilters: setShowAdvancedFiltersMock,
            hasActiveFilters: listState.hasActiveFilters,
            handleClearFilters: handleClearFiltersMock,
            selectedItems,
            toggleSelectedItem,
            clearSelectedItems,
            createMutation: { mutate: createMutate, ...listState.createMutation },
            editMutation: { mutate: editMutate, ...listState.editMutation },
            deleteMutation: { mutate: deleteMutate, ...listState.deleteMutation },
            rotateMutation: { mutate: rotateMutate, ...listState.rotateMutation },
            bulkDeleteMutation: { mutate: bulkDeleteMutate, ...listState.bulkDeleteMutation },
            openModal,
            closeModal,
            activeModal,
            modalData,
        };
    },
    useSecretReveal: () => ({
        copyingSecretId: null,
        copiedSecretId: null,
        copyErrorId: null,
        handleCopySecretValue: vi.fn(),
    }),
    useBulkClassifySecrets: () => ({ mutate: bulkClassifyMutate, ...bulkClassifyState }),
    useSetAutoRotate: () => ({ mutate: autoRotateMutate, ...autoRotateState }),
    useSecretPolicy: () => ({ data: secretPolicyState.data }),
    SecretTableRow: ({
        secret,
        isSelected,
        onToggleSelect,
        onView,
        onEdit,
        onDelete,
        onShare,
        onRotate,
        onAutoRotate,
    }: any) => (
        <tr>
            <td>
                <input
                    type="checkbox"
                    aria-label={`select ${secret.name}`}
                    checked={isSelected}
                    onChange={() => onToggleSelect(secret.id)}
                />
            </td>
            <td>{secret.name}</td>
            <td>
                <button onClick={() => onView(secret)}>View {secret.name}</button>
                <button onClick={() => onEdit(secret)}>Edit {secret.name}</button>
                <button onClick={() => onDelete(secret)}>Delete {secret.name}</button>
                <button onClick={() => onShare(secret)}>Share {secret.name}</button>
                <button onClick={() => onRotate(secret)}>Rotate {secret.name}</button>
                <button onClick={() => onAutoRotate(secret)}>Auto-rotate {secret.name}</button>
            </td>
        </tr>
    ),
    SecretDetailView: ({ secret, onClose, onEdit, onShare, onDelete }: any) => (
        <div>
            <p>Detail: {secret.name}</p>
            <button onClick={() => onEdit(secret)}>Detail Edit</button>
            <button onClick={() => onShare(secret)}>Detail Share</button>
            <button onClick={() => onDelete(secret)}>Detail Delete</button>
            <button onClick={onClose}>Detail Close</button>
        </div>
    ),
}));

vi.mock('../../../features/projects', () => ({
    useProjects: () => ({ data: createProjectsState.data }),
    useProjectEnvironments: () => ({ data: createEnvironmentsState.data }),
}));

vi.mock('../../../features/sharing', () => ({
    ShareSecretModal: ({ secret, onClose, onSuccess }: any) => (
        <div role="dialog" aria-label="share-modal">
            <p>Share: {secret.name}</p>
            <button onClick={onClose}>Close Share</button>
            <button onClick={onSuccess}>Share Success</button>
        </div>
    ),
}));

const secretsFixture = [
    { id: 1, name: 'db-pass', type: 'password', Expiration: null },
    { id: 2, name: 'api-key', type: 'api_key', Expiration: null },
];

function resetState() {
    listState.secrets = [];
    listState.isLoading = false;
    listState.error = null;
    listState.isFetching = false;
    listState.searchInput = '';
    listState.filters = { search: '', type: 'all', classification: '', environment: '', tags: [] };
    listState.environments = [
        { id: 1, name: 'production' },
        { id: 2, name: 'staging' },
    ];
    listState.sortBy = 'modified_desc';
    listState.pagination = { page: 1, pageSize: 20, total: 0, totalPages: 1 };
    listState.showAdvancedFilters = false;
    listState.hasActiveFilters = false;
    listState.createMutation = { isPending: false, isError: false, error: null };
    listState.editMutation = { isPending: false, isError: false, error: null };
    listState.deleteMutation = { isPending: false, isError: false, error: null };
    listState.rotateMutation = { isPending: false, isError: false, error: null };
    listState.bulkDeleteMutation = { isPending: false, isError: false, error: null };
    bulkClassifyState.isPending = false;
    autoRotateState.isPending = false;
    autoRotateState.isError = false;
    autoRotateState.error = null;
    secretPolicyState.data = undefined;
    createProjectsState.data = [];
    createEnvironmentsState.data = [];
}

beforeEach(() => {
    vi.clearAllMocks();
    resetState();
    window.history.pushState({}, '', '/');
});

// What the signed-in user may do. Tests that exercise a control assume the user can; the
// permission-aware cases flip fields on this object (see useCan.ts).
const canState = vi.hoisted(() => ({
    value: { admin: true, writeSecrets: true, deleteSecrets: true, readAudit: true, manageMembers: true },
}));
vi.mock('../../../features/auth/useCan', () => ({ useCan: () => canState.value }));
beforeEach(() => {
    canState.value = { admin: true, writeSecrets: true, deleteSecrets: true, readAudit: true, manageMembers: true };
});

describe('SecretsListPage — loading / empty / error states', () => {
    it('shows a loading indicator while secrets are loading', () => {
        listState.isLoading = true;
        render(<SecretsListPage />);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('shows an empty state with a create action when there are no active filters', () => {
        render(<SecretsListPage />);
        expect(screen.getByText('No secrets found')).toBeInTheDocument();
        expect(screen.getByText('Get started by creating your first secret.')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Create Secret' }));
        expect(screen.getByRole('heading', { name: 'Create New Secret' })).toBeInTheDocument();
    });

    it('shows a filtered empty state without a create action when filters are active', () => {
        listState.hasActiveFilters = true;
        render(<SecretsListPage />);
        expect(screen.getByText('Try adjusting your filters or search terms.')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Create Secret' })).not.toBeInTheDocument();
    });

    it('shows an error alert and retries', () => {
        listState.error = new Error('boom');
        render(<SecretsListPage />);
        expect(screen.getByText('Failed to load secrets')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
        expect(refetchMock).toHaveBeenCalled();
    });
});

describe('SecretsListPage — secrets table', () => {
    it('renders secret rows', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);
        expect(screen.getByText('db-pass')).toBeInTheDocument();
        expect(screen.getByText('api-key')).toBeInTheDocument();
    });

    it('filters to secrets with an expiration when ?filter=expiring is present, and the clear button updates the URL', () => {
        listState.secrets = [
            { id: 1, name: 'db-pass', type: 'password', Expiration: null },
            { id: 2, name: 'api-key', type: 'api_key', Expiration: '2026-12-01T00:00:00Z' },
        ];
        window.history.pushState({}, '', '/?filter=expiring');
        render(<SecretsListPage />);
        expect(screen.getByText('api-key')).toBeInTheDocument();
        expect(screen.queryByText('db-pass')).not.toBeInTheDocument();
        expect(screen.getByText('Showing secrets with expiration set')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /clear filter/i }));
        expect(window.location.search).toBe('');
    });

    it('applies a ?sort= URL param to the sort field on mount', () => {
        window.history.pushState({}, '', '/?sort=expiry_asc');
        render(<SecretsListPage />);
        expect(setSortByMock).toHaveBeenCalledWith('expiry_asc');
    });
});

describe('SecretsListPage — search / filter / sort / page-size controls', () => {
    it('reports search input changes to the list hook', () => {
        render(<SecretsListPage />);
        fireEvent.change(screen.getByPlaceholderText('Search by name, type, or tags...'), {
            target: { value: 'db' },
        });
        expect(setSearchInputMock).toHaveBeenCalledWith('db');
    });

    it('reports type/classification/environment/sort/page-size control changes to the list hook', () => {
        render(<SecretsListPage />);
        const [typeSelect, classificationSelect, environmentSelect, sortSelect, pageSizeSelect] =
            screen.getAllByRole('combobox');

        fireEvent.change(typeSelect!, { target: { value: 'password' } });
        expect(handleFilterChangeMock).toHaveBeenCalledWith('type', 'password');

        fireEvent.change(classificationSelect!, { target: { value: 'confidential' } });
        expect(handleFilterChangeMock).toHaveBeenCalledWith('classification', 'confidential');
        fireEvent.change(classificationSelect!, { target: { value: 'all' } });
        expect(handleFilterChangeMock).toHaveBeenCalledWith('classification', '');

        fireEvent.change(environmentSelect!, { target: { value: 'staging' } });
        expect(handleFilterChangeMock).toHaveBeenCalledWith('environment', 'staging');
        fireEvent.change(environmentSelect!, { target: { value: 'all' } });
        expect(handleFilterChangeMock).toHaveBeenCalledWith('environment', '');

        fireEvent.change(sortSelect!, { target: { value: 'name_asc' } });
        expect(setSortByMock).toHaveBeenCalledWith('name_asc');

        fireEvent.change(pageSizeSelect!, { target: { value: '50' } });
        expect(handlePageSizeChangeMock).toHaveBeenCalledWith(50);
    });

    // SESSION-I regression: useSecretsList's `environments` is the GLOBAL,
    // cross-project list (query key ['environments'], no project scope), so
    // any two projects sharing an environment name (the common case --
    // "development"/"staging"/"production" is every new project's default
    // env set) produce multiple environment ROWS with the same name. The
    // environment filter Select previously mapped one <option> per ROW,
    // keyed by name -- React's reconciler warns "Encountered two children
    // with the same key" and (per React's own docs on duplicate keys) may
    // duplicate or omit affected children, found live against a real
    // multi-project backend by web/e2e/real/pages.spec.ts. This filter is
    // itself name-based (onFilterChange('environment', name) filters
    // secrets by environment NAME across every project), so the correct
    // fix is deduping by name before mapping to options, not switching the
    // value to an id.
    it('deduplicates same-named environments from different projects in the environment filter', () => {
        listState.environments = [
            { id: 1, name: 'production' },
            { id: 2, name: 'staging' },
            { id: 3, name: 'production' }, // same name, different project
            { id: 4, name: 'staging' }, // same name, different project
        ];
        render(<SecretsListPage />);
        const [, , environmentSelect] = screen.getAllByRole('combobox');

        const optionLabels = within(environmentSelect!)
            .getAllByRole('option')
            .map((o) => o.textContent);
        expect(optionLabels).toEqual(['All Environments', 'Production', 'Staging']);
    });

    it('toggles the advanced filters section', () => {
        render(<SecretsListPage />);
        expect(screen.getByRole('button', { name: /more filters/i })).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /more filters/i }));
        expect(setShowAdvancedFiltersMock).toHaveBeenCalledWith(true);
    });

    it('shows the advanced filters panel and a "Hide Filters" label when already expanded', () => {
        listState.showAdvancedFilters = true;
        render(<SecretsListPage />);
        const toggleButton = screen.getByRole('button', { name: /hide filters/i });
        expect(toggleButton).toBeInTheDocument();
        fireEvent.click(toggleButton);
        expect(setShowAdvancedFiltersMock).toHaveBeenCalledWith(false);
    });

    it('shows a "Clear all" action when filters are active and reports the click', () => {
        listState.hasActiveFilters = true;
        render(<SecretsListPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
        expect(handleClearFiltersMock).toHaveBeenCalled();
    });

    it('shows a fetching indicator while refetching in the background', () => {
        listState.isFetching = true;
        render(<SecretsListPage />);
        expect(screen.getByText('Updating results...')).toBeInTheDocument();
    });
});

describe('SecretsListPage — pagination', () => {
    it('shows the page label, disables the previous button on the first page, and reports next-page clicks', () => {
        listState.secrets = secretsFixture;
        listState.pagination = { page: 1, pageSize: 20, total: 40, totalPages: 2 };
        render(<SecretsListPage />);

        expect(screen.getByText('Page 1 of 2')).toBeInTheDocument();
        const [prevButton, nextButton] = screen.getAllByRole('button', { name: '' });
        expect(prevButton).toBeDisabled();

        fireEvent.click(nextButton!);
        expect(handlePageChangeMock).toHaveBeenCalledWith(2);
    });

    it('reports previous-page clicks when not on the first page', () => {
        listState.secrets = secretsFixture;
        listState.pagination = { page: 2, pageSize: 20, total: 40, totalPages: 2 };
        render(<SecretsListPage />);

        const [prevButton] = screen.getAllByRole('button', { name: '' });
        expect(prevButton).not.toBeDisabled();
        fireEvent.click(prevButton!);
        expect(handlePageChangeMock).toHaveBeenCalledWith(1);
    });
});

describe('SecretsListPage — bulk selection', () => {
    it('tracks selected rows via per-row checkboxes', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);
        fireEvent.click(screen.getByLabelText('select db-pass'));
        expect(screen.getByText('1 selected')).toBeInTheDocument();
    });

    it('selects all rows via the header checkbox and clears via the Clear button', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        const headerCheckbox = within(screen.getByTestId('secrets-table')).getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox);
        expect(screen.getByText('2 selected')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
        expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
    });

    it('unchecking the header checkbox clears the selection', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        const headerCheckbox = within(screen.getByTestId('secrets-table')).getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox);
        expect(screen.getByText('2 selected')).toBeInTheDocument();

        fireEvent.click(headerCheckbox);
        expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
    });
});

describe('SecretsListPage — bulk classify / bulk delete', () => {
    it('classifies selected secrets, mapping "unclassified" to an empty classification', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        const headerCheckbox = within(screen.getByTestId('secrets-table')).getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox);

        fireEvent.change(screen.getByLabelText('Classify selected'), { target: { value: 'confidential' } });
        expect(bulkClassifyMutate).toHaveBeenCalledWith(
            { ids: [1, 2], classification: 'confidential' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );

        fireEvent.change(screen.getByLabelText('Classify selected'), { target: { value: 'unclassified' } });
        expect(bulkClassifyMutate).toHaveBeenCalledWith(
            { ids: [1, 2], classification: '' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );

        const onSuccess = bulkClassifyMutate.mock.calls[0][1].onSuccess;
        act(() => onSuccess());
        expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
    });

    it('ignores a Classify-selected change with no value', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        const headerCheckbox = within(screen.getByTestId('secrets-table')).getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox);

        fireEvent.change(screen.getByLabelText('Classify selected'), { target: { value: '' } });
        expect(bulkClassifyMutate).not.toHaveBeenCalled();
    });

    it('deletes selected secrets after confirming in the bulk-delete modal', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        const headerCheckbox = within(screen.getByTestId('secrets-table')).getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox);
        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        expect(screen.getByText('Delete Selected Secrets')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Delete 2 Secret(s)' }));
        expect(bulkDeleteMutate).toHaveBeenCalledWith([1, 2]);
    });

    it('shows a busy label while the bulk-delete mutation is pending', () => {
        listState.secrets = secretsFixture;
        listState.bulkDeleteMutation = { isPending: true, isError: false, error: null };
        render(<SecretsListPage />);

        const headerCheckbox = within(screen.getByTestId('secrets-table')).getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox);
        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        expect(screen.getByRole('button', { name: 'Deleting…' })).toBeDisabled();
    });
});

describe('SecretsListPage — create secret: project/environment defaulting', () => {
    it('defaults the create-form project and environment to the first available once loaded', () => {
        createProjectsState.data = [
            { id: 7, name: 'Proj A' },
            { id: 8, name: 'Proj B' },
        ];
        createEnvironmentsState.data = [{ id: 70, name: 'dev' }];
        render(<SecretsListPage />);

        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);
        expect(screen.getByLabelText(/^Project/)).toHaveValue('7');
        expect(screen.getByLabelText(/^Environment/)).toHaveValue('70');
    });

    it('resets the selected environment when it becomes invalid for the current project', () => {
        createProjectsState.data = [{ id: 1, name: 'P1' }];
        createEnvironmentsState.data = [{ id: 100, name: 'dev' }];
        const { rerender } = render(<SecretsListPage />);

        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);
        expect(screen.getByLabelText(/^Environment/)).toHaveValue('100');

        createEnvironmentsState.data = [{ id: 200, name: 'staging' }];
        rerender(<SecretsListPage />);
        expect(screen.getByLabelText(/^Environment/)).toHaveValue('200');
    });

    it('reports manual project/environment selection changes', () => {
        createProjectsState.data = [
            { id: 7, name: 'Proj A' },
            { id: 8, name: 'Proj B' },
        ];
        createEnvironmentsState.data = [
            { id: 70, name: 'dev' },
            { id: 71, name: 'staging' },
        ];
        render(<SecretsListPage />);

        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);
        fireEvent.change(screen.getByLabelText(/^Project/), { target: { value: '8' } });
        expect(screen.getByLabelText(/^Project/)).toHaveValue('8');

        fireEvent.change(screen.getByLabelText(/^Environment/), { target: { value: '71' } });
        expect(screen.getByLabelText(/^Environment/)).toHaveValue('71');
    });

    it('renders no project/environment options and skips the env-validity effect when neither has loaded yet', () => {
        createProjectsState.data = undefined as unknown as any[];
        createEnvironmentsState.data = undefined as unknown as any[];
        render(<SecretsListPage />);

        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);
        expect(screen.getByLabelText(/^Project/)).toHaveDisplayValue([]);
        expect(screen.getByLabelText(/^Environment/)).toHaveDisplayValue([]);
    });

    it('blocks submission with an inline error when no project/environment is available', () => {
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'new-secret' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret' } });
        fireEvent.click(screen.getByTestId('create-secret-submit'));

        expect(screen.getByText('Select a project and environment for the new secret.')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });
});

describe('SecretsListPage — create secret: naming policy validation', () => {
    beforeEach(() => {
        createProjectsState.data = [{ id: 1, name: 'P1' }];
        createEnvironmentsState.data = [{ id: 10, name: 'dev' }];
    });

    it('shows the naming policy hint and blocks submission for a name violating the pattern', () => {
        secretPolicyState.data = { name: { enabled: true, pattern: '^[a-z]+$', max_length: 20 } };
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);

        expect(screen.getByText(/Naming policy: must match \^\[a-z\]\+\$; max 20 chars\./)).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Invalid123' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret' } });
        fireEvent.click(screen.getByTestId('create-secret-submit'));

        expect(screen.getByText('Name must match the pattern ^[a-z]+$.')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('shows only the max-length hint and blocks submission for a name exceeding it, with no pattern configured', () => {
        secretPolicyState.data = { name: { enabled: true, max_length: 5 } };
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);

        expect(screen.getByText('Naming policy: max 5 chars.')).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'way-too-long-name' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret' } });
        fireEvent.click(screen.getByTestId('create-secret-submit'));

        expect(screen.getByText('Name exceeds the 5-character maximum.')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('allows a name that satisfies the naming pattern and submits the create payload', () => {
        secretPolicyState.data = { name: { enabled: true, pattern: '^[a-z]+$', max_length: 20 } };
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);

        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'validname' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret' } });
        fireEvent.click(screen.getByTestId('create-secret-submit'));

        expect(createMutate).toHaveBeenCalledWith(
            {
                name: 'validname',
                value: 'super-secret',
                type: 'text',
                project_id: 1,
                environment_id: 10,
            },
            expect.objectContaining({ onSuccess: expect.any(Function), onError: expect.any(Function) })
        );
    });

    it('allows a name under the max length when no pattern is configured, and submits', () => {
        secretPolicyState.data = { name: { enabled: true, max_length: 20 } };
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);

        expect(screen.getByText('Naming policy: max 20 chars.')).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'short-name' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret' } });
        fireEvent.click(screen.getByTestId('create-secret-submit'));

        expect(screen.queryByText('Name exceeds the 20-character maximum.')).not.toBeInTheDocument();
        expect(createMutate).toHaveBeenCalled();
    });

    // Documented, not fixed (out of scope for this coverage-only PR): a naming
    // pattern that looks catastrophically-backtracking (per safe-regex's
    // heuristic, e.g. `(a+)+$`) is never validated client-side — this is the
    // intended behavior per checkNamePatternUnsafe/testPatternSafely, not a bug.
    it('skips client-side validation and shows a warning for a naming pattern that looks unsafe', () => {
        secretPolicyState.data = { name: { enabled: true, pattern: '(a+)+$' } };
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);

        expect(screen.getByText(/can't be safely checked in your browser/)).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'anything-goes' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret' } });
        fireEvent.click(screen.getByTestId('create-secret-submit'));

        expect(createMutate).toHaveBeenCalled();
    });
});

describe('SecretsListPage — create secret: submission outcomes', () => {
    beforeEach(() => {
        createProjectsState.data = [{ id: 1, name: 'P1' }];
        createEnvironmentsState.data = [{ id: 10, name: 'dev' }];
    });

    it('resets the draft after a successful create', () => {
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'new-secret' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret' } });
        fireEvent.click(screen.getByTestId('create-secret-submit'));

        expect(createMutate).toHaveBeenCalled();
        const onSuccess = createMutate.mock.calls[0][1].onSuccess;
        act(() => onSuccess());
        expect(screen.getByLabelText(/^Name/)).toHaveValue('');
    });

    it('discards the draft when Cancel is clicked', () => {
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'draft-name' } });
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);
        expect(screen.getByLabelText(/^Name/)).toHaveValue('');
    });

    it('generates a value via the Generate button and reports a type change', () => {
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);

        fireEvent.click(screen.getByRole('button', { name: /generate/i }));
        const valueField = screen.getByLabelText(/^Value/) as HTMLTextAreaElement;
        expect(valueField.value.length).toBeGreaterThan(0);

        fireEvent.change(screen.getByLabelText(/^Type/), { target: { value: 'api_key' } });
        expect(screen.getByLabelText(/^Type/)).toHaveValue('api_key');
    });

    it('shows a busy label while the create mutation is pending', () => {
        listState.createMutation = { isPending: true, isError: false, error: null };
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);

        expect(screen.getByRole('button', { name: 'Creating…' })).toBeDisabled();
    });

    it('shows a server error message when the create mutation fails', () => {
        render(<SecretsListPage />);
        fireEvent.click(screen.getAllByTestId('create-secret-button')[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'new-secret' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret' } });
        fireEvent.click(screen.getByTestId('create-secret-submit'));

        const onError = createMutate.mock.calls[0][1].onError;
        act(() => onError(new Error('name already taken')));
        expect(screen.getByText('Failed to create secret')).toBeInTheDocument();
        expect(screen.getByText('name already taken')).toBeInTheDocument();
    });
});

describe('SecretsListPage — view / edit / delete / rotate / share', () => {
    it('opens the view modal and navigates to edit from it', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('View db-pass'));
        expect(screen.getByText('Detail: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByText('Detail Edit'));
        expect(screen.getByText('Edit Secret: db-pass')).toBeInTheDocument();
        expect(screen.queryByText('Detail: db-pass')).not.toBeInTheDocument();
    });

    it('prefills and submits the edit form', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByLabelText('Name')).toHaveValue('db-pass');

        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
        expect(editMutate).toHaveBeenCalledWith({ id: 1, name: 'db-pass', type: 'password', value: '' });
    });

    it('edits the name, type, and value fields, including via the Generate button', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'renamed-secret' } });
        fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'api_key' } });
        fireEvent.change(screen.getByLabelText('New Value'), { target: { value: 'manual-value' } });
        fireEvent.click(screen.getByRole('button', { name: /generate/i }));

        const valueInput = screen.getByLabelText('New Value') as HTMLInputElement;
        expect(valueInput.value).not.toBe('manual-value');
        expect(valueInput.value.length).toBeGreaterThan(0);

        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
        expect(editMutate).toHaveBeenCalledWith({
            id: 1,
            name: 'renamed-secret',
            type: 'api_key',
            value: valueInput.value,
        });
    });

    it('shows the edit-mutation error message', () => {
        listState.secrets = secretsFixture;
        listState.editMutation = { isPending: false, isError: true, error: new Error('edit failed') };
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByText('Failed to update secret')).toBeInTheDocument();
        expect(screen.getByText('edit failed')).toBeInTheDocument();
    });

    it('falls back to a generic edit-error message for a non-Error value', () => {
        listState.secrets = secretsFixture;
        listState.editMutation = { isPending: false, isError: true, error: 'nope' };
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByText('An unexpected error occurred')).toBeInTheDocument();
    });

    it('shows a busy label while the edit is saving', () => {
        listState.secrets = secretsFixture;
        listState.editMutation = { isPending: true, isError: false, error: null };
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByRole('button', { name: 'Saving…' })).toBeInTheDocument();
    });

    it('deletes a secret after confirming', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Delete db-pass'));
        expect(screen.getByText('Delete Secret')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
        expect(deleteMutate).toHaveBeenCalledWith(1);
    });

    it('shows the delete-mutation error message', () => {
        listState.secrets = secretsFixture;
        listState.deleteMutation = { isPending: false, isError: true, error: new Error('cannot delete') };
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Delete db-pass'));
        expect(screen.getByText('Failed to delete secret')).toBeInTheDocument();
        expect(screen.getByText('cannot delete')).toBeInTheDocument();
    });

    it('falls back to a generic delete-error message for a non-Error value', () => {
        listState.secrets = secretsFixture;
        listState.deleteMutation = { isPending: false, isError: true, error: 'nope' };
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Delete db-pass'));
        expect(screen.getByText('An unexpected error occurred')).toBeInTheDocument();
    });

    it('shows a busy label while the delete is pending', () => {
        listState.secrets = secretsFixture;
        listState.deleteMutation = { isPending: true, isError: false, error: null };
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Delete db-pass'));
        expect(screen.getByRole('button', { name: 'Deleting…' })).toBeInTheDocument();
    });

    it('rotates a secret with a pre-generated value', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Rotate db-pass'));
        expect(screen.getByText('Rotate Secret: db-pass')).toBeInTheDocument();

        const valueInput = screen.getByLabelText('New Value') as HTMLInputElement;
        expect(valueInput.value.length).toBeGreaterThan(0);

        fireEvent.click(screen.getByRole('button', { name: 'Rotate' }));
        expect(rotateMutate).toHaveBeenCalledWith({ id: 1, newValue: valueInput.value });
    });

    it('allows manually editing or regenerating the rotate value', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Rotate db-pass'));
        fireEvent.change(screen.getByLabelText('New Value'), { target: { value: 'manual-rotate-value' } });
        expect(screen.getByLabelText('New Value')).toHaveValue('manual-rotate-value');

        fireEvent.click(screen.getByRole('button', { name: /regenerate/i }));
        const valueInput = screen.getByLabelText('New Value') as HTMLInputElement;
        expect(valueInput.value).not.toBe('manual-rotate-value');

        fireEvent.click(screen.getByRole('button', { name: 'Rotate' }));
        expect(rotateMutate).toHaveBeenCalledWith({ id: 1, newValue: valueInput.value });
    });

    it('shows the rotate-mutation error message', () => {
        listState.secrets = secretsFixture;
        listState.rotateMutation = { isPending: false, isError: true, error: new Error('rotation failed') };
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Rotate db-pass'));
        expect(screen.getByText('Failed to rotate secret')).toBeInTheDocument();
        expect(screen.getByText('rotation failed')).toBeInTheDocument();
    });

    it('shows a busy label and disables Rotate while pending', () => {
        listState.secrets = secretsFixture;
        listState.rotateMutation = { isPending: true, isError: false, error: null };
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Rotate db-pass'));
        expect(screen.getByRole('button', { name: 'Rotating…' })).toBeDisabled();
    });

    // SHARE-2: the page used to close the dialog in onSuccess, which unmounted it
    // before its "Shared!" confirmation rendered. It now only refreshes the list; the
    // dialog closes itself (onClose) once the confirmation has been shown.
    it('refetches on share success and leaves the dialog open for its confirmation', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Share db-pass'));
        expect(screen.getByText('Share: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByText('Share Success'));
        expect(refetchMock).toHaveBeenCalled();
        expect(screen.getByText('Share: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByText('Close Share'));
        expect(screen.queryByText('Share: db-pass')).not.toBeInTheDocument();
    });

    // SHARE-2: a refused update shows the server's reason (apiErrorMessage), not
    // axios's "Request failed with status code 403".
    it("shows the server's reason when an edit is refused", () => {
        listState.secrets = secretsFixture;
        listState.editMutation = {
            isPending: false,
            isError: true,
            error: new AxiosError('Request failed with status code 403', 'ERR_BAD_REQUEST', undefined, undefined, {
                status: 403,
                statusText: 'Forbidden',
                headers: {},
                config: { headers: new AxiosHeaders() },
                data: { error: 'Forbidden', message: 'Insufficient permissions' },
            }),
        };
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByText('Failed to update secret')).toBeInTheDocument();
        expect(screen.getByText('Insufficient permissions')).toBeInTheDocument();
        expect(screen.queryByText('Request failed with status code 403')).not.toBeInTheDocument();
    });

    it('opens the share modal from the view-detail modal', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('View db-pass'));
        fireEvent.click(screen.getByText('Detail Share'));

        expect(screen.getByText('Share: db-pass')).toBeInTheDocument();
        expect(screen.queryByText('Detail: db-pass')).not.toBeInTheDocument();
    });

    it('opens the delete-confirmation modal from the view-detail modal', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('View db-pass'));
        fireEvent.click(screen.getByText('Detail Delete'));

        expect(screen.getByText('Delete Secret')).toBeInTheDocument();
        expect(screen.queryByText('Detail: db-pass')).not.toBeInTheDocument();
    });
});

describe('SecretsListPage — automated rotation', () => {
    it('validates the backend/ref pairing and submits the configured payload, closing on success', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Auto-rotate db-pass'));
        expect(screen.getByText('Automated Rotation: db-pass')).toBeInTheDocument();
        expect(screen.getByLabelText('Enable auto-rotation')).toBeChecked();

        fireEvent.change(screen.getByLabelText('Backend'), { target: { value: 'prod-postgres' } });
        expect(screen.getByText('Backend and ref must be set together.')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();

        fireEvent.change(screen.getByLabelText('Upstream ref'), { target: { value: 'app_svc' } });
        fireEvent.change(screen.getByLabelText('Value length'), { target: { value: '16' } });
        fireEvent.change(screen.getByLabelText('Charset'), { target: { value: 'hex' } });
        expect(screen.queryByText('Backend and ref must be set together.')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Save' }));
        expect(autoRotateMutate).toHaveBeenCalledWith(
            { enabled: true, length: 16, charset: 'hex', backend: 'prod-postgres', ref: 'app_svc' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );

        const onSuccess = autoRotateMutate.mock.calls[0][1].onSuccess;
        act(() => onSuccess());
        expect(screen.queryByText('Automated Rotation: db-pass')).not.toBeInTheDocument();
    });

    it('toggles auto-rotation off and submits with length defaulting to 0 when left blank', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Auto-rotate db-pass'));
        const enabledCheckbox = screen.getByLabelText('Enable auto-rotation');
        expect(enabledCheckbox).toBeChecked();

        fireEvent.click(enabledCheckbox);
        expect(enabledCheckbox).not.toBeChecked();

        fireEvent.click(screen.getByRole('button', { name: 'Save' }));
        expect(autoRotateMutate).toHaveBeenCalledWith(
            { enabled: false, length: 0, charset: '', backend: '', ref: '' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('does not submit when the backend/ref mismatch guard is hit on form submit', () => {
        listState.secrets = secretsFixture;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Auto-rotate db-pass'));
        fireEvent.change(screen.getByLabelText('Backend'), { target: { value: 'prod-postgres' } });

        const form = screen.getByLabelText('Backend').closest('form')!;
        fireEvent.submit(form);
        expect(autoRotateMutate).not.toHaveBeenCalled();
    });

    it('shows the auto-rotate mutation error message', () => {
        listState.secrets = secretsFixture;
        autoRotateState.isPending = false;
        autoRotateState.isError = true;
        autoRotateState.error = new Error('auto-rotate failed');
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Auto-rotate db-pass'));
        expect(screen.getByText('Failed to update auto-rotation')).toBeInTheDocument();
        expect(screen.getByText('auto-rotate failed')).toBeInTheDocument();
    });

    it('falls back to a generic auto-rotate error message for a non-Error value', () => {
        listState.secrets = secretsFixture;
        autoRotateState.isError = true;
        autoRotateState.error = 'nope';
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Auto-rotate db-pass'));
        expect(screen.getByText('An unexpected error occurred')).toBeInTheDocument();
    });

    it('shows a busy label while the auto-rotate mutation is pending', () => {
        listState.secrets = secretsFixture;
        autoRotateState.isPending = true;
        render(<SecretsListPage />);

        fireEvent.click(screen.getByText('Auto-rotate db-pass'));
        expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
    });
});

describe('SecretsListPage permission-aware controls (DEMO-UI-1)', () => {
    it('offers no New Secret / Create Secret to a read-only user and says nothing here is visible', () => {
        canState.value = {
            ...canState.value,
            admin: false,
            writeSecrets: false,
            deleteSecrets: false,
            manageMembers: false,
            readAudit: false,
        };
        render(<SecretsListPage />);
        expect(screen.queryByTestId('create-secret-button')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Create Secret' })).not.toBeInTheDocument();
        expect(screen.getByText('No secrets found')).toBeInTheDocument();
        expect(screen.queryByText('Get started by creating your first secret.')).not.toBeInTheDocument();
    });
});
