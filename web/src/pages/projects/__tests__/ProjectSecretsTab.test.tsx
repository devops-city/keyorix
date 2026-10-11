import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { ProjectSecretsTab } from '../ProjectSecretsTab';

const {
    createMutate,
    editMutate,
    deleteMutate,
    rotateMutate,
    refetchMock,
    setSearchMock,
    setTypeFilterMock,
    handlePageChangeMock,
    handlePageSizeChangeMock,
} = vi.hoisted(() => ({
    createMutate: vi.fn(),
    editMutate: vi.fn(),
    deleteMutate: vi.fn(),
    rotateMutate: vi.fn(),
    refetchMock: vi.fn(),
    setSearchMock: vi.fn(),
    setTypeFilterMock: vi.fn(),
    handlePageChangeMock: vi.fn(),
    handlePageSizeChangeMock: vi.fn(),
}));

const listState = vi.hoisted(() => ({
    secrets: [] as any[],
    isLoading: false,
    error: null as unknown,
    isFetching: false,
    search: '',
    typeFilter: 'all',
    pagination: { page: 1, pageSize: 20, total: 0, totalPages: 1 },
    createMutation: { isPending: false, isError: false, error: null as unknown },
    editMutation: { isPending: false, isError: false, error: null as unknown },
    deleteMutation: { isPending: false, isError: false, error: null as unknown },
    rotateMutation: { isPending: false, isError: false, error: null as unknown },
}));

const envState = vi.hoisted(() => ({ data: [] as any[], isLoading: false }));

vi.mock('../../../features/secrets/useProjectSecrets', () => ({
    useProjectSecrets: () => {
        const [activeModal, setActiveModalState] = React.useState<string | null>(null);
        const [modalData, setModalData] = React.useState<any>(null);
        const openModal = (id: string, data: any = null) => {
            setActiveModalState(id);
            setModalData(data);
        };
        const closeModal = () => {
            setActiveModalState(null);
            setModalData(null);
        };
        return {
            secrets: listState.secrets,
            isLoading: listState.isLoading,
            error: listState.error,
            refetch: refetchMock,
            isFetching: listState.isFetching,
            search: listState.search,
            setSearch: setSearchMock,
            typeFilter: listState.typeFilter,
            setTypeFilter: setTypeFilterMock,
            pagination: listState.pagination,
            handlePageChange: handlePageChangeMock,
            handlePageSizeChange: handlePageSizeChangeMock,
            createMutation: { mutate: createMutate, ...listState.createMutation },
            editMutation: { mutate: editMutate, ...listState.editMutation },
            deleteMutation: { mutate: deleteMutate, ...listState.deleteMutation },
            rotateMutation: { mutate: rotateMutate, ...listState.rotateMutation },
            openModal,
            closeModal,
            activeModal,
            modalData,
        };
    },
}));

vi.mock('../../../features/projects/api', () => ({
    useProjectEnvironments: () => ({ data: envState.data, isLoading: envState.isLoading }),
}));

vi.mock('../../../features/secrets', () => ({
    useSecretReveal: () => ({
        copyingSecretId: null,
        copiedSecretId: null,
        copyErrorId: null,
        handleCopySecretValue: vi.fn(),
    }),
    SecretTableRow: ({ secret, isSelected, onToggleSelect, onView, onEdit, onDelete, onShare, onRotate }: any) => (
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

vi.mock('../../../features/sharing', () => ({
    ShareSecretModal: ({ secret, onClose, onSuccess }: any) => (
        <div role="dialog" aria-label="share-modal">
            <p>Share: {secret.name}</p>
            <button onClick={onClose}>Close Share</button>
            <button onClick={onSuccess}>Share Success</button>
        </div>
    ),
}));

vi.mock('../SecretsDriftPanel', () => ({
    SecretsDriftPanel: () => <div>Drift Panel Content</div>,
}));

vi.mock('../SecretsRotationPlanPanel', () => ({
    SecretsRotationPlanPanel: () => <div>Rotation Plan Content</div>,
}));

const twoEnvs = [
    { id: 2, name: 'staging', projectId: 1 },
    { id: 3, name: 'production', projectId: 1 },
];

const secretsFixture = [
    { id: 1, name: 'db-pass', type: 'password' },
    { id: 2, name: 'api-key', type: 'api_key' },
];

function resetState() {
    listState.secrets = [];
    listState.isLoading = false;
    listState.error = null;
    listState.isFetching = false;
    listState.search = '';
    listState.typeFilter = 'all';
    listState.pagination = { page: 1, pageSize: 20, total: 0, totalPages: 1 };
    listState.createMutation = { isPending: false, isError: false, error: null };
    listState.editMutation = { isPending: false, isError: false, error: null };
    listState.deleteMutation = { isPending: false, isError: false, error: null };
    listState.rotateMutation = { isPending: false, isError: false, error: null };
    envState.data = [];
    envState.isLoading = false;
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

describe('ProjectSecretsTab — environment selection', () => {
    it('defaults to the production environment when present', () => {
        envState.data = twoEnvs;
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('No secrets in production')).toBeInTheDocument();
    });

    it('defaults to the first environment when there is no production environment', () => {
        envState.data = [{ id: 5, name: 'dev', projectId: 1 }];
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('No secrets in dev')).toBeInTheDocument();
    });

    it('switches the active environment when a pill is clicked', () => {
        envState.data = twoEnvs;
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: 'Staging' }));
        expect(screen.getByText('No secrets in staging')).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — secrets table', () => {
    it('shows a loading indicator while secrets are loading', () => {
        listState.isLoading = true;
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('shows an empty state with a New Secret action when there are no secrets', () => {
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('No secrets in production')).toBeInTheDocument();
        expect(screen.getByText('Create your first secret in this environment.')).toBeInTheDocument();
    });

    it('renders secret rows', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('db-pass')).toBeInTheDocument();
        expect(screen.getByText('api-key')).toBeInTheDocument();
    });

    // #2977: the shared SecretTableRow renders a Classification cell, but this
    // table's header omitted it, so ENVIRONMENT sat over the classification
    // badge, SHARING over the environment and MODIFIED over "Private".
    it('has one header per cell of the shared row, in the same order (no shifted columns)', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);
        const headers = screen.getAllByRole('columnheader').map((th) => th.textContent);
        expect(headers).toEqual([
            '',
            'Name',
            'Type',
            'Classification',
            'Environment',
            'Sharing',
            'Modified',
            'Actions',
        ]);
    });

    it('shows an error state and retries', () => {
        listState.error = new Error('boom');
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('Failed to load secrets')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /retry/i }));
        expect(refetchMock).toHaveBeenCalled();
    });

    it('shows a fetching indicator when refetching in the background', () => {
        listState.secrets = secretsFixture;
        listState.isFetching = true;
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('Updating…')).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — toolbar', () => {
    it('reports search input changes to the list hook', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.change(screen.getByPlaceholderText('Search secrets…'), { target: { value: 'db' } });
        expect(setSearchMock).toHaveBeenCalledWith('db');
    });

    it('reports type filter changes to the list hook', () => {
        render(<ProjectSecretsTab projectId={1} />);
        const [typeSelect] = screen.getAllByRole('combobox');
        fireEvent.change(typeSelect, { target: { value: 'password' } });
        expect(setTypeFilterMock).toHaveBeenCalledWith('password');
    });

    it('reports page size changes to the list hook', () => {
        render(<ProjectSecretsTab projectId={1} />);
        const [, pageSizeSelect] = screen.getAllByRole('combobox');
        fireEvent.change(pageSizeSelect, { target: { value: '50' } });
        expect(handlePageSizeChangeMock).toHaveBeenCalledWith(50);
    });
});

describe('ProjectSecretsTab — pagination', () => {
    it('navigates pages and disables edges', () => {
        listState.secrets = secretsFixture;
        listState.pagination = { page: 1, pageSize: 20, total: 40, totalPages: 2 };
        render(<ProjectSecretsTab projectId={1} />);

        expect(screen.getByText('1 / 2')).toBeInTheDocument();
        const [prevButton, nextButton] = screen.getAllByRole('button', { name: '' });
        expect(prevButton).toBeDisabled();

        fireEvent.click(nextButton);
        expect(handlePageChangeMock).toHaveBeenCalledWith(2);
    });
});

describe('ProjectSecretsTab — bulk selection', () => {
    it('tracks selected rows and clears them', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByLabelText('select db-pass'));
        expect(screen.getByText('1 selected')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
        expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
    });

    it('selects all rows via the header checkbox', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        const headerCheckbox = within(screen.getByRole('table')).getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox);
        expect(screen.getByText('2 selected')).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — create secret', () => {
    it('creates a secret with the active environment id and resets the form', () => {
        envState.data = twoEnvs;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'new-secret' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret-value' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Secret' }));

        expect(createMutate).toHaveBeenCalledWith(
            {
                name: 'new-secret',
                value: 'super-secret-value',
                type: 'text',
                project_id: 1,
                environment_id: 3,
            },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('discards the draft when Cancel is clicked', () => {
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'draft-name' } });
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);
        expect(screen.getByLabelText(/^Name/)).toHaveValue('');
    });
});

describe('ProjectSecretsTab — view / edit / delete / rotate / share', () => {
    it('opens the view modal and navigates to edit from it', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('View db-pass'));
        expect(screen.getByText('Detail: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByText('Detail Edit'));
        expect(screen.getByText('Edit Secret: db-pass')).toBeInTheDocument();
        expect(screen.queryByText('Detail: db-pass')).not.toBeInTheDocument();
    });

    it('prefills and submits the edit form', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByLabelText('Name')).toHaveValue('db-pass');

        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
        expect(editMutate).toHaveBeenCalledWith({ id: 1, name: 'db-pass', type: 'password', value: '' });
    });

    it('deletes a secret after confirming', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Delete db-pass'));
        expect(screen.getByText('Delete Secret')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
        expect(deleteMutate).toHaveBeenCalledWith(1);
    });

    it('rotates a secret with a generated value', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Rotate db-pass'));
        expect(screen.getByText('Rotate: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Rotate' }));
        expect(rotateMutate).toHaveBeenCalledWith({ id: 1, newValue: expect.any(String) });
    });

    // SHARE-2: the page used to close the dialog in onSuccess, which unmounted it
    // before its "Shared!" confirmation rendered. It now only refreshes the list; the
    // dialog closes itself (onClose) once the confirmation has been shown.
    it('refetches on share success and leaves the dialog open for its confirmation', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

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
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByText('Failed to update secret')).toBeInTheDocument();
        expect(screen.getByText('Insufficient permissions')).toBeInTheDocument();
        expect(screen.queryByText('Request failed with status code 403')).not.toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — drift & rotation plan reports', () => {
    it('opens the drift report', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /check drift/i }));
        expect(screen.getByText('Drift Panel Content')).toBeInTheDocument();
    });

    it('opens the rotation plan report', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /rotation plan/i }));
        expect(screen.getByText('Rotation Plan Content')).toBeInTheDocument();
    });

    it('closes the drift report from its Close control', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /check drift/i }));
        expect(screen.getByText('Drift Panel Content')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByText('Drift Panel Content')).not.toBeInTheDocument();
    });

    it('closes the rotation plan report from its Close control', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /rotation plan/i }));
        expect(screen.getByText('Rotation Plan Content')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByText('Rotation Plan Content')).not.toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — filtered-empty state', () => {
    it('shows a filter-specific empty message when a type filter excludes everything', () => {
        listState.typeFilter = 'password';
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('No secrets match your filters')).toBeInTheDocument();
        expect(screen.queryByText('Create your first secret in this environment.')).not.toBeInTheDocument();
    });

    it('opens the create modal from the empty-state New Secret button', () => {
        render(<ProjectSecretsTab projectId={1} />);
        const newSecretButtons = screen.getAllByRole('button', { name: /new secret/i });
        // Index 1 is the empty-state's own New Secret action (index 0 is the toolbar's).
        fireEvent.click(newSecretButtons[1]!);
        expect(screen.getByRole('heading', { name: 'New Secret' })).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — bulk selection (toggle off, select-all uncheck)', () => {
    it('deselects a row by clicking its checkbox again', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        const checkbox = screen.getByLabelText('select db-pass');
        fireEvent.click(checkbox);
        expect(screen.getByText('1 selected')).toBeInTheDocument();

        fireEvent.click(checkbox);
        expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
    });

    it('clears all selections by unchecking the header checkbox', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        const headerCheckbox = within(screen.getByRole('table')).getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox); // select all
        expect(screen.getByText('2 selected')).toBeInTheDocument();

        fireEvent.click(headerCheckbox); // uncheck -> clearSelected()
        expect(screen.queryByText('2 selected')).not.toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — pagination (previous page)', () => {
    it('navigates to the previous page', () => {
        listState.secrets = secretsFixture;
        listState.pagination = { page: 2, pageSize: 20, total: 40, totalPages: 2 };
        render(<ProjectSecretsTab projectId={1} />);

        const [prevButton] = screen.getAllByRole('button', { name: '' });
        expect(prevButton).not.toBeDisabled();
        fireEvent.click(prevButton);
        expect(handlePageChangeMock).toHaveBeenCalledWith(1);
    });
});

describe('ProjectSecretsTab — view modal share/delete/close wiring', () => {
    it('closes the view modal detail from its own Close control', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('View db-pass'));
        expect(screen.getByText('Detail: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByText('Detail Close'));
        expect(screen.queryByText('Detail: db-pass')).not.toBeInTheDocument();
    });

    it("closes the view modal via the Modal chrome's own close button (not the detail view's)", () => {
        // Distinct from the "Detail Close" test above: this exercises the Modal
        // component's own `onClose` prop (ProjectSecretsTab.tsx ~line 273), wired to
        // its built-in dismiss (X) button, rather than SecretDetailView's separate
        // onClose prop reached via the mocked "Detail Close" button.
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('View db-pass'));
        expect(screen.getByText('Detail: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByText('Detail: db-pass')).not.toBeInTheDocument();
    });

    it('shares a secret from the view modal', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('View db-pass'));
        fireEvent.click(screen.getByText('Detail Share'));

        expect(screen.getByText('Share: db-pass')).toBeInTheDocument();
        expect(screen.queryByText('Detail: db-pass')).not.toBeInTheDocument();
    });

    it('deletes a secret from the view modal', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('View db-pass'));
        fireEvent.click(screen.getByText('Detail Delete'));

        expect(screen.getByText('Delete Secret')).toBeInTheDocument();
        expect(screen.queryByText('Detail: db-pass')).not.toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — create modal extras', () => {
    it('generates a value and lets the type be changed', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);

        fireEvent.click(screen.getByRole('button', { name: /generate/i }));
        expect(screen.getByLabelText(/^Value/)).not.toHaveValue('');

        // Scoped by label, not position — the toolbar's own type-filter combobox is also
        // on the page while this modal is open.
        const typeSelect = screen.getByLabelText('Type');
        fireEvent.change(typeSelect, { target: { value: 'password' } });
        expect(typeSelect).toHaveValue('password');
    });

    it('does not include environment_id when there is no active environment', () => {
        envState.data = [];
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'no-env-secret' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'value-here' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Secret' }));

        expect(createMutate).toHaveBeenCalledWith(
            { name: 'no-env-secret', value: 'value-here', type: 'text', project_id: 1 },
            expect.any(Object)
        );
    });

    it('does not call create when the form is submitted blank', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);

        const form = screen.getByRole('button', { name: 'Create Secret' }).closest('form')!;
        fireEvent.submit(form);

        expect(createMutate).not.toHaveBeenCalled();
    });

    it('shows the create error as a message and reflects the pending "Creating…" state', () => {
        listState.createMutation = { isPending: true, isError: true, error: new Error('name already exists') };
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);

        expect(screen.getByText('Failed to create secret')).toBeInTheDocument();
        expect(screen.getByText('name already exists')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Creating…' })).toBeInTheDocument();
    });

    it('falls back to a generic message when the create error is not an Error instance', () => {
        listState.createMutation = { isPending: false, isError: true, error: 'raw string error' };
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);

        expect(screen.getByText('Unexpected error')).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — edit modal extras', () => {
    it('lets the name, type and value be edited manually, and includes a Generate control', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'db-pass-renamed' } });

        // Scoped by label, not position — the toolbar's own type-filter combobox is also
        // on the page while this modal is open.
        const typeSelect = screen.getByLabelText('Type');
        fireEvent.change(typeSelect, { target: { value: 'api_key' } });

        fireEvent.change(screen.getByLabelText('New Value'), { target: { value: 'manual-value' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(editMutate).toHaveBeenCalledWith({
            id: 1,
            name: 'db-pass-renamed',
            type: 'api_key',
            value: 'manual-value',
        });
    });

    it('generates a new value in the edit form', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        fireEvent.click(screen.getByRole('button', { name: /generate/i }));
        expect(screen.getByLabelText('New Value')).not.toHaveValue('');
    });

    it('shows the edit error and reflects the pending "Saving…" state', () => {
        listState.secrets = secretsFixture;
        listState.editMutation = { isPending: true, isError: true, error: new Error('conflict') };
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByText('Failed to update secret')).toBeInTheDocument();
        expect(screen.getByText('conflict')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Saving…' })).toBeInTheDocument();
    });

    it('falls back to a generic message when the edit error is not an Error instance', () => {
        listState.secrets = secretsFixture;
        listState.editMutation = { isPending: false, isError: true, error: { weird: true } };
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByText('Unexpected error')).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — delete modal extras', () => {
    it('shows the delete error and reflects the pending "Deleting…" state', () => {
        listState.secrets = secretsFixture;
        listState.deleteMutation = { isPending: true, isError: true, error: new Error('in use') };
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Delete db-pass'));
        expect(screen.getByText('Failed to delete secret')).toBeInTheDocument();
        expect(screen.getByText('in use')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Deleting…' })).toBeInTheDocument();
    });

    it('falls back to a generic message when the delete error is not an Error instance', () => {
        listState.secrets = secretsFixture;
        listState.deleteMutation = { isPending: false, isError: true, error: null };
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Delete db-pass'));
        expect(screen.getByText('Unexpected error')).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — rotate modal extras', () => {
    it('lets the rotate value be edited manually and regenerated', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Rotate db-pass'));
        const valueInput = screen.getByLabelText('New Value') as HTMLInputElement;

        fireEvent.change(valueInput, { target: { value: 'manual-rotate-value' } });
        expect(valueInput).toHaveValue('manual-rotate-value');

        // generateSecret() is deterministic under the test-suite's crypto mock (see
        // src/test/setup.ts), so we only assert Regenerate overwrites the manual edit —
        // not that it differs from a prior generated value.
        fireEvent.click(screen.getByRole('button', { name: /regenerate/i }));
        expect(valueInput.value).not.toBe('manual-rotate-value');
    });

    it('shows the rotate error and reflects the pending "Rotating…" state', () => {
        listState.secrets = secretsFixture;
        listState.rotateMutation = { isPending: true, isError: true, error: new Error('locked') };
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Rotate db-pass'));
        expect(screen.getByText('Failed to rotate secret')).toBeInTheDocument();
        expect(screen.getByText('locked')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Rotating…' })).toBeInTheDocument();
    });

    it('falls back to a generic message when the rotate error is not an Error instance', () => {
        listState.secrets = secretsFixture;
        listState.rotateMutation = { isPending: false, isError: true, error: 42 };
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Rotate db-pass'));
        expect(screen.getByText('Unexpected error')).toBeInTheDocument();
    });
});

// Note: `defaultEnvName`'s innermost `environments[0]?.name ?? 'production'` fallback
// (ProjectSecretsTab.tsx ~line 708) is not exercised beyond what the two "environment
// selection" tests above already hit. Reaching it requires `environments.length > 0`
// with `environments[0].name` nullish, but `defaultEnvName`'s own `.find(e =>
// e.name.toLowerCase() === ...)` unconditionally calls `.toLowerCase()` on every
// environment's name first — an environment with a null/undefined name would throw
// there before the fallback chain is ever reached, and `??` (unlike `||`) doesn't
// treat an empty-string name as missing. So the literal `'production'` default is
// dead code given the component's own invariants; a genuine test would need a
// malformed environment record that also crashes an earlier line, which is not a
// meaningful case to fabricate.
//
// Similarly, the `if (!list.modalData?.secret) return;` guards inside
// EditSecretModal's and RotateSecretModal's onSubmit (~lines 465 and 624) are
// defensive dead code under this component's own invariants: `list.openModal(
// 'edit-secret', …)` / `list.openModal('rotate-secret', …)` are only ever called
// from row/detail actions that already close over a real `secret`, so `modalData`
// is guaranteed to carry one whenever those modals can be open and submitted. There
// is no legitimate UI path — only a synthetic mock of `useProjectSecrets` calling
// `openModal` with no data, which the app itself never does — that would exercise
// the early-return branch, so it's left uncovered rather than fabricated.

describe('ProjectSecretsTab permission-aware controls (DEMO-UI-1)', () => {
    it('offers no New Secret / create prompt to a read-only user', () => {
        canState.value = {
            ...canState.value,
            admin: false,
            writeSecrets: false,
            deleteSecrets: false,
            manageMembers: false,
            readAudit: false,
        };
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('No secrets in production')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /new secret/i })).not.toBeInTheDocument();
        expect(screen.queryByText('Create your first secret in this environment.')).not.toBeInTheDocument();
    });

    it('offers New Secret to a user who can write', () => {
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getAllByRole('button', { name: /new secret/i }).length).toBeGreaterThan(0);
    });
});
