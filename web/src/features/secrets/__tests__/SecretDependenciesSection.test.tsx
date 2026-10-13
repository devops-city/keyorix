import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { Secret } from '../../../types';

const addMutateAsync = vi.fn().mockResolvedValue(undefined);
const removeMutate = vi.fn();

let depsData: any = { secret_id: 1, depends_on: [], dependents: [] };
let impactData: any = { secret_id: 1, secret_name: 'app-token', affected: [] };
let listData: any = { data: [], total: 0, page: 1, pageSize: 20, totalPages: 1 };

vi.mock('../api', () => ({
    useSecretDependencies: () => ({ data: depsData }),
    useSecretImpact: () => ({ data: impactData }),
    useSecrets: () => ({ data: listData }),
    useAddSecretDependency: () => ({ mutateAsync: addMutateAsync, isPending: false }),
    useRemoveSecretDependency: () => ({ mutate: removeMutate, isPending: false }),
}));

// What the signed-in user may do (see auth/useCan.ts). Existing cases assume a writer.
const canState = vi.hoisted(() => ({
    value: { admin: false, writeSecrets: true, deleteSecrets: false, readAudit: false, manageMembers: false },
}));
vi.mock('../../auth/useCan', () => ({ useCan: () => canState.value }));

import { SecretDependenciesSection } from '../SecretDependenciesSection';

const makeSecret = (overrides: Partial<Secret> = {}): Secret => ({
    id: 1,
    name: 'app-token',
    type: 'api_key',
    projectId: 7,
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-06-22T00:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
    classification: 'confidential',
    ...overrides,
});

describe('SecretDependenciesSection', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        depsData = { secret_id: 1, depends_on: [], dependents: [] };
        impactData = { secret_id: 1, secret_name: 'app-token', affected: [] };
        listData = { data: [], total: 0, page: 1, pageSize: 20, totalPages: 1 };
        canState.value = {
            admin: false,
            writeSecrets: true,
            deleteSecrets: false,
            readAudit: false,
            manageMembers: false,
        };
    });

    it('a read-only user sees the graph but no Add form and no Remove buttons (#3142)', () => {
        canState.value = { ...canState.value, writeSecrets: false };
        depsData = {
            secret_id: 1,
            depends_on: [{ id: 10, secret_id: 2, secret_name: 'db-password' }],
            dependents: [{ id: 11, secret_id: 3, secret_name: 'edge-cert' }],
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);

        expect(screen.getByText('db-password')).toBeInTheDocument();
        expect(screen.getByText('edge-cert')).toBeInTheDocument();
        expect(screen.queryByText('Add a dependency')).not.toBeInTheDocument();
        expect(screen.queryByTestId('add-dependency-form')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Add' })).not.toBeInTheDocument();
        expect(screen.queryByText('Remove')).not.toBeInTheDocument();
    });

    it('a writer sees the Add form and Remove buttons', () => {
        depsData = {
            secret_id: 1,
            depends_on: [{ id: 10, secret_id: 2, secret_name: 'db-password' }],
            dependents: [],
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);
        expect(screen.getByTestId('add-dependency-form')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Add' })).toBeInTheDocument();
        expect(screen.getByText('Remove')).toBeInTheDocument();
    });

    it('shows empty states when there are no dependencies', () => {
        render(<SecretDependenciesSection secret={makeSecret()} />);
        expect(screen.getByText(/Rotating this secret affects no other secrets/i)).toBeInTheDocument();
        expect(screen.getByText(/this secret stands alone/i)).toBeInTheDocument();
        expect(screen.getByText(/No other secret depends on this one/i)).toBeInTheDocument();
    });

    it('renders dependencies, dependents, and the blast radius', () => {
        depsData = {
            secret_id: 1,
            depends_on: [{ id: 10, secret_id: 2, secret_name: 'db-password', note: 'derives from' }],
            dependents: [{ id: 11, secret_id: 3, secret_name: 'edge-cert' }],
        };
        impactData = {
            secret_id: 1,
            secret_name: 'app-token',
            affected: [{ secret_id: 3, secret_name: 'edge-cert', depth: 1 }],
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);

        expect(screen.getByText('db-password')).toBeInTheDocument();
        expect(screen.getByText(/derives from/)).toBeInTheDocument();
        expect(screen.getByText(/affects 1 other secret:/i)).toBeInTheDocument();
        // edge-cert appears both as a dependent and in the blast radius.
        expect(screen.getAllByText('edge-cert').length).toBeGreaterThanOrEqual(1);
    });

    it('removes an edge via the mutation', () => {
        depsData = {
            secret_id: 1,
            depends_on: [{ id: 10, secret_id: 2, secret_name: 'db-password' }],
            dependents: [],
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);
        fireEvent.click(screen.getByText('Remove'));
        expect(removeMutate).toHaveBeenCalledWith(10);
    });

    it('only offers same project + environment secrets as candidates, and adds one', async () => {
        listData = {
            data: [
                makeSecret({ id: 2, name: 'db-password' }), // same project+env → candidate
                makeSecret({ id: 5, name: 'other-project', projectId: 99 }), // different project → excluded
                makeSecret({ id: 6, name: 'other-env', environment: 'staging' }), // different env → excluded
            ],
            total: 3,
            page: 1,
            pageSize: 20,
            totalPages: 1,
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);

        expect(screen.getByRole('option', { name: 'db-password' })).toBeInTheDocument();
        expect(screen.queryByRole('option', { name: 'other-project' })).not.toBeInTheDocument();
        expect(screen.queryByRole('option', { name: 'other-env' })).not.toBeInTheDocument();

        fireEvent.change(screen.getByRole('combobox'), { target: { value: '2' } });
        fireEvent.click(screen.getByText('Add'));
        expect(addMutateAsync).toHaveBeenCalledWith({ dependsOnId: 2 });
    });

    it('trims and includes a note when adding a dependency', () => {
        listData = {
            data: [makeSecret({ id: 2, name: 'db-password' })],
            total: 1,
            page: 1,
            pageSize: 20,
            totalPages: 1,
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);

        fireEvent.change(screen.getByRole('combobox'), { target: { value: '2' } });
        fireEvent.change(screen.getByPlaceholderText('Note (optional)'), { target: { value: '  derives from  ' } });
        fireEvent.click(screen.getByText('Add'));

        expect(addMutateAsync).toHaveBeenCalledWith({ dependsOnId: 2, note: 'derives from' });
    });

    it('shows a validation error and does not call the mutation when the selected id is falsy', () => {
        // A candidate with id 0 makes the <select> value the non-empty string "0" (so
        // the Add button isn't disabled by !dependsOnId), while Number("0") is falsy —
        // exercising handleAdd's `if (!target)` guard.
        listData = {
            data: [makeSecret({ id: 0, name: 'zero-id-secret' })],
            total: 1,
            page: 1,
            pageSize: 20,
            totalPages: 1,
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);

        fireEvent.change(screen.getByRole('combobox'), { target: { value: '0' } });
        fireEvent.click(screen.getByText('Add'));

        expect(screen.getByText('Select a secret this one depends on.')).toBeInTheDocument();
        expect(addMutateAsync).not.toHaveBeenCalled();
    });

    it('shows the server-provided error message when adding a dependency fails', async () => {
        addMutateAsync.mockRejectedValueOnce({ response: { data: { error: { message: 'already linked' } } } });
        listData = {
            data: [makeSecret({ id: 2, name: 'db-password' })],
            total: 1,
            page: 1,
            pageSize: 20,
            totalPages: 1,
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);

        fireEvent.change(screen.getByRole('combobox'), { target: { value: '2' } });
        fireEvent.click(screen.getByText('Add'));

        expect(await screen.findByText('already linked')).toBeInTheDocument();
    });

    it('falls back to the error message, then a generic message, when the response shape lacks one', async () => {
        addMutateAsync.mockRejectedValueOnce(new Error('boom'));
        listData = {
            data: [makeSecret({ id: 2, name: 'db-password' })],
            total: 1,
            page: 1,
            pageSize: 20,
            totalPages: 1,
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '2' } });
        fireEvent.click(screen.getByText('Add'));
        expect(await screen.findByText('boom')).toBeInTheDocument();

        addMutateAsync.mockRejectedValueOnce({});
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '2' } });
        fireEvent.click(screen.getByText('Add'));
        expect(await screen.findByText('Failed to add dependency.')).toBeInTheDocument();
    });

    it('treats missing dependency/impact data as empty (optional chaining fallbacks)', () => {
        depsData = undefined;
        impactData = undefined;
        listData = undefined;
        render(<SecretDependenciesSection secret={makeSecret()} />);

        expect(screen.getByText(/Rotating this secret affects no other secrets/i)).toBeInTheDocument();
        expect(screen.getByText(/this secret stands alone/i)).toBeInTheDocument();
        expect(screen.getByText(/No other secret depends on this one/i)).toBeInTheDocument();
        expect(screen.getByText(/No eligible secrets in this project/i)).toBeInTheDocument();
    });

    it('pluralizes the blast-radius count and each hop count correctly', () => {
        impactData = {
            secret_id: 1,
            secret_name: 'app-token',
            affected: [
                { secret_id: 2, secret_name: 'one-hop', depth: 1 },
                { secret_id: 3, secret_name: 'two-hop', depth: 2 },
            ],
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);

        expect(screen.getByText(/affects 2 other secrets:/i)).toBeInTheDocument();
        expect(screen.getByTitle('1 hop away')).toBeInTheDocument();
        expect(screen.getByTitle('2 hops away')).toBeInTheDocument();
    });
});
