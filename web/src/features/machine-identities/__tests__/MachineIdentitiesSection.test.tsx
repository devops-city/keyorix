import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { answerConfirm } from '../../../test/confirm';
import { MachineIdentitiesSection } from '../MachineIdentitiesSection';

const createMutate = vi.fn();
const transitionMutate = vi.fn();
const classifyMutate = vi.fn();
let isAdmin = true;

let identitiesData: any[] = [];
let identitiesLoading = false;

const defaultIdentities = [
    {
        id: 1,
        projectId: 3,
        name: 'ci-runner',
        identityType: 'ci',
        state: 'active',
        description: 'builds',
        classification: 'restricted',
    },
    {
        id: 2,
        projectId: 3,
        name: 'paused-bot',
        identityType: 'automation',
        state: 'suspended',
        description: '',
        classification: '',
    },
];

vi.mock('../api', () => ({
    useMachineIdentities: () => ({ data: identitiesData, isLoading: identitiesLoading }),
    useCreateMachineIdentity: () => ({ mutate: createMutate, isPending: false }),
    useTransitionMachineIdentity: () => ({ mutate: transitionMutate, isPending: false }),
    useClassifyMachineIdentity: () => ({ mutate: classifyMutate, isPending: false }),
    // MachineTokensPanel (rendered when a row is expanded) shares this same api module.
    useMachineTokens: () => ({ data: [], isLoading: false }),
    useIssueMachineToken: () => ({ mutate: vi.fn(), isPending: false }),
    useRevokeMachineToken: () => ({ mutate: vi.fn(), isPending: false }),
    useClassifyMachineToken: () => ({ mutate: vi.fn(), isPending: false }),
}));

vi.mock('../../auth', () => ({
    useAuth: () => ({ isAdmin }),
}));

beforeEach(() => {
    identitiesData = defaultIdentities;
    identitiesLoading = false;
    createMutate.mockReset();
    transitionMutate.mockReset();
    classifyMutate.mockReset();
    isAdmin = true;
    // Suspend/revoke are confirmation-gated (G27); default to confirmed so
    // existing lifecycle-transition tests below don't have to opt in individually.
    vi.spyOn(window, 'confirm').mockReturnValue(true); // must stay unused: the in-app dialog replaced it
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('MachineIdentitiesSection', () => {
    it('lists machine identities with their state', () => {
        render(<MachineIdentitiesSection projectId={3} />);

        expect(screen.getByText('Machine identities')).toBeInTheDocument();
        expect(screen.getByText('ci-runner')).toBeInTheDocument();
        expect(screen.getByText('paused-bot')).toBeInTheDocument();
        expect(screen.getByText('active')).toBeInTheDocument();
        expect(screen.getByText('suspended')).toBeInTheDocument();
    });

    it('an active identity offers suspend + revoke; a suspended one offers reactivate + revoke', async () => {
        render(<MachineIdentitiesSection projectId={3} />);

        // active → suspend
        fireEvent.click(screen.getByRole('button', { name: /^suspend$/i }));
        await answerConfirm('Suspend machine identity "ci-runner"? It will lose access until reactivated.', 'accept');
        await waitFor(() =>
            expect(transitionMutate).toHaveBeenCalledWith({ machineId: 1, action: 'suspend' }, expect.anything())
        );

        // suspended → reactivate (activate action)
        fireEvent.click(screen.getByRole('button', { name: /reactivate/i }));
        expect(transitionMutate).toHaveBeenCalledWith({ machineId: 2, action: 'activate' }, expect.anything());
    });

    it('revokes an active machine identity', async () => {
        render(<MachineIdentitiesSection projectId={3} />);
        // Both the active and the suspended identity offer a revoke action; target the first (ci-runner).
        fireEvent.click(screen.getAllByTitle('Revoke')[0]);
        await answerConfirm('Revoke machine identity "ci-runner"? This cannot be undone.', 'accept');
        await waitFor(() =>
            expect(transitionMutate).toHaveBeenCalledWith({ machineId: 1, action: 'revoke' }, expect.anything())
        );
    });

    it('creates a machine identity with the selected type', () => {
        render(<MachineIdentitiesSection projectId={3} />);

        fireEvent.change(screen.getByPlaceholderText('Machine identity name…'), {
            target: { value: 'deploy-key' },
        });
        fireEvent.click(screen.getByRole('button', { name: /^add$/i }));

        expect(createMutate).toHaveBeenCalledTimes(1);
        expect(createMutate.mock.calls[0][0]).toMatchObject({
            name: 'deploy-key',
            identityType: 'ci',
        });
    });

    it('clears the name field once creation succeeds', () => {
        createMutate.mockImplementation((_vars, opts) => opts.onSuccess());
        render(<MachineIdentitiesSection projectId={3} />);
        const nameInput = screen.getByPlaceholderText('Machine identity name…') as HTMLInputElement;

        fireEvent.change(nameInput, { target: { value: 'deploy-key' } });
        fireEvent.click(screen.getByRole('button', { name: /^add$/i }));

        expect(nameInput.value).toBe('');
    });

    it('creates via the Enter key using the chosen identity type', () => {
        render(<MachineIdentitiesSection projectId={3} />);
        const nameInput = screen.getByPlaceholderText('Machine identity name…');

        fireEvent.change(nameInput, { target: { value: 'k8s-node' } });
        fireEvent.change(screen.getByDisplayValue('CI'), { target: { value: 'k8s' } });
        fireEvent.keyDown(nameInput, { key: 'Enter' });

        expect(createMutate).toHaveBeenCalledTimes(1);
        expect(createMutate.mock.calls[0][0]).toMatchObject({ name: 'k8s-node', identityType: 'k8s' });
    });

    it('a non-Enter keypress on the name field does not create', () => {
        render(<MachineIdentitiesSection projectId={3} />);
        const nameInput = screen.getByPlaceholderText('Machine identity name…');
        fireEvent.change(nameInput, { target: { value: 'k8s-node' } });
        fireEvent.keyDown(nameInput, { key: 'a' });
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('pressing Enter with a blank name does not create', () => {
        render(<MachineIdentitiesSection projectId={3} />);
        fireEvent.keyDown(screen.getByPlaceholderText('Machine identity name…'), { key: 'Enter' });
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('hides management controls (create + lifecycle) for non-admins', () => {
        isAdmin = false;
        render(<MachineIdentitiesSection projectId={3} />);

        // List is still visible (read-only segmentation)…
        expect(screen.getByText('ci-runner')).toBeInTheDocument();
        // …but no create input and no lifecycle actions.
        expect(screen.queryByPlaceholderText('Machine identity name…')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /^suspend$/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /revoke/i })).not.toBeInTheDocument();
    });

    it('admins get a classification picker that calls classify on change', () => {
        render(<MachineIdentitiesSection projectId={3} />);

        const picker = screen.getByLabelText('Classification for ci-runner') as HTMLSelectElement;
        expect(picker.value).toBe('restricted'); // reflects the current label
        fireEvent.change(picker, { target: { value: 'confidential' } });
        expect(classifyMutate).toHaveBeenCalledWith(
            { machineId: 1, classification: 'confidential' },
            expect.anything()
        );
    });

    it('reclassifying to the same value is a no-op', () => {
        render(<MachineIdentitiesSection projectId={3} />);
        const picker = screen.getByLabelText('Classification for ci-runner') as HTMLSelectElement;
        fireEvent.change(picker, { target: { value: 'restricted' } });
        expect(classifyMutate).not.toHaveBeenCalled();
    });

    it('non-admins see a read-only classification badge, no picker', () => {
        isAdmin = false;
        render(<MachineIdentitiesSection projectId={3} />);

        const badges = screen.getAllByTestId('mi-classification-badge');
        expect(badges[0]).toHaveTextContent('Restricted');
        expect(screen.queryByLabelText('Classification for ci-runner')).not.toBeInTheDocument();
    });

    it('shows pending and revoked state styling; revoked identities offer no lifecycle actions', () => {
        identitiesData = [
            {
                id: 5,
                projectId: 3,
                name: 'pending-svc',
                identityType: 'service',
                state: 'pending',
                description: '',
                classification: '',
            },
            {
                id: 6,
                projectId: 3,
                name: 'retired-bot',
                identityType: 'other',
                state: 'revoked',
                description: '',
                classification: '',
            },
        ];
        render(<MachineIdentitiesSection projectId={3} />);

        expect(screen.getByText('pending')).toBeInTheDocument();
        expect(screen.getByText('revoked')).toBeInTheDocument();
        // A pending identity offers Activate (not Reactivate).
        expect(screen.getByTitle('Activate')).toBeInTheDocument();
        // Only the pending identity has lifecycle actions (the revoked one has none).
        expect(screen.getAllByTitle('Revoke')).toHaveLength(1);
    });

    it('renders a loading skeleton and shows an empty state with no identities', () => {
        identitiesLoading = true;
        const { container, rerender } = render(<MachineIdentitiesSection projectId={3} />);
        expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
        expect(screen.queryByText('ci-runner')).not.toBeInTheDocument();

        identitiesLoading = false;
        identitiesData = [];
        rerender(<MachineIdentitiesSection projectId={3} />);
        expect(screen.getByText('No machine identities yet.')).toBeInTheDocument();
    });

    it('expands and collapses the token panel for a machine identity', () => {
        render(<MachineIdentitiesSection projectId={3} />);
        const toggle = screen.getByLabelText('Toggle tokens for ci-runner');

        fireEvent.click(toggle);
        expect(screen.getByText('No tokens issued yet.')).toBeInTheDocument();

        fireEvent.click(toggle);
        expect(screen.queryByText('No tokens issued yet.')).not.toBeInTheDocument();
    });

    it('surfaces the server error message when creating an identity fails', () => {
        createMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'name taken' } } })
        );
        render(<MachineIdentitiesSection projectId={3} />);

        fireEvent.change(screen.getByPlaceholderText('Machine identity name…'), { target: { value: 'dup' } });
        fireEvent.click(screen.getByRole('button', { name: /^add$/i }));

        expect(screen.getByText('name taken')).toBeInTheDocument();
    });

    it('shows a fallback error message when a lifecycle transition fails without server detail', async () => {
        transitionMutate.mockImplementation((_vars, opts) => opts.onError({}));
        render(<MachineIdentitiesSection projectId={3} />);

        fireEvent.click(screen.getByRole('button', { name: /^suspend$/i }));
        await answerConfirm('Suspend machine identity "ci-runner"? It will lose access until reactivated.', 'accept');

        expect(await screen.findByText('Failed to suspend machine identity.')).toBeInTheDocument();
    });

    it('shows the error.error field when reclassifying fails', () => {
        classifyMutate.mockImplementation((_vars, opts) => opts.onError({ response: { data: { error: 'nope' } } }));
        render(<MachineIdentitiesSection projectId={3} />);

        const picker = screen.getByLabelText('Classification for ci-runner') as HTMLSelectElement;
        fireEvent.change(picker, { target: { value: 'confidential' } });

        expect(screen.getByText('nope')).toBeInTheDocument();
    });

    it('asks for confirmation before suspending, and does not suspend when declined', async () => {
        render(<MachineIdentitiesSection projectId={3} />);

        fireEvent.click(screen.getByRole('button', { name: /^suspend$/i }));
        await answerConfirm('Suspend machine identity "ci-runner"? It will lose access until reactivated.', 'cancel');

        expect(transitionMutate).not.toHaveBeenCalled();
        expect(window.confirm).not.toHaveBeenCalled();
    });

    it('suspends once the confirmation is accepted', async () => {
        render(<MachineIdentitiesSection projectId={3} />);

        fireEvent.click(screen.getByRole('button', { name: /^suspend$/i }));
        expect(transitionMutate).not.toHaveBeenCalled();
        await answerConfirm('Suspend machine identity "ci-runner"? It will lose access until reactivated.', 'accept');

        await waitFor(() =>
            expect(transitionMutate).toHaveBeenCalledWith({ machineId: 1, action: 'suspend' }, expect.anything())
        );
        expect(window.confirm).not.toHaveBeenCalled();
    });

    it('asks for confirmation before revoking, and does not revoke when declined', async () => {
        render(<MachineIdentitiesSection projectId={3} />);

        fireEvent.click(screen.getAllByTitle('Revoke')[0]);
        await answerConfirm('Revoke machine identity "ci-runner"? This cannot be undone.', 'cancel');

        expect(transitionMutate).not.toHaveBeenCalled();
        expect(window.confirm).not.toHaveBeenCalled();
    });

    it('revokes once the confirmation is accepted', async () => {
        render(<MachineIdentitiesSection projectId={3} />);

        fireEvent.click(screen.getAllByTitle('Revoke')[0]);
        expect(transitionMutate).not.toHaveBeenCalled();
        await answerConfirm('Revoke machine identity "ci-runner"? This cannot be undone.', 'accept');

        await waitFor(() =>
            expect(transitionMutate).toHaveBeenCalledWith({ machineId: 1, action: 'revoke' }, expect.anything())
        );
        expect(window.confirm).not.toHaveBeenCalled();
    });

    it('does not confirm before reactivating (activate is non-destructive)', () => {
        render(<MachineIdentitiesSection projectId={3} />);

        fireEvent.click(screen.getByRole('button', { name: /reactivate/i }));

        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(transitionMutate).toHaveBeenCalledWith({ machineId: 2, action: 'activate' }, expect.anything());
    });

    it('falls back to the raw identityType when it has no known label', () => {
        identitiesData = [
            {
                id: 7,
                projectId: 3,
                name: 'mystery-bot',
                identityType: 'legacy-batch',
                state: 'active',
                description: '',
                classification: '',
            },
        ];
        render(<MachineIdentitiesSection projectId={3} />);

        expect(screen.getByText('legacy-batch')).toBeInTheDocument();
    });

    it('the admin classification picker falls back to an empty value when classification is unset', () => {
        identitiesData = [
            {
                id: 8,
                projectId: 3,
                name: 'unclassified-svc',
                identityType: 'service',
                state: 'active',
                description: '',
            },
        ];
        render(<MachineIdentitiesSection projectId={3} />);

        const picker = screen.getByLabelText('Classification for unclassified-svc') as HTMLSelectElement;
        expect(picker.value).toBe('');
    });

    it('the read-only classification badge falls back to unclassified styling when classification is unset', () => {
        isAdmin = false;
        identitiesData = [
            {
                id: 9,
                projectId: 3,
                name: 'unclassified-svc',
                identityType: 'service',
                state: 'active',
                description: '',
            },
        ];
        render(<MachineIdentitiesSection projectId={3} />);

        expect(screen.getByTestId('mi-classification-badge')).toHaveTextContent('Unclassified');
    });

    it('flags an active identity not seen in 90+ days as stale', () => {
        identitiesData = [
            {
                id: 10,
                projectId: 3,
                name: 'dormant-runner',
                identityType: 'ci',
                state: 'active',
                description: '',
                classification: '',
                lastSeenAt: new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString(),
            },
        ];
        render(<MachineIdentitiesSection projectId={3} />);

        expect(screen.getByTestId('mi-stale-badge')).toBeInTheDocument();
    });
});
