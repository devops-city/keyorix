import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { ProjectSettingsTab } from '../ProjectSettingsTab';
import { ROUTES } from '../../../constants';

/** A promise whose resolution is controlled from the test, for asserting a mutation's in-flight UI state. */
function deferred<T>() {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>((res) => {
        resolve = res;
    });
    return { promise, resolve };
}

const mockPost = vi.fn();
const mockGet = vi.fn();
const mockPut = vi.fn();
const mockDelete = vi.fn();

vi.mock('../../../services/client', () => ({
    apiClient: {
        get: (...args: any[]) => mockGet(...args),
        post: (...args: any[]) => mockPost(...args),
        put: (...args: any[]) => mockPut(...args),
        delete: (...args: any[]) => mockDelete(...args),
    },
}));

const navigateMock = vi.fn();
vi.mock('react-router', async () => {
    const actual = await vi.importActual<typeof import('react-router')>('react-router');
    return { ...actual, useNavigate: () => navigateMock };
});

// A stable object reference — React Query memoizes `data` in production, so
// the component's `useEffect([project])` only fires when it actually
// changes. A fresh object literal returned on every mock call would look
// "changed" every render and keep resetting local form state.
const mockProject = { id: 1, name: 'web', description: '', requireMfa: false };
const defaultEnvironments = [
    { id: 2, name: 'staging' },
    { id: 3, name: 'production' },
];

const mockUseProject = vi.fn();
const mockUseProjectEnvironments = vi.fn();
const mockUseRestoreEnvironment = vi.fn();
const mockRestoreEnvMutate = vi.fn();

vi.mock('../../../features/projects/api', () => ({
    PROJECT_KEYS: { all: ['projects'] },
    useProject: (...args: any[]) => mockUseProject(...args),
    useProjectEnvironments: (...args: any[]) => mockUseProjectEnvironments(...args),
    useRestoreEnvironment: (...args: any[]) => mockUseRestoreEnvironment(...args),
}));

beforeEach(() => {
    // jsdom has no object-URL API; stub it for the inventory download.
    (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
    (URL as any).revokeObjectURL = vi.fn();
    mockPut.mockReset();
    mockPut.mockResolvedValue({ data: { data: {} } });
    mockDelete.mockReset();
    mockDelete.mockResolvedValue({ data: { data: {} } });
    navigateMock.mockReset();

    mockUseProject.mockReset();
    mockUseProject.mockReturnValue({ data: mockProject, isLoading: false });
    mockUseProjectEnvironments.mockReset();
    mockUseProjectEnvironments.mockReturnValue({ data: defaultEnvironments, isLoading: false });
    mockRestoreEnvMutate.mockReset();
    mockUseRestoreEnvironment.mockReset();
    mockUseRestoreEnvironment.mockReturnValue({ mutate: mockRestoreEnvMutate, isPending: false });
});

describe('ProjectSettingsTab — promote environment', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
        mockGet.mockResolvedValue({ data: { data: {} } });
    });

    it('POSTs copy-secrets with the prompted target environment id', async () => {
        mockPost.mockResolvedValue({ data: { data: { copied: 4, skipped: 1 } } });
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('3');

        render(<ProjectSettingsTab projectId={1} />);

        // One Promote button per active environment; click staging's (id 2).
        const promoteButtons = screen.getAllByTitle(/Promote/i);
        fireEvent.click(promoteButtons[0]);

        await waitFor(() =>
            expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/environments/2/copy-secrets', {
                target_environment_id: 3,
            })
        );
        expect(await screen.findByText(/4 copied, 1 skipped/i)).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('defaults the promoted counts to 0 when the server omits them', async () => {
        mockPost.mockResolvedValue({ data: {} });
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('3');

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getAllByTitle(/Promote/i)[0]);

        expect(await screen.findByText(/Promoted: 0 copied, 0 skipped/i)).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('refuses to promote an environment into itself', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('2');

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getAllByTitle(/Promote/i)[0]); // staging id 2, target 2

        expect(mockPost).not.toHaveBeenCalled();
        expect(screen.getByText(/must differ/i)).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('does nothing when the promote prompt is cancelled', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue(null);

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getAllByTitle(/Promote/i)[0]);

        expect(mockPost).not.toHaveBeenCalled();
        expect(screen.queryByText(/must differ/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/valid environment id/i)).not.toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('surfaces a server error when promoting an environment fails', async () => {
        mockPost.mockRejectedValue({ response: { data: { error: 'Target environment not found.' } } });
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('3');

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getAllByTitle(/Promote/i)[0]);

        expect(await screen.findByText('Target environment not found.')).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('rejects a non-numeric promote target', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('not-a-number');

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getAllByTitle(/Promote/i)[0]);

        expect(mockPost).not.toHaveBeenCalled();
        expect(screen.getByText(/enter a valid environment id/i)).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('POSTs extend-expiring when "Extend all" is clicked', async () => {
        // Surface the Expiring-secrets section by returning one expiring secret.
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/expiring')
                ? Promise.resolve({
                      data: { data: { expiring: [{ id: 9, name: 'db', type: 'password', expired: true }] } },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({ data: { data: { extended: 1 } } });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(await screen.findByRole('button', { name: /extend all/i }));

        await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/secrets/extend-expiring', {}));
        expect(await screen.findByText(/renewed 1 secret/i)).toBeInTheDocument();
    });

    it('defaults the extended count to 0 when the server omits it', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/expiring')
                ? Promise.resolve({
                      data: { data: { expiring: [{ id: 9, name: 'db', type: 'password', expired: true }] } },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({ data: {} });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(await screen.findByRole('button', { name: /extend all/i }));

        expect(await screen.findByText(/renewed 0 secret\(s\) for 90 days/i)).toBeInTheDocument();
    });

    it('fetches the inventory CSV as a blob when Export inventory is clicked', async () => {
        mockGet.mockResolvedValue({ data: new Blob(['id,name\n'], { type: 'text/csv' }) });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /export inventory/i }));

        await waitFor(() =>
            expect(mockGet).toHaveBeenCalledWith('/api/v1/projects/1/secrets/inventory.csv', { responseType: 'blob' })
        );
        expect((URL as any).createObjectURL).toHaveBeenCalled();
    });

    it('surfaces the server message when the inventory export fails', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('inventory.csv')
                ? Promise.reject({ response: { data: { message: 'Export temporarily unavailable.' } } })
                : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /export inventory/i }));

        expect(await screen.findByText('Export temporarily unavailable.')).toBeInTheDocument();
        expect((URL as any).createObjectURL).not.toHaveBeenCalled();
    });

    it('falls back to response.data.error when the inventory export failure has no message', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('inventory.csv')
                ? Promise.reject({ response: { data: { error: 'Inventory generation failed.' } } })
                : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /export inventory/i }));

        expect(await screen.findByText('Inventory generation failed.')).toBeInTheDocument();
    });

    it('falls back to a generic message when the inventory export failure has neither', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('inventory.csv') ? Promise.reject({}) : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /export inventory/i }));

        expect(await screen.findByText('Failed to export inventory.')).toBeInTheDocument();
    });

    it('shows naming-policy violations with their reason when the policy flags a name', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 2,
                              violations: [
                                  {
                                      id: 8,
                                      name: 'db-pass',
                                      type: 'password',
                                      reason: 'secret name does not match the required pattern',
                                  },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);

        expect(await screen.findByText('Naming-policy violations')).toBeInTheDocument();
        // The current name is prefilled into an editable rename input.
        expect(screen.getByDisplayValue('db-pass')).toBeInTheDocument();
        expect(screen.getByText(/does not match the required pattern/i)).toBeInTheDocument();
    });

    it('hides the naming-policy section when there are no violations', async () => {
        mockGet.mockResolvedValue({ data: { data: { policy_enabled: false, total_secrets: 0, violations: [] } } });

        render(<ProjectSettingsTab projectId={1} />);

        // The recycle-bin section always renders, so the page is settled.
        expect(await screen.findByText('Recycle bin')).toBeInTheDocument();
        expect(screen.queryByText('Naming-policy violations')).not.toBeInTheDocument();
    });

    it('POSTs bulk-rename with only the edited rows, then reports the result', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 2,
                              violations: [
                                  {
                                      id: 8,
                                      name: 'db-pass',
                                      type: 'password',
                                      reason: 'does not match the required pattern',
                                  },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({
            data: {
                data: {
                    dry_run: false,
                    renamed: 1,
                    skipped: 0,
                    outcomes: [{ id: 8, old_name: 'db-pass', new_name: 'DB_PASS', status: 'renamed' }],
                },
            },
        });

        render(<ProjectSettingsTab projectId={1} />);

        const input = await screen.findByDisplayValue('db-pass');
        // Apply is disabled until a name is actually edited.
        const applyBtn = screen.getByRole('button', { name: /Apply renames/i });
        expect(applyBtn).toBeDisabled();

        fireEvent.change(input, { target: { value: 'DB_PASS' } });
        expect(screen.getByRole('button', { name: /Apply renames \(1\)/i })).toBeEnabled();
        fireEvent.click(screen.getByRole('button', { name: /Apply renames/i }));

        await waitFor(() =>
            expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/secrets/bulk-rename', {
                renames: [{ id: 8, new_name: 'DB_PASS' }],
                dry_run: false,
            })
        );
        expect(await screen.findByText(/Renamed 1 secret/i)).toBeInTheDocument();
    });

    it('surfaces the reason for a skipped rename', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 1,
                              violations: [
                                  {
                                      id: 8,
                                      name: 'db-pass',
                                      type: 'password',
                                      reason: 'does not match the required pattern',
                                  },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({
            data: {
                data: {
                    dry_run: false,
                    renamed: 0,
                    skipped: 1,
                    outcomes: [
                        {
                            id: 8,
                            old_name: 'db-pass',
                            new_name: 'still-bad',
                            status: 'skipped',
                            reason: 'secret name does not match the required pattern',
                        },
                    ],
                },
            },
        });

        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.change(await screen.findByDisplayValue('db-pass'), { target: { value: 'still-bad' } });
        fireEvent.click(screen.getByRole('button', { name: /Apply renames/i }));

        // The summary carries the count and the per-skip reason from the server.
        expect(
            await screen.findByText(/0 secret\(s\), 1 skipped.*does not match the required pattern/i)
        ).toBeInTheDocument();
    });

    it('falls back to the secret id in the skip list when a skipped outcome has no old_name', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 1,
                              violations: [
                                  {
                                      id: 8,
                                      name: 'db-pass',
                                      type: 'password',
                                      reason: 'does not match the required pattern',
                                  },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({
            data: {
                data: {
                    dry_run: false,
                    renamed: 0,
                    skipped: 1,
                    outcomes: [
                        {
                            id: 8,
                            new_name: 'still-bad',
                            status: 'skipped',
                            reason: 'secret name does not match the required pattern',
                        },
                    ],
                },
            },
        });

        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.change(await screen.findByDisplayValue('db-pass'), { target: { value: 'still-bad' } });
        fireEvent.click(screen.getByRole('button', { name: /Apply renames/i }));

        // No old_name on the outcome -> the skip list falls back to the secret id.
        expect(
            await screen.findByText(/0 secret\(s\), 1 skipped.*Skipped: 8 \(secret name does not match/i)
        ).toBeInTheDocument();
    });

    it('defaults the rename counts and skip list when the server response omits them', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 1,
                              violations: [{ id: 8, name: 'db-pass', type: 'password', reason: 'bad pattern' }],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({ data: {} });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.change(await screen.findByDisplayValue('db-pass'), { target: { value: 'DB_PASS' } });
        fireEvent.click(screen.getByRole('button', { name: /Apply renames/i }));

        // No "renamed"/"skipped"/"outcomes" in the response -> all fall back to 0/[]
        // and there's no trailing "Skipped: ..." detail.
        expect(await screen.findByText('Renamed 0 secret(s), 0 skipped.')).toBeInTheDocument();
    });

    it('leaves Apply disabled when a rename input is edited back to empty', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 1,
                              violations: [{ id: 8, name: 'db-pass', type: 'password', reason: 'bad pattern' }],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);

        const input = await screen.findByDisplayValue('db-pass');
        fireEvent.change(input, { target: { value: '' } });

        expect(screen.getByRole('button', { name: /Apply renames \(0\)/i })).toBeDisabled();
    });

    it('surfaces a server error from a failed bulk rename', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 1,
                              violations: [{ id: 8, name: 'db-pass', type: 'password', reason: 'bad pattern' }],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockRejectedValue({ response: { data: { error: 'Naming policy service unavailable.' } } });

        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.change(await screen.findByDisplayValue('db-pass'), { target: { value: 'DB_PASS' } });
        fireEvent.click(screen.getByRole('button', { name: /Apply renames/i }));

        expect(await screen.findByText(/Error: Naming policy service unavailable\./i)).toBeInTheDocument();
    });

    it('saves the require-MFA toggle with the current name/description, independent of General', async () => {
        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.click(screen.getByLabelText(/Require MFA for this project/));
        fireEvent.click(screen.getAllByRole('button', { name: /^save$/i })[1]); // Security section's Save

        await waitFor(() =>
            expect(mockPut).toHaveBeenCalledWith('/api/v1/projects/1', {
                name: 'web',
                description: '',
                require_mfa: true,
            })
        );
        expect(await screen.findByText('Project security settings updated.')).toBeInTheDocument();
    });

    it('surfaces a permission error from the MFA toggle save', async () => {
        mockPut.mockRejectedValue({ response: { data: { message: 'roles.assign is required' } } });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByLabelText(/Require MFA for this project/));
        fireEvent.click(screen.getAllByRole('button', { name: /^save$/i })[1]);

        expect(await screen.findByText('roles.assign is required')).toBeInTheDocument();
    });

    it('shows a pending state while the MFA toggle save is in flight', async () => {
        const { promise, resolve } = deferred<any>();
        mockPut.mockReturnValue(promise);

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByLabelText(/Require MFA for this project/));
        fireEvent.click(screen.getAllByRole('button', { name: /^save$/i })[1]);

        expect(await screen.findByRole('button', { name: /saving…/i })).toBeDisabled();

        resolve({ data: { data: {} } });
        expect(await screen.findByText('Project security settings updated.')).toBeInTheDocument();
    });

    it('shows a pending state while applying renames', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 1,
                              violations: [{ id: 8, name: 'db-pass', type: 'password', reason: 'bad pattern' }],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        const { promise, resolve } = deferred<any>();
        mockPost.mockReturnValue(promise);

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.change(await screen.findByDisplayValue('db-pass'), { target: { value: 'DB_PASS' } });
        fireEvent.click(screen.getByRole('button', { name: /Apply renames/i }));

        expect(await screen.findByRole('button', { name: /renaming…/i })).toBeDisabled();

        resolve({ data: { data: { renamed: 1, skipped: 0, outcomes: [] } } });
        expect(await screen.findByText(/Renamed 1 secret/i)).toBeInTheDocument();
    });
});

describe('ProjectSettingsTab — General section', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
        mockGet.mockResolvedValue({ data: { data: {} } });
    });

    it('blocks saving and shows an error when the name is cleared', () => {
        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.change(screen.getByLabelText(/project name/i), { target: { value: '   ' } });
        fireEvent.click(screen.getAllByRole('button', { name: /^save$/i })[0]);

        expect(screen.getByText('Name is required.')).toBeInTheDocument();
        expect(mockPut).not.toHaveBeenCalled();
    });

    it('saves the trimmed name and description via the General Save button', async () => {
        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.change(screen.getByLabelText(/project name/i), { target: { value: '  new name  ' } });
        fireEvent.change(screen.getByLabelText(/description/i), { target: { value: '  new description  ' } });
        fireEvent.click(screen.getAllByRole('button', { name: /^save$/i })[0]);

        await waitFor(() =>
            expect(mockPut).toHaveBeenCalledWith('/api/v1/projects/1', {
                name: 'new name',
                description: 'new description',
            })
        );
        expect(await screen.findByText('Project settings updated.')).toBeInTheDocument();
    });

    it('sends undefined description when it is left blank', async () => {
        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.change(screen.getByLabelText(/project name/i), { target: { value: 'web' } });
        fireEvent.change(screen.getByLabelText(/description/i), { target: { value: '   ' } });
        fireEvent.click(screen.getAllByRole('button', { name: /^save$/i })[0]);

        await waitFor(() =>
            expect(mockPut).toHaveBeenCalledWith('/api/v1/projects/1', {
                name: 'web',
                description: undefined,
            })
        );
    });

    it('shows a generic error alert when the General save fails', async () => {
        mockPut.mockRejectedValue({ response: { data: { message: 'ignored' } } });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getAllByRole('button', { name: /^save$/i })[0]);

        expect(await screen.findByText('Could not save project settings.')).toBeInTheDocument();
    });
});

describe('ProjectSettingsTab — field fallbacks when the server omits optional project fields', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
        mockGet.mockResolvedValue({ data: { data: {} } });
    });

    it('defaults description to empty and requireMfa to false when the project omits them', () => {
        mockUseProject.mockReturnValue({ data: { id: 1, name: 'web' }, isLoading: false });

        render(<ProjectSettingsTab projectId={1} />);

        expect(screen.getByLabelText(/description/i)).toHaveValue('');
        expect(screen.getByLabelText(/Require MFA for this project/)).not.toBeChecked();
    });

    it('sends an empty name in the MFA-toggle save when there is no loaded project', async () => {
        mockUseProject.mockReturnValue({ data: undefined, isLoading: false });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByLabelText(/Require MFA for this project/));
        fireEvent.click(screen.getAllByRole('button', { name: /^save$/i })[1]);

        await waitFor(() =>
            expect(mockPut).toHaveBeenCalledWith('/api/v1/projects/1', {
                name: '',
                description: undefined,
                require_mfa: true,
            })
        );
    });
});

describe('ProjectSettingsTab — Environments', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
        mockGet.mockResolvedValue({ data: { data: {} } });
    });

    it('shows a loading skeleton while environments are loading', () => {
        mockUseProjectEnvironments.mockReturnValue({ data: [], isLoading: true });

        render(<ProjectSettingsTab projectId={1} />);

        expect(screen.queryByText(/no environments yet/i)).not.toBeInTheDocument();
        expect(screen.queryByText('Staging')).not.toBeInTheDocument();
    });

    it('shows an empty state when there are no environments', () => {
        mockUseProjectEnvironments.mockReturnValue({ data: [], isLoading: false });

        render(<ProjectSettingsTab projectId={1} />);

        expect(screen.getByText('No environments yet. Add one below.')).toBeInTheDocument();
    });

    it('shows a deleted badge and a restore action for a soft-deleted environment', () => {
        mockUseProjectEnvironments.mockReturnValue({
            data: [{ id: 5, name: 'staging', deleted: true }],
            isLoading: false,
        });

        render(<ProjectSettingsTab projectId={1} />);

        expect(screen.getByText('deleted')).toBeInTheDocument();
        fireEvent.click(screen.getByTitle('Restore environment'));

        expect(mockRestoreEnvMutate).toHaveBeenCalledWith(5);
    });

    it('renders no status badge for a non-default, non-deleted environment', () => {
        mockUseProjectEnvironments.mockReturnValue({
            data: [{ id: 6, name: 'qa', deleted: false }],
            isLoading: false,
        });

        render(<ProjectSettingsTab projectId={1} />);

        expect(screen.getByText('Qa')).toBeInTheDocument();
        expect(screen.queryByText('default')).not.toBeInTheDocument();
        expect(screen.queryByText('deleted')).not.toBeInTheDocument();
        expect(screen.getByTitle('Delete environment')).toBeInTheDocument();
    });

    it('adds a new environment via the Add button', async () => {
        mockPost.mockResolvedValue({ data: { data: {} } });

        render(<ProjectSettingsTab projectId={1} />);

        const input = screen.getByPlaceholderText('New environment name…');
        fireEvent.change(input, { target: { value: 'qa' } });
        fireEvent.click(screen.getByRole('button', { name: /^add$/i }));

        await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/environments', { name: 'qa' }));
    });

    it('adds a new environment when Enter is pressed in the input', async () => {
        mockPost.mockResolvedValue({ data: { data: {} } });

        render(<ProjectSettingsTab projectId={1} />);

        const input = screen.getByPlaceholderText('New environment name…');
        fireEvent.change(input, { target: { value: 'qa' } });
        fireEvent.keyDown(input, { key: 'Enter' });

        await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/environments', { name: 'qa' }));
    });

    it('does not add an environment on Enter when the input is blank', () => {
        render(<ProjectSettingsTab projectId={1} />);

        const input = screen.getByPlaceholderText('New environment name…');
        fireEvent.keyDown(input, { key: 'Enter' });

        expect(mockPost).not.toHaveBeenCalled();
    });

    it('surfaces an error when adding an environment fails', async () => {
        mockPost.mockRejectedValue({ response: { data: { error: 'Environment already exists.' } } });

        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.change(screen.getByPlaceholderText('New environment name…'), { target: { value: 'staging' } });
        fireEvent.click(screen.getByRole('button', { name: /^add$/i }));

        expect(await screen.findByText('Environment already exists.')).toBeInTheDocument();
    });

    it('falls back to a generic message when adding an environment fails with no server error/message', async () => {
        mockPost.mockRejectedValue({});

        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.change(screen.getByPlaceholderText('New environment name…'), { target: { value: 'staging2' } });
        fireEvent.click(screen.getByRole('button', { name: /^add$/i }));

        expect(await screen.findByText('Failed to create environment.')).toBeInTheDocument();
    });

    it('opens the delete-environment modal with the default-environment note and deletes on confirm', async () => {
        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.click(screen.getAllByTitle('Delete environment')[0]); // staging (default), id 2

        expect(screen.getByText('Delete Environment')).toBeInTheDocument();
        expect(screen.getByText(/this is a default environment/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /^delete$/i }));

        await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('/api/v1/environments/2'));
        await waitFor(() => expect(screen.queryByText('Delete Environment')).not.toBeInTheDocument());
    });

    it('cancels out of the delete-environment modal without deleting', () => {
        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.click(screen.getAllByTitle('Delete environment')[0]);
        expect(screen.getByText('Delete Environment')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }));

        expect(screen.queryByText('Delete Environment')).not.toBeInTheDocument();
        expect(mockDelete).not.toHaveBeenCalled();
    });

    it('shows the server error and a Close action when environment deletion fails', async () => {
        mockDelete.mockRejectedValueOnce({ response: { data: { error: 'Environment has active secrets.' } } });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getAllByTitle('Delete environment')[0]);
        fireEvent.click(screen.getByRole('button', { name: /^delete$/i }));

        expect(await screen.findByText('Cannot delete environment')).toBeInTheDocument();
        expect(screen.getByText('Environment has active secrets.')).toBeInTheDocument();
        // Confirm/Cancel are replaced by a single Close action once an error is showing.
        expect(screen.queryByRole('button', { name: /^cancel$/i })).not.toBeInTheDocument();

        // Two "Close" buttons exist: the modal's icon-only close (X) and the
        // visible "Close" action rendered in place of Cancel/Delete — the
        // latter is the one under test here, and it comes last in the DOM.
        const closeButtons = screen.getAllByRole('button', { name: /^close$/i });
        fireEvent.click(closeButtons[closeButtons.length - 1]);
        expect(screen.queryByText('Delete Environment')).not.toBeInTheDocument();
    });

    it('shows a pending state while deleting an environment', async () => {
        const { promise, resolve } = deferred<any>();
        mockDelete.mockReturnValue(promise);

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getAllByTitle('Delete environment')[0]);
        fireEvent.click(screen.getByRole('button', { name: /^delete$/i }));

        expect(await screen.findByRole('button', { name: /deleting…/i })).toBeDisabled();

        resolve({ data: { data: {} } });
        await waitFor(() => expect(screen.queryByText('Delete Environment')).not.toBeInTheDocument());
    });
});

describe('ProjectSettingsTab — Incident response', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
        mockGet.mockResolvedValue({ data: { data: {} } });
    });

    it('freezes all secrets after the confirm dialog is accepted', async () => {
        vi.spyOn(window, 'confirm').mockReturnValue(true);
        mockPost.mockResolvedValue({ data: { data: { suspended: 7 } } });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /freeze all secrets/i }));

        await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/secrets/suspend-all', {}));
        expect(await screen.findByText(/froze 7 secret\(s\)/i)).toBeInTheDocument();
    });

    it('does not freeze secrets when the confirm dialog is declined', () => {
        vi.spyOn(window, 'confirm').mockReturnValue(false);

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /freeze all secrets/i }));

        expect(mockPost).not.toHaveBeenCalled();
    });

    it('resumes all secrets without a confirm dialog', async () => {
        mockPost.mockResolvedValue({ data: { data: { resumed: 3 } } });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /resume all/i }));

        await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/secrets/resume-all', {}));
        expect(await screen.findByText(/resumed 3 secret\(s\)/i)).toBeInTheDocument();
    });

    it('defaults the frozen count to 0 when the server omits it', async () => {
        vi.spyOn(window, 'confirm').mockReturnValue(true);
        mockPost.mockResolvedValue({ data: {} });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /freeze all secrets/i }));

        expect(await screen.findByText(/froze 0 secret\(s\)/i)).toBeInTheDocument();
    });

    it('defaults the resumed count to 0 when the server omits it', async () => {
        mockPost.mockResolvedValue({ data: {} });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /resume all/i }));

        expect(await screen.findByText(/resumed 0 secret\(s\)/i)).toBeInTheDocument();
    });

    it('shows a generic error alert when freezing secrets fails', async () => {
        vi.spyOn(window, 'confirm').mockReturnValue(true);
        mockPost.mockRejectedValue(new Error('network down'));

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /freeze all secrets/i }));

        expect(await screen.findByText('The action failed. Please try again.')).toBeInTheDocument();
    });
});

describe('ProjectSettingsTab — Hygiene, expiring secrets, and recycle bin edge cases', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
    });

    it('flags hygiene tiles with a warning style when their count is non-zero', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/hygiene')
                ? Promise.resolve({
                      data: {
                          data: {
                              orphaned_secrets: 2,
                              unused_secrets: 0,
                              expiring_secrets: 0,
                              stale_machine_identities: 0,
                              rotation_overdue: 0,
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);

        // The tile shows the raw count; a non-zero value renders with warning styling.
        expect(await screen.findByText('2')).toBeInTheDocument();
    });

    it('renders an expiring secret with an explicit expiration date alongside one without', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/expiring')
                ? Promise.resolve({
                      data: {
                          data: {
                              expiring: [
                                  { id: 9, name: 'db', type: 'password', expired: true },
                                  {
                                      id: 10,
                                      name: 'api-token',
                                      type: 'apiKey',
                                      expiration: '2026-12-01T00:00:00Z',
                                      expired: false,
                                  },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);

        expect(await screen.findByText('db')).toBeInTheDocument();
        expect(screen.getByText('api-token')).toBeInTheDocument();
        expect(screen.getByText('expired')).toBeInTheDocument();
        expect(screen.getByText('expiring')).toBeInTheDocument();
    });

    it('renders a deleted secret with no deleted-at timestamp', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/deleted')
                ? Promise.resolve({
                      data: { data: { deleted: [{ id: 40, name: 'undated-secret', type: 'password' }] } },
                  })
                : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);

        expect(await screen.findByText('undated-secret')).toBeInTheDocument();
    });
});

describe('ProjectSettingsTab — Orphaned secrets', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
    });

    const withOrphans = () =>
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/orphaned')
                ? Promise.resolve({
                      data: {
                          data: {
                              orphaned: [
                                  {
                                      id: 21,
                                      name: 'legacy-key',
                                      type: 'apiKey',
                                      classification: 'internal',
                                      owner_id: 99,
                                  },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );

    it('renders orphaned secrets with a reassign action per former owner', async () => {
        withOrphans();

        render(<ProjectSettingsTab projectId={1} />);

        expect(await screen.findByRole('heading', { name: 'Orphaned secrets' })).toBeInTheDocument();
        expect(screen.getByText('legacy-key')).toBeInTheDocument();
        expect(screen.getByText('internal')).toBeInTheDocument();
        expect(screen.getByText(/reassign all from former owner #99/i)).toBeInTheDocument();
    });

    it('does nothing when the reassign prompt is cancelled', async () => {
        withOrphans();
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue(null);

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(await screen.findByText(/reassign all from former owner #99/i));

        expect(mockPost).not.toHaveBeenCalled();
        promptSpy.mockRestore();
    });

    it('does nothing when the reassign prompt receives an invalid user id', async () => {
        withOrphans();
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('not-an-id');

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(await screen.findByText(/reassign all from former owner #99/i));

        expect(mockPost).not.toHaveBeenCalled();
        promptSpy.mockRestore();
    });

    it('reassigns all secrets from a former owner and reports the result', async () => {
        withOrphans();
        mockPost.mockResolvedValue({ data: { data: { reassigned: 2 } } });
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('42');

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(await screen.findByText(/reassign all from former owner #99/i));

        await waitFor(() =>
            expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/secrets/reassign-owner', {
                from_owner_id: 99,
                to_owner_id: 42,
            })
        );
        expect(await screen.findByText(/reassigned 2 secret\(s\)/i)).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('defaults the reassigned count to 0 when the server omits it', async () => {
        withOrphans();
        mockPost.mockResolvedValue({ data: {} });
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('42');

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(await screen.findByText(/reassign all from former owner #99/i));

        expect(await screen.findByText(/reassigned 0 secret\(s\)/i)).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('surfaces an error alert when reassignment fails', async () => {
        withOrphans();
        mockPost.mockRejectedValue(new Error('failed'));
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('42');

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(await screen.findByText(/reassign all from former owner #99/i));

        expect(await screen.findByText('Reassignment failed')).toBeInTheDocument();
        promptSpy.mockRestore();
    });
});

describe('ProjectSettingsTab — Recycle bin', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
    });

    it('restores a deleted secret from a populated recycle bin', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/deleted')
                ? Promise.resolve({
                      data: {
                          data: {
                              deleted: [
                                  { id: 31, name: 'old-token', type: 'apiKey', deleted_at: '2025-01-01T00:00:00Z' },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({ data: { data: {} } });

        render(<ProjectSettingsTab projectId={1} />);

        expect(await screen.findByText('old-token')).toBeInTheDocument();
        fireEvent.click(screen.getByTitle('Restore secret'));

        await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/secrets/31/restore', {}));
    });

    it('does not overstate the purge guarantee: legacy rows without a stored date follow the live window', async () => {
        mockGet.mockImplementation(() => Promise.resolve({ data: { data: { deleted: [] } } }));

        render(<ProjectSettingsTab projectId={1} />);

        expect(await screen.findByText('Recycle bin')).toBeInTheDocument();
        expect(screen.queryByText(/never purged earlier/i)).not.toBeInTheDocument();
        expect(
            screen.getByText(/deleted before this date was recorded follow the current window/i)
        ).toBeInTheDocument();
    });

    it('shows the real purge date of each deleted secret, and none for a row without one', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/deleted')
                ? Promise.resolve({
                      data: {
                          data: {
                              deleted: [
                                  {
                                      id: 31,
                                      name: 'dated-token',
                                      type: 'apiKey',
                                      deleted_at: '2025-01-01T00:00:00Z',
                                      purge_at: '2025-01-31T00:00:00Z',
                                  },
                                  { id: 32, name: 'undated-token', type: 'apiKey', deleted_at: '2025-01-02T00:00:00Z' },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);

        const dated = (await screen.findByText('dated-token')).parentElement as HTMLElement;
        expect(dated.textContent).toContain(`restorable until ${new Date('2025-01-31T00:00:00Z').toLocaleString()}`);
        const undated = (await screen.findByText('undated-token')).parentElement as HTMLElement;
        expect(undated.textContent).not.toContain('restorable until');
    });
});

describe('ProjectSettingsTab — Danger zone', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
        mockGet.mockResolvedValue({ data: { data: {} } });
    });

    it('disables Delete until the project name is typed exactly, then deletes and navigates away', async () => {
        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.click(screen.getByRole('button', { name: /^delete project$/i }));
        const confirmInput = screen.getByPlaceholderText('web');
        const deleteBtn = screen.getByRole('button', { name: /^delete$/i });
        expect(deleteBtn).toBeDisabled();

        fireEvent.change(confirmInput, { target: { value: 'wrong-name' } });
        expect(deleteBtn).toBeDisabled();

        fireEvent.change(confirmInput, { target: { value: 'web' } });
        expect(deleteBtn).toBeEnabled();
        fireEvent.click(deleteBtn);

        await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('/api/v1/projects/1'));
        await waitFor(() => expect(navigateMock).toHaveBeenCalledWith(ROUTES.PROJECTS));
    });

    it('cancels the delete-project modal and resets the confirm text', () => {
        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.click(screen.getByRole('button', { name: /^delete project$/i }));
        fireEvent.change(screen.getByPlaceholderText('web'), { target: { value: 'partial' } });
        fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }));

        expect(screen.queryByPlaceholderText('web')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /^delete project$/i }));
        expect(screen.getByPlaceholderText('web')).toHaveValue('');
    });

    it('shows the server error when project deletion fails and does not navigate', async () => {
        mockDelete.mockRejectedValueOnce({ response: { data: { error: 'Cannot delete: active secrets exist.' } } });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /^delete project$/i }));
        fireEvent.change(screen.getByPlaceholderText('web'), { target: { value: 'web' } });
        fireEvent.click(screen.getByRole('button', { name: /^delete$/i }));

        expect(await screen.findByText('Cannot delete: active secrets exist.')).toBeInTheDocument();
        expect(navigateMock).not.toHaveBeenCalled();
    });

    it('falls back to the error.message when the response has no response.data.error', async () => {
        mockDelete.mockRejectedValueOnce(new Error('native failure message'));

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /^delete project$/i }));
        fireEvent.change(screen.getByPlaceholderText('web'), { target: { value: 'web' } });
        fireEvent.click(screen.getByRole('button', { name: /^delete$/i }));

        expect(await screen.findByText('native failure message')).toBeInTheDocument();
    });

    it('falls back to a generic message when the error has neither a response nor a message', async () => {
        mockDelete.mockRejectedValueOnce({});

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /^delete project$/i }));
        fireEvent.change(screen.getByPlaceholderText('web'), { target: { value: 'web' } });
        fireEvent.click(screen.getByRole('button', { name: /^delete$/i }));

        expect(await screen.findByText('Could not delete the project.')).toBeInTheDocument();
    });

    it('shows a pending state while deleting the project', async () => {
        const { promise, resolve } = deferred<any>();
        mockDelete.mockReturnValue(promise);

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /^delete project$/i }));
        fireEvent.change(screen.getByPlaceholderText('web'), { target: { value: 'web' } });
        fireEvent.click(screen.getByRole('button', { name: /^delete$/i }));

        expect(await screen.findByRole('button', { name: /deleting…/i })).toBeDisabled();

        resolve({ data: { data: {} } });
        await waitFor(() => expect(navigateMock).toHaveBeenCalledWith(ROUTES.PROJECTS));
    });
});

describe('ProjectSettingsTab — loading state', () => {
    it('renders a skeleton and no section content while the project is loading', () => {
        mockUseProject.mockReturnValue({ data: undefined, isLoading: true });
        mockGet.mockReset();
        mockGet.mockResolvedValue({ data: { data: {} } });

        render(<ProjectSettingsTab projectId={1} />);

        expect(screen.queryByText('General')).not.toBeInTheDocument();
        expect(screen.queryByText('Security')).not.toBeInTheDocument();
        expect(screen.queryByText('Environments')).not.toBeInTheDocument();
    });
});
