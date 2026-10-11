import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '../../../test/test-utils';
import { ShareSecretModal, expiresAtFromPreset, SHARE_CONFIRMATION_MS } from '../ShareSecretModal';
import { Secret } from '../../../types';
import { AxiosError, AxiosHeaders } from 'axios';

const mockMutate = vi.fn();
const mockReset = vi.fn();
let isPending = false;
let isError = false;
let mutationError: unknown = null;

// The project-scoped recipient search (SHARE-2), used when the secret's project is
// known. Reassigned per test like searchImpl below.
let projectSearchImpl: (projectId: number, query: string) => Promise<{ recipients: unknown[] }> = async () => ({
    recipients: [],
});
const projectSearchCalls: Array<[number, string]> = [];

vi.mock('../api', () => ({
    searchShareRecipients: (projectId: number, query: string) => {
        projectSearchCalls.push([projectId, query]);
        return projectSearchImpl(projectId, query);
    },
    useShareSecret: () => ({
        mutate: mockMutate,
        reset: mockReset,
        isPending,
        isError,
        error: mutationError,
    }),
}));

// The modal searches users by query before a recipient can be selected. `searchImpl` is
// reassigned per-test (rather than using mockResolvedValueOnce/mockRejectedValueOnce)
// so a stray call from a previous test's not-yet-unmounted debounce timer can never
// consume a queued response meant for the current test.
let searchImpl: (args: { search: string; pageSize: number }) => Promise<{ users: unknown[] }> = async () => ({
    users: [{ id: 7, username: 'bob', display_name: 'Bob', email: 'bob@test.com' }],
});
let globalSearchCalls = 0;

// The modal searches users by query before a recipient can be selected.
vi.mock('../../../services/users', () => ({
    usersApi: {
        list: (...args: [{ search: string; pageSize: number }]) => {
            globalSearchCalls++;
            return searchImpl(...args);
        },
    },
}));

const secret: Secret = {
    id: 1,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-06-17T00:00:00Z',
    owner: 'alice',
    permissions: ['read', 'write'],
    metadata: {},
    tags: [],
    classification: 'confidential',
};

beforeEach(() => {
    isPending = false;
    isError = false;
    mutationError = null;
    mockMutate.mockReset();
    mockReset.mockReset();
    searchImpl = async () => ({
        users: [{ id: 7, username: 'bob', display_name: 'Bob', email: 'bob@test.com' }],
    });
    globalSearchCalls = 0;
    projectSearchCalls.length = 0;
    projectSearchImpl = async () => ({ recipients: [] });
});

describe('expiresAtFromPreset', () => {
    const base = Date.UTC(2026, 5, 17, 12, 0, 0); // 2026-06-17T12:00:00Z

    it('returns undefined for a permanent share', () => {
        expect(expiresAtFromPreset('never', base)).toBeUndefined();
        expect(expiresAtFromPreset('bogus', base)).toBeUndefined();
    });

    it('resolves presets to an ISO timestamp in the future', () => {
        expect(expiresAtFromPreset('1h', base)).toBe('2026-06-17T13:00:00.000Z');
        expect(expiresAtFromPreset('24h', base)).toBe('2026-06-18T12:00:00.000Z');
        expect(expiresAtFromPreset('7d', base)).toBe('2026-06-24T12:00:00.000Z');
    });
});

describe('ShareSecretModal expiry', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('shares with no expiresAt when expiry is "Never"', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));

        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        const [payload] = mockMutate.mock.calls[0];
        expect(payload.username).toBe('bob');
        expect(payload.expiresAt).toBeUndefined();
    });

    // Regression test: the modal must forward the id of the user actually
    // selected from the dropdown (captured at selection time), not just the
    // username string, so useShareSecret can pin the share to that exact
    // account instead of re-resolving it by name at submit time.
    it('forwards the selected recipient id (captured at selection time), not just the username', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));

        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        const [payload] = mockMutate.mock.calls[0];
        expect(payload.recipientId).toBe(7);
    });

    it('passes an ISO expiresAt when a duration preset is chosen', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        fireEvent.change(screen.getByDisplayValue('Never (permanent)'), { target: { value: '24h' } });
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));

        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        const [payload] = mockMutate.mock.calls[0];
        expect(payload.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/); // a real ISO timestamp
        expect(new Date(payload.expiresAt).getTime()).toBeGreaterThan(Date.now());
    });
});

describe('ShareSecretModal recipient search', () => {
    it('shows "Searching…" while the query is in flight, then the results', async () => {
        let resolveUsers: (v: { users: unknown[] }) => void = () => {};
        searchImpl = () =>
            new Promise((resolve) => {
                resolveUsers = resolve;
            });

        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bo' } });

        expect(await screen.findByText('Searching…')).toBeInTheDocument();
        resolveUsers({ users: [{ id: 7, username: 'bob', display_name: 'Bob', email: 'bob@test.com' }] });
        expect(await screen.findByText('Bob')).toBeInTheDocument();
    });

    it('clears results and says so when the user search rejects', async () => {
        searchImpl = async () => {
            throw new Error('network down');
        };

        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });

        expect(await screen.findByText('Could not search users.')).toBeInTheDocument();
        expect(screen.queryByText('Bob')).not.toBeInTheDocument();
    });

    // Unlike the test above (where "No users found" is also the dropdown's default
    // empty state, so it can pass before the fetch ever settles), this waits for the
    // in-flight "Searching…" state first and only then rejects — so the assertion can
    // only succeed if the effect's catch handler actually ran.
    it('reaches the catch handler and clears results when a fetch genuinely rejects mid-flight', async () => {
        let rejectSearch: (e: Error) => void = () => {};
        searchImpl = () =>
            new Promise((_resolve, reject) => {
                rejectSearch = reject;
            });

        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });

        expect(await screen.findByText('Searching…')).toBeInTheDocument();
        rejectSearch(new Error('network down'));
        expect(await screen.findByText('Could not search users.')).toBeInTheDocument();
    });

    // SHARE-2: with the secret's project known, the dialog searches that project's
    // members (GET /projects/{id}/share-recipients), which a project-only admin may
    // call, instead of GET /users, which needs global users.read.
    it("searches the secret's project members, not the global user list", async () => {
        projectSearchImpl = async () => ({
            recipients: [{ id: 9, username: 'alice', display_name: 'Alice' }],
        });
        render(<ShareSecretModal secret={{ ...secret, projectId: 42 }} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: ' ali' } });

        fireEvent.click(await screen.findByText('Alice'));
        expect(projectSearchCalls).toContainEqual([42, 'ali']);
        expect(globalSearchCalls).toBe(0);
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));
        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        expect(mockMutate.mock.calls[0][0].recipientId).toBe(9);
    });

    it('shows a recipient without an email when the search hides it', async () => {
        projectSearchImpl = async () => ({
            recipients: [{ id: 9, username: 'alice', display_name: 'Alice' }],
        });
        render(<ShareSecretModal secret={{ ...secret, projectId: 42 }} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'ali' } });

        expect(await screen.findByText('@alice')).toBeInTheDocument();
        expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
    });

    it("shows the server's reason when the project search is refused", async () => {
        const reason = 'You can only search for share recipients in a project where you can share secrets.';
        projectSearchImpl = async () => {
            throw new AxiosError('Request failed with status code 403', 'ERR_BAD_REQUEST', undefined, undefined, {
                status: 403,
                statusText: 'Forbidden',
                headers: {},
                config: { headers: new AxiosHeaders() },
                data: { error: 'Forbidden', message: reason },
            });
        };
        render(<ShareSecretModal secret={{ ...secret, projectId: 42 }} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'ali' } });

        expect(await screen.findByText(reason)).toBeInTheDocument();
        expect(screen.queryByText('Request failed with status code 403')).not.toBeInTheDocument();
    });

    it('says "No project members found" for an empty project search', async () => {
        render(<ShareSecretModal secret={{ ...secret, projectId: 42 }} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'zed' } });
        await waitFor(() => expect(projectSearchCalls).toContainEqual([42, 'zed']));
        expect(await screen.findByText(/No project members found/)).toBeInTheDocument();
    });

    // "No users found" is also the dropdown's default empty state, so a search that
    // starts from empty results can't prove this ran. Show a real match first, then
    // switch to a response missing the `users` field and wait for the transition
    // back to "No users found" — that can only happen via the `?? []` fallback.
    it('falls back to an empty result list when the search response omits the users field', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        await screen.findByText('Bob');

        searchImpl = async () => ({}) as unknown as { users: unknown[] };
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'zzz' } });

        expect(await screen.findByText(/No users found/)).toBeInTheDocument();
    });

    // Regression / race-condition guard: if the query changes again before an
    // in-flight search settles, the stale response must be ignored so it can't
    // clobber results/loading state that belong to the newer query.
    it('ignores a stale successful response for a query that was superseded before it resolved', async () => {
        let callCount = 0;
        let resolveFirst: (v: { users: unknown[] }) => void = () => {};
        searchImpl = async () => {
            callCount += 1;
            if (callCount === 1) {
                return new Promise<{ users: unknown[] }>((resolve) => {
                    resolveFirst = resolve;
                });
            }
            return { users: [{ id: 9, username: 'carol', display_name: 'Carol', email: 'carol@test.com' }] };
        };

        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bo' } });
        expect(await screen.findByText('Searching…')).toBeInTheDocument();

        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'car' } });
        expect(await screen.findByText('Carol')).toBeInTheDocument();

        // Resolve the superseded first request only after the second has already won.
        resolveFirst({ users: [{ id: 1, username: 'stale', display_name: 'Stale', email: 'stale@test.com' }] });
        await waitFor(() => expect(screen.queryByText('Stale')).not.toBeInTheDocument());
        expect(screen.getByText('Carol')).toBeInTheDocument();
    });

    // Same guard, but for the catch path: a superseded request that later rejects
    // must not be allowed to clear results that belong to the newer, already-resolved query.
    it('ignores a stale rejected response for a query that was superseded before it settled', async () => {
        let callCount = 0;
        let rejectFirst: (e: Error) => void = () => {};
        searchImpl = async () => {
            callCount += 1;
            if (callCount === 1) {
                return new Promise<{ users: unknown[] }>((_resolve, reject) => {
                    rejectFirst = reject;
                });
            }
            return { users: [{ id: 9, username: 'carol', display_name: 'Carol', email: 'carol@test.com' }] };
        };

        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bo' } });
        expect(await screen.findByText('Searching…')).toBeInTheDocument();

        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'car' } });
        expect(await screen.findByText('Carol')).toBeInTheDocument();

        rejectFirst(new Error('stale network error'));
        await waitFor(() => expect(screen.getByText('Carol')).toBeInTheDocument());
        expect(screen.queryByText(/No users found/)).not.toBeInTheDocument();
    });

    it('falls back to username when a matched user has no display name', async () => {
        searchImpl = async () => ({
            users: [{ id: 8, username: 'nodisplay', display_name: '', email: 'nd@test.com' }],
        });

        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'nod' } });
        fireEvent.click(await screen.findByText('nodisplay'));

        expect((screen.getByPlaceholderText(/Search by name/i) as HTMLInputElement).value).toBe('nodisplay');
    });

    it('applies hover style handlers on a dropdown option', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        const option = await screen.findByText('Bob');
        const button = option.closest('button') as HTMLButtonElement;

        fireEvent.mouseEnter(button);
        expect(button.style.backgroundColor).toBeTruthy();
        fireEvent.mouseLeave(button);
        expect(button.style.backgroundColor).toBe('');
    });

    it('closes the dropdown on an outside click', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        await screen.findByText('Bob');

        fireEvent.mouseDown(document.body);
        expect(screen.queryByText('Bob')).not.toBeInTheDocument();
    });

    // Counterpart to the "outside click" test above: a mousedown that lands inside
    // the search input itself is not "outside", so the dropdown must stay open.
    it('keeps the dropdown open when the click lands on the search input itself', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        const input = screen.getByPlaceholderText(/Search by name/i);
        fireEvent.change(input, { target: { value: 'bob' } });
        await screen.findByText('Bob');

        fireEvent.mouseDown(input);
        expect(screen.getByText('Bob')).toBeInTheDocument();
    });

    it('reopens the dropdown on focus when a query is already present', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        const input = screen.getByPlaceholderText(/Search by name/i);
        fireEvent.change(input, { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        expect(screen.queryByText('Bob')).not.toBeInTheDocument();

        fireEvent.focus(input);
        expect(await screen.findByText('Bob')).toBeInTheDocument();
    });

    it('does not reopen the dropdown on focus when the query is empty', () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        const input = screen.getByPlaceholderText(/Search by name/i);

        fireEvent.focus(input);
        expect(screen.queryByText(/No users found/)).not.toBeInTheDocument();
    });
});

describe('ShareSecretModal submission + lifecycle', () => {
    it('does nothing on submit when no recipient is selected yet', () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        // The Modal renders its content through a portal, so query the document rather
        // than the render container.
        const form = document.querySelector('form') as HTMLFormElement;
        fireEvent.submit(form);
        expect(mockMutate).not.toHaveBeenCalled();
    });

    it('Cancel resets all fields, the mutation, and closes the modal', () => {
        const onClose = vi.fn();
        render(<ShareSecretModal secret={secret} isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(screen.getByRole('button', { name: /^Cancel$/i }));

        expect(mockReset).toHaveBeenCalled();
        expect(onClose).toHaveBeenCalled();
    });

    it('changes the permission and includes it in the share payload', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        fireEvent.change(screen.getByDisplayValue('Read Only'), { target: { value: 'write' } });
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));

        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        const [payload] = mockMutate.mock.calls[0];
        expect(payload.permission).toBe('write');
    });

    // The dialog is opened from a secrets-list row, and secretsApi.list maps every row with
    // `permissions: []` (the list endpoint returns no per-secret permissions). The dialog used to
    // hide the write option unless secret.permissions held 'write', so for every real row it never
    // offered it and a write share (the #2941 elevation) could not be created from the UI. The
    // server is the enforcement: POST /secrets/{id}/share needs secrets.write on the secret.
    it('offers the write option for a list row, whose permissions array is empty', () => {
        const listRow: Secret = { ...secret, permissions: [] };
        render(<ShareSecretModal secret={listRow} isOpen onClose={() => {}} />);
        const select = screen.getByDisplayValue('Read Only') as HTMLSelectElement;
        const optionLabels = Array.from(select.options).map((o) => o.textContent);
        expect(optionLabels).toEqual(['Read Only', 'Read + update value/metadata, rotate']);
    });

    it('offers the write option when the secret carries write', () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        const select = screen.getByDisplayValue('Read Only') as HTMLSelectElement;
        const optionLabels = Array.from(select.options).map((o) => o.textContent);
        expect(optionLabels).toContain('Read + update value/metadata, rotate');
    });

    it('says what a write share grants and what it does not (#3001 allowlist)', () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        expect(screen.getByText('The recipient can read this secret.')).toBeInTheDocument();
        fireEvent.change(screen.getByDisplayValue('Read Only'), { target: { value: 'write' } });
        const hint = screen.getByText(/update its value and metadata/);
        expect(hint).toHaveTextContent('rotate it');
        expect(hint).toHaveTextContent(
            /Suspending, changing its expiry, moving, deleting, re-sharing or changing access still needs a project role/
        );
        expect(screen.getByDisplayValue('Read + update value/metadata, rotate')).toHaveAttribute(
            'aria-describedby',
            hint.id
        );
    });

    it('shows a success message, calls onSuccess, and auto-closes after a delay', async () => {
        mockMutate.mockImplementation((_vars: unknown, opts: { onSuccess: () => void }) => opts.onSuccess());
        const onSuccessCb = vi.fn();
        const onCloseCb = vi.fn();

        render(<ShareSecretModal secret={secret} isOpen onClose={onCloseCb} onSuccess={onSuccessCb} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));

        expect(screen.getByText('Shared!')).toBeInTheDocument();
        expect(onSuccessCb).toHaveBeenCalled();

        await waitFor(() => expect(onCloseCb).toHaveBeenCalled(), { timeout: 2000 });
    });

    it('shows the Error message when the mutation fails with an Error instance', () => {
        isError = true;
        mutationError = new Error('Username not found');
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        expect(screen.getByText('Username not found')).toBeInTheDocument();
    });

    it("shows the server's reason, not axios's generic text, when a share is refused (#2976)", () => {
        isError = true;
        mutationError = new AxiosError('Request failed with status code 403', 'ERR_BAD_REQUEST', undefined, undefined, {
            status: 403,
            statusText: 'Forbidden',
            headers: {},
            config: { headers: new AxiosHeaders() },
            data: {
                error: 'Forbidden',
                message: "The recipient is not a member of this secret's project.",
            },
        });
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        expect(screen.getByText("The recipient is not a member of this secret's project.")).toBeInTheDocument();
        expect(screen.queryByText('Request failed with status code 403')).not.toBeInTheDocument();
    });

    it('shows a fallback message when the mutation fails with a non-Error value', () => {
        isError = true;
        mutationError = { code: 'ERR' };
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        expect(screen.getByText('Failed to share secret.')).toBeInTheDocument();
    });

    it('shows "Sharing…" and disables the search input while the mutation is pending', () => {
        isPending = true;
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        expect(screen.getByRole('button', { name: 'Sharing…' })).toBeInTheDocument();
        expect(screen.getByPlaceholderText(/Search by name/i)).toBeDisabled();
    });
});

// SHARE-2: the "Shared!" confirmation must render and stay up before the dialog
// closes itself; the pages used to close the dialog from onSuccess, so it never did.
describe('ShareSecretModal success confirmation', () => {
    const shareWithBob = async (onClose: () => void, onSuccess: () => void) => {
        mockMutate.mockImplementation((_payload: unknown, opts?: { onSuccess?: () => void }) => opts?.onSuccess?.());
        const view = render(<ShareSecretModal secret={secret} isOpen onClose={onClose} onSuccess={onSuccess} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        vi.useFakeTimers();
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));
        return view;
    };

    it('shows "Shared!" and closes itself only after the confirmation delay', async () => {
        const onClose = vi.fn();
        const onSuccess = vi.fn();
        try {
            await shareWithBob(onClose, onSuccess);
            expect(onSuccess).toHaveBeenCalledTimes(1);
            expect(screen.getByText('Shared!')).toBeInTheDocument();
            expect(screen.getByText('Secret shared successfully.')).toBeInTheDocument();
            expect(onClose).not.toHaveBeenCalled();

            act(() => vi.advanceTimersByTime(SHARE_CONFIRMATION_MS - 1));
            expect(onClose).not.toHaveBeenCalled();
            expect(screen.getByText('Shared!')).toBeInTheDocument();
            act(() => vi.advanceTimersByTime(1));
            expect(onClose).toHaveBeenCalledTimes(1);
        } finally {
            vi.useRealTimers();
        }
    });

    it('does not fire a pending auto-close after the dialog is gone', async () => {
        const onClose = vi.fn();
        try {
            const view = await shareWithBob(onClose, () => {});
            view.unmount();
            act(() => vi.advanceTimersByTime(SHARE_CONFIRMATION_MS * 2));
            expect(onClose).not.toHaveBeenCalled();
        } finally {
            vi.useRealTimers();
        }
    });
});
