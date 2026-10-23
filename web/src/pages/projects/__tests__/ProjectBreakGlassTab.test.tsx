import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import { act } from 'react';
import { render, screen, fireEvent, waitFor, within } from '../../../test/test-utils';
import { ProjectBreakGlassTab, formatRemaining } from '../ProjectBreakGlassTab';
import type { BreakGlassActivation, BreakGlassList, BreakGlassSettings } from '../../../services/breakGlass';

const { listMock, activateMock, revokeMock, reviewMock } = vi.hoisted(() => ({
    listMock: vi.fn(),
    activateMock: vi.fn(),
    revokeMock: vi.fn(),
    reviewMock: vi.fn(),
}));

vi.mock('../../../services/breakGlass', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../services/breakGlass')>();
    return {
        ...actual,
        breakGlassApi: { list: listMock, activate: activateMock, revoke: revokeMock, review: reviewMock },
    };
});

vi.mock('../../../features/auth/api', () => ({ useAuth: () => ({ user: { id: 7 } }) }));

const canState = { value: { admin: false, manageMembers: false } };
vi.mock('../../../features/auth/useCan', () => ({ useCan: () => canState.value }));

vi.mock('../../../features/projects/api', () => ({
    useProjectMembers: () => ({
        data: [
            { userId: 7, username: 'alice', displayName: 'Alice A' },
            { userId: 8, username: 'bob', displayName: '' },
        ],
    }),
}));

// Real "now": rows are built relative to it so an hour-long activation is live when rendered.
const NOW = Date.now();
const inMinutes = (m: number) => new Date(NOW + m * 60_000).toISOString();

const activation = (over: Partial<BreakGlassActivation> = {}): BreakGlassActivation => ({
    id: 1,
    userId: 7,
    roleName: 'project_developer',
    justification: 'database is down, paging oncall',
    state: 'active',
    expiresAt: inMinutes(90),
    createdAt: inMinutes(-5),
    revokedBy: undefined,
    revokedAt: undefined,
    reviewedBy: undefined,
    reviewedAt: undefined,
    reviewNote: undefined,
    degraded: false,
    ...over,
});

const refusal = (status: number, data: Record<string, unknown>) =>
    new AxiosError('Request failed', 'ERR_BAD_REQUEST', undefined, undefined, {
        status,
        statusText: '',
        data,
        headers: {},
        config: { headers: new AxiosHeaders() },
    });

const own = (activations: BreakGlassActivation[], settings?: BreakGlassSettings): BreakGlassList => ({
    activations,
    scope: 'own',
    settings,
});
const limits = (over: Partial<BreakGlassSettings> = {}): BreakGlassSettings => ({
    enabled: true,
    emergencyRole: 'project_developer',
    defaultTtlSeconds: 4 * 3600,
    maxTtlSeconds: 8 * 3600,
    ...over,
});
const pickerValues = () =>
    within(screen.getByLabelText('How long'))
        .getAllByRole('option')
        .map((o) => (o as HTMLOptionElement).value);
const project = (activations: BreakGlassActivation[]): BreakGlassList => ({ activations, scope: 'project' });

const renderTab = () => render(<ProjectBreakGlassTab projectId={5} />);

beforeEach(() => {
    vi.clearAllMocks();
    canState.value = { admin: false, manageMembers: false };
    vi.spyOn(window, 'alert').mockImplementation(() => undefined);
    vi.spyOn(window, 'confirm').mockImplementation(() => true);
});

afterEach(() => {
    vi.useRealTimers();
    // Revoke and activate go through the dialog / form, never a browser prompt.
    expect(window.alert).not.toHaveBeenCalled();
    expect(window.confirm).not.toHaveBeenCalled();
});

describe('formatRemaining', () => {
    it('formats hours, minutes and seconds, and clamps at zero', () => {
        expect(formatRemaining(90 * 60_000)).toBe('1h 30m 00s');
        expect(formatRemaining(59_000)).toBe('0m 59s');
        expect(formatRemaining(-5_000)).toBe('0m 00s');
    });
});

describe('ProjectBreakGlassTab — member view', () => {
    it('shows the request form and only the caller’s own activations, without admin columns or Revoke', async () => {
        listMock.mockResolvedValue(own([activation()]));
        renderTab();
        expect(await screen.findByRole('heading', { name: 'Your activations' })).toBeInTheDocument();
        expect(screen.getByLabelText('Justification')).toBeInTheDocument();
        expect(screen.getByText('database is down, paging oncall')).toBeInTheDocument();
        expect(screen.getByText('Active')).toBeInTheDocument();
        expect(screen.queryByText('Who')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
    });

    it('does not offer Revoke to a member even when the permission union claims roles.assign: the server view decides', async () => {
        canState.value = { admin: false, manageMembers: true };
        listMock.mockResolvedValue(own([activation()]));
        renderTab();
        await screen.findByText('database is down, paging oncall');
        expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
    });

    it('counts down to expiry live and flips to Expired when it reaches zero', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] });
        vi.setSystemTime(NOW);
        listMock.mockResolvedValue(own([activation({ expiresAt: new Date(NOW + 3_000).toISOString() })]));
        renderTab();
        expect(await screen.findByTestId('bg-countdown-1')).toHaveTextContent('0m 03s');

        await act(async () => {
            vi.advanceTimersByTime(2_000);
        });
        expect(screen.getByTestId('bg-countdown-1')).toHaveTextContent('0m 01s');

        await act(async () => {
            vi.advanceTimersByTime(2_000);
        });
        expect(screen.queryByTestId('bg-countdown-1')).not.toBeInTheDocument();
        expect(screen.getByText('Expired')).toBeInTheDocument();
        // The row settles on the server's record: one refetch when the countdown lapses.
        await waitFor(() => expect(listMock.mock.calls.length).toBeGreaterThanOrEqual(2));
    });

    it('requires a justification of at least 10 characters before the request can be sent', async () => {
        listMock.mockResolvedValue(own([]));
        renderTab();
        const submit = await screen.findByRole('button', { name: 'Request emergency access' });
        expect(submit).toBeDisabled();
        fireEvent.change(screen.getByLabelText('Justification'), { target: { value: 'too short' } });
        expect(submit).toBeDisabled();
        fireEvent.change(screen.getByLabelText('Justification'), { target: { value: 'prod outage INC-1' } });
        expect(submit).toBeEnabled();
    });

    it('sends the trimmed justification and the picked TTL, then shows the expiry the server granted', async () => {
        listMock.mockResolvedValue(own([]));
        activateMock.mockResolvedValue(activation({ id: 2, expiresAt: inMinutes(30) }));
        renderTab();
        fireEvent.change(await screen.findByLabelText('Justification'), {
            target: { value: '  prod outage INC-123  ' },
        });
        fireEvent.change(screen.getByLabelText('How long'), { target: { value: '30m' } });
        fireEvent.click(screen.getByRole('button', { name: 'Request emergency access' }));
        await waitFor(() => expect(activateMock).toHaveBeenCalledWith(5, 'prod outage INC-123', '30m'));
        expect(await screen.findByText('Emergency access is active')).toBeInTheDocument();
        // The list is re-read after the write.
        await waitFor(() => expect(listMock.mock.calls.length).toBeGreaterThanOrEqual(2));
    });

    it('says so when the grant was degraded because the audit log refused writes (BREAKGLASS-OWED-1)', async () => {
        listMock.mockResolvedValue(own([]));
        activateMock.mockResolvedValue(activation({ id: 3, expiresAt: inMinutes(15), degraded: true }));
        renderTab();
        fireEvent.change(await screen.findByLabelText('Justification'), { target: { value: 'prod outage INC-124' } });
        fireEvent.click(screen.getByRole('button', { name: 'Request emergency access' }));
        expect(await screen.findByTestId('bg-granted-degraded')).toHaveTextContent('recorded as owed and shortened');
    });

    it('badges a degraded activation, saying whether its audit records are still owed', async () => {
        listMock.mockResolvedValue(
            own([
                activation({ id: 4, degraded: true }),
                activation({ id: 5, degraded: true, state: 'revoked', auditSettledAt: inMinutes(-1) }),
                activation({ id: 6 }),
            ])
        );
        renderTab();
        expect(await screen.findByTestId('bg-degraded-4')).toHaveTextContent('Degraded · audit owed');
        expect(screen.getByTestId('bg-degraded-5')).toHaveTextContent(/^Degraded$/);
        expect(screen.queryByTestId('bg-degraded-6')).not.toBeInTheDocument();
    });

    it('omits ttl when the server default is picked', async () => {
        listMock.mockResolvedValue(own([]));
        activateMock.mockResolvedValue(activation());
        renderTab();
        fireEvent.change(await screen.findByLabelText('Justification'), { target: { value: 'prod outage INC-123' } });
        fireEvent.click(screen.getByRole('button', { name: 'Request emergency access' }));
        await waitFor(() => expect(activateMock).toHaveBeenCalledWith(5, 'prod outage INC-123', undefined));
    });

    it('offers only lifetimes within the server’s maximum and shows the server default', async () => {
        listMock.mockResolvedValue(own([], limits({ defaultTtlSeconds: 2 * 3600, maxTtlSeconds: 2 * 3600 })));
        renderTab();
        await screen.findByLabelText('How long');
        expect(pickerValues()).toEqual(['', '15m', '30m', '1h', '2h']);
        expect(screen.getByRole('option', { name: 'Server default (2 hours)' })).toBeInTheDocument();
        expect(screen.getByText(/The server allows at most 2 hours/)).toBeInTheDocument();
        expect(screen.queryByRole('option', { name: '4 hours' })).not.toBeInTheDocument();
        expect(screen.queryByRole('option', { name: '24 hours' })).not.toBeInTheDocument();
    });

    it('adds the server maximum as a choice when it is not one of the usual lifetimes', async () => {
        listMock.mockResolvedValue(own([], limits({ defaultTtlSeconds: 3600, maxTtlSeconds: 5400 })));
        activateMock.mockResolvedValue(activation());
        renderTab();
        await screen.findByLabelText('How long');
        expect(pickerValues()).toEqual(['', '15m', '30m', '1h', '5400s']);
        expect(screen.getByRole('option', { name: '1 hour 30 minutes (server maximum)' })).toBeInTheDocument();
        fireEvent.change(screen.getByLabelText('Justification'), { target: { value: 'prod outage INC-123' } });
        fireEvent.change(screen.getByLabelText('How long'), { target: { value: '5400s' } });
        fireEvent.click(screen.getByRole('button', { name: 'Request emergency access' }));
        await waitFor(() => expect(activateMock).toHaveBeenCalledWith(5, 'prod outage INC-123', '5400s'));
    });

    it('offers a ceiling below the shortest usual lifetime as the only timed choice', async () => {
        listMock.mockResolvedValue(own([], limits({ defaultTtlSeconds: 600, maxTtlSeconds: 600 })));
        renderTab();
        await screen.findByLabelText('How long');
        expect(pickerValues()).toEqual(['', '600s']);
    });

    it('keeps the full picker and the generic note against a server that sends no limits', async () => {
        listMock.mockResolvedValue(own([]));
        renderTab();
        await screen.findByLabelText('How long');
        expect(pickerValues()).toEqual(['', '15m', '30m', '1h', '2h', '4h', '8h', '24h']);
        expect(screen.getByRole('option', { name: 'Server default' })).toBeInTheDocument();
        expect(screen.getByText(/The server caps the lifetime/)).toBeInTheDocument();
    });

    it('says so up front, without a request form, when the server reports break-glass off', async () => {
        listMock.mockResolvedValue(own([activation()], limits({ enabled: false })));
        renderTab();
        expect(await screen.findByText('Break-glass is not enabled on this server')).toBeInTheDocument();
        expect(screen.queryByLabelText('Justification')).not.toBeInTheDocument();
        expect(activateMock).not.toHaveBeenCalled();
        // The member's own history is still theirs to see.
        expect(screen.getByText('database is down, paging oncall')).toBeInTheDocument();
    });

    it('recognises the BreakGlassDisabled code even when the message is in another language', async () => {
        listMock.mockResolvedValue(own([]));
        activateMock.mockRejectedValue(
            refusal(403, { error: 'BreakGlassDisabled', message: 'доступ запрещён: функция выключена', code: 403 })
        );
        renderTab();
        fireEvent.change(await screen.findByLabelText('Justification'), { target: { value: 'prod outage INC-123' } });
        fireEvent.click(screen.getByRole('button', { name: 'Request emergency access' }));
        expect(await screen.findByText('Break-glass is not enabled on this server')).toBeInTheDocument();
        expect(screen.queryByLabelText('Justification')).not.toBeInTheDocument();
    });

    it('still reads an older server’s disabled message (no code) as disabled', async () => {
        listMock.mockResolvedValue(own([]));
        activateMock.mockRejectedValue(
            refusal(403, {
                error: 'Error',
                message:
                    'permission denied: break-glass is not enabled on this server; set break_glass.enabled: true in keyorix.yaml and restart',
                code: 403,
            })
        );
        renderTab();
        fireEvent.change(await screen.findByLabelText('Justification'), { target: { value: 'prod outage INC-123' } });
        fireEvent.click(screen.getByRole('button', { name: 'Request emergency access' }));
        expect(await screen.findByText('Break-glass is not enabled on this server')).toBeInTheDocument();
        expect(screen.queryByLabelText('Justification')).not.toBeInTheDocument();
    });

    it('surfaces the project MFA refusal with a way to enrol', async () => {
        listMock.mockResolvedValue(own([]));
        activateMock.mockRejectedValue(
            refusal(403, { error: 'ProjectMFARequired', message: 'This project requires multi-factor authentication.' })
        );
        renderTab();
        fireEvent.change(await screen.findByLabelText('Justification'), { target: { value: 'prod outage INC-123' } });
        fireEvent.click(screen.getByRole('button', { name: 'Request emergency access' }));
        expect(await screen.findByText('This project requires multi-factor authentication')).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Set up MFA' })).toHaveAttribute(
            'href',
            expect.stringContaining('mfa=required')
        );
    });

    it('shows a server refusal (not a member) in place, keeping what was typed', async () => {
        listMock.mockResolvedValue(own([]));
        activateMock.mockRejectedValue(
            refusal(403, { error: 'Error', message: 'permission denied: break-glass: caller is not a project member' })
        );
        renderTab();
        fireEvent.change(await screen.findByLabelText('Justification'), { target: { value: 'prod outage INC-123' } });
        fireEvent.click(screen.getByRole('button', { name: 'Request emergency access' }));
        expect(await screen.findByText(/caller is not a project member/)).toBeInTheDocument();
        expect(screen.getByLabelText('Justification')).toHaveValue('prod outage INC-123');
    });
});

describe('ProjectBreakGlassTab — outsider', () => {
    it('handles a 403 on the list: a clear refusal, no form, no rows', async () => {
        listMock.mockRejectedValue(
            refusal(403, { error: 'Forbidden', message: 'Insufficient permissions', code: 403 })
        );
        renderTab();
        expect(await screen.findByText('Not allowed')).toBeInTheDocument();
        expect(screen.queryByLabelText('Justification')).not.toBeInTheDocument();
        expect(screen.queryByTestId('bg-row-1')).not.toBeInTheDocument();
        // A refusal is an answer, not a blip: no retry.
        expect(listMock).toHaveBeenCalledTimes(1);
    });

    it('surfaces the MFA refusal on the list', async () => {
        listMock.mockRejectedValue(refusal(403, { error: 'ProjectMFARequired', message: 'MFA needed' }));
        renderTab();
        expect(await screen.findByText('This project requires multi-factor authentication')).toBeInTheDocument();
    });
});

describe('ProjectBreakGlassTab — admin view', () => {
    beforeEach(() => {
        canState.value = { admin: false, manageMembers: true };
    });

    it('lists every activation with who, when, justification and status', async () => {
        listMock.mockResolvedValue(
            project([
                activation({ id: 1, userId: 7 }),
                activation({ id: 2, userId: 8, justification: 'cert expired in prod', state: 'revoked' }),
                activation({ id: 3, userId: 99, state: 'expired', expiresAt: inMinutes(-60) }),
            ])
        );
        renderTab();
        expect(await screen.findByRole('heading', { name: 'All activations on this project' })).toBeInTheDocument();
        expect(screen.getByText('Who')).toBeInTheDocument();
        expect(within(screen.getByTestId('bg-row-1')).getByText('Alice A')).toBeInTheDocument();
        // No display name: falls back to the username; unknown user: to the id.
        expect(within(screen.getByTestId('bg-row-2')).getByText('bob')).toBeInTheDocument();
        expect(within(screen.getByTestId('bg-row-2')).getByText('Revoked')).toBeInTheDocument();
        expect(within(screen.getByTestId('bg-row-3')).getByText('User #99')).toBeInTheDocument();
        expect(within(screen.getByTestId('bg-row-3')).getByText('Expired')).toBeInTheDocument();
        // Revoke only on the live one.
        expect(screen.getAllByRole('button', { name: 'Revoke' })).toHaveLength(1);
    });

    it('revokes only after the confirm dialog, then re-reads the list', async () => {
        listMock.mockResolvedValue(project([activation({ id: 1, userId: 7 })]));
        revokeMock.mockResolvedValue(undefined);
        renderTab();
        fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
        expect(revokeMock).not.toHaveBeenCalled();
        const dialog = await screen.findByRole('dialog');
        expect(within(dialog).getByRole('heading', { name: 'Revoke emergency access?', level: 3 })).toBeInTheDocument();
        expect(within(dialog).getByText(/Alice A will lose the project_developer role/)).toBeInTheDocument();
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        await waitFor(() => expect(revokeMock).toHaveBeenCalledWith(5, 1));
        await waitFor(() => expect(listMock.mock.calls.length).toBeGreaterThanOrEqual(2));
    });

    it('cancelling the dialog revokes nothing', async () => {
        listMock.mockResolvedValue(project([activation()]));
        renderTab();
        fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
        const dialog = await screen.findByRole('dialog');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
        expect(revokeMock).not.toHaveBeenCalled();
    });

    it('shows the server’s refusal when revoke is denied (403), without pretending it worked', async () => {
        listMock.mockResolvedValue(project([activation()]));
        revokeMock.mockRejectedValue(
            refusal(403, { error: 'Forbidden', message: 'Insufficient permissions', code: 403 })
        );
        renderTab();
        fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
        const dialog = await screen.findByRole('dialog');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        expect(await screen.findByText('You do not have permission to revoke access.')).toBeInTheDocument();
    });

    it('hides Revoke from a reader without roles.assign, while still listing everything', async () => {
        canState.value = { admin: false, manageMembers: false };
        listMock.mockResolvedValue(project([activation()]));
        renderTab();
        expect(await screen.findByText('Alice A')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
    });
});

describe('ProjectBreakGlassTab — independent review', () => {
    beforeEach(() => {
        canState.value = { admin: false, manageMembers: true };
    });

    // The signed-in user is #7 (alice). Rows: 1 = alice's own ended activation, 2 = bob's ended one,
    // 3 = bob's still-active one, 4 = bob's already-reviewed one.
    const rows = () =>
        project([
            activation({ id: 1, userId: 7, state: 'revoked' }),
            activation({ id: 2, userId: 8, state: 'revoked' }),
            activation({ id: 3, userId: 8 }),
            activation({
                id: 4,
                userId: 8,
                state: 'expired',
                expiresAt: inMinutes(-60),
                reviewedBy: 9,
                reviewNote: 'ok',
            }),
        ]);

    it('offers Review only on an ended, unreviewed activation that someone else requested', async () => {
        listMock.mockResolvedValue(rows());
        renderTab();
        await screen.findByTestId('bg-row-2');
        expect(screen.getByTestId('bg-review-2')).toBeInTheDocument();
        expect(screen.queryByTestId('bg-review-1')).not.toBeInTheDocument(); // the requester's own
        expect(screen.queryByTestId('bg-review-3')).not.toBeInTheDocument(); // still active
        expect(screen.queryByTestId('bg-review-4')).not.toBeInTheDocument(); // already reviewed
        expect(within(screen.getByTestId('bg-row-4')).getByTestId('bg-reviewed-4')).toBeInTheDocument();
    });

    it('hides Review from a reader without roles.assign and from a member’s own view', async () => {
        canState.value = { admin: false, manageMembers: false };
        listMock.mockResolvedValue(rows());
        renderTab();
        await screen.findByTestId('bg-row-2');
        expect(screen.queryByTestId('bg-review-2')).not.toBeInTheDocument();

        listMock.mockResolvedValue(own([activation({ id: 6, userId: 7, state: 'revoked' })]));
        canState.value = { admin: false, manageMembers: true };
        renderTab();
        await waitFor(() => expect(screen.getByTestId('bg-row-6')).toBeInTheDocument());
        expect(screen.queryByTestId('bg-review-6')).not.toBeInTheDocument();
    });

    it('requires a note of at least 10 characters, then posts it and re-reads the list', async () => {
        listMock.mockResolvedValue(rows());
        reviewMock.mockResolvedValue(undefined);
        renderTab();
        fireEvent.click(await screen.findByTestId('bg-review-2'));
        const dialog = await screen.findByRole('dialog');
        const submit = within(dialog).getByTestId('bg-review-submit');
        expect(submit).toBeDisabled();
        fireEvent.change(within(dialog).getByLabelText('Review note'), { target: { value: 'too short' } });
        expect(submit).toBeDisabled();
        fireEvent.change(within(dialog).getByLabelText('Review note'), {
            target: { value: '  Reviewed: INC-4711 confirmed  ' },
        });
        expect(submit).toBeEnabled();
        fireEvent.click(submit);
        await waitFor(() => expect(reviewMock).toHaveBeenCalledWith(5, 2, 'Reviewed: INC-4711 confirmed'));
        await waitFor(() => expect(listMock.mock.calls.length).toBeGreaterThanOrEqual(2));
    });

    it('shows the server’s refusal in the dialog and keeps it open', async () => {
        listMock.mockResolvedValue(rows());
        reviewMock.mockRejectedValue(
            refusal(403, {
                error: 'Forbidden',
                message: 'you cannot review your own break-glass activation',
                code: 403,
            })
        );
        renderTab();
        fireEvent.click(await screen.findByTestId('bg-review-2'));
        const dialog = await screen.findByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText('Review note'), { target: { value: 'a long enough note' } });
        fireEvent.click(within(dialog).getByTestId('bg-review-submit'));
        expect(await within(dialog).findByRole('alert')).toHaveTextContent('you cannot review your own');
        expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    it('cancelling posts nothing', async () => {
        listMock.mockResolvedValue(rows());
        renderTab();
        fireEvent.click(await screen.findByTestId('bg-review-2'));
        fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
        expect(reviewMock).not.toHaveBeenCalled();
    });
});
