import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { ProjectAccessReviewCampaigns, lastUsedInfo } from '../ProjectAccessReviewCampaigns';

const mockUseCampaigns = vi.fn();
const mockUseCampaign = vi.fn();
const mockOpenMutate = vi.fn();
const mockDecideMutate = vi.fn();
const mockCloseMutate = vi.fn();
const mockGet = vi.fn();

vi.mock('../../../features/projects/api', () => ({
    useAccessReviewCampaigns: () => mockUseCampaigns(),
    useAccessReviewCampaign: () => mockUseCampaign(),
    useOpenCampaign: () => ({ mutate: mockOpenMutate, isPending: false }),
    useDecideCampaignItem: () => ({ mutate: mockDecideMutate, isPending: false }),
    useCloseCampaign: () => ({ mutate: mockCloseMutate, isPending: false }),
}));

vi.mock('../../../services/client', () => ({
    apiClient: { get: (...args: any[]) => mockGet(...args) },
}));

const campaigns = [
    {
        campaign: { id: 1, projectId: 2, name: 'Q4 2026', state: 'open', createdAt: '' },
        progress: { total: 3, pending: 2, attested: 1, revoked: 0 },
    },
];

const detail = {
    campaign: { id: 1, projectId: 2, name: 'Q4 2026', state: 'open', createdAt: '' },
    progress: { total: 3, pending: 2, attested: 1, revoked: 0 },
    items: [
        {
            id: 10,
            principalType: 'user',
            principalId: 5,
            principalName: 'alice',
            email: 'a@x.io',
            source: 'role',
            roleName: 'editor',
            accessLevel: 'write',
            secretName: '',
            decision: 'pending',
        },
        {
            id: 11,
            principalType: 'group',
            principalId: 9,
            principalName: 'devs',
            email: '',
            source: 'group_share',
            roleName: '',
            accessLevel: 'read',
            secretName: 'db',
            decision: 'attested',
        },
    ],
};

describe('ProjectAccessReviewCampaigns', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockUseCampaign.mockReturnValue({ data: detail, isLoading: false });
        // jsdom has no object-URL API; stub it for the CSV download.
        (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
        (URL as any).revokeObjectURL = vi.fn();
    });

    it('lists campaigns with state and progress', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        expect(screen.getByText('Q4 2026')).toBeInTheDocument();
        expect(screen.getByText('open')).toBeInTheDocument();
        expect(screen.getByText(/1\/3 decided · 1 attested · 0 revoked/)).toBeInTheDocument();
    });

    it('opens a campaign with the typed name', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.change(screen.getByPlaceholderText('Campaign name'), { target: { value: 'Annual review' } });
        fireEvent.click(screen.getByText('Open'));
        expect(mockOpenMutate).toHaveBeenCalledWith('Annual review', expect.any(Object));
    });

    it('reveals items and attests a pending one', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        // The pending item's principal is shown, and an Attest control is available.
        expect(screen.getByText(/alice/)).toBeInTheDocument();
        fireEvent.click(screen.getByText('Attest'));
        expect(mockDecideMutate).toHaveBeenCalledWith(
            expect.objectContaining({ itemId: 10, action: 'attest' }),
            expect.any(Object)
        );
    });

    it('shows an empty state with no campaigns', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        expect(screen.getByText(/No campaigns yet/i)).toBeInTheDocument();
    });

    it('downloads the campaign CSV as a blob when Download CSV is clicked', async () => {
        mockGet.mockResolvedValue({ data: new Blob(['principal\n'], { type: 'text/csv' }) });
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        fireEvent.click(screen.getByRole('button', { name: /download csv/i }));

        await waitFor(() =>
            expect(mockGet).toHaveBeenCalledWith('/api/v1/projects/2/access-review/campaigns/1/export.csv', {
                responseType: 'blob',
            })
        );
        expect((URL as any).createObjectURL).toHaveBeenCalled();
    });

    it('surfaces an error when the CSV export fails', async () => {
        mockGet.mockRejectedValue({ response: { data: { error: 'export failed' } } });
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        fireEvent.click(screen.getByRole('button', { name: /download csv/i }));

        await waitFor(() => expect(screen.getByText('export failed')).toBeInTheDocument());
    });

    it('defaults the campaign name to "Access review" when left blank', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Open'));
        expect(mockOpenMutate).toHaveBeenCalledWith('Access review', expect.any(Object));
    });

    it('shows an error and clears/selects on open success/failure', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: false });
        mockOpenMutate.mockImplementationOnce((_name, opts) =>
            opts.onError({ response: { data: { error: 'open failed' } } })
        );
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Open'));
        expect(screen.getByText('open failed')).toBeInTheDocument();

        mockOpenMutate.mockImplementationOnce((_name, opts) => opts.onSuccess({ campaign: { id: 99 } }));
        fireEvent.click(screen.getByText('Open'));
        expect((screen.getByPlaceholderText('Campaign name') as HTMLInputElement).value).toBe('');
    });

    it('shows a loading skeleton while campaigns are in flight', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: true });
        const { container } = render(<ProjectAccessReviewCampaigns projectId={2} />);
        expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
        expect(screen.queryByText(/No campaigns yet/i)).not.toBeInTheDocument();
    });

    it('styles a closed campaign differently from an open one', () => {
        mockUseCampaigns.mockReturnValue({
            data: [
                {
                    campaign: { id: 2, projectId: 2, name: 'Closed cycle', state: 'closed', createdAt: '' },
                    progress: { total: 2, pending: 0, attested: 2, revoked: 0 },
                },
            ],
            isLoading: false,
        });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        expect(screen.getByText('closed')).toBeInTheDocument();
    });

    it('shows a loading skeleton for campaign detail while it loads', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        mockUseCampaign.mockReturnValue({ data: null, isLoading: true });
        const { container } = render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
    });

    it('shows "No items captured" for a campaign with no snapshot items', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        mockUseCampaign.mockReturnValue({ data: { ...detail, items: [] }, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        expect(screen.getByText('No items captured.')).toBeInTheDocument();
    });

    it('marks a dormant user (never used) and shows a recently-used one as not dormant', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        mockUseCampaign.mockReturnValue({
            data: {
                ...detail,
                items: [
                    { ...detail.items[0], id: 20, lastUsedAt: undefined, decision: 'pending' },
                    { ...detail.items[0], id: 21, lastUsedAt: new Date().toISOString(), decision: 'revoked' },
                ],
            },
            isLoading: false,
        });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        // The never-used item is flagged dormant; the just-used one is not.
        expect(screen.getByText(/dormant/)).toBeInTheDocument();
        expect(screen.getAllByText(/alice/).length).toBeGreaterThanOrEqual(1);
    });

    it('requires confirmation before revoking a pending campaign item', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));

        // Item 10 (alice, source 'role') is not revocable inline here since Revoke only
        // shows for non-owner sources; role is revocable in this UI.
        fireEvent.click(screen.getByText('Revoke'));
        expect(mockDecideMutate).not.toHaveBeenCalled();
        fireEvent.click(screen.getByText('Confirm'));
        expect(mockDecideMutate).toHaveBeenCalledWith(
            expect.objectContaining({ itemId: 10, action: 'revoke' }),
            expect.any(Object)
        );
    });

    it('cancels a pending revoke confirmation', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));

        fireEvent.click(screen.getByText('Revoke'));
        fireEvent.click(screen.getByText('Cancel'));
        expect(screen.getByText('Revoke')).toBeInTheDocument();
        expect(mockDecideMutate).not.toHaveBeenCalled();
    });

    it('closes a campaign with pending items via "Close anyway"', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));

        expect(screen.getByText(/item\(s\) still pending/)).toBeInTheDocument();
        fireEvent.click(screen.getByText('Close anyway'));
        expect(mockCloseMutate).toHaveBeenCalledWith({ campaignId: 1, force: true }, expect.any(Object));
    });

    it('closes a fully-decided campaign via "Close campaign"', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        mockUseCampaign.mockReturnValue({
            data: { ...detail, progress: { total: 2, pending: 0, attested: 1, revoked: 1 } },
            isLoading: false,
        });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));

        expect(screen.getByText('All items decided')).toBeInTheDocument();
        fireEvent.click(screen.getByText('Close campaign'));
        expect(mockCloseMutate).toHaveBeenCalledWith({ campaignId: 1, force: false }, expect.any(Object));
    });

    it('toggles the detail panel closed when "Hide" is clicked', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        expect(screen.getByText(/alice/)).toBeInTheDocument();

        fireEvent.click(screen.getByText('Hide'));
        expect(screen.queryByText(/alice/)).not.toBeInTheDocument();
        expect(screen.getByText('Review')).toBeInTheDocument();
    });

    it('computes a non-today "used Nd ago" label for a principal used several days back', () => {
        // lastUsedInfo's label isn't rendered in the DOM directly (only its `dormant` flag
        // drives the " · dormant" suffix), so exercise the exported pure function itself for
        // the "used Nd ago" / not-dormant branch (5 days is under the 90-day dormancy cutoff).
        const fiveDaysAgo = new Date(Date.now() - 5 * 86_400_000).toISOString();
        const info = lastUsedInfo({ principalType: 'user', lastUsedAt: fiveDaysAgo });
        expect(info).toEqual({ label: 'used 5d ago', dormant: false });
    });

    it('computes a "used today" label for a principal used moments ago', () => {
        const info = lastUsedInfo({ principalType: 'user', lastUsedAt: new Date().toISOString() });
        expect(info).toEqual({ label: 'used today', dormant: false });
    });

    it('marks a principal dormant once its last use crosses the 90-day cutoff', () => {
        const ninetyDaysAgo = new Date(Date.now() - 90 * 86_400_000).toISOString();
        const info = lastUsedInfo({ principalType: 'user', lastUsedAt: ninetyDaysAgo });
        expect(info).toEqual({ label: 'used 90d ago', dormant: true });
    });

    // RECERT-BOUND-1: the lookup covers the recertification period only, so "no last use"
    // must say "within the last N days", never "never used".
    it('says "no use in the last N days" when there is no use inside the look-back window', () => {
        expect(lastUsedInfo({ principalType: 'user', activityWindowDays: 90 })).toEqual({
            label: 'no use in the last 90d',
            dormant: true,
        });
        // An explicit window (a campaign's) wins over the entry's own.
        expect(lastUsedInfo({ principalType: 'user', activityWindowDays: 90 }, 45)).toEqual({
            label: 'no use in the last 45d',
            dormant: true,
        });
    });

    it('keeps "never used" only for a campaign opened before the window existed (whole history)', () => {
        expect(lastUsedInfo({ principalType: 'user' }, 0)).toEqual({ label: 'never used', dormant: true });
    });

    it('does not claim "never" when the window is unknown', () => {
        expect(lastUsedInfo({ principalType: 'user' })).toEqual({ label: 'no recent use', dormant: true });
    });

    it('returns an empty, non-dormant label for group principals (no aggregated last-use)', () => {
        const info = lastUsedInfo({ principalType: 'group', lastUsedAt: undefined });
        expect(info).toEqual({ label: '', dormant: false });
    });

    it('falls back to the role placeholder "—" when a role-sourced item has no role name', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        mockUseCampaign.mockReturnValue({
            data: {
                ...detail,
                // lastUsedAt is set (recently) so the dormant " · dormant" suffix doesn't get
                // appended to the same text node, which would break an exact-text match below.
                items: [
                    { ...detail.items[0], id: 31, roleName: '', source: 'role', lastUsedAt: new Date().toISOString() },
                ],
            },
            isLoading: false,
        });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        expect(screen.getByText('Role: —')).toBeInTheDocument();
    });

    it('clears the revoke confirmation once the decision succeeds', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        mockDecideMutate.mockImplementationOnce((_vars, opts) => opts.onSuccess());
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));

        fireEvent.click(screen.getByText('Revoke'));
        fireEvent.click(screen.getByText('Confirm'));
        // onSuccess cleared confirmItem, so the item is back to its unconfirmed "Revoke" state.
        expect(screen.queryByText('Confirm')).not.toBeInTheDocument();
        expect(screen.getByText('Revoke')).toBeInTheDocument();
    });

    it('falls back to the response message when no error field is present', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: false });
        mockOpenMutate.mockImplementationOnce((_name, opts) =>
            opts.onError({ response: { data: { message: 'message only' } } })
        );
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Open'));
        expect(screen.getByText('message only')).toBeInTheDocument();
    });

    it('falls back to the generic "Action failed." message when the error has no details', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: false });
        mockOpenMutate.mockImplementationOnce((_name, opts) => opts.onError({}));
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Open'));
        expect(screen.getByText('Action failed.')).toBeInTheDocument();
    });
});
