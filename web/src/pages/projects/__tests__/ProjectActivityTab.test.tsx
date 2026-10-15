import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within, fireEvent } from '../../../test/test-utils';
import { ProjectActivityTab } from '../ProjectActivityTab';

const useAuditLog = vi.fn();

// The tab reads the load-more feed; toFeed adapts the page-shaped mock below.
function toFeed(r: any) {
    return {
        entries: r?.data?.data ?? [],
        total: r?.data?.total,
        totalExact: true,
        isLoading: r?.isLoading ?? false,
        isError: r?.isError ?? false,
        error: null,
        hasNextPage: r?.hasNextPage ?? false,
        isFetchingNextPage: false,
        fetchNextPage: r?.fetchNextPage ?? (() => undefined),
    };
}

vi.mock('../../../features/audit/api', () => ({
    useAuditLogFeed: (...args: any[]) => toFeed(useAuditLog(...args)),
}));

const events = [
    {
        id: 1,
        event_type: 'secret.created',
        actor: 'alice',
        actor_type: 'user',
        description: 'Created secret db-password',
        timestamp: '2026-01-01T10:00:00Z',
    },
    {
        id: 2,
        event_type: 'secret.deleted',
        actor: '',
        actor_type: 'user',
        description: '',
        timestamp: '2026-01-01T09:00:00Z',
    },
    {
        id: 3,
        event_type: 'unmapped.event',
        actor: 'bob',
        actor_type: 'user',
        description: 'Something not in the badge map',
        timestamp: '2026-01-01T08:00:00Z',
    },
];

function mockAuditLog(
    overrides: Partial<{
        data: typeof events;
        hasNextPage: boolean;
        fetchNextPage: () => void;
        isLoading: boolean;
        isError: boolean;
    }> = {}
) {
    useAuditLog.mockReturnValue({
        data: {
            data: overrides.data ?? events,
            total: (overrides.data ?? events).length,
        },
        hasNextPage: overrides.hasNextPage ?? false,
        fetchNextPage: overrides.fetchNextPage,
        isLoading: overrides.isLoading ?? false,
        isError: overrides.isError ?? false,
    });
}

beforeEach(() => {
    vi.clearAllMocks();
    mockAuditLog();
    window.history.pushState({}, '', '/');
});

describe('ProjectActivityTab', () => {
    it('requests the audit log scoped to the given project', () => {
        render(<ProjectActivityTab projectId={42} />);
        expect(useAuditLog).toHaveBeenCalledWith({ projectId: 42, pageSize: 25 });
    });

    it('shows a loading skeleton while the query is in flight', () => {
        mockAuditLog({ isLoading: true });
        const { container } = render(<ProjectActivityTab projectId={1} />);

        expect(container.querySelectorAll('.animate-pulse')).toHaveLength(5);
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });

    it('shows an error message when the query fails', () => {
        mockAuditLog({ isError: true });
        render(<ProjectActivityTab projectId={1} />);

        expect(screen.getByText('Failed to load activity.')).toBeInTheDocument();
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });

    it('shows an empty state when there are no events', () => {
        mockAuditLog({ data: [] });
        render(<ProjectActivityTab projectId={1} />);

        expect(screen.getByText('No activity yet')).toBeInTheDocument();
        expect(screen.getByText(/Events will appear here/)).toBeInTheDocument();
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });

    it('renders a row per event with its badge, actor, and description', () => {
        render(<ProjectActivityTab projectId={1} />);
        const table = within(screen.getByRole('table'));

        expect(table.getByText('Created')).toBeInTheDocument();
        expect(table.getByText('alice')).toBeInTheDocument();
        expect(table.getByText('Created secret db-password')).toBeInTheDocument();
        expect(table.getByText('bob')).toBeInTheDocument();
    });

    it('falls back to an em dash for a missing actor or description', () => {
        render(<ProjectActivityTab projectId={1} />);
        const table = within(screen.getByRole('table'));

        // Event #2 has empty actor and description — both cells fall back to '—'.
        expect(table.getAllByText('—')).toHaveLength(2);
    });

    it('colors a mapped event type with its badge style and falls back for unmapped types', () => {
        render(<ProjectActivityTab projectId={1} />);
        const table = within(screen.getByRole('table'));

        const mappedBadge = table.getByText('Created');
        expect(mappedBadge).toHaveStyle({ backgroundColor: 'var(--success-subtle)', color: 'var(--success)' });

        const unmappedBadge = table.getByText('Unmapped event');
        expect(unmappedBadge).toHaveStyle({ backgroundColor: 'var(--bg-muted)', color: 'var(--text-secondary)' });
    });

    it('formats event timestamps as relative time, bucketed by how long ago they occurred', () => {
        // Mirrors the `formatRelativeTime` test convention in src/utils/__tests__/utils.test.ts:
        // derive timestamps from the real clock rather than faking system time.
        const ago = (ms: number) => new Date(Date.now() - ms).toISOString();
        mockAuditLog({
            data: [
                { ...events[0], id: 1, timestamp: ago(5_000) }, // just now
                { ...events[0], id: 2, timestamp: ago(2 * 60_000) }, // 2m ago
                { ...events[0], id: 3, timestamp: ago(3 * 3_600_000) }, // 3h ago
                { ...events[0], id: 4, timestamp: ago(5 * 86_400_000) }, // >24h -> locale short date
            ],
        });
        render(<ProjectActivityTab projectId={1} />);
        const table = within(screen.getByRole('table'));

        expect(table.getByText('just now')).toBeInTheDocument();
        expect(table.getByText('2m ago')).toBeInTheDocument();
        expect(table.getByText('3h ago')).toBeInTheDocument();
        // Day-format branch: assert the shape (day + short month, either order, e.g. "Jul 27"
        // or "27 Jul") rather than an exact string — both the day-of-month and the ordering
        // depend on the test machine's locale/timezone, only the >=24h bucketing is under test.
        // Month-abbreviation length also depends on locale/ICU data: most short-form months
        // are 3 letters ("Jul", "Oct"), but some locales render September as 4 ("Sept") --
        // confirmed failing for real on this exact date (5 days back lands in September) before
        // widening {2} to {2,3}, not a hypothetical.
        expect(table.getByText(/^[A-Z][a-z]{2} \d{1,2}, \d{4}, \d{1,2}:\d{2}\s?[AP]M [A-Z]/)).toBeInTheDocument();
    });

    it('hides "Load more" on the last page', () => {
        render(<ProjectActivityTab projectId={1} />);
        expect(screen.getByTestId('audit-loaded-count')).toHaveTextContent('Showing 3 of 3 events');
        expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
    });

    it('falls back to empty events when data is undefined', () => {
        useAuditLog.mockReturnValue({ data: undefined, isLoading: false, isError: false });
        render(<ProjectActivityTab projectId={1} />);

        expect(screen.getByText('No activity yet')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
    });

    it('loads the next page of the project feed on "Load more"', () => {
        const fetchNextPage = vi.fn();
        mockAuditLog({ hasNextPage: true, fetchNextPage });
        render(<ProjectActivityTab projectId={7} />);

        fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
        expect(fetchNextPage).toHaveBeenCalledTimes(1);
        expect(useAuditLog).toHaveBeenLastCalledWith({ projectId: 7, pageSize: 25 });
    });
});
