import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { AuditLogPage } from '../AuditLogPage';
import { useUIStore } from '../../../store/uiStore';
import { XSS_PAYLOADS, assertPayloadRenderedSafely } from '../../../test/xss-payloads';

const useAuditLog = vi.fn();
const useAnomalyAlerts = vi.fn();
const acknowledgeMutate = vi.fn();
const useRoles = vi.fn();
const useGroups = vi.fn();
const apiClientGet = vi.fn();

vi.mock('../../../features/audit', () => ({
    useAuditLog: (...args: any[]) => useAuditLog(...args),
}));

vi.mock('../../../features/dashboard', () => ({
    useAnomalyAlerts: (...args: any[]) => useAnomalyAlerts(...args),
    useAcknowledgeAnomaly: () => ({ mutate: acknowledgeMutate }),
}));

vi.mock('../../../features/admin', () => ({
    useRoles: (...args: any[]) => useRoles(...args),
    useGroups: (...args: any[]) => useGroups(...args),
}));

vi.mock('../../../services/client', () => ({
    apiClient: { get: (...args: any[]) => apiClientGet(...args) },
    apiErrorMessage: (_e: unknown, fallback: string) => fallback,
}));

const entries = [
    {
        id: 1,
        event_type: 'auth.login',
        actor: 'alice',
        actor_type: 'user',
        description: 'Logged in',
        timestamp: '2026-01-01T10:00:00Z',
    },
    {
        id: 2,
        event_type: 'secret.read',
        actor: 'bob',
        actor_type: 'user',
        description: 'Read a secret',
        timestamp: '2026-01-10T10:00:00Z',
    },
    {
        id: 3,
        event_type: 'role.assigned',
        actor: 'ci-bot',
        actor_type: 'machine_identity',
        description: 'Assigned role admin',
        timestamp: '2026-01-15T10:00:00Z',
    },
];

function mockAuditLog(
    overrides: Partial<{ isLoading: boolean; error: unknown; total: number; page: number; totalPages: number }> = {}
) {
    useAuditLog.mockReturnValue({
        data: {
            data: entries,
            total: overrides.total ?? entries.length,
            page: overrides.page ?? 1,
            pageSize: 100,
            totalPages: overrides.totalPages ?? 1,
        },
        isLoading: overrides.isLoading ?? false,
        error: overrides.error ?? null,
    });
}

function mockAnomalies(alerts: any[] = [], isLoading = false) {
    useAnomalyAlerts.mockReturnValue({ data: { data: { alerts } }, isLoading });
}

const initialTheme = useUIStore.getState().theme;

beforeEach(() => {
    vi.clearAllMocks();
    mockAuditLog();
    mockAnomalies();
    useRoles.mockReturnValue({ data: [] });
    useGroups.mockReturnValue({ data: { groups: [], total: 0 } });
    apiClientGet.mockResolvedValue({ data: { data: { users: [] } } });
    window.history.pushState({}, '', '/');
});

afterEach(() => {
    useUIStore.setState({ theme: initialTheme });
});

describe('AuditLogPage — audit tab', () => {
    it('renders every entry with its event badge and total count', () => {
        render(<AuditLogPage />);
        expect(
            screen.getByText('Complete record of all secret access and system events', { exact: false })
        ).toBeInTheDocument();
        expect(screen.getByText('3 events')).toBeInTheDocument();

        // Scope to the table: "Login" also appears as an <option> in the event-type filter.
        const table = within(screen.getByRole('table'));
        expect(table.getByText('Login')).toBeInTheDocument();
        expect(table.getByText('Read')).toBeInTheDocument();
        expect(table.getByText('alice')).toBeInTheDocument();
        expect(table.getByText('bob')).toBeInTheDocument();
        expect(table.getByText('machine')).toBeInTheDocument(); // ci-bot's machine badge
    });

    it('filters by actor', () => {
        render(<AuditLogPage />);
        fireEvent.change(screen.getByPlaceholderText('Filter by actor…'), { target: { value: 'alice' } });

        expect(screen.getByText('alice')).toBeInTheDocument();
        expect(screen.queryByText('bob')).not.toBeInTheDocument();
        expect(screen.getByText('1 event')).toBeInTheDocument();
    });

    it('filters by event type', () => {
        render(<AuditLogPage />);
        fireEvent.change(screen.getByLabelText('Filter by event type'), { target: { value: 'secret.read' } });

        expect(screen.getByText('bob')).toBeInTheDocument();
        expect(screen.queryByText('alice')).not.toBeInTheDocument();
    });

    it('labels secret.versions_listed, offers it as a filter, and keeps it out of the "reads" view', () => {
        useAuditLog.mockReturnValue({
            data: {
                data: [
                    ...entries,
                    {
                        id: 4,
                        event_type: 'secret.versions_listed',
                        actor: 'dave',
                        actor_type: 'user',
                        description: 'User dave listed the versions of secret db',
                        timestamp: '2026-01-16T10:00:00Z',
                    },
                ],
                total: 4,
                page: 1,
                pageSize: 100,
                totalPages: 1,
            },
            isLoading: false,
            error: null,
        });
        render(<AuditLogPage />);
        const table = within(screen.getByRole('table'));
        expect(table.getByText('Versions listed')).toBeInTheDocument();
        expect(table.queryByText('versions listed')).not.toBeInTheDocument();

        fireEvent.change(screen.getByLabelText('Filter by event type'), {
            target: { value: 'secret.versions_listed' },
        });
        expect(screen.getByText('dave')).toBeInTheDocument();
        expect(screen.queryByText('bob')).not.toBeInTheDocument();
    });

    it('labels secret.metadata_read and offers it as a filter', () => {
        useAuditLog.mockReturnValue({
            data: {
                data: [
                    ...entries,
                    {
                        id: 5,
                        event_type: 'secret.metadata_read',
                        actor: 'erin',
                        actor_type: 'user',
                        description: 'User erin looked up secret db',
                        timestamp: '2026-01-16T10:00:00Z',
                    },
                ],
                total: 4,
                page: 1,
                pageSize: 100,
                totalPages: 1,
            },
            isLoading: false,
            error: null,
        });
        render(<AuditLogPage />);
        expect(within(screen.getByRole('table')).getByText('Metadata read')).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText('Filter by event type'), {
            target: { value: 'secret.metadata_read' },
        });
        expect(screen.getByText('erin')).toBeInTheDocument();
        expect(screen.queryByText('bob')).not.toBeInTheDocument();
    });

    it('filters by actor type', () => {
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Machine' }));

        expect(screen.getByText('ci-bot')).toBeInTheDocument();
        expect(screen.queryByText('alice')).not.toBeInTheDocument();
    });

    it('filters by date range', () => {
        render(<AuditLogPage />);
        fireEvent.change(screen.getByLabelText('From date'), { target: { value: '2026-01-05' } });

        expect(screen.queryByText('alice')).not.toBeInTheDocument(); // Jan 1, before the range
        expect(screen.getByText('bob')).toBeInTheDocument(); // Jan 10
    });

    it('shows an error alert when the query fails', () => {
        mockAuditLog({ error: new Error('network down') });
        render(<AuditLogPage />);
        expect(screen.getByText('Failed to load audit log')).toBeInTheDocument();
    });

    it('exports the currently filtered entries as CSV', () => {
        (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
        (URL as any).revokeObjectURL = vi.fn();
        const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        render(<AuditLogPage />);
        fireEvent.click(screen.getByTitle('Export as CSV'));

        expect(URL.createObjectURL).toHaveBeenCalled();
        expect(clickSpy).toHaveBeenCalled();
        clickSpy.mockRestore();
    });

    // CWE-1236 (CSV/formula injection): a username has no character-set restriction
    // beyond length (internal/core/users.go's validateUsernameFormat), and
    // internal/core/impersonation.go's audit description embeds a username with no
    // fixed literal prefix -- so `actor` and `description` can both legitimately start
    // with =, +, -, or @. The backend's own CSV export (audit_export_csv.go) already
    // neutralizes this via csvSafe; this proves the frontend's independent CSV builder
    // does too, since it doesn't call that endpoint.
    it('neutralizes formula-injection and properly quotes CSV-special characters on export', async () => {
        useAuditLog.mockReturnValue({
            data: {
                data: [
                    {
                        id: 1,
                        event_type: 'impersonation.start',
                        actor: "=cmd|'/c calc'!A0",
                        actor_type: 'user',
                        description: '@SUM(1+1), with a comma and a "quote"',
                        timestamp: '2026-01-01T10:00:00Z',
                    },
                ],
                total: 1,
                page: 1,
                pageSize: 100,
                totalPages: 1,
            },
            isLoading: false,
            error: null,
        });

        let capturedBlob: Blob | undefined;
        (URL as any).createObjectURL = vi.fn((b: Blob) => {
            capturedBlob = b;
            return 'blob:mock';
        });
        (URL as any).revokeObjectURL = vi.fn();
        const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        render(<AuditLogPage />);
        fireEvent.click(screen.getByTitle('Export as CSV'));

        expect(capturedBlob).toBeDefined();
        const csvText = await capturedBlob!.text();
        const [, dataRow] = csvText.split('\n');

        // The actor cell must not put a raw '=' as the first character of its cell --
        // csvSafe-style neutralization prefixes it with a leading quote first.
        expect(dataRow.startsWith("2026-01-01T10:00:00.000Z,impersonation.start,'=cmd")).toBe(true);
        // The description cell contains a comma and a double-quote, so proper CSV
        // quoting must wrap it in quotes with internal quotes doubled, AND it must
        // still carry the formula-injection prefix since it starts with '@'.
        expect(dataRow).toContain('"\'@SUM(1+1), with a comma and a ""quote"""');
        clickSpy.mockRestore();
    });
});

describe('AuditLogPage — url filter banner', () => {
    it('shows the banner for a known filter and clears it', () => {
        window.history.pushState({}, '', '/audit?filter=logins');
        render(<AuditLogPage />);

        expect(screen.getByText('Filtered:')).toBeInTheDocument();
        expect(screen.getByText('Login events')).toBeInTheDocument();

        fireEvent.click(screen.getByText('✕ Clear filter'));
        expect(window.location.search).toBe('?tab=audit');
    });
});

describe('AuditLogPage — RBAC tab', () => {
    it('shows the governance banner and only rbac.* events', () => {
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: 'RBAC Events' }));

        expect(screen.getByText('Access governance events')).toBeInTheDocument();
        expect(screen.getByText('ci-bot')).toBeInTheDocument();
        expect(screen.queryByText('alice')).not.toBeInTheDocument();
    });

    it('resolves role/group/user ids to names in RBAC descriptions, leaving unresolved ids untouched', async () => {
        useAuditLog.mockReturnValue({
            data: {
                data: [
                    {
                        id: 1,
                        event_type: 'role.removed',
                        actor: 'admin',
                        actor_type: 'user',
                        description: 'role 9 removed from user 7',
                        timestamp: '2026-01-15T10:00:00Z',
                    },
                    {
                        id: 2,
                        event_type: 'group.member_added',
                        actor: 'admin',
                        actor_type: 'user',
                        description: 'user 7 added to group 3',
                        timestamp: '2026-01-16T10:00:00Z',
                    },
                    {
                        id: 3,
                        event_type: 'role.assigned',
                        actor: 'admin',
                        actor_type: 'user',
                        description: 'role 999 assigned to user 7',
                        timestamp: '2026-01-17T10:00:00Z',
                    },
                ],
                total: 3,
                page: 1,
                pageSize: 100,
                totalPages: 1,
            },
            isLoading: false,
            error: null,
        });
        useRoles.mockReturnValue({ data: [{ id: 9, name: 'project_viewer' }] });
        useGroups.mockReturnValue({ data: { groups: [{ id: 3, name: 'platform-team' }], total: 1 } });
        apiClientGet.mockResolvedValue({
            data: { data: { users: [{ id: 7, displayName: 'Frank OBrien', email: 'frank@example.com' }] } },
        });

        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: 'RBAC Events' }));

        expect(await screen.findByText('project_viewer removed from Frank OBrien')).toBeInTheDocument();
        expect(screen.getByText('Frank OBrien added to platform-team')).toBeInTheDocument();
        // id 999 has no matching role — the raw token is left untouched, not blanked.
        expect(screen.getByText('role 999 assigned to Frank OBrien')).toBeInTheDocument();
    });

    it('does not rewrite ids in non-RBAC event descriptions', () => {
        useAuditLog.mockReturnValue({
            data: {
                data: [
                    {
                        id: 1,
                        event_type: 'secret.read',
                        actor: 'bob',
                        actor_type: 'user',
                        description: 'read secret 9 in project 7',
                        timestamp: '2026-01-15T10:00:00Z',
                    },
                ],
                total: 1,
                page: 1,
                pageSize: 100,
                totalPages: 1,
            },
            isLoading: false,
            error: null,
        });
        useRoles.mockReturnValue({ data: [{ id: 9, name: 'project_viewer' }] });

        render(<AuditLogPage />);
        expect(screen.getByText('read secret 9 in project 7')).toBeInTheDocument();
    });
});

describe('AuditLogPage — Anomaly Alerts tab', () => {
    const alert = {
        ID: 1,
        AlertType: 'unusual_access_time',
        SecretName: 'db-password',
        AccessedBy: 'alice',
        IPAddress: '10.0.0.1',
        Severity: 'high',
        DetectedAt: '2026-01-01T00:00:00Z',
        Acknowledged: false,
        Description: 'Accessed outside business hours',
    };

    it('shows an unacknowledged-count badge on the tab', () => {
        mockAnomalies([alert]);
        render(<AuditLogPage />);
        const anomaliesTab = screen.getByRole('button', { name: /anomaly alerts/i });
        expect(within(anomaliesTab).getByText('1')).toBeInTheDocument();
    });

    it('lists alerts, expands details, and dismisses (acknowledges) one', () => {
        mockAnomalies([alert]);
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: /anomaly alerts/i }));

        expect(screen.getByText('db-password')).toBeInTheDocument();
        expect(screen.getByText('Unusual Access Time')).toBeInTheDocument();

        fireEvent.click(screen.getByText('db-password'));
        expect(screen.getByText('Accessed outside business hours')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
        expect(acknowledgeMutate).toHaveBeenCalledWith(1);
    });

    it('shows an empty state when there are no anomalies', () => {
        mockAnomalies([]);
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: /anomaly alerts/i }));
        expect(screen.getByText('No anomalies detected')).toBeInTheDocument();
    });

    it('shows a spinner while anomalies are loading', () => {
        mockAnomalies([], true);
        const { container } = render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: /anomaly alerts/i }));
        expect(container.querySelector('svg.animate-spin')).toBeInTheDocument();
    });
});

describe('AuditLogPage — initial tab from URL', () => {
    it('opens directly on the anomalies tab when ?tab=anomalies', () => {
        window.history.pushState({}, '', '/audit?tab=anomalies');
        mockAnomalies([]);
        render(<AuditLogPage />);
        expect(screen.getByText('No anomalies detected')).toBeInTheDocument();
    });

    it('opens directly on the rbac tab when ?tab=rbac', () => {
        window.history.pushState({}, '', '/audit?tab=rbac');
        render(<AuditLogPage />);
        expect(screen.getByText('Access governance events')).toBeInTheDocument();
    });
});

describe('AuditLogPage — unmapped event types, missing fields, and invalid timestamps', () => {
    it('falls back to the raw event type and badge, and shows the raw string for an invalid timestamp', () => {
        useAuditLog.mockReturnValue({
            data: {
                data: [
                    {
                        id: 10,
                        event_type: 'custom.unmapped',
                        actor: 'zed',
                        actor_type: 'user',
                        description: 'something odd',
                        timestamp: '2026-01-20T10:00:00Z',
                    },
                    {
                        id: 11,
                        event_type: 'auth.login',
                        actor: 'mallory',
                        actor_type: 'user',
                        description: 'weird time',
                        timestamp: 'not-a-real-date',
                    },
                ],
                total: 2,
                page: 1,
                pageSize: 100,
                totalPages: 1,
            },
            isLoading: false,
            error: null,
        });

        render(<AuditLogPage />);

        const table = within(screen.getByRole('table'));
        expect(table.getByText('Custom unmapped')).toBeInTheDocument();
        expect(table.getByText('not-a-real-date')).toBeInTheDocument();
    });

    it('omits missing actor_type/description fields when exporting CSV', () => {
        useAuditLog.mockReturnValue({
            data: {
                data: [
                    {
                        id: 12,
                        event_type: 'custom.unmapped',
                        actor: 'zed',
                        actor_type: undefined,
                        description: undefined,
                        timestamp: '2026-01-20T10:00:00Z',
                    },
                ],
                total: 1,
                page: 1,
                pageSize: 100,
                totalPages: 1,
            },
            isLoading: false,
            error: null,
        });

        (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
        (URL as any).revokeObjectURL = vi.fn();
        const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        render(<AuditLogPage />);
        fireEvent.click(screen.getByTitle('Export as CSV'));

        expect(URL.createObjectURL).toHaveBeenCalled();
        expect(clickSpy).toHaveBeenCalled();
        clickSpy.mockRestore();
    });
});

describe('AuditLogPage — loading and empty states', () => {
    it('shows a spinner while the audit log is loading', () => {
        mockAuditLog({ isLoading: true });
        const { container } = render(<AuditLogPage />);
        expect(container.querySelector('svg.animate-spin')).toBeInTheDocument();
    });

    it('shows the empty-state message when there are no entries at all', () => {
        useAuditLog.mockReturnValue({
            data: { data: [], total: 0, page: 1, pageSize: 100, totalPages: 1 },
            isLoading: false,
            error: null,
        });
        render(<AuditLogPage />);
        expect(screen.getByText('No audit events match the current filters.')).toBeInTheDocument();
        expect(screen.getByText('0 events')).toBeInTheDocument();
    });

    it('renders sensible defaults when the audit log data is undefined', () => {
        useAuditLog.mockReturnValue({ data: undefined, isLoading: false, error: null });
        render(<AuditLogPage />);
        expect(screen.getByText('No audit events match the current filters.')).toBeInTheDocument();
        expect(
            screen.getByText('Complete record of all secret access and system events', { exact: false })
        ).toBeInTheDocument();
    });

    it('handles missing anomaly data gracefully', () => {
        useAnomalyAlerts.mockReturnValue({ data: undefined, isLoading: false });
        render(<AuditLogPage />);
        const anomaliesTab = screen.getByRole('button', { name: /anomaly alerts/i });
        expect(within(anomaliesTab).queryByText(/^\d+$/)).not.toBeInTheDocument();
    });
});

describe('AuditLogPage — pagination', () => {
    it('shows the range and navigates between pages', () => {
        mockAuditLog({ total: 250, page: 2, totalPages: 3 });
        render(<AuditLogPage />);

        expect(screen.getByText('101–200 of 250')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: '← Prev' }));
        expect(useAuditLog).toHaveBeenLastCalledWith({ page: 1, pageSize: 100 });

        fireEvent.click(screen.getByRole('button', { name: 'Next →' }));
        expect(useAuditLog).toHaveBeenLastCalledWith({ page: 3, pageSize: 100 });
    });
});

describe('AuditLogPage — theme variants', () => {
    it('renders event and anomaly badges correctly in light theme', () => {
        useUIStore.setState({ theme: 'light' });
        mockAnomalies([
            {
                ID: 1,
                AlertType: 'unusual_access_time',
                SecretName: 'db-password',
                AccessedBy: 'alice',
                IPAddress: '10.0.0.1',
                Severity: 'high',
                DetectedAt: '2026-01-01T00:00:00Z',
                Acknowledged: false,
                Description: 'Accessed outside business hours',
            },
        ]);
        render(<AuditLogPage />);
        expect(screen.getByText('alice')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /anomaly alerts/i }));
        expect(screen.getByText('db-password')).toBeInTheDocument();
        fireEvent.click(screen.getByText('db-password'));
        expect(screen.getByText('Accessed outside business hours')).toBeInTheDocument();
    });

    it('renders correctly in system theme', () => {
        useUIStore.setState({ theme: 'system' });
        render(<AuditLogPage />);
        expect(screen.getByText('alice')).toBeInTheDocument();
    });

    it('applies default severity styling in light theme for an unrecognized severity value', () => {
        useUIStore.setState({ theme: 'light' });
        mockAnomalies([
            {
                ID: 5,
                AlertType: 'geo_anomaly',
                SecretName: 'mystery-key',
                AccessedBy: 'zoe',
                IPAddress: '10.0.0.9',
                Severity: 'unmapped',
                DetectedAt: '2026-01-05T00:00:00Z',
                Acknowledged: false,
                Description: '',
            },
        ]);
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: /anomaly alerts/i }));
        expect(screen.getByText('mystery-key')).toBeInTheDocument();
    });
});

describe('AuditLogPage — URL filters', () => {
    const mixedEntries = [
        {
            id: 1,
            event_type: 'auth.login_failed',
            actor: 'attacker',
            actor_type: 'user',
            description: 'Bad password',
            timestamp: '2026-01-01T10:00:00Z',
        },
        {
            id: 2,
            event_type: 'secret.read',
            actor: 'bob',
            actor_type: 'user',
            description: 'Read a secret',
            timestamp: '2026-01-02T10:00:00Z',
        },
        {
            id: 3,
            event_type: 'auth.login',
            actor: 'alice',
            actor_type: 'user',
            description: 'Logged in',
            timestamp: '2026-01-03T10:00:00Z',
        },
    ];

    function mockMixedEntries() {
        useAuditLog.mockReturnValue({
            data: { data: mixedEntries, total: mixedEntries.length, page: 1, pageSize: 100, totalPages: 1 },
            isLoading: false,
            error: null,
        });
    }

    it('shows only failed-login events for ?filter=failed', () => {
        mockMixedEntries();
        window.history.pushState({}, '', '/audit?filter=failed');
        render(<AuditLogPage />);
        expect(screen.getByText('attacker')).toBeInTheDocument();
        expect(screen.queryByText('bob')).not.toBeInTheDocument();
        expect(screen.queryByText('alice')).not.toBeInTheDocument();
    });

    it('shows only secret-read events for ?filter=reads', () => {
        mockMixedEntries();
        window.history.pushState({}, '', '/audit?filter=reads');
        render(<AuditLogPage />);
        expect(screen.getByText('bob')).toBeInTheDocument();
        expect(screen.queryByText('attacker')).not.toBeInTheDocument();
        expect(screen.queryByText('alice')).not.toBeInTheDocument();
    });

    it('shows a generic "Custom filter" label for an unrecognized filter value', () => {
        window.history.pushState({}, '', '/audit?filter=something-else');
        render(<AuditLogPage />);
        expect(screen.getByText('Custom filter')).toBeInTheDocument();
    });
});

describe('AuditLogPage — date-to filter', () => {
    it('excludes entries after the "to" date', () => {
        render(<AuditLogPage />);
        fireEvent.change(screen.getByLabelText('To date'), { target: { value: '2026-01-05' } });

        expect(screen.getByText('alice')).toBeInTheDocument(); // Jan 1, within range
        expect(screen.queryByText('bob')).not.toBeInTheDocument(); // Jan 10, after range
        expect(screen.queryByText('ci-bot')).not.toBeInTheDocument(); // Jan 15, after range
    });
});

describe('AuditLogPage — RBAC tab with multiple event types', () => {
    it('sorts and lists more than one distinct rbac event type', () => {
        useAuditLog.mockReturnValue({
            data: {
                data: [
                    {
                        id: 1,
                        event_type: 'role.assigned',
                        actor: 'ci-bot',
                        actor_type: 'machine_identity',
                        description: 'Assigned role admin',
                        timestamp: '2026-01-15T10:00:00Z',
                    },
                    {
                        id: 2,
                        event_type: 'permission.assigned',
                        actor: 'auditor',
                        actor_type: 'user',
                        description: 'Granted permission',
                        timestamp: '2026-01-16T10:00:00Z',
                    },
                ],
                total: 2,
                page: 1,
                pageSize: 100,
                totalPages: 1,
            },
            isLoading: false,
            error: null,
        });
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: 'RBAC Events' }));

        const table = within(screen.getByRole('table'));
        expect(table.getByText('ci-bot')).toBeInTheDocument();
        expect(table.getByText('auditor')).toBeInTheDocument();
    });
});

describe('AuditLogPage — anomaly table filtering and sorting', () => {
    const richAlerts = [
        {
            ID: 1,
            AlertType: 'unusual_access_time',
            SecretName: 'db-password',
            AccessedBy: 'alice',
            IPAddress: '10.0.0.1',
            Severity: 'critical',
            DetectedAt: '2026-01-01T00:00:00Z',
            Acknowledged: false,
            Description: 'Accessed at 3am',
        },
        {
            ID: 2,
            AlertType: 'bulk_download',
            SecretName: 'api-key',
            AccessedBy: 'bob',
            IPAddress: '10.0.0.2',
            Severity: 'low',
            DetectedAt: '',
            Acknowledged: true,
            Description: '',
        },
        {
            ID: 3,
            AlertType: 'geo_anomaly',
            SecretName: 'zeta-key',
            AccessedBy: 'zoe',
            IPAddress: '10.0.0.3',
            Severity: 'unknown',
            DetectedAt: '2026-01-05T00:00:00Z',
            Acknowledged: false,
            Description: '',
        },
    ];

    function openAnomalies() {
        mockAnomalies(richAlerts);
        const utils = render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: /anomaly alerts/i }));
        return utils;
    }

    it('renders a "—" for a missing detected-at timestamp and an unrecognized severity with default styling', () => {
        openAnomalies();
        // Show acknowledged alerts too, so the (acknowledged) "—" row is visible.
        fireEvent.click(screen.getAllByRole('button', { name: 'All' })[1]);

        const table = within(screen.getByRole('table'));
        expect(table.getByText('api-key')).toBeInTheDocument();
        expect(table.getByText('zeta-key')).toBeInTheDocument();
        expect(table.getAllByText('—').length).toBeGreaterThan(0);
    });

    it('filters by alert type and by acknowledged status', () => {
        openAnomalies();
        fireEvent.change(screen.getByLabelText('Filter by alert type'), { target: { value: 'geo_anomaly' } });
        expect(screen.getByText('zeta-key')).toBeInTheDocument();
        expect(screen.queryByText('db-password')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Acknowledged' }));
        expect(screen.getByText('No alerts match the current filters.')).toBeInTheDocument();

        fireEvent.click(screen.getAllByRole('button', { name: 'All' })[1]);
        expect(screen.getByText('zeta-key')).toBeInTheDocument();
    });

    it('filters by severity', () => {
        openAnomalies();
        fireEvent.click(screen.getByRole('button', { name: 'critical' }));
        expect(screen.getByText('db-password')).toBeInTheDocument();
        expect(screen.queryByText('zeta-key')).not.toBeInTheDocument();
    });

    it('sorts by each column and toggles direction', () => {
        openAnomalies();
        fireEvent.click(screen.getByRole('button', { name: /alert type/i }));
        fireEvent.click(screen.getByRole('button', { name: /secret/i }));
        fireEvent.click(screen.getByRole('button', { name: /actor/i }));
        fireEvent.click(screen.getByRole('button', { name: /severity/i }));
        // Toggle the same column twice more to flip sort direction back and forth (desc -> asc -> desc).
        fireEvent.click(screen.getByRole('button', { name: /severity/i }));
        fireEvent.click(screen.getByRole('button', { name: /severity/i }));

        const table = within(screen.getByRole('table'));
        expect(table.getByText('db-password')).toBeInTheDocument();
    });

    it('sorts by severity when two alerts both have an unrecognized severity value', () => {
        mockAnomalies([
            {
                ID: 10,
                AlertType: 'geo_anomaly',
                SecretName: 'first-key',
                AccessedBy: 'amy',
                IPAddress: '10.0.0.10',
                Severity: 'unmapped',
                DetectedAt: '2026-01-06T00:00:00Z',
                Acknowledged: false,
                Description: '',
            },
            {
                ID: 11,
                AlertType: 'bulk_download',
                SecretName: 'second-key',
                AccessedBy: 'ben',
                IPAddress: '10.0.0.11',
                Severity: 'unmapped',
                DetectedAt: '2026-01-07T00:00:00Z',
                Acknowledged: false,
                Description: '',
            },
        ]);
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: /anomaly alerts/i }));
        fireEvent.click(screen.getByRole('button', { name: /severity/i }));

        const table = within(screen.getByRole('table'));
        expect(table.getByText('first-key')).toBeInTheDocument();
        expect(table.getByText('second-key')).toBeInTheDocument();
    });

    it('expands a high-severity row and a low-severity row, then collapses', () => {
        openAnomalies();
        fireEvent.click(screen.getByText('db-password')); // high/critical -> expand
        expect(screen.getByText('Accessed at 3am')).toBeInTheDocument();
        fireEvent.click(screen.getByText('db-password')); // collapse

        fireEvent.click(screen.getByText('zeta-key')); // unknown severity -> expand
        expect(screen.getByText('#3')).toBeInTheDocument();
    });

    it('shows a "—" detected-at and "Acknowledged" status in the expanded detail panel for an acknowledged alert with no detected-at time', () => {
        const { container } = openAnomalies();
        // Reveal acknowledged alerts too (bulk_download/api-key is Acknowledged: true, DetectedAt: '').
        fireEvent.click(screen.getAllByRole('button', { name: 'All' })[1]);

        fireEvent.click(screen.getByText('api-key')); // expand

        const statusSpan = container.querySelector('span.text-emerald-600');
        expect(statusSpan).toHaveTextContent('Acknowledged');
        expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(2);
    });
});

describe('AuditLogPage XSS regression (WEB track backlog item 3)', () => {
    it.each(XSS_PAYLOADS)('renders a malicious audit description as inert text: %s', (payload) => {
        useAuditLog.mockReturnValue({
            data: {
                data: [
                    {
                        id: 1,
                        event_type: 'secret.read',
                        actor: 'alice',
                        actor_type: 'user',
                        description: payload,
                        timestamp: '2026-01-01T10:00:00Z',
                    },
                ],
                total: 1,
                page: 1,
                pageSize: 100,
                totalPages: 1,
            },
            isLoading: false,
            error: null,
        });
        const { container } = render(<AuditLogPage />);
        assertPayloadRenderedSafely(payload, container);
    });
});
