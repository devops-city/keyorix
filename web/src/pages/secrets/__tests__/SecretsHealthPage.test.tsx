import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, within, fireEvent } from '../../../test/test-utils';
import { SecretsHealthPage } from '../SecretsHealthPage';
import { useUIStore } from '../../../store/uiStore';

const { mockUseSecretsHealth, navigateMock } = vi.hoisted(() => ({
    mockUseSecretsHealth: vi.fn(),
    navigateMock: vi.fn(),
}));

vi.mock('../../../features/secrets/useSecretsHealth', () => ({
    useSecretsHealth: () => mockUseSecretsHealth(),
}));

vi.mock('react-router', async () => {
    const actual = await vi.importActual('react-router');
    return { ...actual, useNavigate: () => navigateMock };
});

// ── fixtures ─────────────────────────────────────────────────────────────────

const baseHealth = {
    score: 82,
    total: 120,
    expiry: {
        expired: 0,
        expiring7d: 2,
        expiring30d: 5,
        healthy: 113,
        pct: 92,
    },
    rotation: {
        available: true,
        pct: 75,
        covered: 40,
        overdue: 0,
        dueSoon: 3,
        ok: 37,
        items: [] as Array<{
            policy_id: number;
            secret_id: number;
            secret_name: string;
            status: string;
            days_overdue: number;
            interval_days: number;
            auto_rotate?: boolean;
            rotation_backend?: string;
        }>,
    },
    access: {
        reads30d: 340,
        failedAuth24h: 0,
        inactiveUsers: 0,
        pct: 88,
    },
    anomalies: {
        count: 0,
        items: [] as Array<{ ID: number; AlertType: string; SecretName: string; AccessedBy: string }>,
    },
    isLoading: false,
    error: null,
};

function makeHealth(overrides: Partial<typeof baseHealth> = {}) {
    return { ...baseHealth, ...overrides };
}

describe('SecretsHealthPage', () => {
    afterEach(() => {
        navigateMock.mockReset();
        useUIStore.setState({ theme: 'dark' });
    });

    // ── loading / error ────────────────────────────────────────────────────

    it('shows a loading state while data is fetching', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ isLoading: true }));
        render(<SecretsHealthPage />);
        expect(screen.getByText(/loading/i)).toBeInTheDocument();
        expect(screen.queryByText('Secrets Health Score')).not.toBeInTheDocument();
    });

    it('shows an error state when the hook reports an error', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ error: new Error('boom') }));
        render(<SecretsHealthPage />);
        expect(screen.getByText('Failed to load health data')).toBeInTheDocument();
        expect(screen.getByText(/Could not fetch secrets or dashboard stats/i)).toBeInTheDocument();
        expect(screen.getByText('Retry')).toBeInTheDocument();
    });

    it('reloads the page when the Retry action is clicked', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ error: new Error('boom') }));
        const reloadMock = vi.fn();
        const originalLocation = window.location;
        Object.defineProperty(window, 'location', {
            configurable: true,
            value: { ...originalLocation, reload: reloadMock },
        });

        render(<SecretsHealthPage />);
        fireEvent.click(screen.getByText('Retry'));
        expect(reloadMock).toHaveBeenCalledOnce();

        Object.defineProperty(window, 'location', {
            configurable: true,
            value: originalLocation,
        });
    });

    // ── header + overall score ─────────────────────────────────────────────

    it('renders the header secret count and overall score ring', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth());
        render(<SecretsHealthPage />);
        expect(screen.getByText('Secrets Health')).toBeInTheDocument();
        expect(screen.getByText(/Hygiene posture across 120 secrets/)).toBeInTheDocument();
        expect(screen.getByText('82')).toBeInTheDocument();
        expect(screen.getByText('Healthy')).toBeInTheDocument();
    });

    it('singularizes the secret count when total is 1', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ total: 1 }));
        render(<SecretsHealthPage />);
        expect(screen.getByText(/Hygiene posture across 1 secret /)).toBeInTheDocument();
    });

    it('labels a mid-range score as "Needs Attention"', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ score: 65 }));
        render(<SecretsHealthPage />);
        expect(screen.getByText('Needs Attention')).toBeInTheDocument();
    });

    it('labels a low score as "At Risk"', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ score: 30 }));
        render(<SecretsHealthPage />);
        expect(screen.getByText('At Risk')).toBeInTheDocument();
    });

    // ── expiry card ─────────────────────────────────────────────────────────

    it('renders expiry breakdown stats', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth());
        render(<SecretsHealthPage />);
        expect(screen.getByText('Expired')).toBeInTheDocument();
        expect(screen.getByText('Expiring within 7 days')).toBeInTheDocument();
        expect(screen.getByText('2')).toBeInTheDocument();
        expect(screen.getByText('Expiring within 30 days')).toBeInTheDocument();
        expect(screen.getByText('5')).toBeInTheDocument();
        expect(screen.getByText('Healthy (no expiry or >30d)')).toBeInTheDocument();
        expect(screen.getByText('113')).toBeInTheDocument();
    });

    it('shows the expired-secrets warning banner when secrets are expired', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ expiry: { ...baseHealth.expiry, expired: 3 } }));
        render(<SecretsHealthPage />);
        expect(screen.getByText(/3 secrets have already expired/)).toBeInTheDocument();
    });

    it('singularizes the expired-secrets warning banner for a single expired secret', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ expiry: { ...baseHealth.expiry, expired: 1 } }));
        render(<SecretsHealthPage />);
        expect(screen.getByText(/1 secret has already expired/)).toBeInTheDocument();
    });

    // Card drill-down links (expiry/rotation/access) share this exact shape;
    // parameterized together here rather than duplicated per card section.
    it.each([
        ['View all expiring →', '/secrets/expiry'],
        ['Manage policies →', '/secrets/rotation'],
        ['View audit log →', '/audit'],
    ])('links "%s" to %s', (linkText, href) => {
        mockUseSecretsHealth.mockReturnValue(makeHealth());
        render(<SecretsHealthPage />);
        const link = screen.getByText(linkText);
        expect(link).toHaveAttribute('href', href);
    });

    // ── rotation card ───────────────────────────────────────────────────────

    it('renders a rotation empty state when no policy applies', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ rotation: { ...baseHealth.rotation, available: false } }));
        render(<SecretsHealthPage />);
        expect(screen.getByText('No rotation policies yet')).toBeInTheDocument();
        expect(screen.getByText('N/A')).toBeInTheDocument();
        expect(
            screen.getByText(/Rotation score is excluded from the total until a rotation policy applies/)
        ).toBeInTheDocument();
    });

    it('renders rotation stats when policies are available', () => {
        mockUseSecretsHealth.mockReturnValue(
            makeHealth({
                rotation: {
                    available: true,
                    pct: 75,
                    covered: 40,
                    overdue: 0,
                    dueSoon: 3,
                    ok: 37,
                    items: [
                        {
                            policy_id: 1,
                            secret_id: 10,
                            secret_name: 'STRIPE_KEY',
                            status: 'ok',
                            days_overdue: 0,
                            interval_days: 90,
                            auto_rotate: true,
                        },
                    ],
                },
            })
        );
        render(<SecretsHealthPage />);
        expect(screen.getByText('Up to date')).toBeInTheDocument();
        expect(screen.getByText('Secrets under policy')).toBeInTheDocument();
        expect(screen.getByText('40')).toBeInTheDocument();
        expect(screen.getByText('Self-rotating')).toBeInTheDocument();
        // one item has auto_rotate: true, so the self-rotating count is 1
        const selfRotatingRow = screen.getByText('Self-rotating').closest('div')!.parentElement!;
        expect(within(selfRotatingRow).getByText('1')).toBeInTheDocument();
    });

    it('lists overdue rotation entries sorted by days overdue, capped at 4, with an overflow note', () => {
        const items = Array.from({ length: 6 }, (_, i) => ({
            policy_id: 1,
            secret_id: i,
            secret_name: `SECRET_${i}`,
            status: 'overdue',
            days_overdue: i + 1,
            interval_days: 30,
        }));
        mockUseSecretsHealth.mockReturnValue(
            makeHealth({
                rotation: {
                    available: true,
                    pct: 10,
                    covered: 6,
                    overdue: 6,
                    dueSoon: 0,
                    ok: 0,
                    items,
                },
            })
        );
        render(<SecretsHealthPage />);
        // Highest days_overdue (6) should be first / present, and the note for the remaining 2.
        expect(screen.getByText('SECRET_5')).toBeInTheDocument();
        expect(screen.getByText('SECRET_4')).toBeInTheDocument();
        expect(screen.getByText('SECRET_3')).toBeInTheDocument();
        expect(screen.getByText('SECRET_2')).toBeInTheDocument();
        expect(screen.queryByText('SECRET_1')).not.toBeInTheDocument();
        expect(screen.queryByText('SECRET_0')).not.toBeInTheDocument();
        expect(screen.getByText('+2 more overdue')).toBeInTheDocument();
    });

    it('shows an auto-rotate badge with backend name for self-rotating overdue secrets', () => {
        mockUseSecretsHealth.mockReturnValue(
            makeHealth({
                rotation: {
                    available: true,
                    pct: 10,
                    covered: 1,
                    overdue: 1,
                    dueSoon: 0,
                    ok: 0,
                    items: [
                        {
                            policy_id: 1,
                            secret_id: 1,
                            secret_name: 'DB_PASSWORD',
                            status: 'overdue',
                            days_overdue: 5,
                            interval_days: 30,
                            auto_rotate: true,
                            rotation_backend: 'vault',
                        },
                    ],
                },
            })
        );
        render(<SecretsHealthPage />);
        expect(screen.getByText('Auto: vault')).toBeInTheDocument();
    });

    it('shows an auto-rotate badge without a backend suffix and a generic tooltip when no backend is set', () => {
        mockUseSecretsHealth.mockReturnValue(
            makeHealth({
                rotation: {
                    available: true,
                    pct: 10,
                    covered: 1,
                    overdue: 1,
                    dueSoon: 0,
                    ok: 0,
                    items: [
                        {
                            policy_id: 1,
                            secret_id: 1,
                            secret_name: 'DB_PASSWORD',
                            status: 'overdue',
                            days_overdue: 5,
                            interval_days: 30,
                            auto_rotate: true,
                        },
                    ],
                },
            })
        );
        render(<SecretsHealthPage />);
        expect(screen.getByText('Auto')).toBeInTheDocument();
        expect(screen.queryByText('Auto: vault')).not.toBeInTheDocument();
        expect(screen.getByTitle('Auto-rotates (Keyorix-generated)')).toBeInTheDocument();
    });

    // ── access card ─────────────────────────────────────────────────────────

    it('renders access stats', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth());
        render(<SecretsHealthPage />);
        expect(screen.getByText('Secret reads (last 30d)')).toBeInTheDocument();
        expect(screen.getByText('340')).toBeInTheDocument();
        expect(screen.getByText('Failed logins (24h)')).toBeInTheDocument();
        expect(screen.getByText('Inactive users (no login 30d)')).toBeInTheDocument();
    });

    it('shows a brute-force warning button when failed auth attempts are high, and navigates on click', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ access: { ...baseHealth.access, failedAuth24h: 7 } }));
        render(<SecretsHealthPage />);
        const warning = screen.getByText(/High number of failed logins/);
        expect(warning).toBeInTheDocument();
        fireEvent.click(warning);
        expect(navigateMock).toHaveBeenCalledWith('/audit?tab=audit&filter=failed');
    });

    it('does not show the brute-force warning below the threshold', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ access: { ...baseHealth.access, failedAuth24h: 4 } }));
        render(<SecretsHealthPage />);
        expect(screen.queryByText(/High number of failed logins/)).not.toBeInTheDocument();
    });

    it('shows an amber dot for inactive users when there are any', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth({ access: { ...baseHealth.access, inactiveUsers: 3 } }));
        render(<SecretsHealthPage />);
        const inactiveRow = screen.getByText('Inactive users (no login 30d)').closest('div')!;
        const dot = inactiveRow.querySelector('div')!;
        expect(dot).toHaveStyle({ backgroundColor: '#f59e0b' });
    });

    // ── anomalies card ──────────────────────────────────────────────────────

    it('shows the clean anomalies state when there are none', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth());
        render(<SecretsHealthPage />);
        expect(screen.getByText('No active anomalies detected')).toBeInTheDocument();
        // No drill-down link is rendered when there is nothing to view.
        expect(screen.queryByText('View anomalies →')).not.toBeInTheDocument();
    });

    it('renders anomaly alerts, humanized, capped at 4, with an overflow link', () => {
        const items = Array.from({ length: 5 }, (_, i) => ({
            ID: i,
            AlertType: 'off_hours',
            SecretName: `SECRET_${i}`,
            AccessedBy: `user${i}@example.com`,
        }));
        mockUseSecretsHealth.mockReturnValue(makeHealth({ anomalies: { count: 5, items } }));
        render(<SecretsHealthPage />);
        expect(screen.getByText('5 active anomalies')).toBeInTheDocument();
        expect(screen.getAllByText('Off-hours')).toHaveLength(4);
        expect(screen.getByText(/SECRET_0/)).toBeInTheDocument();
        expect(screen.queryByText(/SECRET_4/)).not.toBeInTheDocument();
        expect(screen.getByText(/\+1 more/)).toBeInTheDocument();
        const viewAllLinks = screen.getAllByText('view all');
        expect(viewAllLinks.length).toBeGreaterThan(0);
        expect(viewAllLinks[0]).toHaveAttribute('href', '/audit?tab=anomalies');
    });

    it('singularizes the anomaly count label for a single anomaly', () => {
        mockUseSecretsHealth.mockReturnValue(
            makeHealth({
                anomalies: {
                    count: 1,
                    items: [{ ID: 1, AlertType: 'frequency_spike', SecretName: 'S', AccessedBy: 'u@example.com' }],
                },
            })
        );
        render(<SecretsHealthPage />);
        expect(screen.getByText('1 active anomaly')).toBeInTheDocument();
    });

    it('shows the "View anomalies →" link in the section header when anomalies exist', () => {
        mockUseSecretsHealth.mockReturnValue(
            makeHealth({
                anomalies: {
                    count: 1,
                    items: [{ ID: 1, AlertType: 'frequency_spike', SecretName: 'S', AccessedBy: 'u@example.com' }],
                },
            })
        );
        render(<SecretsHealthPage />);
        const link = screen.getByText('View anomalies →');
        expect(link).toHaveAttribute('href', '/audit?tab=anomalies');
    });

    // ── component breakdown ────────────────────────────────────────────────

    it('renders the component score breakdown weights and percentages', () => {
        mockUseSecretsHealth.mockReturnValue(makeHealth());
        render(<SecretsHealthPage />);
        // Scope to the breakdown panel since section-card titles below reuse the same names.
        const breakdown = screen.getByText('Score Breakdown').closest('div')!.parentElement!;
        const expiryRow = within(breakdown).getByText('Expiry Health').closest('div')!.parentElement!;
        expect(within(expiryRow).getByText('40%')).toBeInTheDocument();
        expect(within(expiryRow).getByText('92%')).toBeInTheDocument();

        const rotationRow = within(breakdown).getByText('Rotation Health').closest('div')!.parentElement!;
        expect(within(rotationRow).getByText('30%')).toBeInTheDocument();
        expect(within(rotationRow).getByText('75%')).toBeInTheDocument();

        const accessRow = within(breakdown).getByText('Access Health').closest('div')!.parentElement!;
        expect(within(accessRow).getByText('30%')).toBeInTheDocument();
        expect(within(accessRow).getByText('88%')).toBeInTheDocument();
    });

    it('shows N/A for the rotation component when rotation is unavailable', () => {
        mockUseSecretsHealth.mockReturnValue(
            makeHealth({ rotation: { ...baseHealth.rotation, available: false, pct: 100 } })
        );
        render(<SecretsHealthPage />);
        expect(screen.getAllByText('N/A').length).toBeGreaterThan(0);
    });

    // ── theme-driven colors ─────────────────────────────────────────────────
    // The default store theme is 'dark', so every other test above only exercises
    // the isDark-true branch of each card's inline styles. These cover the
    // isDark-false (light) path, and the system-theme resolution itself.

    it('uses light-theme colors across the expiry/rotation/access/anomaly cards when the theme is light', () => {
        useUIStore.setState({ theme: 'light' });
        mockUseSecretsHealth.mockReturnValue(
            makeHealth({
                expiry: { ...baseHealth.expiry, expired: 2 },
                rotation: {
                    available: true,
                    pct: 10,
                    covered: 1,
                    overdue: 1,
                    dueSoon: 0,
                    ok: 0,
                    items: [
                        {
                            policy_id: 1,
                            secret_id: 1,
                            secret_name: 'DB_PASSWORD',
                            status: 'overdue',
                            days_overdue: 5,
                            interval_days: 30,
                            auto_rotate: true,
                            rotation_backend: 'vault',
                        },
                    ],
                },
                access: { ...baseHealth.access, failedAuth24h: 7 },
                anomalies: {
                    count: 1,
                    items: [{ ID: 1, AlertType: 'frequency_spike', SecretName: 'S', AccessedBy: 'u@example.com' }],
                },
            })
        );
        render(<SecretsHealthPage />);

        expect(screen.getByText(/2 secrets have already expired/)).toHaveStyle({ color: '#991b1b' });
        expect(screen.getByText('DB_PASSWORD')).toHaveStyle({ color: '#991b1b' });
        expect(screen.getByText('Auto: vault')).toHaveStyle({ backgroundColor: '#dbeafe', color: '#1e40af' });
        expect(screen.getByText(/High number of failed logins/)).toHaveStyle({ color: '#991b1b' });
        expect(screen.getByText('1 active anomaly')).toHaveStyle({ color: '#991b1b' });
        expect(screen.getByText('Frequency spike')).toHaveStyle({ color: '#991b1b' });
        expect(screen.getByText(/^S ·/)).toHaveStyle({ color: '#b91c1c' });
    });

    it('resolves the system theme via matchMedia and uses dark colors when the system prefers dark', () => {
        useUIStore.setState({ theme: 'system' });
        (window.matchMedia as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
            matches: true,
            media: '',
            onchange: null,
            addListener: vi.fn(),
            removeListener: vi.fn(),
            addEventListener: vi.fn(),
            removeEventListener: vi.fn(),
            dispatchEvent: vi.fn(),
        });
        mockUseSecretsHealth.mockReturnValue(makeHealth({ expiry: { ...baseHealth.expiry, expired: 2 } }));
        render(<SecretsHealthPage />);

        expect(screen.getByText(/2 secrets have already expired/)).toHaveStyle({ color: '#f87171' });
    });
});
