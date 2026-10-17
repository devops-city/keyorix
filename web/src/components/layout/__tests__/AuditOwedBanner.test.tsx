import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/test-utils';
import { AuditOwedBanner } from '../AuditOwedBanner';
import { useAuthStore } from '../../../store/authStore';
import type { User } from '../../../types';

// Real useSystemInfo hook; only the network layer is mocked.
const getInfo = vi.fn();
vi.mock('../../../services/system', () => ({
    systemApi: { getInfo: (...args: unknown[]) => getInfo(...args) },
}));

const setSession = (isAuthenticated: boolean) =>
    useAuthStore.setState({
        isAuthenticated,
        user: isAuthenticated ? ({ id: 1 } as unknown as User) : null,
    });

const info = (security: Record<string, unknown>) => ({ version: 'v1', security });

const expectNoBanner = async () => {
    await waitFor(() => expect(getInfo).toHaveBeenCalledTimes(1));
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByTestId('audit-owed-banner')).not.toBeInTheDocument();
};

describe('AuditOwedBanner (SUSPEND-AUDIT-LOUD)', () => {
    beforeEach(() => {
        getInfo.mockReset();
        setSession(true);
    });

    it('warns while suspensions are missing from the audit log', async () => {
        getInfo.mockResolvedValue(info({ audit_owed: { pending: 2, failures_since_start: 2 } }));
        render(<AuditOwedBanner />);
        const banner = await screen.findByTestId('audit-owed-banner');
        expect(banner).toHaveAttribute('role', 'alert');
        expect(banner).toHaveTextContent('2 suspensions are missing from the audit log.');
        expect(banner).toHaveTextContent('Access was blocked at once');
    });

    it('uses the singular for one', async () => {
        getInfo.mockResolvedValue(info({ audit_owed: { pending: 1, failures_since_start: 1 } }));
        render(<AuditOwedBanner />);
        expect(await screen.findByTestId('audit-owed-banner')).toHaveTextContent(
            '1 suspension is missing from the audit log.'
        );
    });

    it('warns when the server could not count them', async () => {
        getInfo.mockResolvedValue(info({ audit_owed: { pending: -1, failures_since_start: 0 } }));
        render(<AuditOwedBanner />);
        expect(await screen.findByTestId('audit-owed-banner')).toHaveTextContent(
            'Some suspensions may be missing from the audit log.'
        );
    });

    it('renders nothing once every owed row is written', async () => {
        getInfo.mockResolvedValue(info({ audit_owed: { pending: 0, failures_since_start: 3 } }));
        render(<AuditOwedBanner />);
        await expectNoBanner();
    });

    it('renders nothing for a caller the server does not tell (no system.write) or an older server', async () => {
        getInfo.mockResolvedValue(info({ audit_enabled: true }));
        render(<AuditOwedBanner />);
        await expectNoBanner();
    });
});
