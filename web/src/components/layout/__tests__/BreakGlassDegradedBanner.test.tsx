import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/test-utils';
import { BreakGlassDegradedBanner } from '../BreakGlassDegradedBanner';
import { useAuthStore } from '../../../store/authStore';
import type { User } from '../../../types';

// Real useSystemInfo hook; only the network layer is mocked.
const getInfo = vi.fn();
vi.mock('../../../services/system', () => ({
    systemApi: { getInfo: (...args: unknown[]) => getInfo(...args) },
}));

const info = (security: Record<string, unknown>) => ({ version: 'v1', security });

const expectNoBanner = async () => {
    await waitFor(() => expect(getInfo).toHaveBeenCalledTimes(1));
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByTestId('break-glass-degraded-banner')).not.toBeInTheDocument();
};

describe('BreakGlassDegradedBanner (BREAKGLASS-OWED-1)', () => {
    beforeEach(() => {
        getInfo.mockReset();
        useAuthStore.setState({ isAuthenticated: true, user: { id: 1 } as unknown as User });
    });

    it('alerts while a degraded activation owes audit records and its review', async () => {
        getInfo.mockResolvedValue(
            info({ break_glass_degraded: { unsettled: 1, unreviewed: 2, activation_ids: [4, 9] } })
        );
        render(<BreakGlassDegradedBanner />);
        const banner = await screen.findByTestId('break-glass-degraded-banner');
        expect(banner).toHaveAttribute('role', 'alert');
        expect(banner).toHaveTextContent('Emergency access was granted while the audit log refused writes');
        expect(banner).toHaveTextContent('1 activation still owes audit records');
        expect(banner).toHaveTextContent('2 need the mandatory review');
        expect(banner).toHaveTextContent('#4, #9');
    });

    it('stays while only the review is outstanding', async () => {
        getInfo.mockResolvedValue(info({ break_glass_degraded: { unsettled: 0, unreviewed: 1, activation_ids: [4] } }));
        render(<BreakGlassDegradedBanner />);
        const banner = await screen.findByTestId('break-glass-degraded-banner');
        expect(banner).toHaveTextContent('1 needs the mandatory review');
        expect(banner).not.toHaveTextContent('owes');
    });

    it('says so when the server could not read the state', async () => {
        getInfo.mockResolvedValue(info({ break_glass_degraded: { unsettled: -1, unreviewed: 0, activation_ids: [] } }));
        render(<BreakGlassDegradedBanner />);
        expect(await screen.findByTestId('break-glass-degraded-banner')).toHaveTextContent(
            'the server could not read their state'
        );
    });

    it('renders nothing once settled and reviewed', async () => {
        getInfo.mockResolvedValue(info({ break_glass_degraded: { unsettled: 0, unreviewed: 0, activation_ids: [] } }));
        render(<BreakGlassDegradedBanner />);
        await expectNoBanner();
    });

    it('renders nothing for a caller the server does not tell (no system.write) or an older server', async () => {
        getInfo.mockResolvedValue(info({ audit_enabled: true }));
        render(<BreakGlassDegradedBanner />);
        await expectNoBanner();
    });
});
