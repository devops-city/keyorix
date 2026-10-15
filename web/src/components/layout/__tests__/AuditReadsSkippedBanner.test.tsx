import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/test-utils';
import { AuditReadsSkippedBanner } from '../AuditReadsSkippedBanner';
import { useAuthStore } from '../../../store/authStore';
import type { User } from '../../../types';

// Real useSystemInfo hook; only the network layer is mocked.
const getInfo = vi.fn();
vi.mock('../../../services/system', () => ({
    systemApi: { getInfo: (...args: unknown[]) => getInfo(...args) },
}));

const setSession = (isAuthenticated: boolean, pendingSteps?: string[]) =>
    useAuthStore.setState({
        isAuthenticated,
        user: isAuthenticated ? ({ id: 1, pendingSteps } as unknown as User) : null,
    });

const info = (security: Record<string, unknown>) => ({ version: 'v1', security });

describe('AuditReadsSkippedBanner (ADR-112 Amendment 4)', () => {
    beforeEach(() => {
        getInfo.mockReset();
    });

    it('shows a persistent, non-dismissible alert when the server skips read audits', async () => {
        setSession(true);
        getInfo.mockResolvedValue(info({ audit_reads_skipped: true }));
        render(<AuditReadsSkippedBanner />);
        const banner = await screen.findByTestId('audit-reads-skipped-banner');
        expect(banner).toHaveAttribute('role', 'alert');
        expect(banner).toHaveTextContent('Secret reads are not audited.');
        expect(banner).toHaveTextContent('storage.database.insecure_audit_skip_reads');
        expect(screen.queryByRole('button')).not.toBeInTheDocument();
    });

    it('renders nothing when reads are audited (the default)', async () => {
        setSession(true);
        getInfo.mockResolvedValue(info({ audit_reads_skipped: false }));
        render(<AuditReadsSkippedBanner />);
        await waitFor(() => expect(getInfo).toHaveBeenCalledTimes(1));
        await new Promise((r) => setTimeout(r, 20));
        expect(screen.queryByTestId('audit-reads-skipped-banner')).not.toBeInTheDocument();
    });

    it('renders nothing for an older server that does not report the field', async () => {
        setSession(true);
        getInfo.mockResolvedValue(info({ audit_enabled: true }));
        render(<AuditReadsSkippedBanner />);
        await waitFor(() => expect(getInfo).toHaveBeenCalledTimes(1));
        await new Promise((r) => setTimeout(r, 20));
        expect(screen.queryByTestId('audit-reads-skipped-banner')).not.toBeInTheDocument();
    });

    it('does not request system info while the session is MFA-pending', async () => {
        setSession(true, ['enroll_mfa']);
        render(<AuditReadsSkippedBanner />);
        await new Promise((r) => setTimeout(r, 50));
        expect(getInfo).not.toHaveBeenCalled();
    });
});
