import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/test-utils';
import { Footer } from '../Footer';
import { useAuthStore } from '../../../store/authStore';
import type { User } from '../../../types';

// Real useSystemInfo hook; only the network layer is mocked, so these tests assert whether a
// request is actually issued (the MFA-pending confinement refuses GET /system/info).
const getInfo = vi.fn();
vi.mock('../../../services/system', () => ({
    systemApi: { getInfo: (...args: unknown[]) => getInfo(...args) },
}));

const setSession = (isAuthenticated: boolean, pendingSteps?: string[]) =>
    useAuthStore.setState({
        isAuthenticated,
        user: isAuthenticated ? ({ id: 1, pendingSteps } as unknown as User) : null,
    });

describe('Footer system-info request', () => {
    beforeEach(() => {
        getInfo.mockReset();
        getInfo.mockResolvedValue({ version: 'v9.9.9' });
    });

    it('does not request system info while the session is MFA-pending', async () => {
        setSession(true, ['enroll_mfa']);
        render(<Footer />);
        expect(screen.getByRole('contentinfo')).toBeInTheDocument();
        await new Promise((r) => setTimeout(r, 50));
        expect(getInfo).not.toHaveBeenCalled();
        expect(screen.getByText('Keyorix')).toBeInTheDocument();
    });

    it('does not request system info when unauthenticated', async () => {
        setSession(false);
        render(<Footer />);
        await new Promise((r) => setTimeout(r, 50));
        expect(getInfo).not.toHaveBeenCalled();
    });

    it('requests system info for a fully authenticated session', async () => {
        setSession(true);
        render(<Footer />);
        await waitFor(() => expect(getInfo).toHaveBeenCalledTimes(1));
        expect(await screen.findByText(/^Keyorix v9\.9\.9/)).toBeInTheDocument();
    });
});
