import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router';
import { describe, it, expect, vi } from 'vitest';
import { RequireMfaEnrolment } from '../RequireMfaEnrolment';
import { MFA_ENROLMENT_URL } from '../../../services/client';
import type { User } from '../../../types';

let mockUser: Partial<User> | null = null;
vi.mock('../../../features/auth', () => ({
    useAuth: () => ({ user: mockUser }),
}));

const Where: React.FC = () => {
    const loc = useLocation();
    return <div data-testid="where">{loc.pathname + loc.search}</div>;
};

// A protected page that must never render for a confined session (#3155): if it does,
// its queries would fire and 403.
const renderAt = (path: string, onProtectedRender: () => void) => {
    const Dashboard: React.FC = () => {
        onProtectedRender();
        return <div>Dashboard Page</div>;
    };
    return render(
        <MemoryRouter initialEntries={[path]}>
            <RequireMfaEnrolment>
                <Routes>
                    <Route path="/dashboard" element={<Dashboard />} />
                    <Route path="/profile" element={<div>Profile Page</div>} />
                </Routes>
            </RequireMfaEnrolment>
            <Where />
        </MemoryRouter>
    );
};

describe('RequireMfaEnrolment', () => {
    it('sends a session owing MFA enrolment from a protected page to enrolment without rendering it', () => {
        mockUser = { pendingSteps: ['enroll_mfa'] };
        const rendered = vi.fn();
        renderAt('/dashboard', rendered);
        expect(rendered).not.toHaveBeenCalled();
        expect(screen.queryByText('Dashboard Page')).toBeNull();
        expect(screen.getByTestId('where').textContent).toBe(MFA_ENROLMENT_URL);
    });

    it('lets the confined session stay on the profile page', () => {
        mockUser = { pendingSteps: ['enroll_mfa'] };
        renderAt('/profile', vi.fn());
        expect(screen.getByText('Profile Page')).toBeTruthy();
    });

    it('does not touch a session with nothing pending', () => {
        mockUser = { pendingSteps: [] };
        renderAt('/dashboard', vi.fn());
        expect(screen.getByText('Dashboard Page')).toBeTruthy();
    });

    it('does not confine on a password-only pending step (RequirePasswordChange owns that)', () => {
        mockUser = { pendingSteps: ['change_password'] };
        renderAt('/dashboard', vi.fn());
        expect(screen.getByText('Dashboard Page')).toBeTruthy();
    });
});
