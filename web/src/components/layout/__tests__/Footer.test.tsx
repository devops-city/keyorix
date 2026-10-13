import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { Footer } from '../Footer';

let serverVersion: string | undefined;
vi.mock('../../../features/dashboard/api', () => ({
    useSystemInfo: () => ({ data: serverVersion === undefined ? undefined : { version: serverVersion } }),
}));

describe('Footer', () => {
    it('shows the server version from the API when it is stamped', () => {
        serverVersion = 'v1.2.3';
        render(<Footer />);
        expect(screen.getByText(/^Keyorix v1\.2\.3/)).toBeInTheDocument();
        serverVersion = undefined;
    });

    it('never shows an unstamped server value', () => {
        serverVersion = 'dev';
        render(<Footer />);
        expect(screen.getByText('Keyorix')).toBeInTheDocument();
        serverVersion = undefined;
    });

    it('renders the version label', () => {
        render(<Footer />);
        expect(screen.getByText('Keyorix')).toBeInTheDocument();
    });

    it('renders as a footer landmark', () => {
        render(<Footer />);
        expect(screen.getByRole('contentinfo')).toBeInTheDocument();
    });

    it('applies a custom className alongside the base classes', () => {
        render(<Footer className="custom-footer-class" />);
        const footer = screen.getByRole('contentinfo');
        expect(footer).toHaveClass('border-t');
        expect(footer).toHaveClass('custom-footer-class');
    });

    it('renders without a custom className when none is provided', () => {
        render(<Footer />);
        const footer = screen.getByRole('contentinfo');
        expect(footer).toHaveClass('border-t');
    });
});
