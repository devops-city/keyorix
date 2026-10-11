import { describe, it, expect } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { Footer } from '../Footer';

describe('Footer', () => {
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
