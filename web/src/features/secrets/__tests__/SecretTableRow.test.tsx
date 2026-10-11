import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, within, fireEvent } from '../../../test/test-utils';
import { SecretTableRow } from '../SecretTableRow';
import { Secret } from '../../../types';
import { useUIStore } from '../../../store/uiStore';
import { XSS_PAYLOADS, assertPayloadRenderedSafely } from '../../../test/xss-payloads';

// Mirrors the component's own formatDate() so the assertion is correct
// regardless of the timezone the test runs in.
const formatDate = (d: string) =>
    new Intl.DateTimeFormat('en', { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(d));

const baseSecret: Secret = {
    id: 42,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-01-15T10:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
};

// Helper: SecretTableRow renders a <tr>, so it must be wrapped in a real
// <table><tbody> to avoid React DOM-nesting warnings and to make row-scoped
// queries (getByRole('row')) work as they would in the real app.
const renderRow = (props: Partial<React.ComponentProps<typeof SecretTableRow>> = {}) => {
    const defaultProps: React.ComponentProps<typeof SecretTableRow> = {
        secret: baseSecret,
        isSelected: false,
        onToggleSelect: vi.fn(),
        onView: vi.fn(),
        onEdit: vi.fn(),
        onDelete: vi.fn(),
        onShare: vi.fn(),
        onRotate: vi.fn(),
        onCopy: vi.fn(),
        copyingId: null,
        copiedId: null,
        copyErrorId: null,
    };
    const merged = { ...defaultProps, ...props };
    return {
        ...render(
            <table>
                <tbody>
                    <SecretTableRow {...merged} />
                </tbody>
            </table>
        ),
        props: merged,
    };
};

// What the signed-in user may do. Tests that exercise a control assume the user can; the
// permission-aware cases flip fields on this object (see useCan.ts).
const canState = vi.hoisted(() => ({
    value: { admin: true, writeSecrets: true, deleteSecrets: true, readAudit: true, manageMembers: true },
}));
vi.mock('../../auth/useCan', () => ({ useCan: () => canState.value }));
beforeEach(() => {
    canState.value = { admin: true, writeSecrets: true, deleteSecrets: true, readAudit: true, manageMembers: true };
});

describe('SecretTableRow', () => {
    afterEach(() => {
        // The uiStore is a real Zustand singleton (persist+devtools); restore the
        // default theme so tests below don't leak the override made above.
        useUIStore.setState({ theme: 'dark' });
    });

    it('renders name, type badge, environment, and modified date/owner cell', () => {
        renderRow();
        const row = screen.getByRole('row');
        expect(within(row).getByText('db-password')).toBeInTheDocument();
        expect(within(row).getByText('Password')).toBeInTheDocument();
        expect(within(row).getByText('production')).toBeInTheDocument();
        expect(within(row).getByText(formatDate(baseSecret.lastModified))).toBeInTheDocument();
        expect(within(row).getByText('by alice')).toBeInTheDocument();
    });

    // The list and project tables both put these headers over this row's
    // cells; if the cells move, both headers must move with them (#2977).
    it('renders its cells in header order: select, name, type, classification, environment, sharing, modified, actions', () => {
        renderRow({ secret: { ...baseSecret, classification: 'confidential' } });
        const cells = within(screen.getByRole('row')).getAllByRole('cell');
        expect(cells).toHaveLength(8);
        expect(cells[1]).toHaveTextContent('db-password');
        expect(cells[2]).toHaveTextContent('Password');
        expect(cells[3]).toHaveTextContent('Confidential');
        expect(cells[4]).toHaveTextContent('production');
        expect(cells[5]).toHaveTextContent('Private');
        expect(cells[6]).toHaveTextContent('by alice');
    });

    it('defaults the environment cell to "production" when environment is empty', () => {
        renderRow({ secret: { ...baseSecret, environment: '' } });
        const row = screen.getByRole('row');
        expect(within(row).getByText('production')).toBeInTheDocument();
    });

    it('renders up to 3 tags plus a "+N more" overflow indicator', () => {
        renderRow({ secret: { ...baseSecret, tags: ['a', 'b', 'c', 'd', 'e'] } });
        const row = screen.getByRole('row');
        expect(within(row).getByText('a')).toBeInTheDocument();
        expect(within(row).getByText('b')).toBeInTheDocument();
        expect(within(row).getByText('c')).toBeInTheDocument();
        expect(within(row).queryByText('d')).not.toBeInTheDocument();
        expect(within(row).getByText('+2 more')).toBeInTheDocument();
    });

    it('renders no tag chips when there are no tags', () => {
        renderRow({ secret: { ...baseSecret, tags: [] } });
        const row = screen.getByRole('row');
        expect(within(row).queryByText(/more$/)).not.toBeInTheDocument();
    });

    it('shows a classification badge, defaulting to Unclassified when unset', () => {
        renderRow();
        expect(screen.getByText('Unclassified')).toBeInTheDocument();
    });

    it('shows the correct classification label when set', () => {
        renderRow({ secret: { ...baseSecret, classification: 'confidential' } });
        expect(screen.getByText('Confidential')).toBeInTheDocument();
    });

    it('shows "Private" when the secret is not shared', () => {
        renderRow({ secret: { ...baseSecret, isShared: false } });
        expect(screen.getByText('Private')).toBeInTheDocument();
    });

    it('shows the share count when the secret is shared', () => {
        renderRow({ secret: { ...baseSecret, isShared: true, shareCount: 3 } });
        expect(screen.getByText('3 shares')).toBeInTheDocument();
        expect(screen.queryByText('Private')).not.toBeInTheDocument();
    });

    it('reflects isSelected on the checkbox and applies the selected row background', () => {
        renderRow({ isSelected: true });
        const row = screen.getByRole('row');
        const checkbox = within(row).getByRole('checkbox');
        expect(checkbox).toBeChecked();
        expect(row.className).toContain('bg-accent-subtle');
    });

    it('renders an unchecked checkbox when not selected', () => {
        renderRow({ isSelected: false });
        const checkbox = screen.getByRole('checkbox');
        expect(checkbox).not.toBeChecked();
    });

    it('calls onToggleSelect with the secret id when the checkbox is toggled', () => {
        const onToggleSelect = vi.fn();
        renderRow({ onToggleSelect });
        fireEvent.click(screen.getByRole('checkbox'));
        expect(onToggleSelect).toHaveBeenCalledWith(42);
    });

    it('calls onView with the secret when the View button is clicked', () => {
        const onView = vi.fn();
        renderRow({ onView });
        fireEvent.click(screen.getByTitle('View'));
        expect(onView).toHaveBeenCalledWith(baseSecret);
    });

    it('calls onEdit with the secret when the Edit button is clicked', () => {
        const onEdit = vi.fn();
        renderRow({ onEdit });
        fireEvent.click(screen.getByTitle('Edit'));
        expect(onEdit).toHaveBeenCalledWith(baseSecret);
    });

    it('calls onRotate with the secret when the Rotate button is clicked', () => {
        const onRotate = vi.fn();
        renderRow({ onRotate });
        fireEvent.click(screen.getByTitle('Rotate'));
        expect(onRotate).toHaveBeenCalledWith(baseSecret);
    });

    it('calls onShare with the secret when the Share button is clicked', () => {
        const onShare = vi.fn();
        renderRow({ onShare });
        fireEvent.click(screen.getByTitle('Share'));
        expect(onShare).toHaveBeenCalledWith(baseSecret);
    });

    it('calls onDelete with the secret when the Delete button is clicked', () => {
        const onDelete = vi.fn();
        renderRow({ onDelete });
        fireEvent.click(screen.getByTitle('Delete'));
        expect(onDelete).toHaveBeenCalledWith(baseSecret);
    });

    it('does not render the automated-rotation button when onAutoRotate is not provided', () => {
        renderRow();
        expect(screen.queryByTitle('Automated rotation')).not.toBeInTheDocument();
    });

    it('renders and wires the automated-rotation button when onAutoRotate is provided', () => {
        const onAutoRotate = vi.fn();
        renderRow({ onAutoRotate });
        const button = screen.getByTitle('Automated rotation');
        fireEvent.click(button);
        expect(onAutoRotate).toHaveBeenCalledWith(baseSecret);
    });

    describe('copy button states', () => {
        it('idle: shows the duplicate icon, is enabled, and is not red', () => {
            renderRow({ copyingId: null, copiedId: null, copyErrorId: null });
            const button = screen.getByTitle('Copy value');
            expect(button).not.toBeDisabled();
            expect(button.className).not.toContain('text-red-500');
            expect(button.querySelector('svg')).toBeInTheDocument();
        });

        it('in-flight: disables the button and swaps in a spinner when copyingId matches', () => {
            renderRow({ copyingId: 42 });
            const button = screen.getByTitle('Copy value');
            expect(button).toBeDisabled();
            expect(button.querySelector('.animate-spin')).toBeInTheDocument();
        });

        it('success: shows a green check icon when copiedId matches', () => {
            renderRow({ copiedId: 42 });
            const button = screen.getByTitle('Copy value');
            expect(button).not.toBeDisabled();
            const icon = button.querySelector('svg');
            expect(icon).toBeInTheDocument();
            expect(icon?.getAttribute('class')).toContain('text-green-500');
        });

        it('error: applies the red text class when copyErrorId matches', () => {
            renderRow({ copyErrorId: 42 });
            const button = screen.getByTitle('Copy value');
            expect(button.className).toContain('text-red-500');
            expect(button).not.toBeDisabled();
        });

        it("does not treat another row's in-flight/copied/error id as this row's state", () => {
            renderRow({ copyingId: 99, copiedId: 100, copyErrorId: 101 });
            const button = screen.getByTitle('Copy value');
            expect(button).not.toBeDisabled();
            expect(button.className).not.toContain('text-red-500');
            expect(button.querySelector('.animate-spin')).not.toBeInTheDocument();
        });

        it('calls onCopy with the secret when the copy button is clicked', () => {
            const onCopy = vi.fn();
            renderRow({ onCopy });
            fireEvent.click(screen.getByTitle('Copy value'));
            expect(onCopy).toHaveBeenCalledWith(baseSecret);
        });

        it('does not fire onCopy while the copy button is disabled (in-flight)', () => {
            const onCopy = vi.fn();
            renderRow({ onCopy, copyingId: 42 });
            fireEvent.click(screen.getByTitle('Copy value'));
            expect(onCopy).not.toHaveBeenCalled();
        });
    });

    it.each([
        ['password', 'Password'],
        ['api_key', 'API Key'],
        ['text', 'Text'],
        ['certificate', 'Certificate'],
        ['json', 'JSON'],
    ] as const)('renders the %s type badge with label "%s"', (type, label) => {
        renderRow({ secret: { ...baseSecret, type } });
        expect(screen.getByText(label)).toBeInTheDocument();
    });

    it('falls back to a generic badge (label = the raw type) for an unrecognized secret type', () => {
        renderRow({ secret: { ...baseSecret, type: 'mystery-type' as unknown as Secret['type'] } });
        expect(screen.getByText('Mystery-type')).toBeInTheDocument();
    });

    it('uses the light-theme colors for the type badge when the theme is light', () => {
        useUIStore.setState({ theme: 'light' });
        renderRow({ secret: { ...baseSecret, type: 'password' } });
        const badge = screen.getByText('Password');
        expect(badge.getAttribute('style')).toContain('rgb(224, 231, 255)'); // password's lightBg (#e0e7ff)
    });

    it('uses the dark-theme colors for the type badge when the theme is dark', () => {
        useUIStore.setState({ theme: 'dark' });
        renderRow({ secret: { ...baseSecret, type: 'password' } });
        const badge = screen.getByText('Password');
        expect(badge.getAttribute('style')).toContain('rgba(99, 102, 241, 0.15)'); // password's darkBg
    });

    it('uses the dark-theme colors when theme is "system" and the OS prefers dark', () => {
        vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: true } as MediaQueryList);
        useUIStore.setState({ theme: 'system' });
        renderRow({ secret: { ...baseSecret, type: 'password' } });
        const badge = screen.getByText('Password');
        expect(badge.getAttribute('style')).toContain('rgba(99, 102, 241, 0.15)'); // password's darkBg
        vi.restoreAllMocks();
    });

    it('uses the light-theme colors when theme is "system" and the OS does not prefer dark', () => {
        vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: false } as MediaQueryList);
        useUIStore.setState({ theme: 'system' });
        renderRow({ secret: { ...baseSecret, type: 'password' } });
        const badge = screen.getByText('Password');
        expect(badge.getAttribute('style')).toContain('rgb(224, 231, 255)'); // password's lightBg (#e0e7ff)
        vi.restoreAllMocks();
    });

    describe('XSS regression (WEB track backlog item 3)', () => {
        it.each(XSS_PAYLOADS)('renders a malicious secret name as inert text: %s', (payload) => {
            const { container } = renderRow({ secret: { ...baseSecret, name: payload } });
            assertPayloadRenderedSafely(payload, container);
        });

        it.each(XSS_PAYLOADS)('renders a malicious tag as inert text: %s', (payload) => {
            const { container } = renderRow({ secret: { ...baseSecret, tags: [payload] } });
            assertPayloadRenderedSafely(payload, container);
        });
    });
});

describe('SecretTableRow permission-aware actions (DEMO-UI-1)', () => {
    it('a read-only user sees View and Copy, and none of Edit / Rotate / Share / Delete', () => {
        canState.value = {
            ...canState.value,
            admin: false,
            writeSecrets: false,
            deleteSecrets: false,
            manageMembers: false,
            readAudit: false,
        };
        renderRow();
        const row = screen.getByRole('row');
        expect(within(row).getByTitle('View')).toBeInTheDocument();
        expect(within(row).getByTitle('Copy value')).toBeInTheDocument();
        for (const title of ['Edit', 'Rotate', 'Share', 'Delete']) {
            expect(within(row).queryByTitle(title), title).not.toBeInTheDocument();
        }
    });

    it('a writer who cannot delete keeps Edit / Rotate / Share but loses Delete', () => {
        canState.value = { ...canState.value, admin: false, deleteSecrets: false };
        renderRow();
        const row = screen.getByRole('row');
        for (const title of ['Edit', 'Rotate', 'Share']) expect(within(row).getByTitle(title)).toBeInTheDocument();
        expect(within(row).queryByTitle('Delete')).not.toBeInTheDocument();
    });
});
