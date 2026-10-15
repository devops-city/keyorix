import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { Layout, Page } from '../Layout';

// Layout composes Header/Sidebar/Footer/Breadcrumb/ImpersonationBanner/CmdKSearch.
// Sibling agents are covering those components' own internals in parallel, so
// they're stubbed here as trivial components — these tests only exercise
// Layout's own composition and the sidebar-open/cmdk-open state it owns.
vi.mock('../Header', () => ({
    Header: ({ onMenuClick }: { onMenuClick: () => void }) => (
        <button type="button" onClick={onMenuClick}>
            open-sidebar-trigger
        </button>
    ),
}));

vi.mock('../Sidebar', () => ({
    Sidebar: ({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
        <div data-testid="sidebar-stub" data-open={isOpen}>
            <button type="button" onClick={onClose}>
                close-sidebar-trigger
            </button>
        </div>
    ),
}));

vi.mock('../Footer', () => ({
    Footer: () => <div data-testid="footer-stub">footer stub</div>,
}));

vi.mock('../Breadcrumb', () => ({
    Breadcrumb: ({ items }: { items: { name: string }[] }) => (
        <nav data-testid="breadcrumb-stub">{items.map((item) => item.name).join(' / ')}</nav>
    ),
}));

vi.mock('../ImpersonationBanner', () => ({
    ImpersonationBanner: () => <div data-testid="impersonation-banner-stub">impersonation banner stub</div>,
}));

vi.mock('../AuditReadsSkippedBanner', () => ({
    AuditReadsSkippedBanner: () => <div data-testid="audit-reads-skipped-banner-stub">audit reads banner stub</div>,
}));

vi.mock('../../ui/CmdKSearch', () => ({
    CmdKSearch: ({ onClose }: { onClose: () => void }) => (
        <div data-testid="cmdk-search-stub">
            cmdk stub
            <button type="button" onClick={onClose}>
                close-cmdk-trigger
            </button>
        </div>
    ),
}));

describe('Layout', () => {
    it('renders the header, sidebar, footer, impersonation banner, and routed content', () => {
        render(
            <Layout>
                <div data-testid="page-content">page content</div>
            </Layout>
        );

        expect(screen.getByText('open-sidebar-trigger')).toBeInTheDocument();
        expect(screen.getByTestId('sidebar-stub')).toBeInTheDocument();
        expect(screen.getByTestId('footer-stub')).toBeInTheDocument();
        expect(screen.getByTestId('impersonation-banner-stub')).toBeInTheDocument();
        expect(screen.getByTestId('audit-reads-skipped-banner-stub')).toBeInTheDocument();
        expect(screen.getByTestId('page-content')).toBeInTheDocument();
    });

    it('keeps the impersonation banner and header stuck to the viewport top as a unit', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        // Regression guard for web-layout-extras#0: the banner (and the header
        // below it) must stay pinned while scrolling a tall page, not just be
        // laid out in normal flow above a scrolling body.
        const banner = screen.getByTestId('impersonation-banner-stub');
        const stickyWrapper = banner.parentElement;
        expect(stickyWrapper).toHaveClass('sticky', 'top-0');
        expect(stickyWrapper).toContainElement(screen.getByText('open-sidebar-trigger'));
    });

    it('does not render a breadcrumb when no breadcrumbs prop is passed', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        expect(screen.queryByTestId('breadcrumb-stub')).not.toBeInTheDocument();
    });

    it('does not render a breadcrumb when breadcrumbs is an empty array', () => {
        render(
            <Layout breadcrumbs={[]}>
                <div>content</div>
            </Layout>
        );

        expect(screen.queryByTestId('breadcrumb-stub')).not.toBeInTheDocument();
    });

    it('renders the breadcrumb with the given items when breadcrumbs is non-empty', () => {
        render(
            <Layout
                breadcrumbs={[
                    { name: 'Projects', href: '/projects' },
                    { name: 'Detail', current: true },
                ]}
            >
                <div>content</div>
            </Layout>
        );

        expect(screen.getByTestId('breadcrumb-stub')).toHaveTextContent('Projects / Detail');
    });

    it('renders the footer by default (showFooter defaults to true)', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        expect(screen.getByTestId('footer-stub')).toBeInTheDocument();
    });

    it('hides the footer when showFooter is false', () => {
        render(
            <Layout showFooter={false}>
                <div>content</div>
            </Layout>
        );

        expect(screen.queryByTestId('footer-stub')).not.toBeInTheDocument();
    });

    it('applies the className prop to the page-content wrapper', () => {
        render(
            <Layout className="custom-page-class">
                <div data-testid="page-content">content</div>
            </Layout>
        );

        const wrapper = screen.getByTestId('page-content').parentElement;
        expect(wrapper).toHaveClass('flex-1', 'custom-page-class');
    });

    it('starts with the sidebar closed', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        expect(screen.getByTestId('sidebar-stub')).toHaveAttribute('data-open', 'false');
    });

    it('opens the sidebar when the header menu trigger is clicked', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.click(screen.getByText('open-sidebar-trigger'));

        expect(screen.getByTestId('sidebar-stub')).toHaveAttribute('data-open', 'true');
    });

    it('closes the sidebar when the sidebar close trigger is invoked', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.click(screen.getByText('open-sidebar-trigger'));
        expect(screen.getByTestId('sidebar-stub')).toHaveAttribute('data-open', 'true');

        fireEvent.click(screen.getByText('close-sidebar-trigger'));
        expect(screen.getByTestId('sidebar-stub')).toHaveAttribute('data-open', 'false');
    });

    it('does not render the Cmd-K search overlay by default', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        expect(screen.queryByTestId('cmdk-search-stub')).not.toBeInTheDocument();
    });

    it('opens the Cmd-K search overlay on Ctrl+K', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });

        expect(screen.getByTestId('cmdk-search-stub')).toBeInTheDocument();
    });

    it('opens the Cmd-K search overlay on Cmd+K (metaKey)', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'k', metaKey: true });

        expect(screen.getByTestId('cmdk-search-stub')).toBeInTheDocument();
    });

    it('toggles the Cmd-K search overlay closed on a second Ctrl+K', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
        expect(screen.getByTestId('cmdk-search-stub')).toBeInTheDocument();

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
        expect(screen.queryByTestId('cmdk-search-stub')).not.toBeInTheDocument();
    });

    it('closes the Cmd-K search overlay when its onClose is invoked', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
        expect(screen.getByTestId('cmdk-search-stub')).toBeInTheDocument();

        fireEvent.click(screen.getByText('close-cmdk-trigger'));

        expect(screen.queryByTestId('cmdk-search-stub')).not.toBeInTheDocument();
    });

    it('ignores keydown events for keys other than k', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'j', ctrlKey: true });

        expect(screen.queryByTestId('cmdk-search-stub')).not.toBeInTheDocument();
    });

    it('removes the keydown listener on unmount', () => {
        const removeEventListenerSpy = vi.spyOn(window, 'removeEventListener');

        const { unmount } = render(
            <Layout>
                <div>content</div>
            </Layout>
        );
        unmount();

        expect(removeEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function));
        removeEventListenerSpy.mockRestore();
    });
});

describe('Page', () => {
    it('renders its children', () => {
        render(
            <Page>
                <div data-testid="page-child">child content</div>
            </Page>
        );

        expect(screen.getByTestId('page-child')).toBeInTheDocument();
    });

    it('renders no header block at all when title, subtitle, and actions are all omitted', () => {
        const { container } = render(
            <Page>
                <div>child content</div>
            </Page>
        );

        expect(container.querySelector('h1')).not.toBeInTheDocument();
        expect(container.querySelector('.mb-8')).not.toBeInTheDocument();
    });

    it('renders the title as an h1 when provided', () => {
        render(
            <Page title="Page Title">
                <div>child content</div>
            </Page>
        );

        expect(screen.getByRole('heading', { level: 1, name: 'Page Title' })).toBeInTheDocument();
    });

    it('does not render an h1 when title is omitted', () => {
        render(
            <Page subtitle="Just a subtitle">
                <div>child content</div>
            </Page>
        );

        expect(screen.queryByRole('heading', { level: 1 })).not.toBeInTheDocument();
        expect(screen.getByText('Just a subtitle')).toBeInTheDocument();
    });

    it('renders the subtitle when provided', () => {
        render(
            <Page title="Title" subtitle="A helpful subtitle">
                <div>child content</div>
            </Page>
        );

        expect(screen.getByText('A helpful subtitle')).toBeInTheDocument();
    });

    it('does not render a subtitle paragraph when omitted', () => {
        render(
            <Page title="Title only">
                <div>child content</div>
            </Page>
        );

        expect(screen.queryByText(/subtitle/i)).not.toBeInTheDocument();
    });

    it('renders actions when provided, alongside the header', () => {
        render(
            <Page title="Title" actions={<button type="button">Do Thing</button>}>
                <div>child content</div>
            </Page>
        );

        expect(screen.getByRole('button', { name: 'Do Thing' })).toBeInTheDocument();
    });

    it('renders a header block for actions alone, even without a title or subtitle', () => {
        const { container } = render(
            <Page actions={<button type="button">Only Action</button>}>
                <div>child content</div>
            </Page>
        );

        expect(screen.getByRole('button', { name: 'Only Action' })).toBeInTheDocument();
        expect(container.querySelector('.mb-8')).toBeInTheDocument();
    });

    it('does not render an actions wrapper when actions are omitted', () => {
        const { container } = render(
            <Page title="Title">
                <div>child content</div>
            </Page>
        );

        expect(container.querySelector('.md\\:ml-4')).not.toBeInTheDocument();
    });

    it('applies a custom className to the outer wrapper', () => {
        const { container } = render(
            <Page className="custom-page-class">
                <div>child content</div>
            </Page>
        );

        expect(container.firstChild).toHaveClass('custom-page-class');
    });
});
