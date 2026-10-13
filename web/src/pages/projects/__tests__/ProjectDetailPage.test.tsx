import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Routes, Route } from 'react-router';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { ProjectDetailPage } from '../ProjectDetailPage';

// Stub out every tab component ProjectDetailPage composes so these tests stay
// scoped to what the page itself owns: the project fetch loading/error states,
// header rendering, and tab routing/switching. Tab internals are covered by
// their own test files (ProjectSettingsTab, ProjectAccessReviewTab, etc.) —
// ProjectActivityTab and ProjectMembersTab are covered by sibling PRs in this
// same coverage sweep.
vi.mock('../ProjectSecretsTab', () => ({
    ProjectSecretsTab: ({ projectId }: { projectId: number }) => <div>secrets tab stub ({projectId})</div>,
}));
vi.mock('../ProjectMembersTab', () => ({
    ProjectMembersTab: ({ projectId }: { projectId: number }) => <div>members tab stub ({projectId})</div>,
}));
vi.mock('../ProjectActivityTab', () => ({
    ProjectActivityTab: ({ projectId }: { projectId: number }) => <div>activity tab stub ({projectId})</div>,
}));
vi.mock('../ProjectAccessReviewTab', () => ({
    ProjectAccessReviewTab: ({ projectId }: { projectId: number }) => <div>access review tab stub ({projectId})</div>,
}));
vi.mock('../ProjectBreakGlassTab', () => ({
    ProjectBreakGlassTab: ({ projectId }: { projectId: number }) => <div>break-glass tab stub ({projectId})</div>,
}));
vi.mock('../ProjectSettingsTab', () => ({
    ProjectSettingsTab: ({ projectId }: { projectId: number }) => <div>settings tab stub ({projectId})</div>,
}));

const { recordAccessMock } = vi.hoisted(() => ({ recordAccessMock: vi.fn() }));

vi.mock('../../../store', () => ({
    useProjectMruStore: (selector: (s: { recordAccess: (id: number) => void }) => unknown) =>
        selector({ recordAccess: recordAccessMock }),
}));

let projectQuery: { data: unknown; isLoading: boolean; isError: boolean };

const useProjectMock = vi.fn((_id: number) => projectQuery);

vi.mock('../../../features/projects/api', () => ({
    useProject: (...args: unknown[]) => useProjectMock(...args),
}));

const baseProject = {
    id: 5,
    name: 'Payments Platform',
    description: 'Handles PCI-scoped secrets for the payments team.',
    requireMfa: false,
};

// Render inside the same route shape production uses (`/projects/:id/*` in
// App.tsx) so ProjectDetailPage's internal <Routes>/relative <Link>s resolve
// the same way they do in the real app.
const renderPage = (path = '/projects/5') => {
    window.history.pushState({}, '', path);
    return render(
        <Routes>
            <Route path="/projects/:id/*" element={<ProjectDetailPage />} />
        </Routes>
    );
};

beforeEach(() => {
    // BrowserRouter reads real jsdom history — reset it so state doesn't leak
    // between tests in this file.
    window.history.pushState({}, '', '/');
    recordAccessMock.mockClear();
    useProjectMock.mockClear();
    projectQuery = { data: baseProject, isLoading: false, isError: false };
});

describe('ProjectDetailPage — loading state', () => {
    it('renders a loading skeleton and no header while the project is fetching', () => {
        projectQuery = { data: undefined, isLoading: true, isError: false };
        const { container } = renderPage();
        expect(container.querySelector('.animate-pulse')).toBeInTheDocument();
        expect(screen.queryByText('Payments Platform')).not.toBeInTheDocument();
        expect(screen.queryByText('Projects')).not.toBeInTheDocument();
    });
});

describe('ProjectDetailPage — error state', () => {
    it('shows a failure message with a Back to Projects action when the fetch errors', () => {
        projectQuery = { data: undefined, isLoading: false, isError: true };
        renderPage();
        expect(screen.getByText('Unknown')).toBeInTheDocument();
        expect(screen.getByText(/Failed to load project\./)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Back to Projects' })).toBeInTheDocument();
    });

    it('navigates to the projects list when Back to Projects is clicked', () => {
        projectQuery = { data: undefined, isLoading: false, isError: true };
        renderPage();
        fireEvent.click(screen.getByRole('button', { name: 'Back to Projects' }));
        // The click navigates away from the errored detail route entirely —
        // none of the detail-page chrome (breadcrumb) should remain.
        expect(screen.queryByText('Unknown')).not.toBeInTheDocument();
    });

    it('also renders the error state when the fetch resolves without a project (no data, no error flag)', () => {
        projectQuery = { data: undefined, isLoading: false, isError: false };
        renderPage();
        expect(screen.getByText(/Failed to load project\./)).toBeInTheDocument();
    });
});

describe('ProjectDetailPage — header', () => {
    it('renders the project name, description, and breadcrumb', () => {
        renderPage();
        expect(screen.getByRole('heading', { name: 'Payments Platform' })).toBeInTheDocument();
        expect(screen.getByText('Handles PCI-scoped secrets for the payments team.')).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Projects' })).toHaveAttribute('href', '/projects');
    });

    it('omits the description paragraph when the project has none', () => {
        projectQuery = { data: { ...baseProject, description: undefined }, isLoading: false, isError: false };
        renderPage();
        expect(screen.getByRole('heading', { name: 'Payments Platform' })).toBeInTheDocument();
        expect(screen.queryByText('Handles PCI-scoped secrets for the payments team.')).not.toBeInTheDocument();
    });

    it('records the project as recently accessed once it loads', () => {
        renderPage();
        expect(recordAccessMock).toHaveBeenCalledWith(5);
    });
});

describe('ProjectDetailPage — tab routing', () => {
    it('redirects the bare project URL to the secrets tab by default', () => {
        renderPage('/projects/5');
        expect(screen.getByText('secrets tab stub (5)')).toBeInTheDocument();
        expect(window.location.pathname).toBe('/projects/5/secrets');
    });

    it('renders the members tab when navigated directly to /members', () => {
        renderPage('/projects/5/members');
        expect(screen.getByText('members tab stub (5)')).toBeInTheDocument();
    });

    it('renders the activity tab when navigated directly to /activity', () => {
        renderPage('/projects/5/activity');
        expect(screen.getByText('activity tab stub (5)')).toBeInTheDocument();
    });

    it('renders the access review tab when navigated directly to /access-review', () => {
        renderPage('/projects/5/access-review');
        expect(screen.getByText('access review tab stub (5)')).toBeInTheDocument();
    });

    it('renders the settings tab when navigated directly to /settings', () => {
        renderPage('/projects/5/settings');
        expect(screen.getByText('settings tab stub (5)')).toBeInTheDocument();
    });

    it('redirects an unknown sub-path back to the project root (which then redirects to secrets)', () => {
        renderPage('/projects/5/not-a-real-tab');
        expect(screen.getByText('secrets tab stub (5)')).toBeInTheDocument();
        expect(window.location.pathname).toBe('/projects/5/secrets');
    });

    it('switches tabs when a different tab link is clicked', () => {
        renderPage('/projects/5/secrets');
        expect(screen.getByText('secrets tab stub (5)')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('link', { name: 'Settings' }));

        expect(screen.getByText('settings tab stub (5)')).toBeInTheDocument();
        expect(screen.queryByText('secrets tab stub (5)')).not.toBeInTheDocument();
        expect(window.location.pathname).toBe('/projects/5/settings');
    });

    it('marks the active tab link distinctly from inactive ones', () => {
        renderPage('/projects/5/members');
        const membersLink = screen.getByRole('link', { name: 'Members' });
        const secretsLink = screen.getByRole('link', { name: 'Secrets' });
        // Active tab uses the accent border/text color tokens; inactive tabs
        // use transparent border + secondary text. We only assert they differ
        // rather than pinning exact CSS var values.
        expect(membersLink.style.borderBottomColor).not.toBe(secretsLink.style.borderBottomColor);
    });

    it('renders all five tab labels in the nav', () => {
        renderPage('/projects/5/secrets');
        const nav = screen.getByRole('link', { name: 'Secrets' }).closest('div');
        expect(nav).not.toBeNull();
        const scoped = within(nav as HTMLElement);
        ['Secrets', 'Members', 'Activity', 'Access Review', 'Break-glass', 'Settings'].forEach((label) => {
            expect(scoped.getByRole('link', { name: label })).toBeInTheDocument();
        });
    });
});

describe('ProjectDetailPage — project id parsing', () => {
    it('passes the numeric id parsed from the URL to useProject and the tabs', () => {
        renderPage('/projects/42/secrets');
        expect(useProjectMock).toHaveBeenCalledWith(42);
        expect(screen.getByText('secrets tab stub (42)')).toBeInTheDocument();
    });
});
