import React, { useState } from 'react';
import { Link, useParams, useNavigate, Routes, Route, Navigate, useLocation } from 'react-router';
import { ChevronRightIcon, FolderIcon, PencilSquareIcon } from '@heroicons/react/24/outline';
import { useProject } from '../../features/projects/api';
import { ProjectSecretsTab } from './ProjectSecretsTab';
import { ProjectMembersTab } from './ProjectMembersTab';
import { ProjectActivityTab } from './ProjectActivityTab';
import { ProjectAccessReviewTab } from './ProjectAccessReviewTab';
import { ProjectSettingsTab } from './ProjectSettingsTab';
import { EditProjectModal } from './EditProjectModal';
import { ROUTES } from '../../constants';
import { useProjectMruStore } from '../../store';

// ── Tab definition ───────────────────────────────────────────────────────────

interface Tab {
    id: string;
    label: string;
    path: string;
}

const TABS: Tab[] = [
    { id: 'secrets', label: 'Secrets', path: '/secrets' },
    { id: 'members', label: 'Members', path: '/members' },
    { id: 'activity', label: 'Activity', path: '/activity' },
    { id: 'access-review', label: 'Access Review', path: '/access-review' },
    { id: 'settings', label: 'Settings', path: '/settings' },
];

// ── Breadcrumb ───────────────────────────────────────────────────────────────

const Breadcrumb: React.FC<{ projectName: string }> = ({ projectName }) => (
    <nav className="flex items-center gap-1.5 text-sm mb-5" style={{ color: 'var(--text-muted)' }}>
        <Link to={ROUTES.PROJECTS} className="hover:underline" style={{ color: 'var(--text-secondary)' }}>
            Projects
        </Link>
        <ChevronRightIcon className="h-3.5 w-3.5 shrink-0" />
        <span style={{ color: 'var(--text-primary)' }}>{projectName}</span>
    </nav>
);

// ── TabNav ───────────────────────────────────────────────────────────────────

const TabNav: React.FC<{ projectId: number }> = ({ projectId }) => {
    const location = useLocation();
    const base = `/projects/${projectId}`;

    const isActive = (tab: Tab) => location.pathname.startsWith(`${base}${tab.path}`);

    return (
        // The border sits on the wrapper and the scrolling happens in the inner nav: on a phone the
        // five tabs are wider than the screen, so the strip scrolls inside itself instead of widening
        // the page (#3154). The nav overlaps the wrapper's border by 1px (-mb-px), as ProfilePage does.
        <div className="border-b mb-6" style={{ borderColor: 'var(--border)' }}>
            <nav className="-mb-px flex gap-1 overflow-x-auto">
                {TABS.map((tab) => {
                    const active = isActive(tab);
                    return (
                        <Link
                            key={tab.id}
                            to={`${base}${tab.path}`}
                            className="px-4 py-2.5 text-sm font-medium border-b-2 transition-colors duration-100 shrink-0 whitespace-nowrap"
                            style={{
                                borderBottomColor: active ? 'var(--accent)' : 'transparent',
                                color: active ? 'var(--accent-text)' : 'var(--text-secondary)',
                            }}
                        >
                            {tab.label}
                        </Link>
                    );
                })}
            </nav>
        </div>
    );
};

// ── ProjectDetailPage ────────────────────────────────────────────────────────

export const ProjectDetailPage: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const projectId = Number(id);
    const navigate = useNavigate();
    const { data: project, isLoading, isError } = useProject(projectId);
    const recordAccess = useProjectMruStore((s) => s.recordAccess);
    const [editing, setEditing] = useState(false);

    // Record this project as recently accessed once it loads (drives the
    // sidebar switcher's Recent ordering — ADR-018). Captures both
    // switcher-driven and direct-URL navigation.
    React.useEffect(() => {
        if (project) recordAccess(project.id);
    }, [project, recordAccess]);

    if (isLoading) {
        return (
            <div className="p-6 max-w-5xl mx-auto animate-pulse">
                <div className="h-4 w-32 rounded-sm mb-5" style={{ backgroundColor: 'var(--bg-muted)' }} />
                <div className="h-8 w-56 rounded-sm mb-6" style={{ backgroundColor: 'var(--bg-muted)' }} />
            </div>
        );
    }

    if (isError || !project) {
        return (
            <div className="p-6 max-w-5xl mx-auto">
                <Breadcrumb projectName="Unknown" />
                <div
                    className="rounded-lg px-4 py-3 text-sm"
                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                >
                    Failed to load project.{' '}
                    <button type="button" onClick={() => navigate(ROUTES.PROJECTS)} className="underline">
                        Back to Projects
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="p-6 max-w-5xl mx-auto">
            <Breadcrumb projectName={project.name} />

            {/* Project header */}
            <div className="flex items-center gap-3 mb-6">
                <div
                    className="h-10 w-10 rounded-lg flex items-center justify-center shrink-0"
                    style={{ backgroundColor: 'var(--accent-subtle)' }}
                >
                    <FolderIcon className="h-5 w-5" style={{ color: 'var(--accent)' }} />
                </div>
                <div>
                    <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                        {project.name}
                    </h1>
                    {project.description && (
                        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                            {project.description}
                        </p>
                    )}
                </div>
                <button
                    type="button"
                    onClick={() => setEditing(true)}
                    className="ml-auto inline-flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg transition-colors shrink-0"
                    style={{
                        color: 'var(--text-secondary)',
                        backgroundColor: 'var(--bg-subtle)',
                        border: '1px solid var(--border)',
                    }}
                    title="Edit project"
                >
                    <PencilSquareIcon className="h-4 w-4" />
                    Edit
                </button>
            </div>

            <TabNav projectId={projectId} />

            <Routes>
                <Route index element={<Navigate to="secrets" replace />} />
                <Route path="secrets" element={<ProjectSecretsTab projectId={projectId} />} />
                <Route path="members" element={<ProjectMembersTab projectId={projectId} />} />
                <Route path="activity" element={<ProjectActivityTab projectId={projectId} />} />
                <Route path="access-review" element={<ProjectAccessReviewTab projectId={projectId} />} />
                <Route path="settings" element={<ProjectSettingsTab projectId={projectId} />} />
                <Route path="*" element={<Navigate to={`/projects/${projectId}`} replace />} />
            </Routes>

            {editing && <EditProjectModal project={project} onClose={() => setEditing(false)} />}
        </div>
    );
};
