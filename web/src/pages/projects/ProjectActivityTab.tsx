import React, { useState } from 'react';
import { DocumentTextIcon, ChevronLeftIcon, ChevronRightIcon } from '@heroicons/react/24/outline';
import { useAuditLog } from '../../features/audit/api';
import { Button } from '../../components/ui/Button';
import { parseServerDate } from '../../utils';
import { eventLabel } from '../../utils/eventLabels';
import { formatDateTime } from '../../utils/datetime';
import { useAuditNames } from '../../features/audit/useAuditNames';

interface ProjectActivityTabProps {
    projectId: number;
}

const EVENT_BADGE: Record<string, { bg: string; text: string }> = {
    'secret.created': { bg: 'var(--success-subtle)', text: 'var(--success)' },
    'secret.updated': { bg: 'var(--warning-subtle)', text: 'var(--warning)' },
    'secret.deleted': { bg: 'var(--error-subtle)', text: 'var(--error)' },
    'secret.rotated': { bg: 'var(--warning-subtle)', text: 'var(--warning)' },
    'secret.read': { bg: 'var(--accent-subtle)', text: 'var(--accent-text)' },
    'secret.versions_listed': { bg: 'var(--bg-muted)', text: 'var(--text-muted)' },
    'secret.metadata_read': { bg: 'var(--bg-muted)', text: 'var(--text-muted)' },
    'auth.login': { bg: 'var(--bg-muted)', text: 'var(--text-muted)' },
    'auth.logout': { bg: 'var(--bg-muted)', text: 'var(--text-muted)' },
};

function badgeStyle(eventType: string) {
    return EVENT_BADGE[eventType] ?? { bg: 'var(--bg-muted)', text: 'var(--text-secondary)' };
}

function relativeTime(ts: string): string {
    const diff = Date.now() - parseServerDate(ts).getTime();
    const mins = Math.floor(diff / 60_000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return formatDateTime(ts);
}

/**
 * Phase 3E — Activity tab.
 * Shows audit log events filtered by project_id.
 */
export const ProjectActivityTab: React.FC<ProjectActivityTabProps> = ({ projectId }) => {
    const [page, setPage] = useState(1);
    const PAGE_SIZE = 25;

    const { data, isLoading, isError } = useAuditLog({
        projectId,
        page,
        pageSize: PAGE_SIZE,
    });

    const resolveNames = useAuditNames();
    const events = data?.data ?? [];
    const totalPages = data?.totalPages ?? 1;

    const loadingContent = (
        <div className="p-6 space-y-3">
            {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="flex items-center gap-3 animate-pulse">
                    <div className="h-5 w-24 rounded-full" style={{ backgroundColor: 'var(--bg-muted)' }} />
                    <div className="h-3 flex-1 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                    <div className="h-3 w-16 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                </div>
            ))}
        </div>
    );

    const errorContent = (
        <div className="p-6 text-center">
            <p className="text-sm" style={{ color: 'var(--error)' }}>
                Failed to load activity.
            </p>
        </div>
    );

    const emptyContent = (
        <div className="p-10 text-center">
            <DocumentTextIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
            <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                No activity yet
            </p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Events will appear here when secrets in this project are accessed or modified.
            </p>
        </div>
    );

    const tableContent = (
        <>
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y" style={{ borderColor: 'var(--border)' }}>
                    <thead style={{ backgroundColor: 'var(--bg-subtle)' }}>
                        <tr>
                            {['Event', 'Actor', 'Description', 'Time'].map((h) => (
                                <th
                                    key={h}
                                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider"
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    {h}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                        {events.map((ev) => {
                            const badge = badgeStyle(ev.event_type);
                            return (
                                <tr key={ev.id}>
                                    <td className="px-4 py-3 whitespace-nowrap">
                                        <span
                                            className="text-xs font-medium px-2 py-0.5 rounded-full"
                                            style={{ backgroundColor: badge.bg, color: badge.text }}
                                        >
                                            {eventLabel(ev.event_type)}
                                        </span>
                                    </td>
                                    <td
                                        className="px-4 py-3 text-sm whitespace-nowrap"
                                        style={{ color: 'var(--text-secondary)' }}
                                    >
                                        {ev.actor || '—'}
                                    </td>
                                    <td
                                        className="px-4 py-3 text-sm max-w-xs truncate"
                                        style={{ color: 'var(--text-secondary)' }}
                                    >
                                        {resolveNames(ev.event_type, ev.description) || '—'}
                                    </td>
                                    <td
                                        className="px-4 py-3 text-xs whitespace-nowrap"
                                        style={{ color: 'var(--text-muted)' }}
                                        title={formatDateTime(ev.timestamp, { seconds: true })}
                                    >
                                        {relativeTime(ev.timestamp)}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>

            {totalPages > 1 && (
                <div
                    className="px-4 py-3 border-t flex items-center justify-between"
                    style={{ borderColor: 'var(--border)' }}
                >
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        Page {page} of {totalPages}
                    </p>
                    <div className="flex items-center gap-2">
                        <Button variant="outline" size="sm" onClick={() => setPage((p) => p - 1)} disabled={page === 1}>
                            <ChevronLeftIcon className="h-4 w-4" />
                        </Button>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setPage((p) => p + 1)}
                            disabled={page === totalPages}
                        >
                            <ChevronRightIcon className="h-4 w-4" />
                        </Button>
                    </div>
                </div>
            )}
        </>
    );

    const eventsContent = events.length === 0 ? emptyContent : tableContent;
    const nonLoadingContent = isError ? errorContent : eventsContent;
    const bodyContent = isLoading ? loadingContent : nonLoadingContent;

    return (
        <div>
            <div className="mb-4">
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                    Activity
                </h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    Audit events for this project.
                </p>
            </div>

            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                {bodyContent}
            </div>
        </div>
    );
};
