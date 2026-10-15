import React from 'react';

export interface LoadMoreProps {
    loaded: number;
    total?: number | undefined;
    totalExact: boolean;
    hasMore: boolean;
    isLoadingMore: boolean;
    onLoadMore: () => void;
}

// Keyset paging (docs/specs/audit-list-keyset.md): the server hands out the next
// page after the last loaded row, so the list grows by "Load more" instead of
// jumping to page N. The total is exact up to 10,000 and shown as "10,000+" above.
export const LoadMore: React.FC<LoadMoreProps> = ({
    loaded,
    total,
    totalExact,
    hasMore,
    isLoadingMore,
    onLoadMore,
}) => {
    if (loaded === 0 && !hasMore) return null;
    let of = '';
    if (total !== undefined) of = ` of ${total.toLocaleString()}${totalExact ? '' : '+'}`;
    return (
        <div className="px-5 py-3 border-t border-base flex items-center justify-between">
            <span className="text-xs text-base-muted tabular-nums" data-testid="audit-loaded-count">
                Showing {loaded.toLocaleString()}
                {of} events
            </span>
            {hasMore && (
                <button
                    type="button"
                    onClick={onLoadMore}
                    disabled={isLoadingMore}
                    className="px-3 py-1.5 rounded-md text-xs border border-base bg-surface text-base-secondary hover:bg-subtle disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                    {isLoadingMore ? 'Loading…' : 'Load more'}
                </button>
            )}
        </div>
    );
};
