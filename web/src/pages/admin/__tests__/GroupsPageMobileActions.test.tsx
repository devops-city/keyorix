import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { GroupsPage } from '../GroupsPage';

// jsdom has no layout, so this pins the CSS contract that keeps the Actions column
// reachable on a phone (DEMO-WALK-4 finding 3); the 390 px geometry itself is checked
// by e2e/admin-tables-mobile.spec.ts.
vi.mock('../../../features/admin', () => ({
    useGroups: () => ({
        data: { groups: [{ id: 1, name: 'platform-team', description: 'd', member_count: 2 }] },
        isLoading: false,
        error: null,
    }),
    useRoles: () => ({ data: [], isLoading: false }),
    useGroupRoles: () => ({ data: { roles: [] } }),
    useGroupSharedSecrets: () => ({ data: undefined, isLoading: false }),
    useCreateGroup: () => ({ mutate: vi.fn(), reset: vi.fn() }),
    useUpdateGroup: () => ({ mutate: vi.fn(), reset: vi.fn() }),
    useDeleteGroup: () => ({ mutate: vi.fn(), reset: vi.fn() }),
    useAssignRoleToGroup: () => ({ mutate: vi.fn() }),
    useRemoveRoleFromGroup: () => ({ mutate: vi.fn() }),
}));
vi.mock('../../../features/projects/api', () => ({
    useProjects: () => ({ data: [] }),
    useProjectEnvironments: () => ({ data: undefined }),
}));

describe('GroupsPage on a narrow screen', () => {
    it('scrolls inside the card (not clipped) and pins the Actions column', () => {
        render(<GroupsPage />);
        const table = screen.getByTestId('groups-table');
        expect(table.parentElement).toHaveClass('overflow-x-auto');
        expect(table.parentElement).not.toHaveClass('overflow-hidden');
        const headerCell = screen.getByRole('columnheader', { name: 'Actions' });
        expect(headerCell).toHaveClass('sticky', 'right-0');
        const editCell = screen.getByTitle('Edit group').closest('td');
        expect(editCell).toHaveClass('sticky', 'right-0');
    });
});
