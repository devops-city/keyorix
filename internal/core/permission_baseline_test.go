package core

import (
	"context"
	"errors"
	"testing"
	"time"

	stg "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newBaselineCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store, now: time.Now}
}

// userFilterPageSize matches any UserFilter with the given PageSize AND
// IncludeDeleted: true (other fields may be zero) — GetPermissionBaseline must
// request soft-deleted users too (#G25), or a soft-deleted grant holder's row
// never reaches userByID in the first place.
func userFilterPageSize(n int) any {
	return mock.MatchedBy(func(f *stg.UserFilter) bool {
		return f != nil && f.PageSize == n && f.IncludeDeleted
	})
}

func TestGetPermissionBaseline_Empty(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{}, int64(0), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).Return([]stg.UserGroupMembership{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	assert.Empty(t, baseline.Rows)
}

func TestGetPermissionBaseline_DirectGrant_GlobalScope(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	user := &models.User{ID: 10, Username: "alice", Email: "alice@example.com"}
	grant := &models.UserRole{UserID: 10, RoleID: 5, ProjectID: 0}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{user}, int64(1), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{grant}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{}, nil)
	store.On("GetRole", mock.Anything, uint(5)).Return(&models.Role{ID: 5, Name: "Admin"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(5)).
		Return([]*models.Permission{{Name: "secrets.read"}, {Name: "secrets.write"}}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).Return([]stg.UserGroupMembership{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	assert.Len(t, baseline.Rows, 2)

	row := baseline.Rows[0]
	assert.Equal(t, uint(10), row.UserID)
	assert.Equal(t, "alice", row.Username)
	assert.Equal(t, "alice@example.com", row.Email)
	assert.Equal(t, "Admin", row.RoleName)
	assert.Equal(t, "global", row.Scope)
	assert.False(t, row.GrantExpired)
	assert.False(t, row.HolderDeleted)
}

func TestGetPermissionBaseline_DirectGrant_ProjectScope(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	user := &models.User{ID: 11, Username: "bob", Email: "bob@example.com"}
	grant := &models.UserRole{UserID: 11, RoleID: 7, ProjectID: 3}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{user}, int64(1), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{grant}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{}, nil)
	store.On("GetRole", mock.Anything, uint(7)).Return(&models.Role{ID: 7, Name: "Viewer"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(7)).
		Return([]*models.Permission{{Name: "secrets.read"}}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).Return([]stg.UserGroupMembership{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	require.Len(t, baseline.Rows, 1)
	assert.Equal(t, "project:3", baseline.Rows[0].Scope)
}

// TestGetPermissionBaseline_DirectGrant_EnvironmentScope covers #G25 gap 3 for
// the DIRECT-grant path: a grant scoped to one environment within a project
// must not be reported as applying to the whole project.
func TestGetPermissionBaseline_DirectGrant_EnvironmentScope(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	user := &models.User{ID: 15, Username: "frank", Email: "frank@example.com"}
	grant := &models.UserRole{UserID: 15, RoleID: 7, ProjectID: 3, EnvironmentID: 9}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{user}, int64(1), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{grant}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{}, nil)
	store.On("GetRole", mock.Anything, uint(7)).Return(&models.Role{ID: 7, Name: "Viewer"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(7)).
		Return([]*models.Permission{{Name: "secrets.read"}}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).Return([]stg.UserGroupMembership{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	require.Len(t, baseline.Rows, 1)
	assert.Equal(t, "project:3/environment:9", baseline.Rows[0].Scope)
}

func TestGetPermissionBaseline_GroupInheritedGrant(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	user := &models.User{ID: 12, Username: "carol", Email: "carol@example.com"}
	groupGrant := &models.GroupRole{GroupID: 20, RoleID: 9}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{user}, int64(1), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{groupGrant}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).
		Return([]stg.UserGroupMembership{{UserID: 12, GroupID: 20}}, nil)
	store.On("GetRole", mock.Anything, uint(9)).Return(&models.Role{ID: 9, Name: "Operator"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(9)).
		Return([]*models.Permission{{Name: "audit.read"}}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	require.Len(t, baseline.Rows, 1)
	row := baseline.Rows[0]
	assert.Equal(t, "carol", row.Username)
	assert.Equal(t, "Operator", row.RoleName)
	assert.Equal(t, "global", row.Scope)
	assert.Equal(t, "audit.read", row.Permission)
}

// TestGetPermissionBaseline_GroupInheritedGrant_EnvironmentScope covers #G25
// gap 3 for the GROUP-inherited path: the old code hardcoded every
// group-inherited row's scope to "global" regardless of the group_roles row's
// actual project/environment. A group holding a role scoped to one
// environment must report that real (narrower) scope, not "global".
func TestGetPermissionBaseline_GroupInheritedGrant_EnvironmentScope(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	user := &models.User{ID: 16, Username: "grace", Email: "grace@example.com"}
	groupGrant := &models.GroupRole{GroupID: 21, RoleID: 9, ProjectID: 5, EnvironmentID: 2}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{user}, int64(1), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{groupGrant}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).
		Return([]stg.UserGroupMembership{{UserID: 16, GroupID: 21}}, nil)
	store.On("GetRole", mock.Anything, uint(9)).Return(&models.Role{ID: 9, Name: "Operator"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(9)).
		Return([]*models.Permission{{Name: "audit.read"}}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	require.Len(t, baseline.Rows, 1)
	assert.Equal(t, "project:5/environment:2", baseline.Rows[0].Scope)
}

func TestGetPermissionBaseline_RolePermissionsCached(t *testing.T) {
	t.Parallel()
	// Two grants with the same roleID should only call GetRolePermissions once.
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	u1 := &models.User{ID: 13, Username: "dave", Email: "dave@example.com"}
	u2 := &models.User{ID: 14, Username: "eve", Email: "eve@example.com"}
	grant1 := &models.UserRole{UserID: 13, RoleID: 5, ProjectID: 0}
	grant2 := &models.UserRole{UserID: 14, RoleID: 5, ProjectID: 0}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{u1, u2}, int64(2), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{grant1, grant2}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{}, nil)
	store.On("GetRole", mock.Anything, uint(5)).Return(&models.Role{ID: 5, Name: "Admin"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(5)).
		Return([]*models.Permission{{Name: "secrets.read"}}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).Return([]stg.UserGroupMembership{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	assert.Len(t, baseline.Rows, 2)
	// GetRolePermissions should have been called exactly once for the cached role.
	store.AssertNumberOfCalls(t, "GetRolePermissions", 1)
	// #G44: ListAllUserGroupMemberships must be called exactly once — the whole
	// point of the batch-load fix is NOT one GetUserGroups call per user.
	store.AssertNumberOfCalls(t, "ListAllUserGroupMemberships", 1)
}

func TestGetPermissionBaseline_SkipsGrantsForMissingUsers(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	// Grant references userID 99, which is not returned even by an
	// IncludeDeleted: true ListUsers call — a genuinely orphaned grant (never a
	// merely soft-deleted user), which must still be skipped since there's no
	// username/email to report.
	grant := &models.UserRole{UserID: 99, RoleID: 5, ProjectID: 0}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{}, int64(0), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{grant}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).Return([]stg.UserGroupMembership{}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	assert.Empty(t, baseline.Rows)
}

func TestGetPermissionBaseline_ListUsersError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return(nil, int64(0), errors.New("db error"))

	_, err := c.GetPermissionBaseline(ctx)
	require.Error(t, err)
}

func TestGetPermissionBaseline_ListGrantsError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{}, int64(0), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return(nil, errors.New("grants error"))

	_, err := c.GetPermissionBaseline(ctx)
	require.Error(t, err)
}

func TestGetPermissionBaseline_ListGroupGrantsError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{}, int64(0), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return(nil, errors.New("group grants error"))

	_, err := c.GetPermissionBaseline(ctx)
	require.Error(t, err)
}

func TestGetPermissionBaseline_ListUserGroupMembershipsError(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{}, int64(0), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).Return(nil, errors.New("membership error"))

	_, err := c.GetPermissionBaseline(ctx)
	require.Error(t, err)
}

// TestGetPermissionBaseline_BatchLoadsMembershipOnceForManyUsers is the
// regression test for #G44: group-inherited grant resolution used to call
// GetUserGroups once PER USER. With three users — one in two admin-conferring
// groups, one in a single group, one in no group at all — ListAllUserGroupMemberships
// must be called exactly ONCE (not three times), and each user's rows must
// still resolve to exactly their own group memberships, not another user's.
func TestGetPermissionBaseline_BatchLoadsMembershipOnceForManyUsers(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	userMultiGroup := &models.User{ID: 60, Username: "multi", Email: "multi@example.com"}
	userOneGroup := &models.User{ID: 61, Username: "one", Email: "one@example.com"}
	userNoGroup := &models.User{ID: 62, Username: "none", Email: "none@example.com"}

	groupGrantA := &models.GroupRole{GroupID: 70, RoleID: 90}
	groupGrantB := &models.GroupRole{GroupID: 71, RoleID: 91}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{userMultiGroup, userOneGroup, userNoGroup}, int64(3), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).Return([]*models.UserRole{}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{groupGrantA, groupGrantB}, nil)
	store.On("ListAllUserGroupMemberships", mock.Anything).Return([]stg.UserGroupMembership{
		{UserID: 60, GroupID: 70},
		{UserID: 60, GroupID: 71},
		{UserID: 61, GroupID: 70},
	}, nil)
	store.On("GetRole", mock.Anything, uint(90)).Return(&models.Role{ID: 90, Name: "RoleA"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(90)).
		Return([]*models.Permission{{Name: "perm.a"}}, nil)
	store.On("GetRole", mock.Anything, uint(91)).Return(&models.Role{ID: 91, Name: "RoleB"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(91)).
		Return([]*models.Permission{{Name: "perm.b"}}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	store.AssertNumberOfCalls(t, "ListAllUserGroupMemberships", 1)

	rowsByUser := make(map[uint][]PermissionBaselineRow)
	for _, row := range baseline.Rows {
		rowsByUser[row.UserID] = append(rowsByUser[row.UserID], row)
	}
	require.Len(t, rowsByUser[60], 2, "user in two groups gets both groups' rows")
	require.Len(t, rowsByUser[61], 1, "user in one group gets only that group's row")
	assert.Empty(t, rowsByUser[62], "user in no group gets no group-inherited rows")
}

func TestScopeLabel(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "global", scopeLabel(0, 0))
	assert.Equal(t, "project:7", scopeLabel(7, 0))
	assert.Equal(t, "project:100", scopeLabel(100, 0))
	assert.Equal(t, "project:7/environment:3", scopeLabel(7, 3))
}

// TestGetPermissionBaseline_G25Regression is the detection_idea fixture for
// #G25: a soft-deleted grant holder, an expired time-bound grant, and an
// environment-scoped group role, all in the same baseline export. Every gap
// the ad hoc GetPermissionBaseline independently had is exercised at once:
//
//   - user A is soft-deleted but still holds a (permanent) direct grant — the
//     old code silently dropped this row entirely; it must now appear, with
//     HolderDeleted true.
//   - user B holds a direct grant whose ExpiresAt is in the past — the old
//     code included it (deliberately — full history) but with no way to tell
//     it apart from a live grant; it must now appear with GrantExpired true.
//   - user C inherits a role via group G, whose grant is scoped to one
//     project+environment — the old code hardcoded every group-inherited row's
//     scope to "global"; it must now report the real, narrower scope.
func TestGetPermissionBaseline_G25Regression(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newBaselineCore(store)
	ctx := context.Background()

	deletedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	userA := &models.User{ID: 30, Username: "deleted-holder", Email: "a@example.com",
		DeletedAt: gorm.DeletedAt{Time: deletedAt, Valid: true}}
	userB := &models.User{ID: 31, Username: "expired-holder", Email: "b@example.com"}
	userC := &models.User{ID: 32, Username: "env-scoped-holder", Email: "c@example.com"}

	pastExpiry := time.Now().Add(-1 * time.Hour)
	directGrantA := &models.UserRole{UserID: 30, RoleID: 40} // permanent, global
	directGrantB := &models.UserRole{UserID: 31, RoleID: 40, ExpiresAt: &pastExpiry}

	groupGrant := &models.GroupRole{GroupID: 50, RoleID: 41, ProjectID: 6, EnvironmentID: 8}

	store.On("ListUsers", mock.Anything, userFilterPageSize(100000)).
		Return([]*models.User{userA, userB, userC}, int64(3), nil)
	store.On("ListAllUserRoleGrants", mock.Anything).
		Return([]*models.UserRole{directGrantA, directGrantB}, nil)
	store.On("ListAllGroupRoleGrants", mock.Anything).Return([]*models.GroupRole{groupGrant}, nil)

	store.On("GetRole", mock.Anything, uint(40)).Return(&models.Role{ID: 40, Name: "Direct"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(40)).
		Return([]*models.Permission{{Name: "secrets.read"}}, nil)
	store.On("GetRole", mock.Anything, uint(41)).Return(&models.Role{ID: 41, Name: "GroupRole"}, nil)
	store.On("GetRolePermissions", mock.Anything, uint(41)).
		Return([]*models.Permission{{Name: "audit.read"}}, nil)

	store.On("ListAllUserGroupMemberships", mock.Anything).
		Return([]stg.UserGroupMembership{{UserID: 32, GroupID: 50}}, nil)

	baseline, err := c.GetPermissionBaseline(ctx)
	require.NoError(t, err)
	require.Len(t, baseline.Rows, 3)

	byUser := make(map[uint]PermissionBaselineRow, 3)
	for _, row := range baseline.Rows {
		byUser[row.UserID] = row
	}

	rowA, ok := byUser[30]
	require.True(t, ok, "soft-deleted holder's grant must not be dropped")
	assert.True(t, rowA.HolderDeleted)
	assert.False(t, rowA.GrantExpired)
	assert.Equal(t, "global", rowA.Scope)

	rowB, ok := byUser[31]
	require.True(t, ok)
	assert.False(t, rowB.HolderDeleted)
	assert.True(t, rowB.GrantExpired, "grant with a past ExpiresAt must be flagged expired")

	rowC, ok := byUser[32]
	require.True(t, ok)
	assert.False(t, rowC.HolderDeleted)
	assert.False(t, rowC.GrantExpired)
	assert.Equal(t, "project:6/environment:8", rowC.Scope,
		"an environment-scoped group role must not be reported as broader (global)")
}
