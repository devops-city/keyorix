package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newRBACAuditCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.UserRole{}, &models.Role{}, &models.Permission{},
		// models.SystemMetadata holds the role_permissions cache-invalidation
		// generation (PERF-3 PR-2) that every role_permissions write bumps in the
		// same transaction — see role_permission_cache.go.
		&models.RolePermission{}, &models.SystemMetadata{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SoDPolicy{},
	))
	// The roles and the {project 3, environment 7} scope these tests grant at
	// must exist: the #3546 role-scope check resolves both before a grant.
	for id := uint(1); id <= 4; id++ {
		require.NoError(t, db.Create(&models.Role{ID: id, Name: fmt.Sprintf("audit-test-role-%d", id)}).Error)
	}
	require.NoError(t, db.Create(&models.Project{ID: 3, Name: "p3"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 7, ProjectID: 3, Name: "e7"}).Error)
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// seedRolesAssignGrant grants actorID roles.assign at scope via DIRECT DB
// rows (never through core.AssignUserRole), so the seed itself never emits
// an audit-log entry that would pollute a test's exact audit-entry-count
// assertion. F6 sweep (2026-09-22): granting ANY role now requires the actor
// already hold roles.assign at that scope.
func seedRolesAssignGrant(t *testing.T, db *gorm.DB, actorID, permissionID, roleID uint, scope Scope) {
	t.Helper()
	require.NoError(t, db.Create(&models.Permission{ID: permissionID, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: roleID, Name: "seeded-roles-assign-holder"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: roleID, PermissionID: permissionID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: actorID, RoleID: roleID, ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID}).Error)
}

func TestRBACAuditTrail_AssignAndRemove(t *testing.T) {
	t.Parallel()
	c, db := newRBACAuditCore(t)
	ctx := context.Background()
	seedRolesAssignGrant(t, db, 5, 100, 100, Scope{ProjectID: 3})

	require.NoError(t, c.AssignUserRole(ctx, 5, 10, 2, Scope{ProjectID: 3}, false))
	require.NoError(t, c.RemoveUserRole(ctx, 5, 10, 2, Scope{ProjectID: 3}))

	entries, total, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(2))

	var assigned, removed *RBACAuditEntry
	for _, e := range entries {
		switch e.Action {
		case EventRoleAssigned:
			assigned = e
		case EventRoleRemoved:
			removed = e
		}
	}

	require.NotNil(t, assigned, "expected a role.assigned entry")
	require.NotNil(t, assigned.ActorUserID)
	assert.Equal(t, uint(5), *assigned.ActorUserID)
	require.NotNil(t, assigned.TargetUserID)
	assert.Equal(t, uint(10), *assigned.TargetUserID)
	require.NotNil(t, assigned.RoleID)
	assert.Equal(t, uint(2), *assigned.RoleID)
	require.NotNil(t, assigned.ProjectID)
	assert.Equal(t, uint(3), *assigned.ProjectID)

	require.NotNil(t, removed, "expected a role.removed entry")
	require.NotNil(t, removed.TargetUserID)
	assert.Equal(t, uint(10), *removed.TargetUserID)
}

// TestRBACAuditTrail_EnvironmentIDRoundTrips is #G23: writeRBACAudit already
// stamps EnvironmentID into the event's structured diff (rbacAuditDetail),
// but ListRBACAuditLogs never read it back out into RBACAuditEntry — an
// environment-scoped grant's audit row silently lost its EnvironmentID on
// the read side even though it was captured at write time.
func TestRBACAuditTrail_EnvironmentIDRoundTrips(t *testing.T) {
	t.Parallel()
	c, db := newRBACAuditCore(t)
	ctx := context.Background()
	seedRolesAssignGrant(t, db, 5, 100, 100, Scope{ProjectID: 3, EnvironmentID: 7})

	require.NoError(t, c.AssignUserRole(ctx, 5, 10, 2, Scope{ProjectID: 3, EnvironmentID: 7}, false))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)

	var assigned *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventRoleAssigned {
			assigned = e
		}
	}
	require.NotNil(t, assigned)
	require.NotNil(t, assigned.EnvironmentID)
	assert.Equal(t, uint(7), *assigned.EnvironmentID)
}

// A change made without an authenticated principal (actorID 0, e.g. local CLI)
// records no actor.
func TestRBACAuditTrail_SystemActor(t *testing.T) {
	t.Parallel()
	c, _ := newRBACAuditCore(t)
	ctx := context.Background()

	require.NoError(t, c.AssignUserRole(ctx, 0, 11, 4, Scope{}, false))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Nil(t, entries[0].ActorUserID, "system/CLI actor should be unset")
	require.NotNil(t, entries[0].RoleID)
	assert.Equal(t, uint(4), *entries[0].RoleID)
}

func TestRBACAuditTrail_GroupRole(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.Group{}, &models.Role{}, &models.GroupRole{}, &models.SoDPolicy{},
		&models.Permission{}, &models.RolePermission{}, &models.SystemMetadata{}, &models.UserRole{},
		&models.Project{}, &models.Environment{}, &models.UserGroup{},
	))
	require.NoError(t, db.Create(&models.Group{ID: 7, Name: "platform"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "editor"}).Error)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()
	seedRolesAssignGrant(t, db, 5, 100, 100, Scope{ProjectID: 3})

	require.NoError(t, c.AssignRoleToGroup(ctx, 5, 7, 2, Scope{ProjectID: 3}, false))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, EventRoleGroupAssigned, e.Action)
	require.NotNil(t, e.ActorUserID)
	assert.Equal(t, uint(5), *e.ActorUserID)
	require.NotNil(t, e.GroupID)
	assert.Equal(t, uint(7), *e.GroupID)
	require.NotNil(t, e.RoleID)
	assert.Equal(t, uint(2), *e.RoleID)
	assert.Nil(t, e.TargetUserID, "group event has no target user")
}

func TestRBACAuditTrail_PermissionToRole(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.SystemMetadata{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 8, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	// #169: AssignPermissionToRole now requires the actor already hold the permission
	// being bundled — make actor 5 a global admin so the bypass applies.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 5, RoleID: 1}).Error)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	require.NoError(t, c.AssignPermissionToRole(ctx, 5, 2, 8, false))
	require.NoError(t, c.RemovePermissionFromRole(ctx, 5, 2, 8))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	var added *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventPermissionAdded {
			added = e
		}
	}
	require.NotNil(t, added, "expected a permission.assigned entry")
	require.NotNil(t, added.ActorUserID)
	assert.Equal(t, uint(5), *added.ActorUserID)
	require.NotNil(t, added.RoleID)
	assert.Equal(t, uint(2), *added.RoleID)
	require.NotNil(t, added.PermissionID)
	assert.Equal(t, uint(8), *added.PermissionID)
}

// SetUserRoles diffs the current vs desired set and audits each resulting change.
func TestRBACAuditTrail_SetUserRolesEmitsPerChange(t *testing.T) {
	t.Parallel()
	c, db := newRBACAuditCore(t)
	ctx := context.Background()
	seedRolesAssignGrant(t, db, 9, 100, 100, Scope{})

	// From {} to {1,2}: two assignments.
	require.NoError(t, c.SetUserRoles(ctx, 9, 20, []uint{1, 2}, Scope{}, false))
	// From {1,2} to {2,3}: remove 1, add 3.
	require.NoError(t, c.SetUserRoles(ctx, 9, 20, []uint{2, 3}, Scope{}, false))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)

	var assigns, removes int
	for _, e := range entries {
		switch e.Action {
		case EventRoleAssigned:
			assigns++
		case EventRoleRemoved:
			removes++
		}
		require.NotNil(t, e.ActorUserID)
		assert.Equal(t, uint(9), *e.ActorUserID)
	}
	assert.Equal(t, 3, assigns, "assigned roles 1,2 then 3")
	assert.Equal(t, 1, removes, "removed role 1")
}
