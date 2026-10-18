// authz_readable_scopes_test.go — unit tests for GetReadableScopes.
package core

import (
	"context"
	"errors"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userRoleScopesStub overrides GetUserRoleScopes to return a fixed slice.
func userRoleScopesStub(inner corestorage.Storage, scopes []corestorage.Scope, err error) corestorage.Storage {
	return hooked(inner, &storeHooks{
		GetUserRoleScopes: func(_ corestorage.Storage, _ context.Context, _ uint) ([]corestorage.Scope, error) {
			return scopes, err
		},
	})
}

// TestGetReadableScopes_StorageError verifies that a GetUserRoleScopes error is
// propagated unchanged.
func TestGetReadableScopes_StorageError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newACLCore(t)
	wantErr := errors.New("scopes db failure")
	c2 := newACLCoreWithStorage(c, userRoleScopesStub(c.storage, nil, wantErr))
	_, err := c2.GetReadableScopes(ctx, 1, "secrets.read")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// TestGetReadableScopes_GlobalScopeSkipped verifies that scopes with ProjectID==0
// (global) are silently skipped; the result is empty even though a scope was
// returned by storage.
func TestGetReadableScopes_GlobalScopeSkipped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newACLCore(t)
	stub := userRoleScopesStub(c.storage, []corestorage.Scope{{ProjectID: 0, EnvironmentID: 0}}, nil)
	c2 := newACLCoreWithStorage(c, stub)
	scopes, err := c2.GetReadableScopes(ctx, 1, "secrets.read")
	require.NoError(t, err)
	assert.Empty(t, scopes)
}

// TestGetReadableScopes_AuthorizeError verifies that a scope where Authorize
// returns an error is silently skipped (fail-closed).  The stub provides a
// non-zero-project scope; the real storage (DB) is then closed so that the
// Authorize call fails with a DB error, triggering the aerr != nil continue.
func TestGetReadableScopes_AuthorizeError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	stub := userRoleScopesStub(c.storage, []corestorage.Scope{{ProjectID: 1, EnvironmentID: 0}}, nil)
	c2 := newACLCoreWithStorage(c, stub)

	// Close the DB so that Authorize's storage calls (GetUserRoles, etc.) fail.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	scopes, err := c2.GetReadableScopes(ctx, 1, "secrets.read")
	require.NoError(t, err) // GetReadableScopes itself doesn't propagate Authorize errors
	assert.Empty(t, scopes)
}

// TestGetReadableScopes_AuthorizeFalse verifies that a scope where Authorize
// returns (false, nil) is not included in the result.
func TestGetReadableScopes_AuthorizeFalse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _ := newACLCore(t)
	// User 99 has no role grants in the DB → Authorize returns (false, nil).
	stub := userRoleScopesStub(c.storage, []corestorage.Scope{{ProjectID: 1, EnvironmentID: 0}}, nil)
	c2 := newACLCoreWithStorage(c, stub)
	scopes, err := c2.GetReadableScopes(ctx, 99, "secrets.read")
	require.NoError(t, err)
	assert.Empty(t, scopes)
}

// TestGetReadableScopes_AuthorizeTrue verifies that a scope where the user has
// the required permission is included in the result.
func TestGetReadableScopes_AuthorizeTrue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)

	// Seed a project-scoped secrets.read role for user 88.
	role := &models.Role{Name: "readable_scope_role"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
	require.NoError(t, db.Create(perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 88, RoleID: role.ID, ProjectID: 1}).Error)

	stub := userRoleScopesStub(c.storage, []corestorage.Scope{{ProjectID: 1, EnvironmentID: 0}}, nil)
	c2 := newACLCoreWithStorage(c, stub)
	scopes, err := c2.GetReadableScopes(ctx, 88, "secrets.read")
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	assert.Equal(t, uint(1), scopes[0].ProjectID)
}

// G33: GetReadableScopes must resolve a machine identity's project-scoped role
// grant the same way it resolves an equivalent human user's. Before this fix it
// called the user-only c.storage.GetUserRoleScopes + c.Authorize
// unconditionally, so a machine identity was always resolved to zero readable
// scopes here regardless of its actual machine_identity_roles grants — a sibling
// of connect.go's actorRoleIDs and dashboard.go's GetDashboardStats bugs (found
// during this fix's sibling sweep, same "helper written for humans, never
// updated for machines" shape).
func TestGetReadableScopes_MachineIdentityMatchesEquivalentUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)

	role := &models.Role{Name: "readable_scope_machine_role"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
	require.NoError(t, db.Create(perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	// Human user 77 and machine identity 200 each hold the SAME role at the SAME
	// project scope (project 1, seeded by newACLCore).
	require.NoError(t, db.Create(&models.UserRole{UserID: 77, RoleID: role.ID, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: 200, RoleID: role.ID, ProjectID: 1}).Error)

	humanCtx := WithActorType(ctx, ActorTypeUser)
	machineCtx := WithActorType(ctx, ActorTypeMachine)

	humanScopes, err := c.GetReadableScopes(humanCtx, 77, "secrets.read")
	require.NoError(t, err)
	require.Len(t, humanScopes, 1)
	assert.Equal(t, uint(1), humanScopes[0].ProjectID)

	machineScopes, err := c.GetReadableScopes(machineCtx, 200, "secrets.read")
	require.NoError(t, err)
	require.Len(t, machineScopes, 1, "the machine identity's project-scoped role grant must resolve into a readable scope, exactly like the equivalent human user's")
	assert.Equal(t, uint(1), machineScopes[0].ProjectID)
}
