// restore_admin_ceiling_test.go — focused regression coverage for the
// admin-rank-ceiling gap on restore paths (#147 group restore, #161
// project/environment restore): restoring a soft-deleted principal reinstates
// every role grant it held atomically, so the actor's own authority must be
// checked against that whole role SET, not just gated on a permission string.
package core

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newRestoreCeilingCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.MachineIdentity{}, &models.MachineIdentityRole{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "nonadmin", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "globaladmin", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1}).Error) // user 2 = global admin
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// #147: a principal with no admin authority must be refused restoring a group
// that holds an admin-tier role — restoring would hand that admin access right
// back to any member of the group, including the restoring actor themselves.
func TestRestoreGroup_RefusesNonAdminWhenGroupHoldsAdminRole(t *testing.T) {
	t.Parallel()
	c, db := newRestoreCeilingCore(t)
	ctx := context.Background()

	g, err := c.CreateGroup(ctx, 2, &CreateGroupRequest{Name: "platform-admins"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: g.ID, RoleID: 1}).Error) // admin role
	require.NoError(t, c.DeleteGroup(ctx, 2, g.ID))

	_, err = c.RestoreGroup(ctx, 1, g.ID) // actor 1 has no roles at all
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "administrator"), "got: %v", err)

	// The group must remain soft-deleted — the refusal is not cosmetic.
	_, getErr := c.GetGroup(ctx, g.ID)
	assert.Error(t, getErr, "a refused restore must not resurrect the group")
}

// #147: a global admin CAN restore a group holding an admin-tier role — the
// ceiling check does not block legitimate administrators.
func TestRestoreGroup_AllowsGlobalAdmin(t *testing.T) {
	t.Parallel()
	c, db := newRestoreCeilingCore(t)
	ctx := context.Background()

	g, err := c.CreateGroup(ctx, 2, &CreateGroupRequest{Name: "platform-admins"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: g.ID, RoleID: 1}).Error)
	require.NoError(t, c.DeleteGroup(ctx, 2, g.ID))

	_, err = c.RestoreGroup(ctx, 2, g.ID)
	require.NoError(t, err)
	restored, err := c.GetGroup(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, g.ID, restored.ID)
}

// #147: a group holding only a NON-admin role needs no elevated authority to
// restore — the ceiling check must not over-reach into ordinary restores.
func TestRestoreGroup_AllowsNonAdminWhenGroupHoldsOnlyNonAdminRole(t *testing.T) {
	t.Parallel()
	c, db := newRestoreCeilingCore(t)
	ctx := context.Background()

	g, err := c.CreateGroup(ctx, 1, &CreateGroupRequest{Name: "viewers"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: g.ID, RoleID: 2}).Error) // viewer, non-admin
	require.NoError(t, c.DeleteGroup(ctx, 1, g.ID))

	_, err = c.RestoreGroup(ctx, 1, g.ID)
	require.NoError(t, err, "a non-admin role set needs no elevated authority to restore")
}

// #161: a principal with no admin authority must be refused restoring a
// project that has a directly-bound admin-tier role — restoring reinstates
// EVERY role bound to the project, potentially handing back admin access.
func TestRestoreProject_RefusesNonAdminWhenProjectHoldsAdminRole(t *testing.T) {
	t.Parallel()
	c, db := newRestoreCeilingCore(t)
	ctx := context.Background()

	p, err := c.CreateProject(ctx, "proj", "")
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: 99, RoleID: 1, ProjectID: p.ID}).Error) // admin at project scope
	require.NoError(t, c.DeleteProject(ctx, 0, p.ID, false))

	err = c.RestoreProject(ctx, 1, p.ID) // actor 1 has no roles at all
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "administrator"), "got: %v", err)
}

// #161: a global admin CAN restore a project holding an admin-tier role grant.
func TestRestoreProject_AllowsGlobalAdmin(t *testing.T) {
	t.Parallel()
	c, db := newRestoreCeilingCore(t)
	ctx := context.Background()

	p, err := c.CreateProject(ctx, "proj", "")
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: 99, RoleID: 1, ProjectID: p.ID}).Error)
	require.NoError(t, c.DeleteProject(ctx, 0, p.ID, false))

	require.NoError(t, c.RestoreProject(ctx, 2, p.ID))
}

// #161: the same ceiling check applies to environment restore — a non-admin
// actor is refused when the OWNING PROJECT carries an admin-tier role grant
// (the environment's grants are a subset of the project's).
func TestRestoreEnvironment_RefusesNonAdminWhenProjectHoldsAdminRole(t *testing.T) {
	t.Parallel()
	c, db := newRestoreCeilingCore(t)
	ctx := context.Background()

	p, err := c.CreateProject(ctx, "proj", "")
	require.NoError(t, err)
	// CreateProject seeds default environments; reuse one rather than creating a
	// colliding duplicate.
	envs, err := c.ListEnvironmentsByProject(ctx, p.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]
	require.NoError(t, db.Create(&models.UserRole{UserID: 99, RoleID: 1, ProjectID: p.ID}).Error) // admin at project scope
	require.NoError(t, c.storage.DeleteEnvironment(ctx, env.ID))

	err = c.RestoreEnvironment(ctx, 1, p.ID, env.ID) // actor 1 has no roles at all
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "administrator"), "got: %v", err)
}

// #161: a global admin CAN restore an environment under a project holding an
// admin-tier role grant.
func TestRestoreEnvironment_AllowsGlobalAdmin(t *testing.T) {
	t.Parallel()
	c, db := newRestoreCeilingCore(t)
	ctx := context.Background()

	p, err := c.CreateProject(ctx, "proj", "")
	require.NoError(t, err)
	envs, err := c.ListEnvironmentsByProject(ctx, p.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]
	require.NoError(t, db.Create(&models.UserRole{UserID: 99, RoleID: 1, ProjectID: p.ID}).Error)
	require.NoError(t, c.storage.DeleteEnvironment(ctx, env.ID))

	require.NoError(t, c.RestoreEnvironment(ctx, 2, p.ID, env.ID))
}
