package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// matrixStorageOverride wraps MockStorage and lets individual tests override
// ListAllUserRoleGrants and GetRolePermissions without touching the shared mock.
func matrixStorageOverride(inner corestorage.Storage, listGrantsErr error, listGrantsRows []*models.UserRole, getRolePermsErr error) corestorage.Storage {
	return hooked(inner, &storeHooks{
		ListAllUserRoleGrants: func(next corestorage.Storage, ctx context.Context) ([]*models.UserRole, error) {
			if listGrantsErr != nil {
				return nil, listGrantsErr
			}
			if listGrantsRows != nil {
				return listGrantsRows, nil
			}
			// Fall through to the embedded storage so callers that only need to override
			// GetRolePermissions still get real grants from the DB.
			return next.ListAllUserRoleGrants(ctx)
		},
		GetRolePermissions: func(next corestorage.Storage, ctx context.Context, roleID uint) ([]*models.Permission, error) {
			if getRolePermsErr != nil {
				return nil, getRolePermsErr
			}
			return next.GetRolePermissions(ctx, roleID)
		},
	})
}

func newMatrixCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.User{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// seed helpers
func seedMatrixUser(t *testing.T, db *gorm.DB, id uint, username, email string) {
	t.Helper()
	require.NoError(t, db.Create(&models.User{ID: id, Username: username, Email: email}).Error)
}

func seedMatrixRole(t *testing.T, db *gorm.DB, id uint, name string) {
	t.Helper()
	require.NoError(t, db.Create(&models.Role{ID: id, Name: name}).Error)
}

func seedMatrixPerm(t *testing.T, db *gorm.DB, id uint, name, resource, action string) {
	t.Helper()
	require.NoError(t, db.Create(&models.Permission{ID: id, Name: name, Resource: resource, Action: action}).Error)
}

func seedMatrixRolePerm(t *testing.T, db *gorm.DB, roleID, permID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.RolePermission{RoleID: roleID, PermissionID: permID}).Error)
}

// TestGetPermissionMatrix_GlobalGrant — a user with a global role (project_id=0)
// yields a row with Scope="global" and no project/environment name.
func TestGetPermissionMatrix_GlobalGrant(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	seedMatrixUser(t, db, 1, "alice", "alice@example.com")
	seedMatrixRole(t, db, 10, "admin")
	seedMatrixPerm(t, db, 100, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 10, 100)
	// global grant: project_id=0, environment_id=0
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10, ProjectID: 0, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	r := rows[0]
	assert.Equal(t, uint(1), r.UserID)
	assert.Equal(t, "alice", r.Username)
	assert.Equal(t, "alice@example.com", r.Email)
	assert.Equal(t, uint(10), r.RoleID)
	assert.Equal(t, "admin", r.RoleName)
	assert.Equal(t, "secrets.read", r.PermissionName)
	assert.Equal(t, "secrets", r.Resource)
	assert.Equal(t, "read", r.Action)
	assert.Equal(t, "global", r.Scope)
	assert.Zero(t, r.ProjectID)
	assert.Empty(t, r.ProjectName)
	assert.Nil(t, r.ExpiresAt)
}

// TestGetPermissionMatrix_ProjectScoped — a project-scoped grant appears with the
// project's name in the row.
func TestGetPermissionMatrix_ProjectScoped(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 5, Name: "project-a"}).Error)
	seedMatrixUser(t, db, 2, "bob", "bob@example.com")
	seedMatrixRole(t, db, 20, "viewer")
	seedMatrixPerm(t, db, 200, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 20, 200)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 20, ProjectID: 5, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	r := rows[0]
	assert.Equal(t, "bob", r.Username)
	assert.Equal(t, "project", r.Scope)
	assert.Equal(t, uint(5), r.ProjectID)
	assert.Equal(t, "project-a", r.ProjectName)
	assert.Zero(t, r.EnvironmentID)
	assert.Nil(t, r.ExpiresAt)
}

// TestGetPermissionMatrix_FilterByProject — projectID filter excludes grants for
// other projects while including global grants (project_id=0).
func TestGetPermissionMatrix_FilterByProject(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-alpha"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "proj-beta"}).Error)

	seedMatrixUser(t, db, 10, "carol", "carol@example.com")
	seedMatrixRole(t, db, 30, "editor")
	seedMatrixPerm(t, db, 300, "secrets.write", "secrets", "write")
	seedMatrixRolePerm(t, db, 30, 300)

	// grant in project-1
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 30, ProjectID: 1, EnvironmentID: 0}).Error)
	// grant in project-2 (should be excluded when filtering by project 1)
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 30, ProjectID: 2, EnvironmentID: 0}).Error)
	// global grant (should be included even with project filter)
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 30, ProjectID: 0, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 1)
	require.NoError(t, err)
	// project-1 grant + global grant = 2 rows; project-2 grant excluded
	require.Len(t, rows, 2)

	scopes := make(map[string]bool)
	for _, r := range rows {
		scopes[r.Scope] = true
		assert.NotEqual(t, uint(2), r.ProjectID, "project-2 grant must be excluded")
	}
	assert.True(t, scopes["project"], "project-scoped row expected")
	assert.True(t, scopes["global"], "global row must be included in project filter")
}

// TestGetPermissionMatrix_MultiplePermissions — a role with 2 permissions produces
// 2 rows per grant.
func TestGetPermissionMatrix_MultiplePermissions(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	seedMatrixUser(t, db, 3, "dave", "dave@example.com")
	seedMatrixRole(t, db, 40, "poweruser")
	seedMatrixPerm(t, db, 400, "secrets.read", "secrets", "read")
	seedMatrixPerm(t, db, 401, "secrets.write", "secrets", "write")
	seedMatrixRolePerm(t, db, 40, 400)
	seedMatrixRolePerm(t, db, 40, 401)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 40, ProjectID: 0, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 2, "2 permissions × 1 grant = 2 rows")

	permNames := map[string]bool{}
	for _, r := range rows {
		permNames[r.PermissionName] = true
		assert.Equal(t, "dave", r.Username)
		assert.Equal(t, "poweruser", r.RoleName)
		assert.Equal(t, "global", r.Scope)
	}
	assert.True(t, permNames["secrets.read"])
	assert.True(t, permNames["secrets.write"])

	// Confirm time-bound: seed a JIT grant for project_id=1 and verify ExpiresAt is set.
	// Filtering by project_id=1 also includes global grants (project_id=0), so we get
	// 4 rows total (2 from the existing global grant + 2 from the JIT project-scoped grant).
	exp := time.Now().Add(2 * time.Hour)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 40, ProjectID: 1, EnvironmentID: 0, ExpiresAt: &exp}).Error)

	rows, err = c.GetPermissionMatrix(ctx, 1)
	require.NoError(t, err)
	require.Len(t, rows, 4, "2 global rows + 2 project-scoped JIT rows")

	var timedRows []*PermissionMatrixRow
	for _, r := range rows {
		if r.ExpiresAt != nil {
			timedRows = append(timedRows, r)
		}
	}
	require.Len(t, timedRows, 2, "2 JIT rows expected")
	for _, r := range timedRows {
		assert.True(t, r.ExpiresAt.After(time.Now()))
		assert.Equal(t, "project", r.Scope)
	}
}

// TestGetPermissionMatrix_EnvironmentScoped — a grant with both project_id and
// environment_id set yields Scope="environment" and records both names.
func TestGetPermissionMatrix_EnvironmentScoped(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 7, Name: "proj-gamma"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 3, ProjectID: 7, Name: "staging"}).Error)
	seedMatrixUser(t, db, 20, "frank", "frank@example.com")
	seedMatrixRole(t, db, 50, "env-reader")
	seedMatrixPerm(t, db, 500, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 50, 500)
	// environment-scoped grant: both project_id and environment_id are non-zero
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 20, RoleID: 50, ProjectID: 7, EnvironmentID: 3,
	}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	r := rows[0]
	assert.Equal(t, "frank", r.Username)
	assert.Equal(t, "environment", r.Scope, "scope should be 'environment' when both project_id and environment_id are set")
	assert.Equal(t, uint(7), r.ProjectID)
	assert.Equal(t, "proj-gamma", r.ProjectName)
	assert.Equal(t, uint(3), r.EnvironmentID)
	assert.Equal(t, "staging", r.EnvironmentName)
}

// TestGetPermissionMatrix_SoftDeletedProjectFallback — a grant that references a
// project that no longer exists (soft-deleted or missing) falls back to the
// "project-<id>" synthetic name rather than failing.
func TestGetPermissionMatrix_SoftDeletedProjectFallback(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	// seed user + role + permission, but deliberately omit the project row
	seedMatrixUser(t, db, 30, "grace", "grace@example.com")
	seedMatrixRole(t, db, 60, "viewer")
	seedMatrixPerm(t, db, 600, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 60, 600)
	// grant references project_id=99 which does not exist
	require.NoError(t, db.Create(&models.UserRole{UserID: 30, RoleID: 60, ProjectID: 99, EnvironmentID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1, "missing project must not drop the row")

	r := rows[0]
	assert.Equal(t, "project", r.Scope)
	assert.Equal(t, fmt.Sprintf("project-%d", 99), r.ProjectName,
		"project name must fall back to 'project-<id>' for missing projects")
}

// TestGetPermissionMatrix_MissingEnvironmentFallback — a grant with a valid project
// but a missing environment falls back to the "env-<id>" synthetic name.
func TestGetPermissionMatrix_MissingEnvironmentFallback(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 8, Name: "proj-delta"}).Error)
	// no environment row for env_id=77 — intentionally absent
	seedMatrixUser(t, db, 31, "heidi", "heidi@example.com")
	seedMatrixRole(t, db, 61, "env-writer")
	seedMatrixPerm(t, db, 601, "secrets.write", "secrets", "write")
	seedMatrixRolePerm(t, db, 61, 601)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 31, RoleID: 61, ProjectID: 8, EnvironmentID: 77,
	}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1, "missing environment must not drop the row")

	r := rows[0]
	assert.Equal(t, "environment", r.Scope)
	assert.Equal(t, "proj-delta", r.ProjectName)
	assert.Equal(t, fmt.Sprintf("env-%d", 77), r.EnvironmentName,
		"environment name must fall back to 'env-<id>' for missing environments")
}

// TestGetPermissionMatrix_UnknownUserSkipped — a grant whose user_id has no matching
// user row is silently skipped (stale JIT grant scenario).
func TestGetPermissionMatrix_UnknownUserSkipped(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	seedMatrixUser(t, db, 40, "ivan", "ivan@example.com")
	seedMatrixRole(t, db, 70, "admin")
	seedMatrixPerm(t, db, 700, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 70, 700)

	// valid grant
	require.NoError(t, db.Create(&models.UserRole{UserID: 40, RoleID: 70, ProjectID: 0}).Error)
	// grant for non-existent user_id=999 (SQLite does not enforce FK by default)
	require.NoError(t, db.Create(&models.UserRole{UserID: 999, RoleID: 70, ProjectID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	// Only the valid grant should produce a row; the stale one is skipped.
	require.Len(t, rows, 1, "stale grant with unknown user must be skipped")
	assert.Equal(t, uint(40), rows[0].UserID)
}

// TestGetPermissionMatrix_MissingRoleSkipped — a grant whose role_id has no matching
// role row causes the entire grant to be skipped (defensive: stale/orphaned grant).
func TestGetPermissionMatrix_MissingRoleSkipped(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	seedMatrixUser(t, db, 41, "judy", "judy@example.com")
	seedMatrixRole(t, db, 80, "real-role")
	seedMatrixPerm(t, db, 800, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 80, 800)

	// valid grant
	require.NoError(t, db.Create(&models.UserRole{UserID: 41, RoleID: 80, ProjectID: 0}).Error)
	// grant referencing a role that doesn't exist in the roles table
	require.NoError(t, db.Create(&models.UserRole{UserID: 41, RoleID: 9999, ProjectID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1, "grant with missing role must be skipped")
	assert.Equal(t, uint(80), rows[0].RoleID)
}

// TestGetPermissionMatrix_EmptyDB — an empty deployment returns an empty slice.
func TestGetPermissionMatrix_EmptyDB(t *testing.T) {
	t.Parallel()
	c, _ := newMatrixCore(t)
	rows, err := c.GetPermissionMatrix(context.Background(), 0)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// TestGetPermissionMatrix_ListGrantsError — storage failure in ListAllUserRoleGrants
// propagates as an error.
func TestGetPermissionMatrix_ListGrantsError(t *testing.T) {
	t.Parallel()
	base := &MockStorage{}
	override := matrixStorageOverride(base, errors.New("db connection lost"), nil, nil)
	c := NewKeyorixCore(override)
	_, err := c.GetPermissionMatrix(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list grants")
}

// TestGetPermissionMatrix_GetRolePermsError — a storage failure in GetRolePermissions
// causes that grant to be silently skipped (continue path at line 152-154).
func TestGetPermissionMatrix_GetRolePermsError(t *testing.T) {
	t.Parallel()
	// Build a LocalStorage-backed core that has a valid user + role, then wrap it
	// with the override that injects an error from GetRolePermissions.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.User{},
	))
	local := store.NewLocalStorage(db)
	require.NoError(t, db.Create(&models.User{ID: 50, Username: "kate", Email: "kate@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 90, Name: "the-role"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 50, RoleID: 90, ProjectID: 0}).Error)

	override := matrixStorageOverride(local, nil, nil, errors.New("permissions table gone"))
	c := NewKeyorixCore(override)

	// The grant is silently skipped: no error returned, but no rows produced.
	rows, err := c.GetPermissionMatrix(context.Background(), 0)
	require.NoError(t, err)
	assert.Empty(t, rows, "grant with GetRolePermissions failure must be skipped silently")
}

// TestGetPermissionMatrix_RoleWithNoPermissions — a role that has zero permissions
// contributes no rows (empty perms slice, inner loop never executes).
func TestGetPermissionMatrix_RoleWithNoPermissions(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	seedMatrixUser(t, db, 42, "lena", "lena@example.com")
	seedMatrixRole(t, db, 85, "empty-role") // no permissions assigned
	require.NoError(t, db.Create(&models.UserRole{UserID: 42, RoleID: 85, ProjectID: 0}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	assert.Empty(t, rows, "a role with zero permissions must produce no matrix rows")
}

// TestGetPermissionMatrix_ProjectNameCache — the same project_id resolved twice
// uses the cache; only one DB lookup occurs (indirectly verified by result
// correctness across multiple grants for the same project).
func TestGetPermissionMatrix_ProjectNameCache(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 10, Name: "cached-proj"}).Error)
	seedMatrixUser(t, db, 43, "mike", "mike@example.com")
	seedMatrixUser(t, db, 44, "nina", "nina@example.com")
	seedMatrixRole(t, db, 86, "viewer")
	seedMatrixPerm(t, db, 860, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 86, 860)
	// two grants for the same project — project name should be resolved once and cached
	require.NoError(t, db.Create(&models.UserRole{UserID: 43, RoleID: 86, ProjectID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 44, RoleID: 86, ProjectID: 10}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, r := range rows {
		assert.Equal(t, "cached-proj", r.ProjectName)
	}
}

// TestGetPermissionMatrix_EnvNameCache — the same environment_id resolved twice
// exercises the envCache hit path in getEnvName (the second lookup returns from cache).
func TestGetPermissionMatrix_EnvNameCache(t *testing.T) {
	t.Parallel()
	c, db := newMatrixCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 11, Name: "proj-env-cache"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 4, ProjectID: 11, Name: "prod"}).Error)
	seedMatrixUser(t, db, 45, "oscar", "oscar@example.com")
	seedMatrixUser(t, db, 46, "petra", "petra@example.com")
	seedMatrixRole(t, db, 87, "env-reader")
	seedMatrixPerm(t, db, 870, "secrets.read", "secrets", "read")
	seedMatrixRolePerm(t, db, 87, 870)
	// Two grants for the same environment: second lookup must hit the envCache.
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 45, RoleID: 87, ProjectID: 11, EnvironmentID: 4,
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 46, RoleID: 87, ProjectID: 11, EnvironmentID: 4,
	}).Error)

	rows, err := c.GetPermissionMatrix(ctx, 0)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, r := range rows {
		assert.Equal(t, "prod", r.EnvironmentName, "cached env name must match DB value")
		assert.Equal(t, "environment", r.Scope)
	}
}
