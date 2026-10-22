package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestListProjectRoleAssignments_GlobalExcludesEnvironmentScopedGrant (#2857):
// ListProjectRoleAssignments(ctx, 0) feeds every core-side "who else is a global
// admin" count, so it must apply the same filter as the storage-side guard
// (ListGlobalAdminAssignmentsForUpdate: project_id = 0 AND environment_id = 0).
// A {ProjectID: 0, EnvironmentID: X} grant resolves only at scopes in
// environment X (UserRoleGrant.AppliesAt), never at global scope, so counting it
// as a global holder let the last real global admin be removed. The shape was
// reachable through POST /api/v1/user-roles until #3546 refused it (server/http
// TestAssignRoleHTTP_EnvironmentScopedGlobalProjectGrantIsRefused); grants
// written before that may still have it, so the filter stays.
// Runs on SQLite and, with KEYORIX_TEST_PG_DSN, on Postgres.
func TestListProjectRoleAssignments_GlobalExcludesEnvironmentScopedGrant(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		checkGlobalHolderScope(t, newStoreS3(t, "global_holder_scope", &models.UserRole{}, &models.GroupRole{}, &models.Group{}))
	})
	t.Run("postgres", func(t *testing.T) {
		db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
		require.NoError(t, db.AutoMigrate(&models.UserRole{}, &models.GroupRole{}, &models.Group{}))
		checkGlobalHolderScope(t, NewLocalStorage(db))
	})
}

func checkGlobalHolderScope(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Group{ID: 9, Name: "g", NameFolded: "g"}).Error)
	// Environment-scoped grants with ProjectID 0: not global.
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 4, RoleID: 1, ProjectID: 0, EnvironmentID: 3}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 9, RoleID: 1, ProjectID: 0, EnvironmentID: 3}).Error)
	// Calibration: a real global grant, and a project-scoped env grant.
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 5, RoleID: 1}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 9, RoleID: 2}).Error)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 6, RoleID: 1, ProjectID: 2, EnvironmentID: 3}).Error)

	global, err := ls.ListProjectRoleAssignments(ctx, 0)
	require.NoError(t, err)
	require.ElementsMatch(t, []storage.RoleAssignment{
		{PrincipalType: "user", PrincipalID: 5, RoleID: 1},
		{PrincipalType: "group", PrincipalID: 9, RoleID: 2},
	}, global, "#2857: a {0, env 3} grant is returned as a global-scope assignment")

	// The storage-side guard's query agrees on the same rows.
	locked, err := ls.ListGlobalAdminAssignmentsForUpdate(ctx, []uint{1, 2})
	require.NoError(t, err)
	require.ElementsMatch(t, global, locked, "the two global-holder queries must agree")

	// A project listing still includes its environment-scoped grants.
	project, err := ls.ListProjectRoleAssignments(ctx, 2)
	require.NoError(t, err)
	require.Equal(t, []storage.RoleAssignment{{PrincipalType: "user", PrincipalID: 6, RoleID: 1, ProjectID: 2, EnvironmentID: 3}}, project)
}
