package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newRestoreTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	// #370: DeleteSecret revokes ShareRecord rows in the same transaction as the
	// secret's own soft-delete; SecretACL rows are revoked in the same transaction too (CWE-284).
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{}, &models.DynamicSecretConfig{}))
	return NewLocalStorage(db)
}

func TestRestoreProjectCascade(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app", Description: "d"})
	require.NoError(t, err)
	_, err = ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: proj.ID, EnvironmentID: 1, Name: "db-pw", IsSecret: true, Type: "text", Status: "active",
	})
	require.NoError(t, err)

	// Soft-delete the project (cascades to envs + secrets).
	require.NoError(t, ls.DeleteProject(ctx, proj.ID))

	// Default list excludes the deleted project; include_deleted surfaces it.
	active, err := ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	assert.Empty(t, active, "soft-deleted project must not appear by default")

	all, err := ls.ListProjectsWithCounts(ctx, true)
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.True(t, all[0].Deleted)
	assert.NotEmpty(t, all[0].DeletedAt)

	// Restore brings back the project, its environments, AND its secrets —
	// secrets now soft-delete with the project and restore with it (ADR-033).
	// RestoreProject also reports how many of each it actually resurrected (#311),
	// so the caller can audit the cascade's true blast radius.
	restoredEnvs, restoredSecrets, err := ls.RestoreProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, restoredEnvs)
	assert.Equal(t, 1, restoredSecrets)

	restored, err := ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	require.Len(t, restored, 1)
	assert.False(t, restored[0].Deleted)
	assert.Equal(t, int64(1), restored[0].SecretCount, "secrets are soft-deleted with the project and restored (ADR-033)")
	assert.Equal(t, int64(1), restored[0].EnvironmentCount, "environment should be restored")

	envs, err := ls.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Len(t, envs, 1)
}

// A secret retired INDEPENDENTLY (soft-deleted on its own, before the project) must
// NOT be resurrected when the project is later deleted and restored — only the rows
// the project-delete cascade removed should come back. Otherwise a deliberately-
// trashed secret silently returns live (and its retained shares re-grant access).
func TestRestoreProject_DoesNotResurrectIndependentlyDeletedSecret(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	_, err = ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	retired, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: 1, Name: "retired", IsSecret: true, Type: "text", Status: "active"})
	require.NoError(t, err)
	kept, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: 1, Name: "kept", IsSecret: true, Type: "text", Status: "active"})
	require.NoError(t, err)

	// "retired" is deliberately soft-deleted earlier (stamp an hour-old deleted_at so
	// it is unambiguously before the project-delete cascade timestamp).
	require.NoError(t, ls.db.Unscoped().Model(&models.SecretNode{}).
		Where("id = ?", retired.ID).Update("deleted_at", time.Now().Add(-time.Hour)).Error)

	// Delete then restore the whole project.
	require.NoError(t, ls.DeleteProject(ctx, proj.ID))
	restoredEnvs, restoredSecrets, err := ls.RestoreProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, restoredEnvs)
	assert.Equal(t, 1, restoredSecrets, "only the cascade-deleted secret is counted, not the independently-retired one")

	// "kept" (cascade-deleted with the project) is restored.
	_, err = ls.GetSecret(ctx, kept.ID)
	require.NoError(t, err, "a secret deleted by the project cascade is restored with it")

	// "retired" (independently deleted earlier) stays in the recycle bin.
	_, err = ls.GetSecret(ctx, retired.ID)
	require.Error(t, err, "an independently-retired secret must NOT be resurrected by a project restore")
	var stillDeleted models.SecretNode
	require.NoError(t, ls.db.Unscoped().First(&stillDeleted, retired.ID).Error)
	assert.True(t, stillDeleted.DeletedAt.Valid, "retired secret remains soft-deleted")
}

// An individual environment or secret must NOT be restorable while its parent project
// is still soft-deleted — otherwise a holder of a still-extant project-scoped grant (a
// soft-deleted project does not revoke its role grants) could resurrect a live, readable
// scope under a project an admin deleted to revoke access.
func TestRestoreChild_RefusedWhileParentProjectDeleted(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: env.ID, Name: "db-pw", IsSecret: true, Type: "text", Status: "active"})
	require.NoError(t, err)

	// Soft-delete the whole project (cascades to env + secret).
	require.NoError(t, ls.DeleteProject(ctx, proj.ID))

	// Individually restoring the secret is refused — the parent project is deleted.
	err = ls.RestoreSecret(ctx, sec.ID)
	require.Error(t, err, "a secret must not be restorable under a soft-deleted project")
	assert.Contains(t, err.Error(), "parent project is deleted")

	// Likewise the environment.
	err = ls.RestoreEnvironment(ctx, proj.ID, env.ID)
	require.Error(t, err, "an environment must not be restorable under a soft-deleted project")
	assert.Contains(t, err.Error(), "parent project is deleted")

	// The secret stays in the recycle bin (still soft-deleted, not readable).
	_, err = ls.GetSecret(ctx, sec.ID)
	require.Error(t, err)

	// Restoring the project first (cascade) brings the children back — the supported path.
	_, _, err = ls.RestoreProject(ctx, proj.ID)
	require.NoError(t, err)
	_, err = ls.GetSecret(ctx, sec.ID)
	require.NoError(t, err, "after the project is restored, its cascade-deleted secret is live again")
}

// A secret whose parent ENVIRONMENT is still soft-deleted (but project live) is also
// refused, so a child can never outlive a deleted parent scope.
func TestRestoreSecret_RefusedWhileParentEnvironmentDeleted(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: env.ID, Name: "db-pw", IsSecret: true, Type: "text", Status: "active"})
	require.NoError(t, err)

	// Delete the secret, then the environment (project stays live).
	require.NoError(t, ls.DeleteSecret(ctx, sec.ID))
	require.NoError(t, ls.DeleteEnvironment(ctx, env.ID))

	err = ls.RestoreSecret(ctx, sec.ID)
	require.Error(t, err, "a secret must not be restorable under a soft-deleted environment")
	assert.Contains(t, err.Error(), "parent environment is deleted")

	// With the environment restored, the secret can be restored.
	require.NoError(t, ls.RestoreEnvironment(ctx, proj.ID, env.ID))
	require.NoError(t, ls.RestoreSecret(ctx, sec.ID))
	_, err = ls.GetSecret(ctx, sec.ID)
	require.NoError(t, err)
}

func TestRestoreProjectNotDeleted(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)

	// Restoring a project that isn't deleted is a no-op error.
	_, _, err = ls.RestoreProject(ctx, proj.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not deleted")
}

func TestRestoreEnvironment(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: proj.ID})
	require.NoError(t, err)

	require.NoError(t, ls.DeleteEnvironment(ctx, env.ID))

	// Excluded from the normal list, present in the include-deleted list.
	live, err := ls.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Empty(t, live)

	withDeleted, err := ls.ListEnvironmentsByProjectIncludingDeleted(ctx, proj.ID)
	require.NoError(t, err)
	assert.Len(t, withDeleted, 1)

	// Restoring under the wrong project is a no-op → not found (cross-project guard).
	err = ls.RestoreEnvironment(ctx, proj.ID+999, env.ID)
	require.Error(t, err)
	stillDeleted, err := ls.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Empty(t, stillDeleted)

	require.NoError(t, ls.RestoreEnvironment(ctx, proj.ID, env.ID))
	live, err = ls.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Len(t, live, 1)

	// Restoring a live environment errors.
	err = ls.RestoreEnvironment(ctx, proj.ID, env.ID)
	require.Error(t, err)
}
