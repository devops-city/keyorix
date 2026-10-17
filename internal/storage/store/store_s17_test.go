// store_s17_test.go — local white-box coverage sweep for s17 gaps.
//
// Targets (local/white-box):
//   - local_scheduler_lock.go:36   WithSchedulerLock fn-error path
//   - local_audit_checkpoint_lock.go:37  WithAuditCheckpointLock fn-error path
//   - local_notifications.go:31    CreateNotification happy path + DB-error
//   - local_secrets.go:51          CreateProject happy path + DB-error
//   - local_secrets.go:166         deleteProjectCascade cascade + not-found
package store

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newS17Store opens an in-memory SQLite DB, optionally running AutoMigrate for
// the supplied model values, and returns a LocalStorage backed by it.
func newS17Store(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// local_scheduler_lock.go — fn-error propagation (SQLite path, line 38)
// ---------------------------------------------------------------------------

// TestWithSchedulerLock_FnError verifies that a non-nil error returned by fn
// propagates when running on SQLite (always-run, no advisory lock).
func TestWithSchedulerLock_FnError(t *testing.T) {
	ls := newS17Store(t)
	sentinel := errors.New("scheduler job failed")

	ran, err := ls.WithSchedulerLock(context.Background(), 42, func() error {
		return sentinel
	})

	assert.True(t, ran, "SQLite always reports ran=true")
	require.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// local_audit_checkpoint_lock.go — fn-error propagation (SQLite path, line 41)
// ---------------------------------------------------------------------------

// TestWithAuditCheckpointLock_S17_FnError verifies that a non-nil error returned
// by fn propagates out of WithAuditCheckpointLock on SQLite.
func TestWithAuditCheckpointLock_S17_FnError(t *testing.T) {
	ls := newS17Store(t)
	sentinel := errors.New("checkpoint write failed")

	err := ls.WithAuditCheckpointLock(context.Background(), func() error {
		return sentinel
	})

	require.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// local_notifications.go:31 — CreateNotification
// ---------------------------------------------------------------------------

// TestCreateNotification_S17_HappyPath exercises the successful creation
// path, covering the return (n, nil) branch at line 38.
func TestCreateNotification_S17_HappyPath(t *testing.T) {
	ls := newS17Store(t, &models.Notification{})
	pid := uint(5)
	n := &models.Notification{
		UserID:    2,
		ProjectID: &pid,
		Type:      "rotation.reminder",
		Title:     "Rotate soon",
		Message:   "please rotate",
	}
	got, err := ls.CreateNotification(context.Background(), n)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.NotZero(t, got.ID)
	assert.Equal(t, uint(2), got.UserID)
}

// TestCreateNotification_S17_BrokenDB exercises the generic DB-error path
// (table absent) in CreateNotification (line 34).
func TestCreateNotification_S17_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t) // no AutoMigrate — no table
	n := &models.Notification{UserID: 1, Type: "test", Title: "T", Message: "m"}
	_, err := ls.CreateNotification(context.Background(), n)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secrets.go:51 — CreateProject
// ---------------------------------------------------------------------------

// TestCreateProject_S17_HappyPath exercises the successful project creation
// path (line 62) on a properly migrated schema.
func TestCreateProject_S17_HappyPath(t *testing.T) {
	ls := newS17Store(t,
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.ShareRecord{},
		&models.DynamicSecretConfig{},
	)
	p, err := ls.CreateProject(context.Background(), &models.Project{Name: "my-app"})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.NotZero(t, p.ID)
	assert.Equal(t, "my-app", p.Name)
}

// TestCreateProject_S17_BrokenDB exercises the generic DB-error return of
// CreateProject when no projects table exists (line 58).
func TestCreateProject_S17_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.CreateProject(context.Background(), &models.Project{Name: "x"})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secrets.go:166 — deleteProjectCascade (via DeleteProject)
// ---------------------------------------------------------------------------

// TestDeleteProjectCascade_S17_CascadesSoftDeletes triggers deleteProjectCascade
// via DeleteProject and asserts that the project, its secrets, and its
// environments are all soft-deleted.
func TestDeleteProjectCascade_S17_CascadesSoftDeletes(t *testing.T) {
	ls := newS17Store(t,
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{},
		&models.DynamicSecretConfig{},
	)
	ctx := context.Background()

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "cascade-test"})
	require.NoError(t, err)

	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)

	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Name:          "db-pw",
		IsSecret:      true,
		Type:          "text",
		Status:        "active",
	})
	require.NoError(t, err)

	require.NoError(t, ls.DeleteProject(ctx, proj.ID))

	// Active list excludes the soft-deleted project.
	active, err := ls.ListProjects(ctx)
	require.NoError(t, err)
	for _, p := range active {
		assert.NotEqual(t, proj.ID, p.ID)
	}

	// Soft-deleted secret is no longer accessible.
	_, err = ls.GetSecret(ctx, sec.ID)
	require.Error(t, err, "soft-deleted secret must not be retrievable")

	// No live environments remain.
	envs, err := ls.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Empty(t, envs)
}

// TestDeleteProjectCascade_S17_NotFoundError verifies the "project not found"
// error when deleteProjectCascade finds 0 rows affected (line 233-235).
func TestDeleteProjectCascade_S17_NotFoundError(t *testing.T) {
	ls := newS17Store(t,
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{},
		&models.DynamicSecretConfig{},
	)
	err := ls.DeleteProject(context.Background(), 99999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
