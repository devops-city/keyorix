// local_coverage_test.go — targeted coverage for uncovered branches in local
// storage functions (store-local coverage improvement run).
//
// Targets (all previously under-covered local paths):
//
//	local_scheduler_lock.go:36       WithSchedulerLock         (9.5%)
//	local_audit_checkpoint_lock.go:37 WithAuditCheckpointLock  (23.5%)
//	local_secrets.go:166             deleteProjectCascade      (66.7%)
//	local_secret_dependencies.go:48  ListSecretDepsForUpdate   (71.4%)
//	local_secret_dependencies.go:79  CreateSecretDepExclusive  (77.3%)
//	local_purge.go:51                PurgeDeletedUsersBefore   (77.8%)
//	local_secrets.go:478             DeleteSecret              (77.8%)
//	local_secrets.go:636             ListOrphanedSecrets       (80.0%)
//
// All tests use either newBrokenDB (no AutoMigrate — forces "no such table"
// errors cheaply) or a properly-migrated in-memory SQLite store.
package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newCovStore opens a unique in-memory SQLite and migrates the provided models.
func newCovStore(t *testing.T, ms ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "localcoverage_", sqlite.Open, &gorm.Config{})
	if len(ms) > 0 {
		require.NoError(t, db.AutoMigrate(ms...))
	}
	return NewLocalStorage(db)
}

// newSecretOnlyStore has secret_nodes but NOT share_records, so the share-
// revoke step inside DeleteSecret and deleteProjectCascade fails with "no
// such table".
func newSecretOnlyStore(t *testing.T) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "localcoverage_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}))
	return NewLocalStorage(db)
}

// newDepOnlyBrokenStore has secret_dependencies but NOT the tables for any
// other model — useful for testing broken-DB paths inside the dependency
// functions.
func newDepOnlyBrokenStore(t *testing.T) *LocalStorage {
	t.Helper()
	// No AutoMigrate → all table-touching queries fail.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// WithSchedulerLock — additional paths
// ---------------------------------------------------------------------------

// TestWithSchedulerLock_Cov_ConcurrentSQLite exercises multiple goroutines
// calling WithSchedulerLock on SQLite simultaneously to flush concurrent-
// execution paths of runProtected through the coverage counter.
func TestWithSchedulerLock_Cov_ConcurrentSQLite(t *testing.T) {
	ls := newCovStore(t)
	ctx := context.Background()

	const n = 6
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		key := int64(i + 1)
		go func(k int64) {
			defer wg.Done()
			ran, err := ls.WithSchedulerLock(ctx, k, func(context.Context) error { return nil })
			assert.True(t, ran)
			assert.NoError(t, err)
		}(key)
	}
	wg.Wait()
}

// TestWithSchedulerLock_Cov_PanicInFnAfterMultipleCalls verifies panic
// recovery across repeated calls with different keys.
func TestWithSchedulerLock_Cov_PanicInFnAfterMultipleCalls(t *testing.T) {
	ls := newCovStore(t)
	ctx := context.Background()

	// Normal call first.
	ran, err := ls.WithSchedulerLock(ctx, 100, func(context.Context) error { return nil })
	require.NoError(t, err)
	assert.True(t, ran)

	// Panicking call — must not propagate.
	ran, err = ls.WithSchedulerLock(ctx, 200, func(context.Context) error {
		panic("deliberate panic in scheduler fn")
	})
	assert.True(t, ran)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panicked")

	// Next call with a different key still works after the panic.
	ran, err = ls.WithSchedulerLock(ctx, 300, func(context.Context) error { return nil })
	require.NoError(t, err)
	assert.True(t, ran)
}

// ---------------------------------------------------------------------------
// WithAuditCheckpointLock — additional paths
// ---------------------------------------------------------------------------

// TestWithAuditCheckpointLock_Cov_SequentialCalls verifies that the mutex
// is released after each call so a long sequence of sequential invocations
// succeeds without deadlocking.
func TestWithAuditCheckpointLock_Cov_SequentialCalls(t *testing.T) {
	ls := newCovStore(t)
	ctx := context.Background()

	for i := range 5 {
		err := ls.WithAuditCheckpointLock(ctx, func(context.Context) error { return nil })
		require.NoError(t, err, "iteration %d must not error or deadlock", i)
	}
}

// TestWithAuditCheckpointLock_Cov_MutexSerializesConcurrent drives many
// goroutines to exercise the auditCheckpointMu serialization code path
// (non-postgres branch) in parallel.
func TestWithAuditCheckpointLock_Cov_MutexSerializesConcurrent(t *testing.T) {
	ls := newCovStore(t)
	ctx := context.Background()

	const n = 10
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		counter int
	)
	errs := make([]error, n)

	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = ls.WithAuditCheckpointLock(ctx, func(context.Context) error {
				mu.Lock()
				counter++
				mu.Unlock()
				return nil
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d must not error", i)
	}
	mu.Lock()
	assert.Equal(t, n, counter)
	mu.Unlock()
}

// ---------------------------------------------------------------------------
// deleteProjectCascade error paths (via DeleteProject)
// ---------------------------------------------------------------------------

// TestDeleteProjectCascade_Cov_ShareRevokeError triggers the
// "failed to revoke project secret shares" branch by having a project with a
// live secret but no share_records table.
func TestDeleteProjectCascade_Cov_ShareRevokeError(t *testing.T) {
	ls := newSecretOnlyStore(t)
	ctx := context.Background()

	// Create a project with a live secret so the cascade reaches the share-
	// revoke step, where it will fail because share_records doesn't exist.
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "cov-cascade"})
	require.NoError(t, err)

	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "env1", ProjectID: proj.ID})
	require.NoError(t, err)

	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Name:          "sec1",
		IsSecret:      true,
		Type:          "password",
		Status:        "active",
	})
	require.NoError(t, err)

	// DeleteProject calls deleteProjectCascade; the share-revoke step errors.
	err = ls.DeleteProject(ctx, proj.ID)
	require.Error(t, err)
}

// TestDeleteProjectCascade_Cov_BrokenDB uses a completely broken DB so the
// very first step of the cascade (soft-delete secrets) fails immediately.
func TestDeleteProjectCascade_Cov_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.DeleteProject(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// DeleteSecret error paths
// ---------------------------------------------------------------------------

// TestDeleteSecret_Cov_BrokenDB verifies the result.Error != nil path (the
// delete itself fails because there is no secret_nodes table).
func TestDeleteSecret_Cov_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.DeleteSecret(context.Background(), 42)
	require.Error(t, err)
}

// TestDeleteSecret_Cov_ShareRevokeError triggers the share-revoke error
// branch: secret_nodes exists (so the delete succeeds and RowsAffected > 0)
// but share_records does NOT — the share-cleanup step fails with "no such
// table".
func TestDeleteSecret_Cov_ShareRevokeError(t *testing.T) {
	ls := newSecretOnlyStore(t)
	ctx := context.Background()

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "p-share-err"})
	require.NoError(t, err)

	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "e1", ProjectID: proj.ID})
	require.NoError(t, err)

	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Name:          "pw1",
		IsSecret:      true,
		Type:          "password",
		Status:        "active",
	})
	require.NoError(t, err)

	// Deletion finds the row (RowsAffected=1) but then fails on the missing
	// share_records table.
	err = ls.DeleteSecret(ctx, sec.ID)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// ListOrphanedSecrets error path
// ---------------------------------------------------------------------------

// TestListOrphanedSecrets_Cov_BrokenDB exercises the error-return branch
// (DB error propagated as ErrorRetrievalFailed).
func TestListOrphanedSecrets_Cov_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListOrphanedSecrets(context.Background(), 1)
	require.Error(t, err)
}

// TestListOrphanedSecrets_Cov_HappyEmpty verifies that a project with live
// secrets but no deleted/missing owners returns an empty list (not nil error).
func TestListOrphanedSecrets_Cov_HappyEmpty(t *testing.T) {
	ls := newCovStore(t,
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.User{},
	)
	ctx := context.Background()

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "p-orphan"})
	require.NoError(t, err)

	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "e1", ProjectID: proj.ID})
	require.NoError(t, err)

	// Live user.
	user := &models.User{Username: "alive", Email: "alive@x.test"}
	require.NoError(t, ls.db.Create(user).Error)

	// Secret whose owner is alive — NOT an orphan.
	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Name:          "sec1",
		IsSecret:      true,
		Type:          "password",
		Status:        "active",
		OwnerID:       user.ID,
	})
	require.NoError(t, err)

	orphans, err := ls.ListOrphanedSecrets(ctx, proj.ID)
	require.NoError(t, err)
	assert.Empty(t, orphans)
}

// ---------------------------------------------------------------------------
// ListSecretDependenciesForProjectForUpdate error path
// ---------------------------------------------------------------------------

// TestListSecretDepsForProjectForUpdate_Cov_BrokenDB exercises the error
// branch (query fails because secret_dependencies table does not exist).
func TestListSecretDepsForProjectForUpdate_Cov_BrokenDB(t *testing.T) {
	ls := newDepOnlyBrokenStore(t)
	_, err := ls.ListSecretDependenciesForProjectForUpdate(context.Background(), 1)
	require.Error(t, err)
}

// TestListSecretDepsForProjectForUpdate_Cov_EmptyProject verifies the SQLite
// non-postgres branch when there are no edges — returns empty slice, no error.
func TestListSecretDepsForProjectForUpdate_Cov_EmptyProject(t *testing.T) {
	ls := newCovStore(t, &models.SecretDependency{})
	rows, err := ls.ListSecretDependenciesForProjectForUpdate(context.Background(), 999)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// ---------------------------------------------------------------------------
// CreateSecretDependencyExclusive — additional coverage
// ---------------------------------------------------------------------------

// TestCreateSecretDependencyExclusive_Cov_BrokenDB exercises the transaction
// error path when the DB has no tables.
func TestCreateSecretDependencyExclusive_Cov_BrokenDB(t *testing.T) {
	ls := newDepOnlyBrokenStore(t)
	_, err := ls.CreateSecretDependencyExclusive(context.Background(), &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 10, DependsOnSecretID: 20,
	})
	require.Error(t, err)
}

// TestCreateSecretDependencyExclusive_Cov_MultipleEdgesInProject verifies
// that multiple distinct edges within the same project can all be created
// (no false duplicate/cycle detection).
func TestCreateSecretDependencyExclusive_Cov_MultipleEdgesInProject(t *testing.T) {
	ls := newCovStore(t, &models.SecretDependency{})
	ctx := context.Background()

	// A→B in project 1.
	d1, err := ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 10, DependsOnSecretID: 20,
	})
	require.NoError(t, err)
	assert.NotZero(t, d1.ID)

	// C→D in project 1 — different pair, must NOT be rejected.
	d2, err := ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 30, DependsOnSecretID: 40,
	})
	require.NoError(t, err)
	assert.NotZero(t, d2.ID)
	assert.NotEqual(t, d1.ID, d2.ID)

	// E→F in project 2 — different project, different pair.
	d3, err := ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 2, DependentSecretID: 50, DependsOnSecretID: 60,
	})
	require.NoError(t, err)
	assert.NotZero(t, d3.ID)
}

// ---------------------------------------------------------------------------
// PurgeDeletedUsersBefore — additional error paths
// ---------------------------------------------------------------------------

// TestPurgeDeletedUsersBefore_Cov_BrokenDB exercises the top-level error
// path when the users table does not exist.
func TestPurgeDeletedUsersBefore_Cov_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.Error(t, err)
}

// TestPurgeDeletedUsersBefore_Cov_PurgesWithImpersonation exercises the
// Session cascade branch that deletes sessions where impersonated_by matches
// a purged user — covering the impersonated_by arm of the OR predicate.
func TestPurgeDeletedUsersBefore_Cov_PurgesWithImpersonation(t *testing.T) {
	ls := newCovStore(t,
		&models.User{},
		&models.Project{},
		&models.Environment{},
		&models.UserRole{},
		&models.GroupRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.ShareRecord{},
		&models.PersonalAccessToken{},
		&models.Session{},
		&models.SecretACL{},
	)
	ctx := context.Background()
	now := time.Now()

	// ghost: soft-deleted 40 days ago; will be purged.
	// admin: still live.
	require.NoError(t, ls.db.Create(&models.User{ID: 1, Username: "ghost", Email: "ghost@x"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 2, Username: "admin", Email: "admin@x"}).Error)
	require.NoError(t, ls.db.Unscoped().Model(&models.User{}).
		Where("id = ?", 1).Update("deleted_at", now.AddDate(0, 0, -40)).Error)

	// A session where ghost was the impersonated user.
	ghostID := uint(1)
	require.NoError(t, ls.db.Create(&models.Session{
		UserID: 2, SessionToken: "s-imp", ImpersonatedBy: &ghostID,
	}).Error)

	cutoff := now.AddDate(0, 0, -30)
	n, err := ls.PurgeDeletedUsersBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "ghost must be purged")

	// The impersonation session referencing ghost must also be gone.
	var sessionCount int64
	require.NoError(t, ls.db.Model(&models.Session{}).
		Where("impersonated_by = ?", 1).Count(&sessionCount).Error)
	assert.Zero(t, sessionCount, "session with impersonated_by=ghost must be purged")
}
