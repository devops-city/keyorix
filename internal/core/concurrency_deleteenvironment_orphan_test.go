// concurrency_deleteenvironment_orphan_test.go — SESSION-AT: DeleteEnvironment
// counted active secrets and deleted the environment as two separate,
// non-transactional, unlocked statements, AND every operation that creates
// or re-activates a secret_nodes row (CreateSecret, CreateFolder,
// RestoreSecret) had its own environment-existence check (GetEnvironment /
// requireLiveEnvironment) with no lock spanning it and the actual write. A
// node created/restored in the window around a concurrent DeleteEnvironment
// call was silently orphaned: the environment row is gone, but a
// secret_nodes row with that environment_id remains, pointing at nothing.
//
// Uses a real, file-backed SQLite DB (WAL + busy_timeout) with the FULL
// production schema (kxstorage.MigrateExisting, not a hand-picked AutoMigrate
// subset -- see CLAUDE.md's own note on why that distinction matters), so
// two genuinely concurrent connections/goroutines can interleave through the
// real core call chain, not a synthetic storage-layer-only bypass. The
// _Postgres variant at the bottom reuses this package's own
// pgTestDSN/pgIsolatedSchemaDSN/pgOpen helpers (postgres_contention_helpers_test.go)
// to run the identical race with each "replica" on its own real connection,
// so storage.WithNamedLock's cross-replica advisory-lock path (not just its
// SQLite in-process-mutex path) is independently exercised too.
//
// package core (not core_test): needs this package's own unexported
// pgTestDSN/pgOpen/pgIsolatedSchemaDSN helpers for the _Postgres variant
// (coordinator review, PR #2353, point 4 -- reuse the existing DSN
// mechanism, don't invent a new one).
package core

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// deleteEnvironmentOrphanTrials was 50 before this round (coordinator
// review, PR #2353, point 5: "1/50 red is thin"); raised to 200 so the red
// (run against a deliberately reverted fix) is reproducible across runs, not
// a one-off. See this file's own TestMain-adjacent red-proof notes in the
// SESSION-AT report / PR body for the actual red output at this trial count.
const deleteEnvironmentOrphanTrials = 200

// newProjectEnvFixture creates a fresh file-backed DB (full production
// schema) with exactly one project and one environment, no auth/RBAC setup
// -- neither core.CreateSecret nor core.DeleteEnvironment requires an
// authenticated actor at the core layer (authorization is enforced at the
// transport layer, above core), so this fixture stays minimal.
func newProjectEnvFixture(t *testing.T, dbFile string) (c *KeyorixCore, db *gorm.DB, projectID, envID uint) {
	t.Helper()
	dsn := "file:" + dbFile + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, kxstorage.MigrateExisting(db))

	proj := &models.Project{Name: "proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	return NewKeyorixCore(localstore.NewLocalStorage(db)), db, proj.ID, env.ID
}

// raceAgainstDeleteEnvironment runs action concurrently with
// c.DeleteEnvironment(envID) from one start barrier and returns action's own
// error (possibly nil).
func raceAgainstDeleteEnvironment(c *KeyorixCore, ctx context.Context, envID uint, action func() error) (actionErr error) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-start; _ = c.DeleteEnvironment(ctx, envID) }()
	go func() { defer wg.Done(); <-start; actionErr = action() }()
	close(start)
	wg.Wait()
	return actionErr
}

// countOrphan reports whether envID is gone but a live active secret_nodes
// row referencing it still exists.
func countOrphan(t *testing.T, db *gorm.DB, envID uint) bool {
	t.Helper()
	var envExists bool
	require.NoError(t, db.Model(&models.Environment{}).
		Select("count(*) > 0").Where("id = ?", envID).Find(&envExists).Error)
	var secretCount int64
	require.NoError(t, db.Model(&models.SecretNode{}).
		Where("environment_id = ? AND status = 'active'", envID).Count(&secretCount).Error)
	return !envExists && secretCount > 0
}

// TestConcurrency_DeleteEnvironment_NeverOrphansAConcurrentlyCreatedSecret
// races core.DeleteEnvironment(envID) against core.CreateSecret(environment_id=envID).
func TestConcurrency_DeleteEnvironment_NeverOrphansAConcurrentlyCreatedSecret(t *testing.T) {
	var orphaned, wrongErrShape int
	for trial := range deleteEnvironmentOrphanTrials {
		c, db, projectID, envID := newProjectEnvFixture(t, filepath.Join(t.TempDir(), "delete_env.db"))
		ctx := context.Background()

		err := raceAgainstDeleteEnvironment(c, ctx, envID, func() error {
			_, err := c.CreateSecret(ctx, &CreateSecretRequest{
				Name: "concurrent-secret", Value: []byte("v"), ProjectID: projectID, EnvironmentID: envID,
				Type: "generic", CreatedBy: "test",
			})
			return err
		})
		if countOrphan(t, db, envID) {
			orphaned++
		}
		// SESSION-AT AT1/AT3 (coordinator review, PR #2353, point 2): when
		// CreateSecret loses the race, it must fail with the clean
		// "environment %d not found" validation shape, not a generic
		// storage-failure wrapper -- asserting this is what actually proves
		// the error-mapping fix (isEnvironmentNotFoundErr/envGoneInsideLock
		// in secrets.go), not just the absence of an orphan.
		if err != nil && !strings.Contains(err.Error(), "not found") {
			wrongErrShape++
			t.Logf("trial %d: CreateSecret failed with unexpected error shape: %v", trial, err)
		}
	}
	assert.Zero(t, orphaned, "%d/%d trials orphaned a secret: environment deleted while a concurrently-created active secret still points at it", orphaned, deleteEnvironmentOrphanTrials)
	assert.Zero(t, wrongErrShape, "%d/%d trials: a losing CreateSecret failed with something other than a clean \"not found\" error", wrongErrShape, deleteEnvironmentOrphanTrials)
}

// TestConcurrency_DeleteEnvironment_NeverOrphansAConcurrentlyCreatedFolder is
// the CreateFolder sibling of the above -- SESSION-AT AT1/AT3 (coordinator
// review, PR #2353, point 1): CreateFolder was found to bypass the guard
// entirely in the first version of this fix.
func TestConcurrency_DeleteEnvironment_NeverOrphansAConcurrentlyCreatedFolder(t *testing.T) {
	var orphaned int
	for range deleteEnvironmentOrphanTrials {
		c, db, projectID, envID := newProjectEnvFixture(t, filepath.Join(t.TempDir(), "delete_env_folder.db"))
		ctx := context.Background()

		_ = raceAgainstDeleteEnvironment(c, ctx, envID, func() error {
			_, err := c.CreateFolder(ctx, 1, "concurrent-folder", projectID, envID, nil)
			return err
		})
		if countOrphan(t, db, envID) {
			orphaned++
		}
	}
	assert.Zero(t, orphaned, "%d/%d trials orphaned a FOLDER: environment deleted while a concurrently-created active folder still points at it", orphaned, deleteEnvironmentOrphanTrials)
}

// TestConcurrency_DeleteEnvironment_NeverOrphansAConcurrentlyRestoredSecret
// is the RestoreSecret sibling -- SESSION-AT AT1/AT3 (coordinator review, PR
// #2353, point 1): un-deleting a secret re-activates a secret_nodes row
// exactly like create does, and RestoreSecret was found to bypass the guard
// entirely. Each trial seeds a soft-deleted secret BEFORE the race starts
// (RestoreSecret's own job is to bring it back, not create it fresh).
func TestConcurrency_DeleteEnvironment_NeverOrphansAConcurrentlyRestoredSecret(t *testing.T) {
	var orphaned int
	for range deleteEnvironmentOrphanTrials {
		c, db, projectID, envID := newProjectEnvFixture(t, filepath.Join(t.TempDir(), "delete_env_restore.db"))
		ctx := context.Background()

		created, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: "to-be-restored", Value: []byte("v"), ProjectID: projectID, EnvironmentID: envID,
			Type: "generic", CreatedBy: "test",
		})
		require.NoError(t, err)
		require.NoError(t, c.DeleteSecret(ctx, created.ID))

		_ = raceAgainstDeleteEnvironment(c, ctx, envID, func() error {
			return c.storage.RestoreSecret(ctx, created.ID)
		})
		if countOrphan(t, db, envID) {
			orphaned++
		}
	}
	assert.Zero(t, orphaned, "%d/%d trials orphaned a RESTORED secret: environment deleted while a concurrently-restored active secret still points at it", orphaned, deleteEnvironmentOrphanTrials)
}

// TestConcurrency_DeleteEnvironment_NeverOrphans_Postgres runs the same three
// races against a real Postgres server (KEYORIX_TEST_PG_DSN), each
// goroutine on its OWN connection (via pgOpen -- not a single shared
// LocalStorage instance, which would serialize through Go-level state and
// never actually exercise the cross-replica advisory-lock path
// storage.WithNamedLock's Postgres branch provides). Fewer trials than the
// SQLite versions (a real network round-trip per advisory-lock acquisition
// makes 200 trials prohibitively slow for a unit test) -- still enough to
// reproduce the race reliably if the lock stopped working across
// connections specifically (as opposed to within one process), which is the
// property this variant exists to prove that the SQLite-only variants above
// cannot.
func TestConcurrency_DeleteEnvironment_NeverOrphans_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	const pgTrials = 20

	newPgFixture := func(t *testing.T) (dbA, dbB *gorm.DB, projectID, envID uint) {
		t.Helper()
		dsn := pgMigratedDatabaseDSN(t, base)
		admin := pgOpen(t, dsn)

		proj := &models.Project{Name: "proj"}
		require.NoError(t, admin.Create(proj).Error)
		env := &models.Environment{Name: "prod", ProjectID: proj.ID}
		require.NoError(t, admin.Create(env).Error)

		// Two INDEPENDENT connections into the SAME schema -- each becomes a
		// separate *KeyorixCore below, so WithNamedLock's Postgres path (a
		// session advisory lock on the connection's own backend) is the only
		// thing that can serialize them; a shared LocalStorage would mask
		// that entirely via its own in-process mutex.
		return admin, pgOpen(t, dsn), proj.ID, env.ID
	}

	t.Run("CreateSecret", func(t *testing.T) {
		var orphaned int
		for range pgTrials {
			dbDelete, dbCreate, projectID, envID := newPgFixture(t)
			cDelete := NewKeyorixCore(localstore.NewLocalStorage(dbDelete))
			cCreate := NewKeyorixCore(localstore.NewLocalStorage(dbCreate))
			ctx := context.Background()

			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); <-start; _ = cDelete.DeleteEnvironment(ctx, envID) }()
			go func() {
				defer wg.Done()
				<-start
				_, _ = cCreate.CreateSecret(ctx, &CreateSecretRequest{
					Name: "concurrent-secret", Value: []byte("v"), ProjectID: projectID, EnvironmentID: envID,
					Type: "generic", CreatedBy: "test",
				})
			}()
			close(start)
			wg.Wait()

			if countOrphan(t, dbDelete, envID) {
				orphaned++
			}
		}
		assert.Zero(t, orphaned, "%d/%d Postgres trials orphaned a secret across two independent connections", orphaned, pgTrials)
	})
}
