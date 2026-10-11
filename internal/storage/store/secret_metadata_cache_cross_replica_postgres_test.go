// secret_metadata_cache_cross_replica_postgres_test.go — proves the
// read-path metadata cache (PERF-3, docs/specs/read-path-caching.md) is
// correct ACROSS replicas, not just within one process. Two independent
// *gorm.DB pools (two store.LocalStorage instances, each with its OWN
// in-process cache — see secret_metadata_cache.go's header for why that
// per-instance isolation is itself load-bearing for this test to mean
// anything) share ONE real Postgres schema, migrated through the real
// production entry point (storagefactory.NewStorageFactory().CreateStorage),
// mirroring backend_differential_fuzz_test.go's own setup.
//
// Postgres only, skipped cleanly when KEYORIX_TEST_PG_DSN is unset.
package store_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	storagefactory "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var crossReplicaSchemaSeq atomic.Int64

// newCrossReplicaPair returns two independent store.LocalStorage instances
// (own *gorm.DB pool, own in-process cache each) sharing one real Postgres
// schema, migrated through the production path. t.Cleanup drops the schema.
func newCrossReplicaPair(t *testing.T) (*store.LocalStorage, *store.LocalStorage) {
	t.Helper()
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping cross-replica Postgres test")
	}
	// Own prefix: cross_replica_postgres_helpers_test.go (RBAC cache) names its
	// schemas perf3_crcache_<pid>_<seq> from a DIFFERENT counter, so sharing the
	// prefix let the two helpers hand out the same name and one test's
	// DROP SCHEMA ... CASCADE destroy the other's tables ("relation secret_nodes
	// does not exist", pg_namespace duplicate key) -- seen in CI on #2764.
	schema := fmt.Sprintf("perf3_crsecret_%d_%d", os.Getpid(), crossReplicaSchemaSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		cleaner, cerr := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
		if cerr == nil {
			_ = cleaner.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		}
	})
	targetDSN := pgdsn.PGSearchPathDSN(pgDSN, schema)

	_, err = storagefactory.NewStorageFactory().CreateStorage(&config.Config{
		Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: targetDSN}},
	})
	require.NoError(t, err)

	openReplica := func() *store.LocalStorage {
		db, oerr := gorm.Open(postgres.Open(targetDSN), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, oerr)
		sqlDB, derr := db.DB()
		require.NoError(t, derr)
		sqlDB.SetMaxOpenConns(2)
		sqlDB.SetMaxIdleConns(1)
		t.Cleanup(func() { _ = sqlDB.Close() })
		return store.NewLocalStorage(db)
	}
	return openReplica(), openReplica()
}

// TestCrossReplica_SecretMetadataCache_UpdateVisibleOnNextRead is this
// plan's core correctness claim for PR-1: a secret write committed by
// replica A is visible on replica B's VERY NEXT read, even though B has its
// own independent, already-warm cache for that same secret.
func TestCrossReplica_SecretMetadataCache_UpdateVisibleOnNextRead(t *testing.T) {
	t.Parallel()
	replicaA, replicaB := newCrossReplicaPair(t)
	ctx := context.Background()

	created, err := replicaA.CreateSecret(ctx, &models.SecretNode{
		Name: "cr-secret", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Warm BOTH replicas' caches on the pre-update row.
	before, err := replicaA.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "", before.Description)
	beforeB, err := replicaB.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "", beforeB.Description)

	// Replica A commits a write.
	before.Description = "set by replica A"
	before.UpdatedAt = time.Now()
	_, err = replicaA.UpdateSecret(ctx, before)
	require.NoError(t, err)

	// Replica B's VERY NEXT read must see it — not after any delay, not
	// after any explicit cross-process invalidation call (there is none;
	// see secret_metadata_cache.go's header for why this cache needs none).
	afterB, err := replicaB.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "set by replica A", afterB.Description,
		"replica B served a stale pre-update snapshot from its own cache after replica A's committed write")
}

// TestCrossReplica_SecretMetadataCache_DeleteVisibleOnNextRead is the
// access-schedule-adjacent "a read window closes immediately" case the
// spec's PR-1 section calls for, generalized to the node itself: a delete
// committed by replica A must be visible to replica B's very next read.
func TestCrossReplica_SecretMetadataCache_DeleteVisibleOnNextRead(t *testing.T) {
	t.Parallel()
	replicaA, replicaB := newCrossReplicaPair(t)
	ctx := context.Background()

	created, err := replicaA.CreateSecret(ctx, &models.SecretNode{
		Name: "cr-secret-del", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	_, err = replicaB.GetSecret(ctx, created.ID) // warm B's cache
	require.NoError(t, err)

	require.NoError(t, replicaA.DeleteSecret(ctx, created.ID))

	_, err = replicaB.GetSecret(ctx, created.ID)
	require.Error(t, err, "replica B served a stale pre-delete snapshot from its own cache after replica A's committed delete")
}

// TestCrossReplica_SecretAccessSchedule_RemovalVisibleOnNextRead is the
// spec's literal "access-schedule removal (read window closes) takes
// effect on the very next read on every replica" test.
func TestCrossReplica_SecretAccessSchedule_RemovalVisibleOnNextRead(t *testing.T) {
	t.Parallel()
	replicaA, replicaB := newCrossReplicaPair(t)
	ctx := context.Background()

	created, err := replicaA.CreateSecret(ctx, &models.SecretNode{
		Name: "cr-secret-sched", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, replicaA.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{
		SecretNodeID: created.ID, AllowedDays: "1,2,3,4,5", StartHour: 9, EndHour: 17, Timezone: "UTC",
	}))

	warmB, err := replicaB.GetSecretAccessSchedule(ctx, created.ID) // warm B's cache on the live schedule
	require.NoError(t, err)
	require.NotNil(t, warmB)

	require.NoError(t, replicaA.DeleteSecretAccessSchedule(ctx, created.ID))

	gone, err := replicaB.GetSecretAccessSchedule(ctx, created.ID)
	require.NoError(t, err)
	require.Nil(t, gone, "replica B served a stale pre-removal schedule from its own cache after replica A removed it")
}
