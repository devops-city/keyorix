package core

// postgres_contention_helpers_test.go — shared setup for cross-replica
// Postgres HA-lock contention tests in this package. Distinct from
// TestConcurrency_BootstrapSystem_CrossReplicaExactlyOneAdmin's own
// sharedBootstrapStorage: that helper hands every simulated "replica" the
// SAME storage.Storage instance, so they all serialize through one shared
// LocalStorage's process-local bootstrapMu regardless of whether the
// Postgres advisory lock in WithBootstrapLock does anything at all — a
// single-instance test cannot distinguish "the lock works" from "the lock is
// gone". These helpers instead give each simulated replica its own *gorm.DB
// connection (own LocalStorage, own bootstrapMu) into the SAME isolated
// Postgres schema, so pg_advisory_lock is the only thing left that can still
// serialize them.

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var corePgContentionSchemaCounter int64

// pgTestDSN returns the KEYORIX_TEST_PG_DSN base DSN, skipping the test (not
// failing it) when unset.
func pgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres HA-lock contention test")
	}
	return dsn
}

// pgIsolatedSchemaDSN creates a fresh schema on the real Postgres server at
// base, dropped on test cleanup, and returns a DSN with search_path pointed
// at it.
func pgIsolatedSchemaDSN(t *testing.T, base string) string {
	t.Helper()
	n := atomic.AddInt64(&corePgContentionSchemaCounter, 1)
	schema := fmt.Sprintf("core_contend_%d_%d", os.Getpid(), n)

	admin := pgOpen(t, base)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		cleaner := pgOpen(t, base)
		_ = cleaner.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
	})

	return pgdsn.PGSearchPathDSN(base, schema)
}

// pgMigratedDatabaseDSN returns a DSN for a fresh database that already holds
// the production schema (kxstorage.MigrateExisting), cloned from a template
// built once per schema fingerprint (pgdsn.MigratedDatabase). Use it instead
// of pgIsolatedSchemaDSN + MigrateExisting. Tests of the migration itself must
// keep an empty schema or database.
func pgMigratedDatabaseDSN(t *testing.T, base string) string {
	t.Helper()
	return pgdsn.MigratedDatabase(t, base, "core_migrated", pgdsn.SchemaFingerprint(), kxstorage.MigrateExisting)
}

// pgOpen opens a *gorm.DB against dsn, closing it on test cleanup. Each call
// is a genuinely separate connection — the independence contention tests in
// this file rely on.
//
// Capped to a small pool (coordinator review, PR #2370): database/sql's
// default MaxOpenConns is 0 (unlimited), so an uncapped pool can silently
// open far more than one real TCP connection under concurrent load. A
// cross-replica test calling pgOpen several times per trial, across many
// trials, with every pool's actual close deferred to this test's own
// t.Cleanup (which doesn't run until the whole test FUNCTION returns, not
// per-trial), accumulates enough live connections across a full test binary
// run to exhaust a CI Postgres service's low max_connections — found live:
// the full-matrix merge-group run failed opening a replica pool with
// "FATAL: sorry, too many clients already (SQLSTATE 53300)". A handful of
// connections per logical "replica" is never actually needed here — these
// tests issue one serialized operation per replica, not concurrent queries
// within one — so capping costs nothing real.
func pgOpen(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err, "open Postgres connection (dsn schema-scoped, see pgIsolatedSchemaDSN)")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(2)
	sqlDB.SetMaxIdleConns(1)
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})
	return db
}
