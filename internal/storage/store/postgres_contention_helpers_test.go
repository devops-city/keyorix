package store

// postgres_contention_helpers_test.go — shared setup for the Postgres HA-lock
// contention tests (audit chain, bootstrap lock, scheduler lease, FOR UPDATE
// row locks). Every lock these tests cover is a no-op on SQLite by design (see
// each lock file's own doc comment) — a single-connection test proves nothing
// about them, since a broken pg_advisory_lock/FOR UPDATE passes trivially
// under one connection. These helpers give each test multiple, INDEPENDENT
// *gorm.DB connections (and, correspondingly, independent LocalStorage
// instances with their own process-local mutexes) into the SAME isolated
// Postgres schema — simulating separate server replica processes racing the
// same database, which is the only way the advisory/row lock is the sole
// thing standing between the writers and a corrupted result.
//
// Gated behind KEYORIX_TEST_PG_DSN (see internal/cli/encryption/rotate_e2e_test.go
// for the existing precedent this mirrors) — skipped, not silently passed,
// when unset. CI sets it (see .github/workflows/ci.yml's postgres service
// container); a local run needs a reachable Postgres and the env var set.

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var pgContentionSchemaCounter atomic.Int64

// pgTestDSN returns the KEYORIX_TEST_PG_DSN base DSN, skipping the test (not
// failing it) when unset — the same opt-in shape as every other Postgres-gated
// test in this repo.
func pgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres HA-lock contention test")
	}
	return dsn
}

// pgIsolatedSchemaDSN creates a fresh schema on the real Postgres server at
// base, dropped on test cleanup, and returns a DSN with search_path pointed at
// it. Every gorm.Open against the returned DSN gets an independent connection
// into the SAME schema — that shared target is what makes the resulting
// connections comparable to separate replica processes racing one database.
func pgIsolatedSchemaDSN(t *testing.T, base string) string {
	t.Helper()
	n := pgContentionSchemaCounter.Add(1)
	schema := fmt.Sprintf("contend_%d_%d", os.Getpid(), n)

	admin := pgOpen(t, base)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		cleaner := pgOpen(t, base)
		_ = cleaner.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
	})

	return pgdsn.PGSearchPathDSN(base, schema)
}

// pgOpen opens a *gorm.DB against dsn, closing it on test cleanup. Each call
// returns a genuinely separate connection (separate *sql.DB pool) — never
// share one *gorm.DB across the "instances" a contention test races, or the
// test would only ever exercise a single connection's own serialization, not
// the cross-connection lock this whole file exists to verify.
func pgOpen(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}
