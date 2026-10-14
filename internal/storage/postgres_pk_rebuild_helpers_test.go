package storage

// postgres_pk_rebuild_helpers_test.go — setup for exercising rolePKIsComplete/
// rebuildRolePKPostgres against a REAL Postgres server. Unlike the contention
// tests elsewhere in this campaign (internal/storage/store,
// internal/core), this one isolates by creating a fresh, disposable DATABASE
// per test, so each test's tables genuinely live in that database's own
// "public" schema. (Historically this was forced: rolePKIsComplete,
// tableExists and columnExists hard-coded or ignored the schema, making a
// table under a non-public schema invisible to them. #1980 scoped them to
// current_schema(); see migrate_postgres_nonpublic_schema_test.go.)

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

var pkRebuildDBCounter atomic.Int64

// pgTestDSN returns the KEYORIX_TEST_PG_DSN base DSN, skipping the test (not
// failing it) when unset.
func pgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres role-PK migration test")
	}
	return dsn
}

// pgIsolatedDatabaseDSN creates a fresh, empty database on the real Postgres
// server at base, dropped on test cleanup, and returns a DSN pointing at it.
func pgIsolatedDatabaseDSN(t *testing.T, base string) string {
	t.Helper()
	n := pkRebuildDBCounter.Add(1)
	dbName := fmt.Sprintf("pk_rebuild_%d_%d", os.Getpid(), n)

	admin := pgRawOpen(t, base)
	require.NoError(t, admin.Exec("CREATE DATABASE "+dbName).Error)
	t.Cleanup(func() {
		cleaner := pgRawOpen(t, base)
		// FORCE (PG 13+) drops even if something still holds a connection —
		// this test always closes its own connections first, but a failed
		// test run may not have.
		_ = cleaner.Exec("DROP DATABASE IF EXISTS " + dbName + " WITH (FORCE)").Error
	})

	return pgdsn.PGReplaceDBName(base, dbName)
}

// pgRawOpen opens a *gorm.DB against dsn, closing it on test cleanup.
func pgRawOpen(t *testing.T, dsn string) *gorm.DB {
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
