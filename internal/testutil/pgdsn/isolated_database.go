package pgdsn

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var isolatedDBCounter atomic.Int64

// IsolatedDatabase creates a fresh, empty database on the Postgres server at
// base, drops it on test cleanup, and returns base pointed at it.
//
// Use it, not a search_path schema, when the code under test takes a Postgres
// advisory lock. Advisory locks are scoped to the database, not the schema, so
// tests in separate schemas of one database share every lock key. go test runs
// packages in parallel against the one KEYORIX_TEST_PG_DSN database, and a
// test in one package that takes a lock (the audit index build lock, say)
// makes the same lock fail or wait in another package's test (#3295).
//
// prefix names the database (<prefix>_<pid>_<n>), so a leftover from a killed
// run shows which test created it.
func IsolatedDatabase(tb testing.TB, base, prefix string) string {
	tb.Helper()
	name := fmt.Sprintf("%s_%d_%d", prefix, os.Getpid(), isolatedDBCounter.Add(1))
	// A database name cannot be a bind parameter; quote it as an identifier.
	ident := pgx.Identifier{name}.Sanitize()
	exec := func(stmt string) error {
		db, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			return err
		}
		if sqlDB, err := db.DB(); err == nil {
			defer func() { _ = sqlDB.Close() }()
		}
		return db.Exec(stmt).Error
	}
	if err := exec("CREATE DATABASE " + ident); err != nil {
		tb.Fatalf("create database %s: %v", name, err)
	}
	tb.Cleanup(func() {
		// FORCE (PG 13+) also ends connections a failed test left open.
		_ = exec("DROP DATABASE IF EXISTS " + ident + " WITH (FORCE)")
	})
	return PGReplaceDBName(base, name)
}
