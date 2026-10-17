// Package sqlitetest opens the throwaway in-memory SQLite databases this
// repo's tests use, with the ONE connection-pool setting shared-cache SQLite
// actually requires — so that setting lives in a single place instead of being
// remembered, or forgotten, at every `gorm.Open` call site (#2906).
//
// The problem it closes. A test DB has to be BOTH in-memory and visible to
// every connection in the pool, which forces the DSN shape this repo uses
// everywhere:
//
//	file:<unique-name>?mode=memory&cache=shared
//
// `mode=memory` WITHOUT `cache=shared` is not an option: each pooled
// connection would then get its own private, empty database (a trap this repo
// has already documented — see internal/core/core_sequence_fuzz_test.go).
// But `cache=shared` means every connection in the pool contends for
// SQLite's TABLE-level shared-cache locks, and a read-vs-write collision there
// surfaces as SQLITE_LOCKED, "database table is locked".
//
// A busy timeout does NOT help with that. `_busy_timeout` (and its `_timeout`
// alias) drives SQLite's busy HANDLER, which is consulted for SQLITE_BUSY —
// not for the SQLITE_LOCKED a shared cache raises; retrying that one requires
// sqlite3_unlock_notify, which this driver does not wire up. So a test whose
// DSN carries `_timeout=30000` is not protected, and that is precisely the
// shape #2906's flake was reported on.
//
// What works is capping the pool to ONE connection: with a single connection
// there is no second connection in the cache to collide with, and Go's own
// database/sql pool serialises concurrent callers — including the detached
// goSafe audit writers that make the collision reachable from an otherwise
// sequential test. Measured on this repo's own tables, a four-second
// read/write/transaction hammer across 8 goroutines produces ~180k
// "database table is locked" errors on an uncapped pool and exactly zero on a
// capped one (sqlitetest_test.go keeps both halves of that measurement as
// standing tests).
//
// Test-only: nothing outside *_test.go files may import this package.
package sqlitetest

import (
	"fmt"
	"sync/atomic"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// dbSeq keeps every DSN this process hands out unique, so two tests (or two
// calls from the same test) never share a database by accident. Shared-cache
// names are process-global: two `gorm.Open`s on the same name ARE the same
// database.
var dbSeq atomic.Int64

// DSN builds a unique in-memory shared-cache DSN. Exported for the few callers
// that need the string rather than a *gorm.DB (a factory under test, a driver
// opened through database/sql directly) — they must cap their own pool to one
// connection, which is the whole reason to prefer Open.
func DSN(prefix string) string {
	// sqlitetest: deliberate cache=shared (the one sanctioned shared-cache DSN).
	return fmt.Sprintf("file:%s%d?mode=memory&cache=shared&_busy_timeout=30000", prefix, dbSeq.Add(1))
}

// Open returns a *gorm.DB on a fresh, private in-memory database, with the
// pool capped to a single connection and the DB closed on tb's cleanup.
// prefix only has to be recognisable in a DSN; uniqueness is added here.
//
// Closing on cleanup matters for more than tidiness: a shared-cache in-memory
// database lives exactly as long as some connection to it is open, so leaking
// the pool leaks the whole database for the rest of the test binary's run.
func Open(tb testing.TB, prefix string) *gorm.DB {
	tb.Helper()
	return OpenWithConfig(tb, prefix, &gorm.Config{Logger: logger.Discard})
}

// OpenWithConfig is Open for a caller that needs its own *gorm.Config (a
// different logger, NamingStrategy, DisableForeignKeyConstraintWhenMigrating,
// …). The pool cap and the cleanup are applied identically; the config is the
// only thing the caller gets to choose.
func OpenWithConfig(tb testing.TB, prefix string, cfg *gorm.Config) *gorm.DB {
	tb.Helper()
	return OpenWithDialector(tb, prefix, sqlite.Open, cfg)
}

// OpenWithDialector is OpenWithConfig for a caller whose tests must run on a
// different GORM dialector than gorm.io/driver/sqlite — in practice
// internal/storage/sqlitedialect (modernc.org/sqlite), the dialect production
// uses, whose error translator and migrator the tests under internal/storage,
// internal/core and server/admin exercise. open receives the unique DSN and
// returns the dialector; the pool cap and the cleanup are identical.
func OpenWithDialector(tb testing.TB, prefix string, open func(dsn string) gorm.Dialector, cfg *gorm.Config) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(open(DSN(prefix)), cfg)
	if err != nil {
		tb.Fatalf("sqlitetest: open in-memory sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		tb.Fatalf("sqlitetest: reach the underlying *sql.DB: %v", err)
	}
	// One connection, and one that is never retired: a second connection would
	// reintroduce shared-cache table-lock contention, and letting the single
	// idle connection be closed would drop the in-memory database with it.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)
	sqlDB.SetConnMaxIdleTime(0)
	tb.Cleanup(func() { _ = sqlDB.Close() })
	return db
}
