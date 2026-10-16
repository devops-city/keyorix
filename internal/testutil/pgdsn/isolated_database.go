package pgdsn

import (
	"database/sql"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
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
// run shows which test created it. It must be a valid unquoted identifier.
func IsolatedDatabase(tb testing.TB, base, prefix string) string {
	tb.Helper()
	name := fmt.Sprintf("%s_%d_%d", prefix, os.Getpid(), isolatedDBCounter.Add(1))
	admin, err := sql.Open("pgx", base)
	if err != nil {
		tb.Fatalf("open %s: %v", prefix, err)
	}
	defer func() { _ = admin.Close() }()
	// A database name cannot be a bind parameter; quote it as an identifier.
	ident := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec("CREATE DATABASE " + ident); err != nil { //nolint:gosec // nosemgrep: go.lang.security.audit.sqli.gosql-sqli.gosql-sqli -- DDL takes no bind parameters; ident is a quoted identifier built from the caller's prefix, the pid and a counter, never external input
		tb.Fatalf("create database %s: %v", name, err)
	}
	tb.Cleanup(func() {
		cleaner, err := sql.Open("pgx", base)
		if err != nil {
			return
		}
		defer func() { _ = cleaner.Close() }()
		// FORCE (PG 13+) also ends connections a failed test left open.
		_, _ = cleaner.Exec("DROP DATABASE IF EXISTS " + ident + " WITH (FORCE)") //nolint:gosec // nosemgrep: go.lang.security.audit.sqli.gosql-sqli.gosql-sqli -- as CREATE DATABASE above
	})
	return PGReplaceDBName(base, name)
}
