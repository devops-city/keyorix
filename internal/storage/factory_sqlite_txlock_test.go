package storage

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/require"
)

// TestSqliteDSN_TxlockImmediate pins the #1996-chokepoint-flake fix: every
// SQLite DSN this codebase builds must request BEGIN IMMEDIATE (_txlock=immediate),
// exactly once, regardless of whether the caller supplied their own DSN query
// parameters already (sqliteDSN's "?" vs "&" separator branch) — a duplicated
// parameter would still work with SQLite's driver (last one wins) but would
// signal the append logic picked the wrong separator.
func TestSqliteDSN_TxlockImmediate(t *testing.T) {
	t.Run("plain path", func(t *testing.T) {
		dsn := sqliteDSN("/tmp/foo.db")
		require.Equal(t, 1, strings.Count(dsn, "_txlock=immediate"),
			"expected exactly one _txlock=immediate parameter, got DSN: %s", dsn)
	})

	t.Run("path with pre-existing query params", func(t *testing.T) {
		dsn := sqliteDSN("/tmp/foo.db?_time_format=sqlite")
		require.Equal(t, 1, strings.Count(dsn, "_txlock=immediate"),
			"expected exactly one _txlock=immediate parameter, got DSN: %s", dsn)
		require.Contains(t, dsn, "_time_format=sqlite", "the operator's own pre-existing parameter must be preserved")
		require.Equal(t, 1, strings.Count(dsn, "?"), "a second '?' would malform the DSN query string")
	})
}

// TestSqliteDSN_PostgresPathUntouched pins that the _txlock=immediate DSN
// pragma (a SQLite-only concept — Postgres has no BEGIN IMMEDIATE/DEFERRED
// distinction on this axis) never leaks into the Postgres connection string.
// createPostgresStorage connects via config.ResolvePostgresConnConfig, an
// entirely separate function from sqliteDSN — this test guards that
// separation structurally so a future refactor that accidentally routes both
// backends through one shared DSN builder gets caught here.
func TestSqliteDSN_PostgresPathUntouched(t *testing.T) {
	d := &config.DatabaseConfig{
		Host: "db.example.com",
		Port: "5432",
		Name: "keyorix",
		User: "keyorix",
	}
	cc, err := config.ResolvePostgresConnConfig(d)
	require.NoError(t, err)
	for _, k := range []string{"_txlock", "_busy_timeout", "_journal_mode"} {
		require.NotContains(t, cc.RuntimeParams, k, "Postgres connection must never carry the SQLite-only %s pragma", k)
	}
}
