package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/require"
)

// TestSQLiteDSN_SynchronousIsAlwaysFULL pins the storage-layer half of
// ADR-112 Amendment 1's Postgres-only decision (Andrei, 2026-10-05): the fast
// audit mode has NO SQLite branch, so this DSN says FULL unconditionally and
// there is no code path, config or otherwise, that can make it say NORMAL.
//
// The guard that keeps the two halves consistent is in internal/config: a
// SQLite backend with the setting present refuses to start
// (TestConfigValidate_RejectsFastAuditModeOnSQLite). This test is the other
// side — that even if such a config somehow reached the factory, the DSN it
// builds is still durable.
func TestSQLiteDSN_SynchronousIsAlwaysFULL(t *testing.T) {
	for _, path := range []string{"/data/secrets.db", sqlitetest.DSN("fastaudit_")} {
		dsn := sqliteDSN(path)
		require.Contains(t, dsn, "_synchronous=FULL",
			"the SQLite DSN must say FULL unconditionally: ADR-112 §3's baseline is that a secret value is "+
				"never returned before its audit record is durably committed, and Amendment 1's opt-out is "+
				"PostgreSQL-only")
		require.NotContains(t, dsn, "NORMAL",
			"a NORMAL branch has reappeared in the SQLite DSN. It was removed deliberately: PRAGMA "+
				"synchronous is per-connection and the pool is shared, so NORMAL relaxes EVERY table (a power "+
				"loss could undo a just-committed secret rotation or revocation), and the measured p99 got "+
				"worse under concurrency anyway. See sqliteDSN's doc comment.")
		// The setting may only ever change `synchronous`, and now not even
		// that — so every other pragma must be present regardless (#436,
		// #465, #1996).
		for _, want := range []string{"_foreign_keys=1", "_busy_timeout=10000", "_journal_mode=WAL", "_txlock=immediate"} {
			require.Containsf(t, dsn, want, "the SQLite DSN dropped %q", want)
		}
	}
}

// TestFastAuditMode_SQLiteStaysDurableThroughTheRealOpenPath is the same
// property end-to-end through the REAL production path, because a DSN string
// assertion alone does not prove SQLite honoured it. Mirrors
// TestSQLitePragmas_EnabledOnFreshConnection's method (CreateStorage to open,
// then a SECOND independent connection through OpenGormDB to read the pragma
// back) against a temp-FILE-backed database — never ":memory:", where
// journal_mode=WAL is silently downgraded and the pragma under test would not
// be exercised at all.
//
// Note the config here deliberately does NOT set
// InsecureAuditSkipDurableSync: that combination cannot be loaded at all
// (config validation rejects it), so constructing it here would test a state
// no deployment can reach. The reachable question is the one asked:
// does a SQLite install still get FULL now that the setting exists at all?
func TestFastAuditMode_SQLiteStaysDurableThroughTheRealOpenPath(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "fast-audit-pragma.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	db, err := OpenGormDB(cfg)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	var synchronous int
	require.NoError(t, sqlDB.QueryRow("PRAGMA synchronous").Scan(&synchronous))
	require.Equal(t, 2, synchronous,
		"PRAGMA synchronous must be FULL (2) on a live SQLite connection. Asserted on a SECOND connection "+
			"opened through OpenGormDB, so it proves the value is a property of every connection this "+
			"codebase opens against the configured path, not a one-off inside CreateStorage.")

	var journalMode string
	require.NoError(t, sqlDB.QueryRow("PRAGMA journal_mode").Scan(&journalMode))
	require.Equal(t, "wal", journalMode, "journal_mode must still be WAL (#465)")
}
