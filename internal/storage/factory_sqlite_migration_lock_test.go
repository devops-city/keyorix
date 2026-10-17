package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAcquireSQLiteMigrationLock_SecondAttemptFails pins #STORAGE-FACTORY-003:
// migrationMu (a sync.Mutex) only serializes migrateDatabase within a single OS
// process; nothing previously stopped two separate OS processes pointed at the
// same local SQLite file from racing DDL statements. This simulates a second
// OS process by acquiring the lock a second time via a second, independent
// open of the same lock file (an flock is scoped to the open file description,
// not the process, so two separate os.OpenFile calls model two separate
// processes for this purpose) while the first holder still has it, and asserts
// the second attempt fails fast (non-blocking) with an actionable error rather
// than hanging or silently succeeding.
func TestAcquireSQLiteMigrationLock_SecondAttemptFails(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrent-lock.db")

	first, err := acquireSQLiteMigrationLock(dbPath)
	require.NoError(t, err, "first acquisition must succeed")
	defer first.release()

	second, err := acquireSQLiteMigrationLock(dbPath)
	require.Error(t, err, "a second, concurrent acquisition attempt must fail while the first holder still holds the lock")
	assert.Nil(t, second)
	assert.Contains(t, err.Error(), "already holds the migration lock")

	// After the first holder releases, a subsequent acquisition must succeed —
	// this is not a permanently stuck lock, just held for the duration of one
	// process's connect-and-migrate critical section.
	first.release()
	third, err := acquireSQLiteMigrationLock(dbPath)
	require.NoError(t, err, "acquisition must succeed again once the prior holder releases")
	defer third.release()
}

// TestAcquireSQLiteMigrationLock_InMemoryDSN_SkipsLocking verifies that a
// storage.database.path denoting an in-memory database — "file:name?mode=memory
// [&cache=shared]" or ":memory:", both used throughout this package's own test
// suite via sqliteDSN — does not attempt to create an on-disk lock file at all.
// An in-memory database is confined to the process that opened it by
// construction, so no cross-process lock is meaningful; naively appending
// ".migration.lock" to the raw DSN string would otherwise create a garbage file
// on disk whose name embeds literal "?"/"&"/":" characters from the DSN.
func TestAcquireSQLiteMigrationLock_InMemoryDSN_SkipsLocking(t *testing.T) {
	for _, dbPath := range []string{
		sqlitetest.DSN("sometest_"),
		"file:sometest?mode=memory",
		":memory:",
	} {
		lock, err := acquireSQLiteMigrationLock(dbPath)
		require.NoError(t, err, "in-memory DSN %q must not error", dbPath)
		assert.Nil(t, lock, "in-memory DSN %q must not acquire a real lock", dbPath)
		lock.release() // must be a safe no-op on a nil lock
	}
}

// TestAcquireSQLiteMigrationLock_QueryStringStripped verifies that a real
// on-disk path carrying an operator-supplied DSN query-string suffix (per
// sqliteDSN's own doc comment: "the operator already supplied their own DSN
// query parameters") builds its lock filename from the path portion only, not
// the full DSN string — and that a plain path and its "?"-suffixed DSN form
// correctly contend for the SAME lock (they name the same underlying file).
func TestAcquireSQLiteMigrationLock_QueryStringStripped(t *testing.T) {
	base := filepath.Join(t.TempDir(), "operator-dsn.db")

	first, err := acquireSQLiteMigrationLock(base + "?_pragma=foo(1)")
	require.NoError(t, err)
	defer first.release()

	// The plain path (no query string) names the same file and must contend
	// for the same lock.
	_, err = acquireSQLiteMigrationLock(base)
	require.Error(t, err, "the DSN-suffixed and plain forms of the same path must contend for the same lock")
	assert.Contains(t, err.Error(), "already holds the migration lock")
}

// TestCreateStorage_SQLite_FailsWhenMigrationLockHeldByAnotherProcess exercises
// the real production entry point: a second CreateStorage call against the same
// local SQLite file, while a lock simulating another OS process already holding
// the migration lock is in place, must fail loud at boot with an actionable
// error instead of racing the first process's migration or hanging.
func TestCreateStorage_SQLite_FailsWhenMigrationLockHeldByAnotherProcess(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "boot-lock-held.db")

	// Simulate another OS process already mid-migration by holding the lock
	// directly, out of band from CreateStorage.
	heldByOther, err := acquireSQLiteMigrationLock(dbPath)
	require.NoError(t, err)
	defer heldByOther.release()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = dbPath

	_, err = NewStorageFactory().CreateStorage(cfg)
	require.Error(t, err, "CreateStorage must fail loud, not hang or race, when another process already holds the migration lock")
	assert.Contains(t, err.Error(), "already holds the migration lock")
}
