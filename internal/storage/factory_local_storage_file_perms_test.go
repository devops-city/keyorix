package storage

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/require"
)

// withUmask sets the process umask for the duration of fn and restores the prior value
// afterward. #1647's whole point is that file mode depends on the process's inherited
// umask, so this is the only way to exercise both a lax (022) and maximally lax (000)
// inherited environment from a single test binary. Not safe to run with t.Parallel() in
// this package (umask is process-global) — none of this package's other tests use it.
func withUmask(t *testing.T, mask int, fn func()) {
	t.Helper()
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	fn()
}

// TestCreateLocalStorage_FreshDatabase_AlwaysSecureModeRegardlessOfUmask is the red-first
// regression test for #1647: before the fix (no explicit mode passed anywhere in the
// SQLite open path), this test fails under umask 022 with the database created at 0644.
// After the fix (prepareLocalStorageFile pre-creates the file at 0600 before gorm.Open
// ever touches it), the assertion holds regardless of the inherited umask.
func TestCreateLocalStorage_FreshDatabase_AlwaysSecureModeRegardlessOfUmask(t *testing.T) {
	for _, mask := range []int{0o022, 0o000} {
		t.Run(modeLabel(mask), func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "secrets.db")
			cfg := &config.Config{Storage: config.StorageConfig{Database: config.DatabaseConfig{Path: dbPath}}}

			var storageInstance any
			withUmask(t, mask, func() {
				f := &DefaultStorageFactory{}
				var err error
				storageInstance, err = f.createLocalStorage(cfg)
				require.NoError(t, err)
			})
			// Close only after the asserts: closing SQLite checkpoints and removes -wal.
			if closer, ok := storageInstance.(interface{ Close() error }); ok {
				defer func() { _ = closer.Close() }()
			}

			assertMode(t, dbPath, 0o600)
			// -wal is created eagerly by the journal_mode=WAL pragma during Open; -shm may
			// or may not exist yet depending on whether a read/write transaction has
			// touched the shared cache — check it only if present, same as the production
			// tightenExistingLocalStorageFiles logic does.
			assertMode(t, dbPath+"-wal", 0o600)
			if _, err := os.Stat(dbPath + "-shm"); err == nil {
				assertMode(t, dbPath+"-shm", 0o600)
			}
		})
	}
}

// TestCreateLocalStorage_PreExistingLaxPermissions_TightenedOnOpen covers the "what
// happens to a database created before this fix shipped" question #1647 explicitly calls
// out: the file keeps its original (possibly world-readable) mode until an operator
// upgrades and restarts, at which point tightenExistingLocalStorageFiles corrects it —
// loudly (a log line), not silently, and without refusing to start.
func TestCreateLocalStorage_PreExistingLaxPermissions_TightenedOnOpen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")

	// Simulate a database that predates this fix: created directly at a lax mode, as the
	// old code path (no explicit os.OpenFile mode) would have under umask 000.
	require.NoError(t, os.WriteFile(dbPath, nil, 0o644))
	require.NoError(t, os.WriteFile(dbPath+"-wal", nil, 0o644))
	require.NoError(t, os.WriteFile(dbPath+"-shm", nil, 0o644))

	cfg := &config.Config{Storage: config.StorageConfig{Database: config.DatabaseConfig{Path: dbPath}}}
	f := &DefaultStorageFactory{}
	storageInstance, err := f.createLocalStorage(cfg)
	require.NoError(t, err)
	if closer, ok := storageInstance.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}

	assertMode(t, dbPath, 0o600)
	assertMode(t, dbPath+"-wal", 0o600)
	assertMode(t, dbPath+"-shm", 0o600)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err, "expected %s to exist", path)
	require.Equalf(t, want, info.Mode().Perm(), "%s has mode %04o, want %04o", path, info.Mode().Perm(), want)
}

func modeLabel(mask int) string {
	switch mask {
	case 0o022:
		return "umask_022"
	case 0o000:
		return "umask_000"
	default:
		return "umask_other"
	}
}
