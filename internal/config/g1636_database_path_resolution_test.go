// g1636_database_path_resolution_test.go — #1636: a relative
// storage.database.path used to resolve against the process's cwd wherever
// internal/storage/factory.go happened to open it, not against the directory
// the config file itself was read from. Two processes loading the identical
// config (same absolute KEYORIX_CONFIG_PATH) but launched from different
// working directories silently opened two different SQLite files. These
// tests pin Load()'s fix: cfg.Storage.Database.Path is now resolved to an
// absolute path anchored at baseDir (the config file's own directory) before
// Load returns, so "same config" reliably means "same database" regardless
// of the caller's cwd.
package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// TestLoad_DatabasePathResolvedAbsoluteRegardlessOfCwd is the core #1636
// regression: the same config file, loaded via the same absolute
// KEYORIX_CONFIG_PATH, from two different process working directories, must
// resolve storage.database.path to the identical absolute path both times.
// Before the fix, each call resolved "keyorix.db" against its OWN cwd,
// producing two different (both non-absolute) values.
func TestLoad_DatabasePathResolvedAbsoluteRegardlessOfCwd(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("storage:\n  type: sqlite\n  database:\n    path: keyorix.db\n"), 0600))

	cwdA := t.TempDir()
	cwdB := t.TempDir()

	loadFrom := func(t *testing.T, cwd string) string {
		t.Helper()
		orig, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.Chdir(cwd))
		defer func() { require.NoError(t, os.Chdir(orig)) }()

		cfg, err := Load(configPath)
		require.NoError(t, err)
		return cfg.Storage.Database.Path
	}

	resolvedA := loadFrom(t, cwdA)
	resolvedB := loadFrom(t, cwdB)

	assert.True(t, filepath.IsAbs(resolvedA), "resolved database.path must be absolute, got %q", resolvedA)
	assert.Equal(t, resolvedA, resolvedB, "the same config, loaded from two different working directories, must resolve to the same database file")
	assert.Equal(t, filepath.Join(configDir, "keyorix.db"), resolvedA, "must anchor to the config file's own directory, not either process's cwd")
}

// TestResolveConfigRelativePath_AlreadyAbsolute_PassesThroughUnchanged confirms
// an operator who already configured an absolute path is left alone -- no
// double-joining, no surprise rewrite of a value they set deliberately.
func TestResolveConfigRelativePath_AlreadyAbsolute_PassesThroughUnchanged(t *testing.T) {
	got, err := resolveConfigRelativePath("/some/base", "/already/absolute/secrets.db")
	require.NoError(t, err)
	assert.Equal(t, "/already/absolute/secrets.db", got)
}

// TestResolveConfigRelativePath_InMemoryDSN_Untouched mirrors
// acquireSQLiteMigrationLock's own in-memory detection (see
// internal/storage/factory_sqlite_migration_lock.go) -- an in-memory
// database names no real file to anchor, and joining it against baseDir
// would corrupt the DSN into a garbage on-disk path.
func TestResolveConfigRelativePath_InMemoryDSN_Untouched(t *testing.T) {
	got, err := resolveConfigRelativePath("/some/base", ":memory:")
	require.NoError(t, err)
	assert.Equal(t, ":memory:", got)

	inMemory := sqlitetest.DSN("g1636_")
	got, err = resolveConfigRelativePath("/some/base", inMemory)
	require.NoError(t, err)
	assert.Equal(t, inMemory, got)
}

// TestResolveConfigRelativePath_QueryStringSuffixPreserved confirms an
// operator-supplied DSN query suffix (e.g. a custom pragma) survives the
// resolution unchanged, appended to the now-absolute path -- the file portion
// is resolved, the suffix is not touched or reordered.
func TestResolveConfigRelativePath_QueryStringSuffixPreserved(t *testing.T) {
	got, err := resolveConfigRelativePath("/base/dir", "secrets.db?_pragma=foo(1)")
	require.NoError(t, err)
	assert.Equal(t, "/base/dir/secrets.db?_pragma=foo(1)", got)
}

// TestResolveConfigRelativePath_Empty_PassesThroughUnchanged confirms an
// empty configured path (the "operator didn't set database.path at all"
// case, defaulted later in internal/storage/factory.go) is left for that
// caller to default -- Load() has no config-file-relative anchor to offer
// when the field itself carries no value.
func TestResolveConfigRelativePath_Empty_PassesThroughUnchanged(t *testing.T) {
	got, err := resolveConfigRelativePath("/some/base", "")
	require.NoError(t, err)
	assert.Equal(t, "", got)
}

// TestResolveConfigRelativePath_DotDot_Rejected pins the traversal guard that
// used to live only in internal/cli/system/init.go's initializeDatabase (a
// CLI-only check, never run on the server's own boot path): filepath.Abs/Join
// would otherwise silently collapse "../escapes.db" into a clean absolute
// path outside baseDir with no ".." substring left to catch afterward.
// Centralizing the rejection in Load() covers both callers, not just the CLI.
func TestResolveConfigRelativePath_DotDot_Rejected(t *testing.T) {
	_, err := resolveConfigRelativePath("/some/base", "../escapes.db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "..")
}

// TestLoad_DatabasePathTraversal_Rejected confirms Load() itself fails loudly
// (not silently escaping baseDir) when the config's database.path contains
// "..", the same shape TestResolveConfigRelativePath_DotDot_Rejected pins at
// the helper level, exercised through the real Load() entrypoint.
func TestLoad_DatabasePathTraversal_Rejected(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("storage:\n  type: local\n  database:\n    path: ../escapes.db\n"), 0600))

	_, err := Load(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "..")
}
