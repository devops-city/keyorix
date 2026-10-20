// factory_local_storage_missing_path_log_test.go — INV-STORAGE-22 (#2504).
//
// ADR-095 Task 3 recommends createLocalStorage refuse to boot against a
// missing SQLite path instead of silently creating a fresh, empty database.
// That refusal is now BUILT, as the opt-in database.require_existing_path
// (FIX-2): its default stays false because nothing in the supported
// first-boot paths creates the file beforehand, so a default-on refusal
// would break every containerized first boot — the flip is the deliberate
// sign-off ADR-095 asks for, and DatabaseConfig.RequireExistingPath's doc
// comment carries the reasoning.
//
// Two things therefore need guarding, and both are here:
//
//  1. With the option OFF (the default), the only operator-visible signal
//     that a mistyped path or unmounted volume produced a brand-new empty
//     store is #1636's boot log line. These tests exist because that signal
//     was silently inverted once: #1652 put prepareLocalStorageFile's
//     O_CREATE pre-create ahead of the os.Stat that decides which line to
//     log, so every missing path was reported as "opening existing SQLite
//     database" and the "NEW, EMPTY database" warning could never fire.
//  2. With the option ON, boot must actually refuse — and must still succeed
//     when the file is there, and when the DSN is in-memory (nothing to
//     pre-exist). A refusal that fired unconditionally would be exactly as
//     useless as one that never fired.
//
// What this does NOT cover: whether the DEFAULT should be flipped (a product
// decision, surfaced to the coordinator, not settled by a test), and the
// Postgres backend (no file to stat; the option is SQLite-only by
// construction).
package storage

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	newEmptyDatabaseLog = "a NEW, EMPTY database will be created here"
	openingExistingLog  = "storage: opening existing SQLite database at"
)

// bootLocalStorageCapturingLog runs CreateStorage against path and returns
// every log line that mentions path.
func bootLocalStorageCapturingLog(t *testing.T, path string) []string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = path
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "with database.require_existing_path unset (the default), boot against a missing path must still succeed")
	require.NotNil(t, st)

	var lines []string
	for l := range bytes.SplitSeq(buf.Bytes(), []byte("\n")) {
		if bytes.Contains(l, []byte(path)) {
			lines = append(lines, string(l))
		}
	}
	return lines
}

func TestCreateLocalStorage_MissingPath_LogsNewEmptyDatabase(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// A missing file in a missing directory: the mistyped-path /
	// unmounted-volume shape ADR-095 Task 3 is about.
	path := filepath.Join(t.TempDir(), "typo", "secrets.db")
	_, statErr := os.Stat(path)
	require.True(t, os.IsNotExist(statErr), "precondition: path must not exist before boot")

	got := strings.Join(bootLocalStorageCapturingLog(t, path), "\n")
	assert.Contains(t, got, newEmptyDatabaseLog,
		"booting against a missing SQLite path must warn that a new, empty database is being created")
	assert.NotContains(t, got, openingExistingLog,
		"a missing SQLite path must never be reported as an existing database")
}

// bootLocalStorage boots the real factory against path with
// database.require_existing_path set to requireExisting, and returns the
// error (if any) verbatim.
func bootLocalStorage(t *testing.T, path string, requireExisting bool) error {
	t.Helper()
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = path
	cfg.Storage.Database.RequireExistingPath = requireExisting
	st, err := NewStorageFactory().CreateStorage(cfg)
	if err == nil {
		require.NotNil(t, st)
	}
	return err
}

// TestCreateLocalStorage_RequireExistingPath_RefusesMissing is INV-STORAGE-22's
// red half: the mistyped-path / unmounted-volume shape must not produce a
// working server backed by a brand-new empty store.
func TestCreateLocalStorage_RequireExistingPath_RefusesMissing(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dir := t.TempDir()
	path := filepath.Join(dir, "typo", "secrets.db")

	err := bootLocalStorage(t, path, true)
	require.Error(t, err, "with database.require_existing_path set, boot against a missing SQLite path must refuse")
	assert.Contains(t, err.Error(), "no database found at")
	assert.Contains(t, err.Error(), "keyorix-server admin init",
		"the refusal must name the deliberate way to create one, not just say no")

	// Assert the EFFECT, not only the returned error: a refusal that had
	// already let prepareLocalStorageFile create the file (or its parent
	// directory tree) would leave exactly the empty database this option
	// exists to prevent, and the error alone cannot tell the two apart.
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "a refused boot must not have created the database file")
	_, dirErr := os.Stat(filepath.Dir(path))
	assert.True(t, os.IsNotExist(dirErr), "a refused boot must not have created the database's parent directory either")
}

// TestCreateLocalStorage_RequireExistingPath_OpensExisting is the green half.
// A guard that refused unconditionally would be as useless as one that never
// fired, so this is not optional coverage.
func TestCreateLocalStorage_RequireExistingPath_OpensExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	path := filepath.Join(t.TempDir(), "secrets.db")
	require.NoError(t, bootLocalStorage(t, path, false), "first boot (option off) creates the database")
	require.FileExists(t, path)

	assert.NoError(t, bootLocalStorage(t, path, true),
		"with the file present, database.require_existing_path must not block boot")
}

// TestCreateLocalStorage_RequireExistingPath_InMemoryExempt: an in-memory DSN
// has no file that could pre-exist, so the option must be a no-op there rather
// than making every in-memory configuration unbootable. Exempt by construction
// (localStorageDBFile reports isRealFile=false), not by a name carve-out.
func TestCreateLocalStorage_RequireExistingPath_InMemoryExempt(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	for _, dsn := range []string{":memory:", sqlitetest.DSN("fix2inmem_")} {
		t.Run(dsn, func(t *testing.T) {
			assert.NoError(t, bootLocalStorage(t, dsn, true),
				"an in-memory DSN has no file to pre-exist; require_existing_path must not refuse it")
		})
	}
}

// TestCreateLocalStorage_DSNQuerySuffix_ExistenceResolvedThroughLocalStorageDBFile:
// database.path may carry a DSN query suffix. Asking os.Stat about the raw
// string can never resolve such a path, which made an existing database report
// as missing — harmless while the only consumer was a log line, a false refusal
// once require_existing_path consumes the same answer.
func TestCreateLocalStorage_DSNQuerySuffix_ExistenceResolvedThroughLocalStorageDBFile(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	file := filepath.Join(t.TempDir(), "secrets.db")
	require.NoError(t, bootLocalStorage(t, file, false), "create the database first")
	require.FileExists(t, file)

	withSuffix := file + "?_busy_timeout=10000"
	assert.NoError(t, bootLocalStorage(t, withSuffix, true),
		"a DSN query suffix must not make an existing database look missing to require_existing_path")
}

func TestCreateLocalStorage_ExistingPath_LogsOpeningExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	path := filepath.Join(t.TempDir(), "secrets.db")
	_ = bootLocalStorageCapturingLog(t, path) // first boot creates it

	got := strings.Join(bootLocalStorageCapturingLog(t, path), "\n")
	assert.Contains(t, got, openingExistingLog,
		"a second boot against the same file must report it as existing")
	assert.NotContains(t, got, newEmptyDatabaseLog,
		"an existing database must never be reported as new and empty")
}
