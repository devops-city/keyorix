// backup_restore_property_test.go is design-b3-backup-v2.md §11.1's core
// property test: restore(backup(state)) == state, across all 4
// source/target backend directions (SQLite->SQLite, Postgres->Postgres,
// SQLite->Postgres, Postgres->SQLite), through the real `admin backup`/
// `admin restore` CLI commands, seeded from storage.AllModels() (see
// backup_restore_property_seed_test.go) so a model added to the registry in
// the future is covered automatically rather than needing a hand-written
// fixture here.
//
// "== state" is checked by taking a SECOND backup of the just-restored
// target and comparing every table's rows against the original backup's, via
// normalizedNDJSONRows below rather than a raw byte/hash comparison: a
// same-backend round trip (SQLite->SQLite, Postgres->Postgres) preserves the
// exact NDJSON bytes, but a CROSS-backend round trip legitimately does not --
// found live via this test's own SQLite->Postgres and Postgres->SQLite
// subtests, where every timestamp column round-tripped correctly (the same
// absolute instant) but with a different time.Location in its RFC3339
// encoding (SQLite's driver returns UTC; Postgres's timestamptz round-trips
// through the process's local zone by default) -- a real, harmless backend
// representation difference, not a restore data-loss bug. Comparing by
// PARSED instant rather than raw text is the correct property here; a raw
// hash would reject every cross-backend restore regardless of correctness.
// Postgres->Postgres and any direction touching Postgres are pg-gated (skip
// without KEYORIX_TEST_PG_DSN); SQLite->SQLite always runs.
package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// extractArchive extracts archivePath into a throwaway staging dir
// (t.TempDir(), auto-cleaned) and returns its manifest plus that staging
// dir's path -- the same ExtractArchive restore.go itself calls, used here
// only to read the manifest and per-table NDJSON files back out for
// comparison, never to load anything into a database.
func extractArchive(t *testing.T, archivePath string) (backupfmt.Manifest, string) {
	t.Helper()
	f, err := os.Open(archivePath) // #nosec G304 -- test-controlled path, this file's own fixture
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck

	stagingDir := t.TempDir()
	manifest, err := backupfmt.ExtractArchive(f, stagingDir, 0, 0)
	require.NoError(t, err)
	return manifest, stagingDir
}

func manifestTablesByName(m backupfmt.Manifest) map[string]backupfmt.TableEntry {
	out := make(map[string]backupfmt.TableEntry, len(m.Tables))
	for _, te := range m.Tables {
		out[te.Name] = te
	}
	return out
}

// normalizeJSONValue rewrites any string value that parses as an RFC3339(Nano)
// timestamp into its UTC form, recursively, leaving every other value (and
// every other type: number, bool, null, non-timestamp string) untouched --
// so two encodings of the SAME instant in different time.Locations compare
// equal, while an actual content difference (including a genuinely different
// instant) still does not.
func normalizeJSONValue(v any) any {
	switch x := v.(type) {
	case string:
		if ts, err := time.Parse(time.RFC3339Nano, x); err == nil {
			return ts.UTC().Format(time.RFC3339Nano)
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = normalizeJSONValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = normalizeJSONValue(vv)
		}
		return out
	default:
		return v
	}
}

// normalizedNDJSONRows reads path (one JSON object per line, writer.go's
// NDJSON convention) and returns each line normalized per normalizeJSONValue
// -- comparable across backends despite differing time.Time encodings.
func normalizedNDJSONRows(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled staging path
	require.NoError(t, err)

	var rows []map[string]any
	for line := range bytes.SplitSeq(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal(line, &m), "decode row in %s", path)
		rows = append(rows, normalizeJSONValue(m).(map[string]any))
	}
	return rows
}

// configureBackendTestDir writes a fresh config file for backend ("sqlite"
// or "postgres") rooted at dir, returning it. For postgres, dsn must already
// be a freshly created, empty, isolated database (pgAdminIsolatedDatabaseDSN).
func configureBackendTestDir(t *testing.T, backend, dir, pgBaseDSN string) string {
	t.Helper()
	switch backend {
	case "sqlite":
		dbPath := filepath.Join(dir, "secrets.db")
		return writeBackupRestoreTestConfig(t, dir, dbPath)
	case "postgres":
		dsn := pgAdminIsolatedDatabaseDSN(t, pgBaseDSN)
		return writePostgresBackupRestoreTestConfig(t, dir, dsn)
	default:
		t.Fatalf("unknown backend %q", backend)
		return ""
	}
}

func runPropertyRoundTrip(t *testing.T, srcBackend, dstBackend string) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	var pgBaseDSN string
	if srcBackend == "postgres" || dstBackend == "postgres" {
		pgBaseDSN = pgAdminTestDSN(t)
	}

	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	encSvc := encryption.NewService(encCfg, srcDir)
	require.NoError(t, encSvc.Initialize("test-passphrase-1234"))

	configPathFlag = configureBackendTestDir(t, srcBackend, srcDir, pgBaseDSN)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(srcCfg) // creates + migrates the source DB
	require.NoError(t, err)

	gdb, err := storage.OpenGormDB(srcCfg)
	require.NoError(t, err)
	seedOneRowPerModel(t, gdb)
	sealSeededAuditCheckpoint(t, gdb, encSvc)

	archive1Path := filepath.Join(t.TempDir(), "backup1.tar.gz")
	backupOutput = archive1Path
	backupExclusive = false // default path (REPEATABLE READ on Postgres), same as a real operator run
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "backup1 output:\n%s", out)
	manifest1, stage1 := extractArchive(t, archive1Path)
	require.NotEmpty(t, manifest1.Tables)

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = configureBackendTestDir(t, dstBackend, dstDir, pgBaseDSN)
	restoreInput = archive1Path
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "restore output:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID",
		"restore must run verify-audit automatically and report its verdict")

	// Second backup, of the just-restored target -- this is the "state"
	// half of restore(backup(state)) == state, compared against manifest1
	// below.
	archive2Path := filepath.Join(t.TempDir(), "backup2.tar.gz")
	backupOutput = archive2Path
	backupExclusive = false
	out, err = captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "backup2 (post-restore) output:\n%s", out)
	manifest2, stage2 := extractArchive(t, archive2Path)

	m1 := manifestTablesByName(manifest1)
	m2 := manifestTablesByName(manifest2)

	var names1, names2 []string
	for n := range m1 {
		names1 = append(names1, n)
	}
	for n := range m2 {
		names2 = append(names2, n)
	}
	require.ElementsMatch(t, names1, names2,
		"table set differs between the original backup and the restored-then-rebacked-up state")

	for name, te1 := range m1 {
		te2 := m2[name]
		require.Equal(t, te1.RowCount, te2.RowCount, "table %q: row count differs after restore(backup(state))", name)
		if name == "system_metadata" { // internal/backupfmt's unexported systemMetadataTableName
			// EXCEPTION, not an oversight: system_metadata's schema_epoch row
			// is deliberately regenerated, not restored -- LoadArchive skips
			// loading the archived row (isSystemMetadataSchemaEpochRow), and
			// the target's own independent migration pass writes its own via
			// recordSchemaEpoch, whose UpdatedAt is a genuine time.Now() at
			// the moment THAT migration ran -- always different from the
			// source's. Row count still must match (checked above); content
			// cannot.
			continue
		}
		rows1 := normalizedNDJSONRows(t, filepath.Join(stage1, te1.TarName))
		rows2 := normalizedNDJSONRows(t, filepath.Join(stage2, te2.TarName))
		require.Equal(t, rows1, rows2,
			"table %q: rows differ after restore(backup(state)) -- restore did not preserve this table's rows exactly", name)
	}
}

func TestBackupRestore_PropertyRoundTrip(t *testing.T) {
	dirs := []struct {
		name, src, dst string
	}{
		{"SQLite_to_SQLite", "sqlite", "sqlite"},
		{"Postgres_to_Postgres", "postgres", "postgres"},
		{"SQLite_to_Postgres", "sqlite", "postgres"},
		{"Postgres_to_SQLite", "postgres", "sqlite"},
	}
	for _, d := range dirs {
		t.Run(d.name, func(t *testing.T) {
			runPropertyRoundTrip(t, d.src, d.dst)
		})
	}
}

// TestBackupRestore_PropertyRoundTrip_V1ArchiveOnHEAD proves design §11.1's
// second requirement: a v1 (physical-format) archive produced by a REAL
// older release still restores cleanly on this (v2-writing) binary.
// testdata/v0.95.0-backup.tar.gz is not synthetic -- it's the literal
// `admin backup` output of the actual v0.95.0 release binary
// (keyorix-server_darwin_arm64, downloaded via `gh release download v0.95.0`)
// run against a freshly `admin init`'d + `admin migrate`'d local/sqlite
// instance, encrypted with the passphrase this test supplies below. Kept
// deliberately small (an otherwise-empty database, ~21KB compressed) --
// this test's job is proving the v1 archive SHAPE still restores, not
// exercising data volume (that's H6's scripts/release-qa/ proof, which
// restores a real populated database into Postgres and checks secrets/
// audit/authz).
func TestBackupRestore_PropertyRoundTrip_V1ArchiveOnHEAD(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "v095-fixture-passphrase-1234")

	// Resolve the fixture's path BEFORE chdirTest moves the process into
	// dstDir below -- "testdata/..." is relative to this package's own
	// directory (Go test's default working directory), not wherever the
	// restore target's config file happens to live.
	wd, err := os.Getwd()
	require.NoError(t, err)
	fixturePath := filepath.Join(wd, "testdata", "v0.95.0-backup.tar.gz")

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	dstDBPath := filepath.Join(dstDir, "secrets.db")
	// The fixture's own config used "keys/dek.key"/"keys/kek.salt" (admin
	// init's real default template, not this test package's own
	// writeBackupRestoreTestConfig helper, which uses top-level paths) --
	// restore's key-file-set check refuses a mismatched path set, so the
	// target config must match what the archive actually recorded.
	cfgPath := filepath.Join(dstDir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf(`storage:
  type: local
  database:
    path: %s
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
`, dstDBPath)), 0600))
	configPathFlag = cfgPath

	restoreInput = fixturePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID")
}
