// backup_restore_tz_test.go: FIX-3088. A backup taken from, and restored on, a
// host whose time.Local is not UTC must reproduce every row exactly. The
// original failure: audit row 1, written with a zero EventTime
// (0001-01-01 00:00:00 UTC), was read back Local-located (Europe/Berlin shows it
// as 00:53:28 LMT), encoded to NDJSON with RFC 3339's minute-resolution offset,
// and so restored 44 seconds off, which broke the row's entry_hash and made the
// automatic post-restore verify-audit report BROKEN.
//
// The host TZ is a real one: each zone's round trip runs in a subprocess of the
// test binary started with TZ=<zone>, so the runtime derives time.Local from the
// environment exactly as on such a host and every database read returns
// Local-located times. No test assigns time.Local: it is a package global, and
// writing it races with any goroutine calling time.Now (timers, servers, earlier
// subtests' background workers).
package admin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

var backupRestoreHostTZs = []string{"UTC", "Europe/Berlin", "America/Los_Angeles", "Asia/Kolkata"}

// hostTZChildEnv selects helper mode: the value is the zone this process was
// started under (TZ=<zone>) and must run the test body once.
const hostTZChildEnv = "KEYORIX_TEST_HOST_TZ_CHILD"

// hostTZChild returns the zone when this process is a host-TZ subprocess, after
// checking that the runtime really adopted it as time.Local.
func hostTZChild(t *testing.T) (string, bool) {
	t.Helper()
	tz := os.Getenv(hostTZChildEnv)
	if tz == "" {
		return "", false
	}
	want, err := time.LoadLocation(tz)
	require.NoError(t, err)
	for _, ref := range []time.Time{
		time.Date(1850, 6, 1, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
	} {
		_, gotOff := ref.In(time.Local).Zone()
		_, wantOff := ref.In(want).Zone()
		require.Equal(t, wantOff, gotOff, "subprocess time.Local does not match TZ=%s at %v", tz, ref)
	}
	return tz, true
}

// runInHostTZ re-executes this test binary (same flags, so -race is kept) for
// test `name` with TZ=tz and requires that exactly that test ran and passed.
func runInHostTZ(t *testing.T, name, tz string) {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TZ=") && !strings.HasPrefix(kv, hostTZChildEnv+"=") {
			env = append(env, kv)
		}
	}
	env = append(env, "TZ="+tz, hostTZChildEnv+"="+tz)
	cmd := exec.Command(exe, "-test.run=^"+name+"$", "-test.v", "-test.count=1")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "subprocess TZ=%s failed:\n%s", tz, out)
	require.Contains(t, string(out), "--- PASS: "+name+" ", "subprocess TZ=%s did not run %s:\n%s", tz, name, out)
	require.NotContains(t, string(out), "--- SKIP", "subprocess TZ=%s skipped:\n%s", tz, out)
}

// seedAuditEventsForTZ logs the events whose times are the hard cases: the
// zero time as row 1 (a caller that leaves EventTime unset), a pre-1900
// instant, and ordinary current times.
func seedAuditEventsForTZ(t *testing.T, st storage.Storage) {
	t.Helper()
	ctx := context.Background()
	for _, ev := range []*models.AuditEvent{
		{EventType: "secret.read"}, // zero EventTime -> audit row id 1
		{EventType: "secret.read", EventTime: time.Date(1850, 6, 1, 12, 0, 0, 0, time.UTC)},
		{EventType: "secret.read", EventTime: time.Now()},
		{EventType: "secret.read", EventTime: time.Now().Add(-90 * 24 * time.Hour).In(time.Local)},
	} {
		require.NoError(t, st.LogAuditEvent(ctx, ev))
	}
}

// dumpAllTables returns, per table of every model, the rows rendered with every
// time normalised to UTC microseconds and sorted, so two databases can be
// compared for exact row equality independent of host TZ and row order.
func dumpAllTables(t *testing.T, db *gorm.DB) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, m := range kstorage.AllModels() {
		stmt := &gorm.Statement{DB: db}
		require.NoError(t, stmt.Parse(m))
		table := stmt.Schema.Table
		if !db.Migrator().HasTable(table) {
			continue
		}
		var rows []map[string]any
		require.NoError(t, db.Table(table).Find(&rows).Error, table)
		lines := make([]string, 0, len(rows))
		for _, r := range rows {
			keys := make([]string, 0, len(r))
			for k := range r {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			line := ""
			for _, k := range keys {
				v := r[k]
				if tv, ok := v.(time.Time); ok {
					v = fmt.Sprintf("T%d", tv.UnixMicro())
				}
				line += fmt.Sprintf("%s=%v;", k, v)
			}
			lines = append(lines, line)
		}
		sort.Strings(lines)
		out[table] = lines
	}
	return out
}

// restoreRewrittenTables are tables a restore legitimately re-stamps (the schema
// epoch rows get a fresh updated_at when restore re-runs the migration), so
// their timestamps are not expected to match the source.
var restoreRewrittenTables = map[string]bool{"system_metadata": true}

// seededAuditRows is how many audit rows seedAuditEventsForTZ logs. Rows after
// that (the backup's own admin.backup_created event, the restore's events) are
// written outside the archive's snapshot and are not part of the comparison.
const seededAuditRows = 4

func auditRowWithID(rows []string, marker string) string {
	for _, r := range rows {
		if strings.Contains(r, marker) {
			return r
		}
	}
	return "<missing>"
}

func requireSameRows(t *testing.T, src, dst map[string][]string) {
	t.Helper()
	require.Len(t, src["audit_events"], seededAuditRows+1, "expected the seeded rows plus the backup's own event in the source")
	for table, srcRows := range src {
		if restoreRewrittenTables[table] {
			continue
		}
		dstRows := dst[table]
		if table == "audit_events" {
			for id := 1; id <= seededAuditRows; id++ {
				marker := fmt.Sprintf(";id=%d;", id)
				require.Equal(t, auditRowWithID(srcRows, marker), auditRowWithID(dstRows, marker),
					"audit row %d differs after restore", id)
			}
			continue
		}
		require.Equal(t, srcRows, dstRows, "table %s differs after restore", table)
	}
}

func TestAdminBackupRestore_SQLite_RoundTripAcrossHostTZ(t *testing.T) {
	if _, child := hostTZChild(t); child {
		sqliteRoundTripOnThisHost(t)
		return
	}
	for _, tz := range backupRestoreHostTZs {
		t.Run(tz, func(t *testing.T) {
			runInHostTZ(t, "TestAdminBackupRestore_SQLite_RoundTripAcrossHostTZ", tz)
		})
	}
}

func sqliteRoundTripOnThisHost(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, srcDir).Initialize("test-passphrase-1234"))
	configPathFlag = writeBackupRestoreTestConfig(t, srcDir, filepath.Join(srcDir, "secrets.db"))
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := kstorage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)
	seedAuditEventsForTZ(t, st)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	backupOutput = archivePath
	require.NoError(t, runAdminBackup(nil, nil))

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	dstDBPath := filepath.Join(dstDir, "secrets.db")
	configPathFlag = writeBackupRestoreTestConfig(t, dstDir, dstDBPath)
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID")

	srcDB := sqliteRawOpenForTZTest(t, filepath.Join(srcDir, "secrets.db"))
	dstDB := sqliteRawOpenForTZTest(t, dstDBPath)
	requireSameRows(t, dumpAllTables(t, srcDB), dumpAllTables(t, dstDB))
}

// TestAdminBackupRestore_Postgres_RoundTripAcrossHostTZ is the FIX-3088
// reproduction: red on main for every non-UTC zone, green with the codec fix.
func TestAdminBackupRestore_Postgres_RoundTripAcrossHostTZ(t *testing.T) {
	base := pgAdminTestDSN(t)
	if _, child := hostTZChild(t); child {
		postgresRoundTripOnThisHost(t, base)
		return
	}
	for _, tz := range backupRestoreHostTZs {
		t.Run(tz, func(t *testing.T) {
			runInHostTZ(t, "TestAdminBackupRestore_Postgres_RoundTripAcrossHostTZ", tz)
		})
	}
}

func postgresRoundTripOnThisHost(t *testing.T, base string) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	srcDSN := pgAdminIsolatedDatabaseDSN(t, base)
	dstDSN := pgAdminIsolatedDatabaseDSN(t, base)

	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, srcDir).Initialize("test-passphrase-1234"))
	configPathFlag = writePostgresBackupRestoreTestConfig(t, srcDir, srcDSN)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := kstorage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)
	seedAuditEventsForTZ(t, st)

	archivePath := filepath.Join(t.TempDir(), "pg-backup.tar.gz")
	backupOutput = archivePath
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dstDir, dstDSN)
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID")

	srcDB := pgAdminRawOpen(t, srcDSN)
	dstDB := pgAdminRawOpen(t, dstDSN)
	requireSameRows(t, dumpAllTables(t, srcDB), dumpAllTables(t, dstDB))

	// Row 1 specifically: stored instant is the zero time, in both.
	for name, db := range map[string]*gorm.DB{"source": srcDB, "restored": dstDB} {
		var first models.AuditEvent
		require.NoError(t, db.Order("id ASC").First(&first).Error, name)
		require.True(t, first.EventTime.IsZero(), "%s audit row 1 event_time = %v", name, first.EventTime)
	}
}

func sqliteRawOpenForTZTest(t *testing.T, path string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlitedialect.Open(path), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}
