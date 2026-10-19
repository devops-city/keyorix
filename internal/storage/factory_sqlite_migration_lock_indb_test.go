// factory_sqlite_migration_lock_indb_test.go — INV-STORAGE-23 (#2505): two
// OS processes migrating the same SQLite file are serialized by SQLite itself
// (withSQLiteInDBMigrationLock's BEGIN EXCLUSIVE), not by the
// <dbPath>.migration.lock sidecar.
//
// The two migrators are real, separate OS processes -- this test binary
// re-executed (TestSQLiteMigrationLockHelperProcess) -- each going through the
// real NewStorageFactory().CreateStorage entry point. In-process goroutines
// would prove nothing here: migrationMu serializes them before either lock is
// reached.
//
// Each case reaches the same database file in a way the path-keyed sidecar
// cannot see, which is exactly what it leaves open:
//   - a symlink to the database file (a different path string, so a
//     different sidecar file);
//   - the same path, with the holder's sidecar deleted while held (the next
//     process creates a fresh sidecar inode and flocks that instead).
//
// What it does NOT cover, and why:
//   - a HARD link to the database file. Found by this test: in WAL mode
//     SQLite takes its write lock in the -shm file, which it names after the
//     path it was given; it resolves symlinks for that, but cannot see a hard
//     link, so two hard-linked names get two independent WAL indexes and no
//     lock between them -- SQLite's own "How To Corrupt An SQLite Database
//     File" (multiple links to a file). No lock inside the database can
//     serialize that, and the sidecar never did either (different name,
//     different sidecar). Don't hard-link a live database.
//   - two processes on different hosts sharing the file over a network
//     filesystem: SQLite's locking is only as good as that filesystem's POSIX
//     locks (a documented SQLite limitation), as was flock's.
package storage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const (
	migLockHelperEnv      = "KEYORIX_TEST_MIGLOCK_HELPER"
	migLockHelperRoleEnv  = "KEYORIX_TEST_MIGLOCK_ROLE"
	migLockHelperDBEnv    = "KEYORIX_TEST_MIGLOCK_DB"
	migLockHelperMarkEnv  = "KEYORIX_TEST_MIGLOCK_MARKERS"
	migLockHelperExitFail = 3
)

// writeMigLockMarker records that role reached a point, with a monotonic-
// enough wall-clock timestamp so the parent can order events across
// processes.
func writeMigLockMarker(dir, name string) {
	_ = os.WriteFile(filepath.Join(dir, name), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600)
}

func readMigLockMarker(dir, name string) (int64, bool) {
	b, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- test-owned temp dir
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil
}

// TestSQLiteMigrationLockHelperProcess is not a test on its own: it is the
// migrator process TestSQLiteMigrationLock_CrossProcess_SerializedBySQLiteItself
// re-executes this binary as. It returns immediately in a normal run.
func TestSQLiteMigrationLockHelperProcess(t *testing.T) {
	if os.Getenv(migLockHelperEnv) != "1" {
		return
	}
	role := os.Getenv(migLockHelperRoleEnv)
	dbPath := os.Getenv(migLockHelperDBEnv)
	markers := os.Getenv(migLockHelperMarkEnv)

	if err := i18n.InitializeForTesting(); err != nil {
		fmt.Fprintf(os.Stderr, "i18n: %v\n", err)
		os.Exit(migLockHelperExitFail)
	}

	// Inside every lock withMigrationLock takes, before migrating.
	migrationLockHeldHook = func() {
		writeMigLockMarker(markers, role+".entered")
		if role != "holder" {
			return
		}
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := readMigLockMarker(markers, "release"); ok {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// Taken after the migration returns but still inside every lock, so it is
	// strictly earlier than the lock's release and than any other process's
	// entry. ("<role>.done" is written after CreateStorage returns, i.e. after
	// the release, and cannot order the two processes.)
	migrationLockWorkDoneHook = func() { writeMigLockMarker(markers, role+".migrated") }
	// Fires only on migrateDatabase's fresh-install path: this process
	// created the schema rather than finding it already there.
	freshInstall := false
	migrationCheckpoint = func(string) { freshInstall = true }

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = dbPath
	writeMigLockMarker(markers, role+".attempting")
	s, err := NewStorageFactory().CreateStorage(cfg)
	if freshInstall {
		writeMigLockMarker(markers, role+".freshinstall")
	}
	writeMigLockMarker(markers, role+".done")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MIGRATE-ERROR: %v\n", err)
		os.Exit(migLockHelperExitFail)
	}
	if c, ok := s.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	os.Exit(0)
}

type migLockProc struct {
	cmd    *exec.Cmd
	stderr *bytes.Buffer
	done   chan error
}

func startMigLockHelper(t *testing.T, ctx context.Context, role, dbPath, markers string) *migLockProc {
	t.Helper()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSQLiteMigrationLockHelperProcess$", "-test.count=1") // #nosec G204 -- re-executes this test binary
	cmd.Env = append(os.Environ(),
		migLockHelperEnv+"=1",
		migLockHelperRoleEnv+"="+role,
		migLockHelperDBEnv+"="+dbPath,
		migLockHelperMarkEnv+"="+markers,
	)
	p := &migLockProc{cmd: cmd, stderr: &bytes.Buffer{}, done: make(chan error, 1)}
	cmd.Stderr = p.stderr
	require.NoError(t, cmd.Start())
	go func() { p.done <- cmd.Wait() }()
	return p
}

func waitMigLockMarker(t *testing.T, markers, name string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := readMigLockMarker(markers, name); ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for marker %q", timeout, name)
}

func waitMigLockProc(t *testing.T, p *migLockProc, name string) int {
	t.Helper()
	select {
	case err := <-p.done:
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("%s: %v", name, err)
	case <-time.After(90 * time.Second):
		t.Fatalf("%s did not exit within 90s; stderr:\n%s", name, p.stderr.String())
	}
	return -1
}

func TestSQLiteMigrationLock_CrossProcess_SerializedBySQLiteItself(t *testing.T) {
	if os.Getenv(migLockHelperEnv) == "1" {
		t.Skip("running as a migrator helper process")
	}
	cases := []struct {
		name string
		// alias is called once the holder holds every lock; it returns the
		// path the contender uses for the same database file.
		alias func(t *testing.T, realPath string) string
	}{
		{
			name: "symlinked path",
			alias: func(t *testing.T, realPath string) string {
				link := filepath.Join(filepath.Dir(realPath), "alias-symlink.db")
				require.NoError(t, os.Symlink(realPath, link))
				return link
			},
		},
		{
			name: "same path, sidecar lock file deleted while held",
			alias: func(t *testing.T, realPath string) string {
				require.NoError(t, os.Remove(realPath+sqliteMigrationLockSuffix))
				return realPath
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			dir := t.TempDir()
			markers := filepath.Join(dir, "markers")
			require.NoError(t, os.Mkdir(markers, 0o700))
			realPath := filepath.Join(dir, "shared.db")

			holder := startMigLockHelper(t, ctx, "holder", realPath, markers)
			waitMigLockMarker(t, markers, "holder.entered", 60*time.Second)

			contenderPath := c.alias(t, realPath)
			contender := startMigLockHelper(t, ctx, "contender", contenderPath, markers)
			waitMigLockMarker(t, markers, "contender.attempting", 60*time.Second)

			// Give the contender ample time to get past gorm.Open and every
			// lock it can get past; it must not reach the migration while the
			// holder is still inside its own.
			time.Sleep(1500 * time.Millisecond)
			_, contenderEnteredEarly := readMigLockMarker(markers, "contender.entered")
			writeMigLockMarker(markers, "release")

			holderExit := waitMigLockProc(t, holder, "holder")
			contenderExit := waitMigLockProc(t, contender, "contender")

			require.False(t, contenderEnteredEarly,
				"BUG (INV-STORAGE-23): the contender (via %q) entered the migration while the holder (via %q) "+
					"still held every migration lock -- two processes were migrating the same SQLite file at once", contenderPath, realPath)
			require.Equal(t, 0, holderExit, "holder must migrate successfully; stderr:\n%s", holder.stderr.String())

			// The contender either waited and then found a migrated database
			// (exit 0), or gave up cleanly with the actionable lock error.
			switch contenderExit {
			case 0:
				entered, ok := readMigLockMarker(markers, "contender.entered")
				require.True(t, ok)
				holderMigrated, ok := readMigLockMarker(markers, "holder.migrated")
				require.True(t, ok)
				assert.GreaterOrEqual(t, entered, holderMigrated,
					"the contender may only enter the migration after the holder finished")
			case migLockHelperExitFail:
				assert.Contains(t, contender.stderr.String(), "another process is migrating the SQLite database",
					"a contender that gives up must say why")
			default:
				t.Fatalf("contender exited %d; stderr:\n%s", contenderExit, contender.stderr.String())
			}

			_, holderFresh := readMigLockMarker(markers, "holder.freshinstall")
			_, contenderFresh := readMigLockMarker(markers, "contender.freshinstall")
			assert.True(t, holderFresh, "the holder performed the fresh install")
			assert.False(t, contenderFresh, "exactly one process may perform the fresh install")

			// The schema ends correct: every model's table, the epoch, and an
			// intact file.
			require.NoError(t, i18n.InitializeForTesting())
			defer i18n.ResetForTesting()
			db, err := gormOpenForTest(t, realPath)
			require.NoError(t, err)
			for _, m := range AllModels() {
				assert.True(t, db.Migrator().HasTable(m), "table for %T missing after both migrators ran", m)
			}
			var epoch models.SystemMetadata
			require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&epoch).Error)
			assert.Equal(t, strconv.Itoa(currentSchemaEpoch), epoch.Value)
			var integrity string
			require.NoError(t, db.Raw("PRAGMA integrity_check").Scan(&integrity).Error)
			assert.Equal(t, "ok", integrity)
		})
	}
}

// TestWithSQLiteInDBMigrationLock_HeldElsewhere_FailsCleanlyWithoutMigrating:
// while another connection holds the database's write lock (standing in for
// another process -- SQLite's locks hold between connections of one process
// too), a migrator that cannot get the lock within its busy_timeout returns
// the actionable error and never runs the migration.
func TestWithSQLiteInDBMigrationLock_HeldElsewhere_FailsCleanlyWithoutMigrating(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	dbPath := filepath.Join(t.TempDir(), "held.db")

	other, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)
	otherSQL, err := other.DB()
	require.NoError(t, err)
	defer otherSQL.Close() //nolint:errcheck
	conn, err := otherSQL.Conn(context.Background())
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck
	_, err = conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE")
	require.NoError(t, err)
	defer conn.ExecContext(context.Background(), "ROLLBACK") //nolint:errcheck

	// Same DSN shape as production, with a short busy_timeout so the test
	// doesn't wait out the production 10s.
	db, err := gorm.Open(sqlite.Open(dbPath+"?_foreign_keys=1&_busy_timeout=200&_journal_mode=WAL&_txlock=immediate"), gormConfig())
	require.NoError(t, err)

	ran := false
	err = withSQLiteInDBMigrationLock(db, dbPath, func(*gorm.DB) error { ran = true; return nil })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "another process is migrating the SQLite database")
	assert.False(t, ran, "the migration must not run without the lock")
}

// TestWithSQLiteInDBMigrationLock_ErrorRollsBackEverything: the migration is
// one transaction, so a failure partway leaves nothing behind -- including
// DDL, which SQLite (unlike some databases) rolls back.
func TestWithSQLiteInDBMigrationLock_ErrorRollsBackEverything(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "rollback.db"))
	require.NoError(t, err)

	err = withSQLiteInDBMigrationLock(db, "rollback.db", func(tx *gorm.DB) error {
		require.NoError(t, tx.Exec("CREATE TABLE half_migrated (id INTEGER)").Error)
		// A nested db.Transaction (as migrateDatabase uses) must nest on the
		// same connection, not deadlock against our own lock.
		require.NoError(t, tx.Transaction(func(inner *gorm.DB) error {
			return inner.Exec("INSERT INTO half_migrated (id) VALUES (1)").Error
		}))
		return fmt.Errorf("simulated migration failure")
	})
	require.ErrorContains(t, err, "simulated migration failure")
	assert.False(t, tableExists(db, "half_migrated"), "a failed migration must leave no partial schema behind")

	// And the lock was released: a following migration succeeds.
	require.NoError(t, withSQLiteInDBMigrationLock(db, "rollback.db", func(tx *gorm.DB) error {
		return tx.Exec("CREATE TABLE after_rollback (id INTEGER)").Error
	}))
	assert.True(t, tableExists(db, "after_rollback"))
}
