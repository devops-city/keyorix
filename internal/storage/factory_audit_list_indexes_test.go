package storage

// factory_audit_list_indexes_test.go — the audit list indexes
// (store.AuditListIndexes) are created on fresh and upgraded databases, replace
// the single-column project_id / machine_identity_id indexes, and on Postgres
// are built CONCURRENTLY: idempotent, an INVALID leftover is rebuilt, and audit
// writes are never blocked (docs/specs/audit-list-keyset.md §4, §5.5).

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ensureAuditListIndexesForTest runs the index step the factory runs after
// migrateDatabase, synchronously, on either dialect.
func ensureAuditListIndexesForTest(t *testing.T, db *gorm.DB) {
	t.Helper()
	if db.Dialector.Name() == "postgres" {
		sqlDB, err := db.DB()
		require.NoError(t, err)
		require.NoError(t, store.BuildAuditListIndexesPostgres(context.Background(), sqlDB, false, t.Logf))
		return
	}
	require.NoError(t, store.EnsureAuditListIndexesSQLite(db, t.Logf))
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCapture) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *logCapture) joined() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

// requireAuditListIndexesState asserts every composite exists and every
// replaced single-column index is gone.
func requireAuditListIndexesState(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, ix := range store.AuditListIndexes {
		require.True(t, indexExists(db, ix.Name), "%s must exist", ix.Name)
	}
	for _, name := range store.AuditListReplacedIndexes {
		require.False(t, indexExists(db, name), "%s is replaced by a composite and must be dropped", name)
	}
}

func insertAuditRowsRaw(t *testing.T, db *gorm.DB, n int) {
	t.Helper()
	for i := range n {
		require.NoError(t, db.Exec("INSERT INTO audit_events (event_type, project_id, machine_identity_id, event_time) VALUES (?, ?, ?, ?)",
			"secret.read", 1+i%3, 1+i%2, time.Now().UTC().Add(time.Duration(i)*time.Second)).Error)
	}
}

func TestAuditListIndexes_SQLite_FreshAndUpgrade(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "audit-list-idx.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}

	// Fresh install: the step the factory runs creates the composites, and
	// the model no longer creates the single-column indexes.
	require.NoError(t, f.migrateSQLite(db))
	requireAuditListIndexesState(t, db)

	// Upgrade from a release that had the single-column indexes and none of
	// the composites, with data in the table.
	for _, ix := range store.AuditListIndexes {
		require.NoError(t, db.Exec("DROP INDEX "+ix.Name).Error)
	}
	require.NoError(t, db.Exec("CREATE INDEX idx_audit_events_project_id ON audit_events (project_id)").Error)
	require.NoError(t, db.Exec("CREATE INDEX idx_audit_events_machine_identity_id ON audit_events (machine_identity_id)").Error)
	insertAuditRowsRaw(t, db, 20)

	logs := &logCapture{}
	require.NoError(t, f.migrateDatabase(db))
	require.NoError(t, store.EnsureAuditListIndexesSQLite(db, logs.logf))
	requireAuditListIndexesState(t, db)
	for _, ix := range store.AuditListIndexes {
		require.Contains(t, logs.joined(), "audit index build: creating "+ix.Name+" on audit_events (~20 rows)")
		require.Contains(t, logs.joined(), "audit index build: "+ix.Name+" done in ")
	}

	// Idempotent: nothing left to build, nothing logged.
	again := &logCapture{}
	require.NoError(t, store.EnsureAuditListIndexesSQLite(db, again.logf))
	require.Empty(t, again.joined())
}

// pgAuditListDB is an isolated Postgres database migrated by migrateDatabase
// only (no index step), with the audit list indexes removed and the two
// single-column indexes of earlier releases present: the state of an upgrade.
func pgAuditListDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, _ := pgAuditListDBDSN(t)
	return db
}

// pgAuditListDBDSN is pgAuditListDB plus the database's DSN.
func pgAuditListDBDSN(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	dsn := pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	db := pgRawOpen(t, dsn)
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
	for _, ix := range store.AuditListIndexes {
		require.NoError(t, db.Exec("DROP INDEX IF EXISTS "+ix.Name).Error)
	}
	require.NoError(t, db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_events_project_id ON audit_events (project_id)").Error)
	require.NoError(t, db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_events_machine_identity_id ON audit_events (machine_identity_id)").Error)
	insertAuditRowsRaw(t, db, 20)
	return db, dsn
}

func TestAuditListIndexes_Postgres_BuildIsIdempotentAndDropsReplaced(t *testing.T) {
	db := pgAuditListDB(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	ctx := context.Background()

	pending, err := store.AuditListIndexesPendingPostgres(ctx, sqlDB)
	require.NoError(t, err)
	require.True(t, pending)

	logs := &logCapture{}
	require.NoError(t, store.BuildAuditListIndexesPostgres(ctx, sqlDB, false, logs.logf))
	requireAuditListIndexesState(t, db)
	require.Contains(t, logs.joined(), "CONCURRENTLY")
	for _, ix := range store.AuditListIndexes {
		var def string
		require.NoError(t, db.Raw("SELECT indexdef FROM pg_indexes WHERE indexname = ?", ix.Name).Scan(&def).Error)
		require.Contains(t, def, "("+strings.Join(ix.Columns, ", ")+")", "%s definition", ix.Name)
	}

	pending, err = store.AuditListIndexesPendingPostgres(ctx, sqlDB)
	require.NoError(t, err)
	require.False(t, pending)
	again := &logCapture{}
	require.NoError(t, store.BuildAuditListIndexesPostgres(ctx, sqlDB, false, again.logf))
	require.Empty(t, again.joined(), "a second build must issue no DDL")
}

func TestAuditListIndexes_Postgres_InvalidIndexIsRebuilt(t *testing.T) {
	db := pgAuditListDB(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	ctx := context.Background()

	// An interrupted CREATE INDEX CONCURRENTLY leaves an INVALID index under
	// the name. Produce one the same way: a concurrent unique build that
	// fails on duplicates (every seeded row is secret.read).
	err = db.Exec("CREATE UNIQUE INDEX CONCURRENTLY idx_audit_events_event_time_id ON audit_events (event_type)").Error
	require.Error(t, err)
	var valid bool
	require.NoError(t, db.Raw(`SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
		WHERE c.relname = 'idx_audit_events_event_time_id'`).Scan(&valid).Error)
	require.False(t, valid, "fixture: the leftover must be INVALID")

	logs := &logCapture{}
	require.NoError(t, store.BuildAuditListIndexesPostgres(ctx, sqlDB, false, logs.logf))
	require.Contains(t, logs.joined(), "idx_audit_events_event_time_id is INVALID")
	var def string
	require.NoError(t, db.Raw("SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_audit_events_event_time_id'").Scan(&def).Error)
	require.Contains(t, def, "(event_time, id)")
	require.NotContains(t, def, "UNIQUE")
	pending, err := store.AuditListIndexesPendingPostgres(ctx, sqlDB)
	require.NoError(t, err)
	require.False(t, pending)
}

// TestAuditListIndexes_Postgres_BuildNeverBlocksAuditWrites is the red/green
// proof of "never block audit writes". A writer transaction stays open, so any
// index build has to wait for it. While the build waits, a second audit INSERT
// must complete. The control case shows that the harness does reproduce the
// hazard: a plain CREATE INDEX queues a SHARE lock behind the open writer, and
// the second INSERT queues behind that lock until the timeout.
func TestAuditListIndexes_Postgres_BuildNeverBlocksAuditWrites(t *testing.T) {
	run := func(t *testing.T, build func(ctx context.Context, db *gorm.DB) error) (insertErr error) {
		db := pgAuditListDB(t)
		ctx := context.Background()

		// The open writer: an uncommitted audit INSERT.
		holder := db.Begin()
		require.NoError(t, holder.Error)
		require.NoError(t, holder.Exec("INSERT INTO audit_events (event_type, event_time) VALUES ('secret.read', now())").Error)

		buildDone := make(chan error, 1)
		go func() { buildDone <- build(ctx, db) }()
		// Let the build reach its wait on the open writer.
		waitForLockWait(t, db)

		insCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		insertErr = db.WithContext(insCtx).Exec("INSERT INTO audit_events (event_type, event_time) VALUES ('secret.read', now())").Error

		require.NoError(t, holder.Commit().Error)
		require.NoError(t, <-buildDone)
		return insertErr
	}

	t.Run("CONCURRENTLY: the INSERT completes while the build waits", func(t *testing.T) {
		err := run(t, func(ctx context.Context, db *gorm.DB) error {
			sqlDB, err := db.DB()
			if err != nil {
				return err
			}
			return store.BuildAuditListIndexesPostgres(ctx, sqlDB, false, t.Logf)
		})
		require.NoError(t, err, "an audit INSERT must not wait for the index build")
	})

	t.Run("control: a plain CREATE INDEX blocks the INSERT", func(t *testing.T) {
		err := run(t, func(ctx context.Context, db *gorm.DB) error {
			return db.WithContext(ctx).Exec("CREATE INDEX idx_audit_events_event_time_id ON audit_events (event_time, id)").Error
		})
		require.Error(t, err, "harness check: a non-concurrent build must block the INSERT, or this test proves nothing")
	})
}

// waitForLockWait polls pg_stat_activity until some other session of this
// database is waiting on a lock (the index build waiting for the open writer).
func waitForLockWait(t *testing.T, db *gorm.DB) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var n int64
		require.NoError(t, db.Raw(`SELECT COUNT(*) FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event_type = 'Lock'`).Scan(&n).Error)
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the index build never started waiting on the open writer transaction")
}

// openBuildPool is the dedicated pool factory a background build gets.
func openBuildPool(dsn string) func() (*sql.DB, error) {
	return func() (*sql.DB, error) { return sql.Open("pgx", dsn) }
}

func requireNothingPending(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	pending, err := store.AuditListIndexesPendingPostgres(context.Background(), sqlDB)
	require.NoError(t, err)
	require.False(t, pending, "every audit list index valid, replaced ones dropped")
}

// holdAuditWriter opens a transaction with an uncommitted audit INSERT, which
// every CREATE INDEX CONCURRENTLY on audit_events must wait for.
func holdAuditWriter(t *testing.T, db *gorm.DB) *gorm.DB {
	t.Helper()
	holder := db.Begin()
	require.NoError(t, holder.Error)
	require.NoError(t, holder.Exec("INSERT INTO audit_events (event_type, event_time) VALUES ('secret.read', now())").Error)
	t.Cleanup(func() { holder.Rollback() })
	return holder
}

func TestEnsureAuditListIndexes_Postgres_SmallTableBuildsBeforeServing(t *testing.T) {
	db, dsn := pgAuditListDBDSN(t)
	ls := store.NewLocalStorage(pgRawOpen(t, dsn))
	ensureAuditListIndexesPostgres(ls, db, openBuildPool(dsn))
	requireNothingPending(t, db)
	require.False(t, ls.WaitAuditListIndexBuild(), "below the threshold nothing is left to the background")
}

func TestEnsureAuditListIndexes_Postgres_LargeTableBuildsInBackground(t *testing.T) {
	db, dsn := pgAuditListDBDSN(t)
	old := auditIndexSyncBuildMaxRows
	auditIndexSyncBuildMaxRows = 5 // the fixture's 20 rows are "large"
	t.Cleanup(func() { auditIndexSyncBuildMaxRows = old })

	ls := store.NewLocalStorage(pgRawOpen(t, dsn))
	ensureAuditListIndexesPostgres(ls, db, openBuildPool(dsn))
	require.True(t, ls.WaitAuditListIndexBuild(), "above the threshold the build runs in the background")
	requireNothingPending(t, db)
}

// TestEnsureAuditListIndexes_Postgres_SyncTimeoutFallsBackToBackground: an
// open writer transaction makes the startup build wait; the start must not
// wait with it. Past the timeout it goes on in the background and finishes
// (dropping and rebuilding what the cancelled build left INVALID) once the
// writer commits.
func TestEnsureAuditListIndexes_Postgres_SyncTimeoutFallsBackToBackground(t *testing.T) {
	db, dsn := pgAuditListDBDSN(t)
	old := auditIndexSyncBuildTimeout
	auditIndexSyncBuildTimeout = time.Second
	t.Cleanup(func() { auditIndexSyncBuildTimeout = old })
	holder := holdAuditWriter(t, db)

	ls := store.NewLocalStorage(pgRawOpen(t, dsn))
	start := time.Now()
	ensureAuditListIndexesPostgres(ls, db, openBuildPool(dsn))
	require.Less(t, time.Since(start), 20*time.Second, "the start must not wait for the open writer")

	require.NoError(t, holder.Commit().Error)
	require.True(t, ls.WaitAuditListIndexBuild(), "the build continued in the background")
	requireNothingPending(t, db)
}

// TestStartAuditListIndexBuild_Postgres_CloseCancelsAndNextStartRebuilds:
// Close returns promptly while the background build waits (it cancels the
// CREATE INDEX CONCURRENTLY), and the next start rebuilds what it left.
func TestStartAuditListIndexBuild_Postgres_CloseCancelsAndNextStartRebuilds(t *testing.T) {
	db, dsn := pgAuditListDBDSN(t)
	holder := holdAuditWriter(t, db)

	ls := store.NewLocalStorage(pgRawOpen(t, dsn))
	bdb, err := openBuildPool(dsn)()
	require.NoError(t, err)
	ls.StartAuditListIndexBuild(bdb, t.Logf)
	waitForLockWait(t, db)

	closed := make(chan error, 1)
	go func() { closed <- ls.Close() }()
	select {
	case <-closed:
	case <-time.After(20 * time.Second):
		t.Fatal("Close did not cancel the background index build")
	}
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// Close returning means the build's session is gone: no backend may still
	// hold the build lock, or the next start sees ErrAuditIndexBuildLockHeld.
	var held int
	require.NoError(t, sqlDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted
		   AND classid = $1 AND objid = $2 AND objsubid = 1`,
		store.AuditIndexBuildLockClassID, store.AuditIndexBuildLockObjID).Scan(&held))
	require.Zero(t, held, "Close returned while a backend still held the audit index build lock")
	pending, err := store.AuditListIndexesPendingPostgres(context.Background(), sqlDB)
	require.NoError(t, err)
	require.True(t, pending, "the cancelled build left work for the next start")

	require.NoError(t, holder.Commit().Error)
	logs := &logCapture{}
	require.NoError(t, store.BuildAuditListIndexesPostgres(context.Background(), sqlDB, false, logs.logf), "the next start")
	requireAuditListIndexesState(t, db)
	requireNothingPending(t, db)
}
