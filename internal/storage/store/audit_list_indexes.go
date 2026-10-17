// audit_list_indexes.go — the audit_events time indexes behind GetAuditLogs'
// newest-first order, and how they are built without blocking audit writes
// (docs/specs/audit-list-keyset.md §4).
//
// They are declared here, once, and created by code rather than by gorm tags:
// a tag is a plain CREATE INDEX inside the migration transaction, which on
// Postgres takes a SHARE lock and blocks every audit INSERT (every secret read)
// for the whole build. On Postgres they are built with CREATE INDEX
// CONCURRENTLY, outside any transaction; on SQLite (one writer, built before
// the server listens) with a plain CREATE INDEX inside the migration.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// AuditListIndex is one audit_events index of the list views.
type AuditListIndex struct {
	Name    string
	Columns []string
}

// AuditListIndexes are the indexes GetAuditLogs' plans rely on. Every key is
// monotonic in time, so inserts append at the right edge of each b-tree.
var AuditListIndexes = []AuditListIndex{
	{Name: "idx_audit_events_event_time_id", Columns: []string{"event_time", "id"}},
	{Name: "idx_audit_events_project_event_time", Columns: []string{"project_id", "event_time"}},
	{Name: "idx_audit_events_secret_event_time", Columns: []string{"secret_node_id", "event_time"}},
	{Name: "idx_audit_events_machine_event_time", Columns: []string{"machine_identity_id", "event_time"}},
}

// AuditListReplacedIndexes are the single-column indexes the composites above
// make redundant. They are dropped only after every AuditListIndexes entry is
// valid, so no point in the upgrade loses an index a query uses.
var AuditListReplacedIndexes = []string{
	"idx_audit_events_project_id",
	"idx_audit_events_machine_identity_id",
}

// auditIndexBuildLockKey is the Postgres advisory lock that lets one
// replica build while the others skip. It differs from the migration lock
// (postgresMigrationLockKey, internal/storage): the build runs after the
// migration transaction has committed and released that one.
const auditIndexBuildLockKey = 0x4B455941_49445842 // "KEYAIDXB"

// The pg_locks classid/objid halves of auditIndexBuildLockKey (a bigint advisory
// key is stored as its high and low 32 bits), for tests that assert the lock is
// released.
const (
	AuditIndexBuildLockClassID = auditIndexBuildLockKey >> 32
	AuditIndexBuildLockObjID   = auditIndexBuildLockKey & 0xFFFFFFFF
)

// ErrAuditIndexBuildLockHeld: another session holds auditIndexBuildLockKey, so
// that process is building. Nothing was changed.
var ErrAuditIndexBuildLockHeld = errors.New("audit index build: another session holds the build lock")

func (ix AuditListIndex) columnList() string { return strings.Join(ix.Columns, ", ") }

// AuditEventsRowEstimate is MAX(id)-MIN(id)+1 of audit_events (two primary-key
// lookups): a cheap upper bound of the row count, used to log what a build will
// cover and to decide whether a Postgres build can run before serving.
func AuditEventsRowEstimate(ctx context.Context, db *gorm.DB) (int64, error) {
	var r struct {
		Lo *int64
		Hi *int64
	}
	if err := db.WithContext(ctx).Raw("SELECT MIN(id) AS lo, MAX(id) AS hi FROM audit_events").Scan(&r).Error; err != nil {
		return 0, err
	}
	if r.Lo == nil || r.Hi == nil {
		return 0, nil
	}
	return *r.Hi - *r.Lo + 1, nil
}

// EnsureAuditListIndexesSQLite creates the missing AuditListIndexes with a
// plain CREATE INDEX IF NOT EXISTS (one progress line per index built) and then
// drops AuditListReplacedIndexes. It runs inside the SQLite migration
// transaction, before the server listens; SQLite has a single writer, so the
// build holds the database for its duration either way.
func EnsureAuditListIndexesSQLite(db *gorm.DB, logf func(string, ...any)) error {
	if !db.Migrator().HasTable("audit_events") {
		return nil
	}
	var rows int64 = -1
	for _, ix := range AuditListIndexes {
		if db.Migrator().HasIndex("audit_events", ix.Name) || !hasColumns(db, ix.Columns) {
			continue
		}
		if rows < 0 {
			var err error
			if rows, err = AuditEventsRowEstimate(context.Background(), db); err != nil {
				return fmt.Errorf("audit index build: estimate rows: %w", err)
			}
		}
		// An empty table (a fresh install) builds instantly; only a real build
		// is worth a progress line.
		if rows > 0 {
			logf("audit index build: creating %s on audit_events (~%d rows); the database is busy until it finishes", ix.Name, rows)
		}
		start := time.Now()
		if err := db.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON audit_events (%s)", ix.Name, ix.columnList())).Error; err != nil {
			return fmt.Errorf("audit index build: create %s: %w", ix.Name, err)
		}
		if rows > 0 {
			logf("audit index build: %s done in %s", ix.Name, time.Since(start).Round(time.Millisecond))
		}
	}
	for _, name := range AuditListReplacedIndexes {
		if err := db.Exec("DROP INDEX IF EXISTS " + name).Error; err != nil {
			return fmt.Errorf("audit index build: drop %s: %w", name, err)
		}
	}
	return nil
}

func hasColumns(db *gorm.DB, cols []string) bool {
	for _, c := range cols {
		if !db.Migrator().HasColumn("audit_events", c) {
			return false
		}
	}
	return true
}

// pgIndexState is "absent", "valid" or "invalid" (an interrupted CREATE INDEX
// CONCURRENTLY leaves an INVALID index that queries never use).
func pgIndexState(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, name string) (string, error) {
	var valid bool
	err := q.QueryRowContext(ctx, `SELECT i.indisvalid FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		WHERE i.indrelid = 'audit_events'::regclass AND c.relname = $1`, name).Scan(&valid)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "absent", nil
	case err != nil:
		return "", err
	case valid:
		return "valid", nil
	default:
		return "invalid", nil
	}
}

// AuditListIndexesPendingPostgres reports whether a Postgres build has work to
// do: an AuditListIndexes entry absent or invalid, or a replaced index still
// present. Catalog reads only.
func AuditListIndexesPendingPostgres(ctx context.Context, db *sql.DB) (bool, error) {
	for _, ix := range AuditListIndexes {
		st, err := pgIndexState(ctx, db, ix.Name)
		if err != nil {
			return false, err
		}
		if st != "valid" {
			return true, nil
		}
	}
	for _, name := range AuditListReplacedIndexes {
		st, err := pgIndexState(ctx, db, name)
		if err != nil {
			return false, err
		}
		if st != "absent" {
			return true, nil
		}
	}
	return false, nil
}

// BuildAuditListIndexesPostgres brings AuditListIndexes to valid and then drops
// AuditListReplacedIndexes, every statement CONCURRENTLY and in autocommit on
// one dedicated connection, never inside a transaction. CONCURRENTLY takes
// SHARE UPDATE EXCLUSIVE, which does not conflict with an INSERT's ROW
// EXCLUSIVE, so audit writes continue throughout. An INVALID index (a build
// interrupted by a crash or a cancelled ctx) is dropped and rebuilt. When
// another process holds the build lock it returns without doing anything: that
// process is building, and an INVALID index seen meanwhile is its build in
// progress, not a leftover; it returns ErrAuditIndexBuildLockHeld. Idempotent:
// with everything in place it issues no DDL.
//
// The build lock is held through advisoryLockSession on a second connection
// that stays idle while the DDL runs: a session lock by default, and with xact
// (storage.database.pooler: pgbouncer-transaction, INV-STORE-advisory-lock-
// pooler-scope) a transaction-scoped one inside a pinned READ COMMITTED
// transaction, which holds no snapshot between statements, so CREATE INDEX
// CONCURRENTLY never waits for it. A cancelled ctx aborts the DDL on its own
// connection; the lock connection never runs the cancelled statement, so the
// lock is released (unlock, or ROLLBACK) before this returns. db must allow
// two open connections.
func BuildAuditListIndexesPostgres(ctx context.Context, db *sql.DB, xact bool, logf func(string, ...any)) error {
	lockConn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = lockConn.Close() }()
	sess, err := openAdvisoryLockSession(ctx, lockConn, xact)
	if err != nil {
		return fmt.Errorf("audit index build: lock: %w", err)
	}
	defer sess.close(ctx)
	if xact {
		// Not left to default_transaction_isolation: a REPEATABLE READ lock
		// transaction keeps its snapshot, and CREATE INDEX CONCURRENTLY would
		// wait for it, that is for itself.
		if _, err := lockConn.ExecContext(ctx, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"); err != nil {
			return fmt.Errorf("audit index build: lock: %w", err)
		}
	}
	locked, err := sess.tryLock(ctx, auditIndexBuildLockKey)
	if err != nil {
		return fmt.Errorf("audit index build: lock: %w", err)
	}
	if !locked {
		return ErrAuditIndexBuildLockHeld
	}
	defer sess.unlock(ctx, auditIndexBuildLockKey, "audit index build")

	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	wctx, finish := sess.watch(ctx, "audit index build lock")
	return finish(buildAuditListIndexes(wctx, conn, logf))
}

// buildAuditListIndexes is BuildAuditListIndexesPostgres' DDL on conn, run with
// the build lock held.
func buildAuditListIndexes(ctx context.Context, conn *sql.Conn, logf func(string, ...any)) error {
	for _, ix := range AuditListIndexes {
		st, err := pgIndexState(ctx, conn, ix.Name)
		if err != nil {
			return fmt.Errorf("audit index build: inspect %s: %w", ix.Name, err)
		}
		if st == "valid" {
			continue
		}
		if st == "invalid" {
			logf("audit index build: %s is INVALID (an interrupted build); dropping it to rebuild", ix.Name)
			if _, err := conn.ExecContext(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+ix.Name); err != nil {
				return fmt.Errorf("audit index build: drop invalid %s: %w", ix.Name, err)
			}
		}
		logf("audit index build: creating %s CONCURRENTLY (audit writes continue)", ix.Name)
		start := time.Now()
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("CREATE INDEX CONCURRENTLY IF NOT EXISTS %s ON audit_events (%s)", ix.Name, ix.columnList())); err != nil {
			return fmt.Errorf("audit index build: create %s: %w", ix.Name, err)
		}
		after, err := pgIndexState(ctx, conn, ix.Name)
		if err != nil {
			return fmt.Errorf("audit index build: inspect %s after build: %w", ix.Name, err)
		}
		if after != "valid" {
			return fmt.Errorf("audit index build: %s not valid after build (state %q)", ix.Name, after)
		}
		logf("audit index build: %s done in %s", ix.Name, time.Since(start).Round(time.Millisecond))
	}
	for _, name := range AuditListReplacedIndexes {
		st, err := pgIndexState(ctx, conn, name)
		if err != nil {
			return fmt.Errorf("audit index build: inspect %s: %w", name, err)
		}
		if st == "absent" {
			continue
		}
		if _, err := conn.ExecContext(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+name); err != nil {
			return fmt.Errorf("audit index build: drop replaced %s: %w", name, err)
		}
		logf("audit index build: dropped %s (replaced by a composite)", name)
	}
	return nil
}
