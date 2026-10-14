// factory_sqlite_migration_lock.go — cross-process exclusive lock guarding a
// local SQLite database's connect-and-migrate critical section
// (#STORAGE-FACTORY-003).
//
// migrationMu (see factory.go) only serializes createLocalStorage/migrateDatabase
// across goroutines WITHIN A SINGLE OS PROCESS; its own doc comment rests on the
// assumption that "SQLite deployments are single-process-per-file by
// construction" — but that assumption was never actually enforced anywhere.
// Nothing previously stopped two separate Keyorix OS processes pointed at the
// same local SQLite file (a misconfigured multi-replica deployment, or a
// `keyorix encryption ...` CLI invocation run concurrently with a live server
// process) from racing gorm.Open's WAL-mode switch and migrateDatabase's DDL
// statements against each other, unlike the Postgres path which already gets an
// additional cross-process protection via withMigrationLock's session-level
// advisory lock.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"gorm.io/gorm"
)

// sqliteMigrationLockSuffix is appended to the configured SQLite database path
// to build the sidecar lock file acquireSQLiteMigrationLock takes an flock(2) on.
const sqliteMigrationLockSuffix = ".migration.lock"

// sqliteMigrationLock holds an acquired exclusive flock(2) on a local SQLite
// database's migration lock sidecar file.
type sqliteMigrationLock struct {
	f *os.File
}

// release unlocks the flock and closes the underlying file descriptor. Safe to
// call on a nil receiver or a lock whose file is nil (defensive; every actual
// caller only calls this after a successful acquireSQLiteMigrationLock).
func (l *sqliteMigrationLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}

// acquireSQLiteMigrationLock takes a NON-BLOCKING exclusive flock(2) on
// <dbPath>.migration.lock, mirroring keymanager_filelock.go's DEK lock (flock is
// owned by the open file descriptor and released automatically by the kernel on
// process exit/crash/kill -9 — no stale-lock/PID-liveness bookkeeping to get
// wrong) and local_bootstrap_lock.go's cross-process critical-section pattern.
//
// Unlike keymanager_filelock.go's lock (which falls back to a blocking wait),
// this is non-blocking ONLY: a second process racing to connect/migrate the same
// local SQLite file must fail loud and fast at boot with an actionable error,
// not hang indefinitely waiting on a lock that may never be released (e.g. a
// wedged sibling process would otherwise stall this process's boot forever) —
// matching this file's fail-loud-over-silently-degrading design convention
// (warnIfDuplicatesExist, the invalid storage.type branch in CreateStorage,
// etc.) rather than the blocking-with-a-log-line convention used for the DEK
// lock, since a lock held here is expected to be brief (a single boot's connect
// + migrate) rather than an operator-triggered rotate/migrate-provider run.
//
// dbPath is the raw storage.database.path value, which — per sqliteDSN's own
// doc comment — may already carry DSN query parameters (an operator-supplied
// "?_pragma=..." suffix) or denote a private/shared in-memory database
// ("file:name?mode=memory[&cache=shared]" or ":memory:", both used throughout
// this package's own test suite). Neither case names a real on-disk file this
// lock can meaningfully protect:
//   - a query-string suffix is not part of the actual filesystem path, so it is
//     stripped before building the lock filename (otherwise the lock file's own
//     name would embed literal "?"/"&" characters from the DSN);
//   - an in-memory database is confined to the process (and, for a shared
//     cache, the process's connection pool) that opened it by construction —
//     there is no second OS process that could ever share it, so no lock is
//     needed at all and none is taken (acquireSQLiteMigrationLock returns a
//     nil lock and a nil error; release() on a nil lock is a no-op).
func acquireSQLiteMigrationLock(dbPath string) (*sqliteMigrationLock, error) {
	base := dbPath
	if idx := strings.IndexByte(base, '?'); idx != -1 {
		base = base[:idx]
	}
	if base == "" || base == ":memory:" || strings.Contains(dbPath, "mode=memory") {
		return nil, nil
	}

	lockPath := base + sqliteMigrationLockSuffix
	// #nosec G304 -- lockPath is derived from the operator-configured SQLite
	// database path (storage.database.path), not attacker input.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open SQLite migration lock file %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf(
			"another process already holds the migration lock on %s — only one Keyorix process (server or CLI) may connect to/migrate a local SQLite database at a time; stop the other process before starting this one",
			lockPath,
		)
	}
	return &sqliteMigrationLock{f: f}, nil
}

// sqliteExclusiveTxConn is the gorm ConnPool withSQLiteInDBMigrationLock runs
// the migration on: one dedicated *sql.Conn that already holds BEGIN
// EXCLUSIVE. Implementing gorm.TxCommitter makes every db.Transaction inside
// migrateDatabase nest as a SAVEPOINT on this same connection (exactly as the
// Postgres branch's tx handle does) rather than trying to BEGIN a second
// transaction -- which SQLite would reject on this connection, and which on
// any other pooled connection would block on our own exclusive lock.
//
// It deliberately exposes only gorm.ConnPool's methods plus Commit/Rollback --
// NOT *sql.Conn's BeginTx -- so it looks to GORM exactly like a *sql.Tx: its
// default per-write transaction (Create/Update/...) then runs inline instead
// of attempting a nested BEGIN.
type sqliteExclusiveTxConn struct {
	conn *sql.Conn
}

func (c sqliteExclusiveTxConn) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return c.conn.PrepareContext(ctx, query)
}

func (c sqliteExclusiveTxConn) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return c.conn.ExecContext(ctx, query, args...)
}

func (c sqliteExclusiveTxConn) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return c.conn.QueryContext(ctx, query, args...)
}

func (c sqliteExclusiveTxConn) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return c.conn.QueryRowContext(ctx, query, args...)
}

func (c sqliteExclusiveTxConn) Commit() error {
	_, err := c.conn.ExecContext(context.Background(), "COMMIT")
	return err
}

func (c sqliteExclusiveTxConn) Rollback() error {
	_, err := c.conn.ExecContext(context.Background(), "ROLLBACK")
	return err
}

var (
	_ gorm.ConnPool    = sqliteExclusiveTxConn{}
	_ gorm.TxCommitter = sqliteExclusiveTxConn{}
)

// withSQLiteInDBMigrationLock runs fn inside a BEGIN EXCLUSIVE transaction on
// a dedicated connection of db (INV-STORAGE-23, ADR-095 Task 4.3), committing
// only if fn succeeds. The lock is SQLite's own lock on the database file, so
// two processes migrating the same file are serialized by SQLite itself --
// whatever path each one used to reach it, with or without a surviving
// sidecar lock file (acquireSQLiteMigrationLock is keyed on the path string,
// so it misses both), and released by the OS if the holder dies. It is also
// schema-independent: it needs no table to exist, so it guards the very first
// migration that creates every table (the chicken-and-egg problem ADR-095
// notes rules out a lease row).
//
// A second migrator waits for the lock up to the connection's busy_timeout
// (sqliteBusyTimeoutMillis via sqliteDSN), then fails with an actionable
// error; one that gets the lock after the first finished sees an
// already-migrated database and migrateDatabase's idempotent steps no-op. The
// same-path case still fails immediately on the sidecar flock taken before
// this (withMigrationLock).
//
// Because the migration is one transaction, a crash or error anywhere in it
// leaves the database exactly as it was before this boot began.
func withSQLiteInDBMigrationLock(db *gorm.DB, dbPath string, fn func(*gorm.DB) error) (err error) {
	ctx := context.Background()
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("SQLite migration lock: get connection pool: %w", err)
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("SQLite migration lock: get dedicated connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		if isSQLiteBusy(err) {
			return fmt.Errorf(
				"another process is migrating the SQLite database %s (still held after waiting %dms for its exclusive lock) "+
					"— only one Keyorix process (server or CLI) may connect to/migrate a local SQLite database at a time; "+
					"stop the other process before starting this one: %w",
				dbPath, sqliteBusyTimeoutMillis, err)
		}
		return fmt.Errorf("SQLite migration lock: BEGIN EXCLUSIVE: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			// Covers fn's error and a panic alike (the panic keeps propagating
			// after this deferred rollback). The rollback's own error is
			// secondary to whatever made us roll back.
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	tx := db.Session(&gorm.Session{NewDB: true, Context: ctx})
	tx.Statement.ConnPool = sqliteExclusiveTxConn{conn}
	if err := fn(tx); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("SQLite migration lock: COMMIT: %w", err)
	}
	committed = true
	return nil
}

// isSQLiteBusy reports whether err is SQLite's SQLITE_BUSY ("database is
// locked") -- matched on the message, so this package does not depend on the
// driver's error type for one diagnostic branch.
func isSQLiteBusy(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if msg := e.Error(); strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked") {
			return true
		}
	}
	return false
}
