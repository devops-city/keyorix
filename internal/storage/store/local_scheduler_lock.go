// local_scheduler_lock.go — single-replica gating for background schedulers
// (ADR-039 HA). On PostgreSQL a session-scoped advisory lock ensures only one
// replica runs a given periodic job (purge, dynamic-secrets sweep, anomaly
// detection) per tick; on SQLite (inherently single-instance) the job always runs.
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// runProtected runs a scheduler job, converting a panic into an error so a single
// bad tick can't kill the scheduler goroutine (and so the advisory lock is still
// released by the caller's defers). Mirrors that the pre-ADR-039 schedulers had no
// panic guard either, but this is now the natural choke point to add one.
func runProtected(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("scheduler job panicked: %v", r)
		}
	}()
	return fn(ctx)
}

// WithSchedulerLock runs fn iff this process can acquire the advisory lock `key`.
//
// PostgreSQL: takes a session advisory lock on a dedicated pooled connection via
// pg_try_advisory_lock. If another replica holds it, returns (false, nil) so the
// caller skips this tick. The lock is always released (pg_advisory_unlock) before
// the connection returns to the pool — a session lock would otherwise outlive the
// tick on the pooled connection.
//
// The lock session comes from the dedicated scheduler lock pool when one is set
// (SetSchedulerLockDB; the storage factory always sets one), never from the
// request pool fn's own queries use. See SetSchedulerLockDB for why.
//
// SQLite / non-Postgres: there is only one instance, so fn always runs.
func (ls *LocalStorage) WithSchedulerLock(ctx context.Context, key int64, fn func(ctx context.Context) error) (bool, error) {
	if ls.db.Dialector.Name() != "postgres" {
		return true, runProtected(ctx, fn)
	}
	lockDB := ls.schedulerLockDB
	if lockDB == nil {
		sqlDB, err := ls.db.DB()
		if err != nil {
			return false, err
		}
		lockDB = sqlDB
	}
	conn, err := lockDB.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }() // returns the conn to the pool (after the unlock below)

	sess, err := openAdvisoryLockSession(ctx, conn, ls.transactionPooling)
	if err != nil {
		return false, err
	}
	defer sess.close(ctx)
	locked, err := sess.tryLock(ctx, key)
	if err != nil {
		return false, err
	}
	if !locked {
		return false, nil // another replica is running this job — skip
	}
	// Release before the deferred Close so the pooled connection carries no lock. If
	// the unlock itself fails, the session (and the lock with it) must not go back to
	// the pool: pg_try_advisory_lock checks server-wide, so a connection that silently
	// keeps carrying the lock would make every future attempt at this key — on any
	// connection, any replica — see it as permanently held, wedging the job cluster-
	// wide until that connection happens to be evicted. Marking it bad via conn.Raw
	// forces database/sql to physically close it instead of pooling it, which
	// terminates the Postgres backend and releases every advisory lock it held.
	defer sess.unlock(ctx, key, "scheduler")
	wctx, finish := sess.watch(ctx, "scheduler lock")
	return true, finish(runProtected(wctx, fn))
}

// SetSchedulerLockDB gives WithSchedulerLock a pool of its own for the advisory-
// lock sessions, separate from the request pool. A lock session is pinned for the
// whole job while the job's queries need a connection of their own; on one shared
// pool, enough jobs ticking together pinned every connection, each waiting for
// one more, and the server hung for good (hold-and-wait; POOL-HANG-1). With a
// separate pool, a job never holds a request-pool connection while it waits for
// anything, so the request pool always drains. The lock semantics are unchanged:
// still one session advisory lock per job on its own session, in the same
// database, released before the session is pooled again.
//
// Without one (a LocalStorage built directly by tests or examples), the request
// pool is used as before. Call it before serving traffic.
func (ls *LocalStorage) SetSchedulerLockDB(db *sql.DB) {
	ls.schedulerLockDB = db
}
