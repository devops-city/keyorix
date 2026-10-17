// local_bootstrap_lock.go — serializes BootstrapSystem's first-admin seeding
// sequence (ADR-039 HA) across every replica.
//
// BootstrapSystem's "is this a fresh install" check through admin/RBAC/project
// seeding was previously guarded only by a KeyorixCore-level sync.Mutex
// (bootstrapMu), which serializes concurrent callers within ONE server process
// but does nothing for two different replicas of an HA deployment racing
// POST /system/init against the same shared database: each replica's mutex
// only guards its own process, so both can observe "not yet initialised"
// before either's write is visible to the other and each independently seed a
// "first admin" — a duplicate-admin race and/or partially corrupted RBAC seed
// (#core-auth-03).
package store

import (
	"context"
	"fmt"
)

// bootstrapAdvisoryLockKey is the Postgres advisory-lock key guarding
// BootstrapSystem's check-then-create sequence across processes. Distinct from
// auditAdvisoryLockKey and auditCheckpointAdvisoryLockKey — the three critical
// sections are independent and must not contend with each other.
const bootstrapAdvisoryLockKey = 0x4B455941_424F4F54 // "KEYABOOT"

// WithBootstrapLock runs fn with BootstrapSystem's check-then-create sequence
// serialized: a process-level mutex covers the common single-writer self-host
// topology and SQLite (inherently single-instance — there is no DB-level
// advisory lock to take); a PostgreSQL session-scoped advisory lock
// (pg_advisory_lock) extends that across processes/replicas (ADR-039 HA).
//
// Like WithAuditCheckpointLock, this BLOCKS until the lock is acquired rather
// than skipping on contention — a replica that loses the race must actually
// re-run its "already initialised?" check under the lock and observe the
// winner's now-committed state, not silently no-op (which would leave its
// caller waiting on a response that never seeds anything and never reports
// AlreadyInitialized either).
func (ls *LocalStorage) WithBootstrapLock(ctx context.Context, fn func(ctx context.Context) error) error {
	ls.bootstrapMu.Lock()
	defer ls.bootstrapMu.Unlock()

	if ls.db.Dialector.Name() != "postgres" {
		return fn(ctx)
	}

	sqlDB, err := ls.db.DB()
	if err != nil {
		return err
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // returns the conn to the pool (after the unlock below)

	sess, err := openAdvisoryLockSession(ctx, conn, ls.transactionPooling)
	if err != nil {
		return fmt.Errorf("failed to acquire bootstrap advisory lock: %w", err)
	}
	defer sess.close(ctx)
	if err := sess.lock(ctx, int64(bootstrapAdvisoryLockKey)); err != nil {
		return fmt.Errorf("failed to acquire bootstrap advisory lock: %w", err)
	}
	// Release before the deferred Close so the pooled connection carries no lock.
	defer sess.unlock(ctx, int64(bootstrapAdvisoryLockKey), "bootstrap lock")

	wctx, finish := sess.watch(ctx, "bootstrap lock")
	return finish(fn(wctx))
}
