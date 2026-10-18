// local_audit_checkpoint_lock.go — serializes the audit-checkpoint write path
// (ADR-029) across every trigger and replica.
//
// WriteAuditCheckpoint's chain-walk + decide + create-checkpoint sequence is
// reachable from three unsynchronized triggers: the background scheduler tick,
// an operator's POST /api/v1/audit/checkpoint call, and the gRPC
// WriteAuditCheckpoint RPC. With no lock, two overlapping calls — including two
// landing on different replicas under ADR-039 HA — can interleave and commit a
// checkpoint out of chain-length order: the row with the higher DB id can end
// up certifying FEWER chained events than an earlier-committed row, silently
// reopening the truncation-detection gap ADR-029 exists to close (#300).
package store

import (
	"context"
	"fmt"
)

// auditCheckpointAdvisoryLockKey is the Postgres advisory-lock key guarding
// WriteAuditCheckpoint's chain-walk + decide + create sequence across processes.
// Distinct from auditAdvisoryLockKey (local_audit_chain.go), which guards
// per-event chain appends — the two critical sections are independent and must
// not contend with each other.
const auditCheckpointAdvisoryLockKey = 0x4B455941_43484B50 // "KEYACHKP"

// WithAuditCheckpointLock runs fn with the audit-checkpoint write path
// serialized: a process-level mutex covers the common single-writer self-host
// topology and SQLite (inherently single-instance — there is no DB-level
// advisory lock to take); a PostgreSQL session-scoped advisory lock
// (pg_advisory_lock) extends that across processes/replicas (ADR-039 HA).
//
// Unlike WithSchedulerLock, this BLOCKS until the lock is acquired rather than
// skipping on contention — the scheduler, HTTP, and gRPC triggers must each
// actually run their checkpoint decision against state left by the previous
// writer, not silently no-op, or an operator-triggered write racing the
// scheduler would just be dropped instead of serialized.
func (ls *LocalStorage) WithAuditCheckpointLock(ctx context.Context, fn func(ctx context.Context) error) error {
	ls.auditCheckpointMu.Lock()
	defer ls.auditCheckpointMu.Unlock()

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
		return fmt.Errorf("failed to acquire audit-checkpoint advisory lock: %w", err)
	}
	defer sess.close(ctx)
	if err := sess.lock(ctx, int64(auditCheckpointAdvisoryLockKey)); err != nil {
		return fmt.Errorf("failed to acquire audit-checkpoint advisory lock: %w", err)
	}
	// Release before the deferred Close so the pooled connection carries no lock.
	defer sess.unlock(ctx, int64(auditCheckpointAdvisoryLockKey), "audit-checkpoint lock")

	wctx, finish := sess.watch(ctx, "audit-checkpoint lock")
	return finish(fn(wctx))
}
