package store

// advisory_lock_liveness_postgres_test.go — a lock held in a pinned transaction
// (storage.database.pooler: pgbouncer-transaction) whose backend is killed is
// reported as lost, not silently dropped (INV-STORE-advisory-lock-pooler-scope).
// pg-gated (KEYORIX_TEST_PG_DSN).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

func shortPinnedLockPing(t *testing.T) {
	t.Helper()
	oldInterval, oldTimeout := config.PinnedLockPingInterval, config.PinnedLockPingTimeout
	config.PinnedLockPingInterval = 100 * time.Millisecond
	config.PinnedLockPingTimeout = 300 * time.Millisecond
	t.Cleanup(func() {
		config.PinnedLockPingInterval, config.PinnedLockPingTimeout = oldInterval, oldTimeout
	})
}

// terminateLockBackend ends the backend holding advisory lock key and returns
// how many it ended.
func terminateLockBackend(t *testing.T, ctx context.Context, base string, key int64) int {
	t.Helper()
	admin := pgOpen(t, base)
	var n int
	require.NoError(t, admin.WithContext(ctx).Raw(`SELECT count(*) FROM (
			SELECT pg_terminate_backend(pid) FROM pg_locks
			WHERE locktype = 'advisory' AND granted AND objsubid = 1 AND classid = ? AND objid = ?) k`,
		int64(uint32(uint64(key)>>32)), int64(uint32(uint64(key)&0xFFFFFFFF))).Scan(&n).Error)
	return n
}

// TestWithNamedLock_TransactionPooling_KilledLockBackendIsReported: the holder's
// context is cancelled with cause ErrAdvisoryLockLost soon after the lock
// backend dies, and WithNamedLock returns that error even though fn returned
// nothing of its own. A healthy hold of the same length is not reported.
func TestWithNamedLock_TransactionPooling_KilledLockBackendIsReported(t *testing.T) {
	base := pgTestDSN(t)
	shortPinnedLockPing(t)
	ls := NewLocalStorage(pgOpen(t, pgIsolatedSchemaDSN(t, base)))
	ls.SetTransactionPooling(true)
	ctx := context.Background()
	const lockKey = "liveness-test"

	// Healthy: several ping intervals pass, nothing is reported.
	require.NoError(t, ls.WithNamedLock(ctx, lockKey, func(ctx context.Context) error {
		time.Sleep(450 * time.Millisecond)
		return ctx.Err()
	}))

	var cause error
	start := time.Now()
	err := ls.WithNamedLock(ctx, lockKey, func(ctx context.Context) error {
		require.Equal(t, 1, terminateLockBackend(t, ctx, base, namedLockKey(lockKey)))
		select {
		case <-ctx.Done():
			cause = context.Cause(ctx)
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("the holder's context was never cancelled after its lock backend was terminated")
		}
	})
	require.ErrorIs(t, err, ErrAdvisoryLockLost)
	require.ErrorIs(t, cause, ErrAdvisoryLockLost)
	require.Less(t, time.Since(start), 3*time.Second)

	// The lost session did not wedge the key.
	require.NoError(t, ls.WithNamedLock(ctx, lockKey, func(context.Context) error { return nil }))
}

// TestWithSchedulerLock_TransactionPooling_KilledLockBackendIsReported: the
// scheduler tick learns its lock is gone when it returns.
func TestWithSchedulerLock_TransactionPooling_KilledLockBackendIsReported(t *testing.T) {
	base := pgTestDSN(t)
	shortPinnedLockPing(t)
	ls := NewLocalStorage(pgOpen(t, pgIsolatedSchemaDSN(t, base)))
	ls.SetTransactionPooling(true)
	const key int64 = 0x4B455953_4C495645 // "KEYSLIVE"

	ran, err := ls.WithSchedulerLock(context.Background(), key, func() error {
		if terminateLockBackend(t, context.Background(), base, key) != 1 {
			return errors.New("no lock backend to terminate")
		}
		time.Sleep(600 * time.Millisecond) // several ping intervals
		return nil
	})
	require.True(t, ran)
	require.ErrorIs(t, err, ErrAdvisoryLockLost)
}

// pinnedLockKeyHeld reports whether some backend holds advisory lock key,
// seen from a session of its own.
func pinnedLockKeyHeld(t *testing.T, ctx context.Context, base string, key int64) bool {
	t.Helper()
	var n int
	require.NoError(t, pgOpen(t, base).WithContext(ctx).Raw(`SELECT count(*) FROM pg_locks
			WHERE locktype = 'advisory' AND granted AND objsubid = 1 AND classid = ? AND objid = ?`,
		int64(uint32(uint64(key)>>32)), int64(uint32(uint64(key)&0xFFFFFFFF))).Scan(&n).Error)
	return n > 0
}

// TestWithNamedLock_TransactionPooling_NestedWaitIsNotALoss (REVIEW-2 on
// #3299): a nested WithNamedLock under another key waits in Postgres on the
// outer call's pinned session while another replica holds the inner key. The
// liveness check must not share that connection with the waiting lock
// statement: a ping queued behind it ran with an expired timeout, pgx closed
// the connection, the pinning transaction ended and both locks were dropped,
// reported as ErrAdvisoryLockLost. The wait here is longer than one ping
// timeout; nothing may be reported, and the outer lock is still held after
// the inner one is granted.
func TestWithNamedLock_TransactionPooling_NestedWaitIsNotALoss(t *testing.T) {
	base := pgTestDSN(t)
	shortPinnedLockPing(t)
	dsn := pgIsolatedSchemaDSN(t, base)
	replicaA := NewLocalStorage(pgOpen(t, dsn))
	replicaA.SetTransactionPooling(true)
	replicaB := NewLocalStorage(pgOpen(t, dsn))
	replicaB.SetTransactionPooling(true)
	ctx := context.Background()
	const outerKey, innerKey = "liveness-nested-outer", "liveness-nested-inner"
	innerHold := config.PinnedLockPingTimeout + 2*time.Second

	innerHeld := make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		aDone <- replicaA.WithNamedLock(ctx, innerKey, func(context.Context) error {
			close(innerHeld)
			time.Sleep(innerHold)
			return nil
		})
	}()
	<-innerHeld

	var outerHeldAfterInner bool
	err := replicaB.WithNamedLock(ctx, outerKey, func(ctx context.Context) error {
		waitStart := time.Now()
		if err := replicaB.WithNamedLock(ctx, innerKey, func(ctx context.Context) error {
			// Several ping intervals while both keys are held.
			time.Sleep(500 * time.Millisecond)
			return ctx.Err()
		}); err != nil {
			return err
		}
		if waited := time.Since(waitStart); waited < config.PinnedLockPingTimeout {
			return errors.New("the nested call did not wait longer than one ping timeout: test proves nothing")
		}
		outerHeldAfterInner = pinnedLockKeyHeld(t, ctx, base, namedLockKey(outerKey))
		return context.Cause(ctx)
	})
	require.NoError(t, <-aDone)
	require.NoError(t, err)
	require.True(t, outerHeldAfterInner, "the outer advisory lock was dropped while its holder was still inside")
}
