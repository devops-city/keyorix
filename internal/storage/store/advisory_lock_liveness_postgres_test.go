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
	old := config.PinnedLockPingInterval
	config.PinnedLockPingInterval = 100 * time.Millisecond
	t.Cleanup(func() { config.PinnedLockPingInterval = old })
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
