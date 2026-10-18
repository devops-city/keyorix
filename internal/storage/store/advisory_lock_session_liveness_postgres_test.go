package store

// advisory_lock_session_liveness_postgres_test.go — a SESSION advisory lock
// (the default shape: a direct connection or pgbouncer-session) whose backend
// is killed is reported as lost, and the critical section stops, instead of
// running on beside the replica that takes the lock next
// (INV-STORAGE-session-advisory-lock-loss, LOCKLOSS-SESSION-1). The
// transaction shape has its own tests in advisory_lock_liveness_postgres_test.go.
// pg-gated (KEYORIX_TEST_PG_DSN).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// sessionLockHolders runs one lock holder's critical section (body) under its
// lock on ls, in the session shape. key is the advisory key it takes.
var sessionLockHolders = []struct {
	name string
	key  int64
	run  func(ls *LocalStorage, body func(context.Context) error) error
}{
	{"WithNamedLock", namedLockKey("session-liveness"), func(ls *LocalStorage, body func(context.Context) error) error {
		return ls.WithNamedLock(context.Background(), "session-liveness", body)
	}},
	{"WithSchedulerLock", 0x4B455953_534C4956, func(ls *LocalStorage, body func(context.Context) error) error { // "KEYSSLIV"
		ran, err := ls.WithSchedulerLock(context.Background(), 0x4B455953_534C4956, body)
		if !ran && err == nil {
			return errors.New("the scheduler lock was not taken")
		}
		return err
	}},
	{"WithBootstrapLock", int64(bootstrapAdvisoryLockKey), func(ls *LocalStorage, body func(context.Context) error) error {
		return ls.WithBootstrapLock(context.Background(), body)
	}},
	{"WithAuditCheckpointLock", int64(auditCheckpointAdvisoryLockKey), func(ls *LocalStorage, body func(context.Context) error) error {
		return ls.WithAuditCheckpointLock(context.Background(), body)
	}},
}

// TestSessionAdvisoryLock_KilledLockBackend_StopsTheHolder: for every
// session-shape lock holder, a pg_terminate_backend on the lock's backend (a
// failover, a network partition or a PostgreSQL restart look the same to the
// holder) releases the lock, and a second replica can take it at once. The
// first holder's context must then be cancelled with cause
// ErrAdvisoryLockLost, so its work stops, and the call must return that
// error. A healthy hold of several ping intervals is not reported.
func TestSessionAdvisoryLock_KilledLockBackend_StopsTheHolder(t *testing.T) {
	base := pgTestDSN(t)
	shortPinnedLockPing(t)
	dsn := pgIsolatedSchemaDSN(t, base)
	replicaA := NewLocalStorage(pgOpen(t, dsn))
	replicaB := NewLocalStorage(pgOpen(t, dsn))
	require.False(t, replicaA.TransactionPooling(), "this test is about the session shape")

	for _, h := range sessionLockHolders {
		t.Run(h.name, func(t *testing.T) {
			// Healthy: several ping intervals pass, nothing is reported.
			require.NoError(t, h.run(replicaA, func(ctx context.Context) error {
				time.Sleep(450 * time.Millisecond)
				return context.Cause(ctx)
			}))

			var cause error
			bTookIt := false
			start := time.Now()
			err := h.run(replicaA, func(ctx context.Context) error {
				if n := terminateLockBackend(t, context.Background(), base, h.key); n != 1 {
					return errors.New("no lock backend to terminate")
				}
				// The lock is gone: the other replica gets it while A is still
				// inside. Exactly the overlap A must be told about.
				bTookIt = h.run(replicaB, func(context.Context) error { return nil }) == nil
				select {
				case <-ctx.Done():
					cause = context.Cause(ctx)
					return nil
				case <-time.After(5 * time.Second):
					return errors.New("the holder's context was never cancelled after its lock backend was terminated: the work runs on unguarded")
				}
			})
			require.True(t, bTookIt, "the second replica could not take the released lock: the test proves nothing")
			require.ErrorIs(t, cause, ErrAdvisoryLockLost)
			require.ErrorIs(t, err, ErrAdvisoryLockLost)
			require.Less(t, time.Since(start), 3*time.Second)

			// The lost session did not wedge the key.
			require.NoError(t, h.run(replicaA, func(context.Context) error { return nil }))
		})
	}
}

// TestWithNamedLock_SessionLock_NestedWaitIsNotALoss: the session-shape twin
// of TestWithNamedLock_TransactionPooling_NestedWaitIsNotALoss. A nested
// WithNamedLock under another key waits in PostgreSQL (pg_advisory_lock) on
// the outer call's session while another replica holds the inner key, longer
// than one ping timeout. The watch must not ping behind that wait (pgx would
// close the healthy connection and drop both locks), and the nested unlock
// must not race a ping either: nothing is reported, and the outer lock is
// still held after the inner one is granted and released.
func TestWithNamedLock_SessionLock_NestedWaitIsNotALoss(t *testing.T) {
	base := pgTestDSN(t)
	shortPinnedLockPing(t)
	dsn := pgIsolatedSchemaDSN(t, base)
	replicaA := NewLocalStorage(pgOpen(t, dsn))
	replicaB := NewLocalStorage(pgOpen(t, dsn))
	ctx := context.Background()
	const outerKey, innerKey = "session-liveness-nested-outer", "session-liveness-nested-inner"
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
			time.Sleep(500 * time.Millisecond) // several ping intervals while both keys are held
			return context.Cause(ctx)
		}); err != nil {
			return err
		}
		if waited := time.Since(waitStart); waited < config.PinnedLockPingTimeout {
			return errors.New("the nested call did not wait longer than one ping timeout: test proves nothing")
		}
		time.Sleep(300 * time.Millisecond) // pings after the nested unlock
		outerHeldAfterInner = pinnedLockKeyHeld(t, ctx, base, namedLockKey(outerKey))
		return context.Cause(ctx)
	})
	require.NoError(t, <-aDone)
	require.NoError(t, err)
	require.True(t, outerHeldAfterInner, "the outer advisory lock was dropped while its holder was still inside")
}
