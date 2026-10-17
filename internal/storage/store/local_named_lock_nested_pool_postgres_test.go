// local_named_lock_nested_pool_postgres_test.go — #3358: a nested
// WithNamedLock call must never wait in the in-process queue while it holds a
// named-lock-pool session.
//
// The defect (REVIEW-1, introduced by #3235): a nested call (outer key held,
// so it already holds one lock session) queued in-process for its inner key
// while keeping that session. A top-level caller that owned the inner key
// in-process waited for a lock session. With every session of the named-lock
// pool held by such nested callers, neither side could move until the
// contexts ended, and every other WithNamedLock caller in the process, on any
// key (CreateSecret's environment-secret-guard included), waited for a
// session as well.
//
// The fix: a nested call on Postgres skips the in-process queue and blocks in
// Postgres on the session it already holds. It takes no new connection, and
// pg_advisory_lock still excludes every other holder of the key.
//
// Every test is bounded by a context deadline, so an unfixed build fails with
// a diagnosis instead of hanging the package.
package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// namedLockPoolSize mirrors storage.NamedLockPoolSize (the factory's cap on
// the named-lock pool); this package cannot import internal/storage.
const namedLockPoolSize = 8

// waitInProcessOwner blocks until some caller owns key in ls's in-process
// queue, so a test can order "Y owns the key" before "X asks for it".
func waitInProcessOwner(t *testing.T, ls *LocalStorage, key string) {
	t.Helper()
	require.Eventually(t, func() bool {
		ls.namedLockMu.mu.Lock()
		e := ls.namedLockMu.locks[key]
		ls.namedLockMu.mu.Unlock()
		if e == nil {
			return false
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.held
	}, 5*time.Second, 5*time.Millisecond, "the top-level caller never took %q in-process", key)
}

// TestWithNamedLock_NestedCallerHoldingEveryLockSession_DoesNotDeadlock is
// the production shape of #3358: namedLockPoolSize concurrent role changes
// for one user in different projects (project-admin-guard:<P> ->
// sod-grant:user:<U>) hold every lock session, and a direct AssignUserRole
// for that user (top-level sod-grant:user:<U>) owns the inner key in-process
// before they ask for it. A bystander on an unrelated key
// (environment-secret-guard, CreateSecret's lock) must also complete.
//
// On the unfixed build every caller ends with "context deadline exceeded".
func TestWithNamedLock_NestedCallerHoldingEveryLockSession_DoesNotDeadlock(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	ls := NewLocalStorage(pgOpen(t, dsn))
	lockPool := pgLockPool(t, dsn)
	lockPool.SetMaxOpenConns(namedLockPoolSize)
	ls.SetNamedLockDB(lockPool)

	const inner = "sod-grant:user:7"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var inside, maxInside atomic.Int32
	exclusive := func(context.Context) error {
		n := inside.Add(1)
		for {
			m := maxInside.Load()
			if n <= m || maxInside.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inside.Add(-1)
		return nil
	}

	// X_1..X_n: each takes its own outer key (one lock session each, the
	// whole pool) and then waits until Y owns the inner key in-process.
	var xHaveSessions sync.WaitGroup
	xHaveSessions.Add(namedLockPoolSize)
	yOwnsInner := make(chan struct{})
	xErrs := make([]error, namedLockPoolSize)
	var wg sync.WaitGroup
	for i := range namedLockPoolSize {
		wg.Go(func() {
			outer := fmt.Sprintf("project-admin-guard:%d", i+1)
			xErrs[i] = ls.WithNamedLock(ctx, outer, func(ctx context.Context) error {
				xHaveSessions.Done()
				<-yOwnsInner
				return ls.WithNamedLock(ctx, inner, exclusive)
			})
		})
	}
	xHaveSessions.Wait()

	// Y: top-level on the inner key. It owns the key in-process at once and
	// then waits for a lock session, all of which the X callers hold.
	var yErr error
	wg.Go(func() { yErr = ls.WithNamedLock(ctx, inner, exclusive) })
	waitInProcessOwner(t, ls, inner)

	// Bystander: unrelated key, also needs a lock session.
	var bystanderErr error
	wg.Go(func() {
		bystanderErr = ls.WithNamedLock(ctx, "environment-secret-guard:1", func(context.Context) error { return nil })
	})

	close(yOwnsInner)
	wg.Wait()

	for i, err := range xErrs {
		require.NoError(t, err, "nested caller X_%d (project-admin-guard -> %s) did not complete: it waited in-process while holding a lock session (#3358)", i+1, inner)
	}
	require.NoError(t, yErr, "top-level caller on %s did not complete: every lock session was held by nested callers waiting for it in-process (#3358)", inner)
	require.NoError(t, bystanderErr, "an unrelated named lock (environment-secret-guard) stalled behind the nested callers (#3358)")
	require.Equal(t, int32(1), maxInside.Load(), "%s must still be held by one caller at a time", inner)
}

// TestWithNamedLock_NestedCallerSkipsQueue_StillSerializesWithTopLevelHolder
// pins the other half of the fix: a nested call that bypasses the in-process
// queue must still wait for a top-level holder of the same key that already
// holds it in Postgres, and must not enter its critical section early.
func TestWithNamedLock_NestedCallerSkipsQueue_StillSerializesWithTopLevelHolder(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	ls := NewLocalStorage(pgOpen(t, dsn))
	ls.SetNamedLockDB(pgLockPool(t, dsn))

	const inner = "sod-grant:user:9"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	yInside := make(chan struct{})
	releaseY := make(chan struct{})
	var yReleased atomic.Bool
	var wg sync.WaitGroup
	var yErr, xErr error
	wg.Go(func() {
		yErr = ls.WithNamedLock(ctx, inner, func(context.Context) error {
			close(yInside)
			<-releaseY
			yReleased.Store(true)
			return nil
		})
	})
	<-yInside

	xEntered := make(chan struct{})
	wg.Go(func() {
		xErr = ls.WithNamedLock(ctx, "project-admin-guard:1", func(ctx context.Context) error {
			return ls.WithNamedLock(ctx, inner, func(context.Context) error {
				if !yReleased.Load() {
					t.Error("the nested caller entered its critical section while the top-level holder still held the key")
				}
				close(xEntered)
				return nil
			})
		})
	})

	select {
	case <-xEntered:
		t.Fatal("the nested caller took the key while the top-level holder held it")
	case <-time.After(300 * time.Millisecond):
	}
	close(releaseY)
	wg.Wait()
	require.NoError(t, yErr)
	require.NoError(t, xErr)
	select {
	case <-xEntered:
	default:
		t.Fatal("the nested caller never acquired the key after the holder released it")
	}
}
