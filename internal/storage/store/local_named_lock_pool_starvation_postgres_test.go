// local_named_lock_pool_starvation_postgres_test.go — #2853: WithNamedLock
// must not let contention on one key exhaust the connection pool.
//
// The defect: the Postgres path checked a connection out of the pool and then
// blocked on pg_advisory_lock STILL HOLDING IT, while the lock holder needed a
// further connection to do its work inside fn. With max_open_conns = M, M
// concurrent callers on one key occupied the pool and the holder could never
// finish — a permanent deadlock, and the pool is shared by every request in the
// process, so it took down unrelated traffic too.
//
// The fix: a per-key in-process FIFO queue, entered BEFORE any connection is
// taken, so at most one goroutine per key per process ever reaches
// pg_advisory_lock. Waiters hold no connection; a cancelled waiter leaves the
// queue having taken none at all.
//
// Every test here is bounded by a context deadline rather than left to hang, so
// on an unfixed build it FAILS with a diagnosis instead of wedging CI for the
// package timeout. Each one wedges without the queue and passes with it.
package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// namedLockPoolDB opens a Postgres pool capped at maxConns, which is the whole
// point of these tests: the deadlock is a function of pool size versus the
// number of concurrent callers on one key.
func namedLockPoolDB(t *testing.T, maxConns int) *gorm.DB {
	t.Helper()
	db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(maxConns)
	sqlDB.SetMaxIdleConns(maxConns)
	require.Equal(t, maxConns, sqlDB.Stats().MaxOpenConnections)
	return db
}

// probeQuery is the "ordinary work" every real WithNamedLock caller does inside
// fn, and the thing the holder was starved of: a query that needs a connection
// from the same pool.
func probeQuery(ctx context.Context, db *gorm.DB) error {
	var n int64
	return db.WithContext(ctx).Raw("SELECT 1").Scan(&n).Error
}

// TestWithNamedLock_HolderCompletesUnderPoolSmallerThanWaiters is the minimal
// reproduction: pool of 2, two callers on one key, holder does a query inside
// its critical section.
//
// Without the in-process queue: caller 2 takes a connection and parks it on
// pg_advisory_lock; caller 1 holds the lock on the other connection and blocks
// forever waiting for a third. Observed on the unfixed build — the HOLDER, which
// owns the lock, failed inside its own critical section with "context deadline
// exceeded".
func TestWithNamedLock_HolderCompletesUnderPoolSmallerThanWaiters(t *testing.T) {
	db := namedLockPoolDB(t, 2)
	ls := NewLocalStorage(db)
	const key = "named-lock-pool-starvation-minimal"

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	inside := make(chan struct{})
	var holderErr, waiterErr error
	var wg sync.WaitGroup

	wg.Go(func() {
		holderErr = ls.WithNamedLock(ctx, key, func(ctx context.Context) error {
			close(inside)
			// Give the waiter time to arrive and (on an unfixed build) park a
			// connection before we ask the pool for one.
			time.Sleep(500 * time.Millisecond)
			return probeQuery(ctx, db)
		})
	})

	<-inside
	wg.Go(func() {
		waiterErr = ls.WithNamedLock(ctx, key, func(ctx context.Context) error { return nil })
	})

	wg.Wait()
	require.NoError(t, holderErr,
		"the lock HOLDER could not complete its own critical section — the waiter's parked connection exhausted the pool (#2853)")
	require.NoError(t, waiterErr, "the waiter never acquired the lock")
}

// TestWithNamedLock_ManyWaitersOnOneKey_DoNotExhaustPool is the shape an HA
// deployment actually sees: many concurrent requests on one hot key, a pool far
// smaller than the waiter count. All of them must complete, and each must have
// run with genuine exclusivity.
//
// 10 waiters on a pool of 3 wedges solidly without the queue (3 connections
// parked on pg_advisory_lock, nothing left for the holder's work).
func TestWithNamedLock_ManyWaitersOnOneKey_DoNotExhaustPool(t *testing.T) {
	const waiters = 10
	const poolSize = 3 // deliberately < waiters
	db := namedLockPoolDB(t, poolSize)
	ls := NewLocalStorage(db)
	const key = "named-lock-pool-starvation-many"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var mu sync.Mutex
	concurrent, maxConcurrent := 0, 0

	errs := make([]error, waiters)
	var wg sync.WaitGroup
	for i := range waiters {
		wg.Go(func() {
			errs[i] = ls.WithNamedLock(ctx, key, func(ctx context.Context) error {
				mu.Lock()
				concurrent++
				if concurrent > maxConcurrent {
					maxConcurrent = concurrent
				}
				mu.Unlock()
				// Real work: needs a pooled connection, which is what starved.
				err := probeQuery(ctx, db)
				mu.Lock()
				concurrent--
				mu.Unlock()
				return err
			})
		})
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "caller %d did not complete: %d callers on a pool of %d starved each other (#2853)", i, waiters, poolSize)
	}
	assert.Equal(t, 1, maxConcurrent, "WithNamedLock must still give exclusive access under one key")
}

// TestWithNamedLock_CancelledWhileQueued_ReleasesAndTakesNoConnection: a waiter
// abandoned by its request context must leave the queue, return that context's
// error, and — critically — must not have taken a pooled connection while
// queued, nor leave the key wedged for the callers behind it.
//
// The pool is 2 — the documented minimum for the Postgres path, one connection
// for the advisory-lock session and one for the work inside fn. That makes it
// exactly the right discriminator here: the holder needs both, so if EITHER of
// the two queued waiters below held a connection the holder could not run its
// own query. (A pool of 1 cannot work on Postgres at all, with or without this
// fix, for the same reason — see WithNamedLock's connection budget note.)
// Separately, if a cancelled waiter failed to hand ownership on, the surviving
// waiter would never acquire the key.
func TestWithNamedLock_CancelledWhileQueued_ReleasesAndTakesNoConnection(t *testing.T) {
	db := namedLockPoolDB(t, 2)
	ls := NewLocalStorage(db)
	const key = "named-lock-cancelled-while-queued"

	outer, cancelOuter := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelOuter()

	holderInside := make(chan struct{})
	holderMayFinish := make(chan struct{})
	var holderErr error
	var wg sync.WaitGroup

	wg.Go(func() {
		holderErr = ls.WithNamedLock(outer, key, func(ctx context.Context) error {
			close(holderInside)
			<-holderMayFinish
			// The holder already owns one of the two connections (its advisory
			// session), so this second one only succeeds if neither queued
			// waiter is holding the other.
			return probeQuery(ctx, db)
		})
	})
	<-holderInside

	// A waiter that will be cancelled while queued.
	cancelledCtx, cancelWaiter := context.WithCancel(outer)
	var cancelledErr error
	wg.Go(func() {
		cancelledErr = ls.WithNamedLock(cancelledCtx, key, func(ctx context.Context) error {
			t.Error("the cancelled waiter must never enter its critical section")
			return nil
		})
	})

	// A second waiter that must still get the lock after the first is cancelled.
	survivorRan := make(chan struct{})
	var survivorErr error
	wg.Go(func() {
		survivorErr = ls.WithNamedLock(outer, key, func(ctx context.Context) error {
			close(survivorRan)
			return probeQuery(ctx, db)
		})
	})

	// Let both waiters reach the queue, then cancel the first.
	time.Sleep(300 * time.Millisecond)
	cancelWaiter()
	time.Sleep(200 * time.Millisecond)
	close(holderMayFinish)

	wg.Wait()

	require.NoError(t, holderErr, "the holder could not complete — a queued waiter was holding a connection (#2853)")
	require.Error(t, cancelledErr, "a waiter cancelled while queued must return an error, not acquire the lock")
	assert.True(t, errors.Is(cancelledErr, context.Canceled),
		"the cancelled waiter's error must carry context.Canceled, got %v", cancelledErr)
	require.NoError(t, survivorErr, "the key stayed wedged after a queued waiter was cancelled")
	select {
	case <-survivorRan:
	default:
		t.Fatal("the surviving waiter never entered its critical section — a cancelled waiter failed to hand ownership on")
	}
}
