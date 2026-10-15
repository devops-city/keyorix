package solewriter

// Lease and callback tests for the poller (REVIEW-SINGLE-WRITER coordinator
// review at 286c9f28, findings 1, 2, 4 and 6). Same harness as
// solewriter_postgres_test.go.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stopPoller stops Run's poller so a test can drive pollOnce itself.
func stopPoller(g *Guard) {
	g.stopOnce.Do(func() { close(g.stop) })
	<-g.done
}

// TestPoll_ReentryAfterALapseCallsOnReenter: a good poll after the lease ran
// out calls OnReenter once; a good poll inside the lease does not.
func TestPoll_ReentryAfterALapseCallsOnReenter(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	var reentries atomic.Int64
	g.OnReenter(func() { reentries.Add(1) })
	stopPoller(g)

	g.pollOnce(context.Background())
	require.Zero(t, reentries.Load(), "a poll inside the lease is not a re-entry")

	require.Eventually(t, func() bool { return !g.Authoritative() }, LeaseDuration+500*time.Millisecond, 20*time.Millisecond)
	g.pollOnce(context.Background())
	require.True(t, g.Authoritative())
	require.Equal(t, int64(1), reentries.Load(), "a good poll after the lease ran out must call OnReenter")

	g.pollOnce(context.Background())
	require.Equal(t, int64(1), reentries.Load(), "only the first poll after a lapse is a re-entry")
}

// TestLease_AnchoredAtPollSend: the lease counts from when the poll was sent,
// so a poll that waits on a lock does not push trust past LeaseDuration after
// what it actually saw.
func TestLease_AnchoredAtPollSend(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	stopPoller(g)

	const hold = 150 * time.Millisecond // well below pollStatementTimeout (300 ms): the poll waits, then succeeds
	locked := make(chan error, 1)
	go func() {
		locked <- w.foreignTx("LOCK TABLE "+EpochTable+" IN ACCESS EXCLUSIVE MODE", "SELECT pg_sleep(0.15)")
	}()
	require.Eventually(t, func() bool {
		var n int64
		require.NoError(t, w.foreign.Raw("SELECT count(*) FROM pg_locks WHERE relation = ?::regclass AND mode = 'AccessExclusiveLock' AND granted",
			w.schema+"."+EpochTable).Scan(&n).Error)
		return n > 0
	}, 2*time.Second, 5*time.Millisecond)

	sent := time.Now()
	g.pollOnce(context.Background())
	took := time.Since(sent)
	require.NoError(t, <-locked)
	require.Empty(t, g.Status().LastPollError, "the poll must succeed after waiting")
	require.Greater(t, took, hold/2, "the poll did not wait on the lock; the test proves nothing")

	g.mu.Lock()
	anchor := g.lastGoodMono
	g.mu.Unlock()
	require.Less(t, anchor.Sub(sent), hold/4, "the lease is anchored %s after the poll was sent (poll took %s)", anchor.Sub(sent), took)
}

// TestPoll_CallbacksRunOutsideTheGuardLock: a callback may call back into the
// guard (a cache flush reads Epoch or Authoritative) without deadlocking the
// poller.
func TestPoll_CallbacksRunOutsideTheGuardLock(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	seen := make(chan int64, 16)
	g.OnEpochChange(func(int64) { seen <- g.Epoch() })
	require.NoError(t, w.own().Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error)
	select {
	case <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("OnEpochChange calling g.Epoch() never returned: the callback runs under g.mu")
	}
}

// TestClose_WaitsForThePoller: Close returns only after the poller has
// returned, so a poll in flight never runs on the closed connection (which
// reads as a lost lock and logs a false "holder lock lost").
func TestClose_WaitsForThePoller(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	inCallback, release := make(chan struct{}), make(chan struct{})
	var once atomic.Bool
	g.OnEpochChange(func(int64) {
		if once.CompareAndSwap(false, true) {
			close(inCallback)
			<-release
		}
	})
	require.NoError(t, w.own().Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error)
	select {
	case <-inCallback:
	case <-time.After(2 * time.Second):
		t.Fatal("no epoch change seen")
	}
	closed := make(chan struct{})
	go func() { g.Close(); close(closed) }()
	select {
	case <-closed:
		close(release)
		t.Fatal("Close returned while the poller was still running")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after the poller finished")
	}
	select {
	case <-g.done:
	default:
		t.Fatal("Close returned before the poller")
	}
}
