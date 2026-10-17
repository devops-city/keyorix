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
	"gorm.io/gorm"
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
	filled := g.Tracker().BeginFill() // an entry filled before the lapse ended
	require.True(t, filled.Store())
	g.pollOnce(context.Background())
	require.True(t, g.Authoritative())
	require.Equal(t, int64(1), reentries.Load(), "a good poll after the lease ran out must call OnReenter")
	require.False(t, g.Valid(filled.Gen()), "nothing filled before a lapse may be served after it")

	g.pollOnce(context.Background())
	require.Equal(t, int64(1), reentries.Load(), "only the first poll after a lapse is a re-entry")
}

// TestLease_AnchoredAtPollSend: the lease counts from when the poll was sent,
// so a poll that waits on a lock does not push trust past LeaseDuration after
// what it actually saw.
//
// No wall-clock window: the guard reads an injected clock, and the test moves
// it an hour ahead while the poll is held at the server (its backend seen in
// a lock wait, so it was sent and not yet answered). A lease anchored at the
// answer, or anywhere after the send, reads the moved clock. The lock is held
// until the test releases it, not for a fixed sleep: a loaded runner that is
// slow to see the wait only makes the wait longer (the earlier version slept
// 150 ms in the locking transaction and failed in CI when the poll was sent
// late in that sleep, FLAKE-SOLEWRITER-1).
func TestLease_AnchoredAtPollSend(t *testing.T) {
	w := newSWWorld(t)
	var ahead atomic.Int64 // added to the real clock, both readings
	clock := func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) }
	g := w.start(Options{Now: clock, Wall: clock})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	stopPoller(g)

	// A poll that hits its statement_timeout (pollStatementTimeout) before
	// the release proves nothing either way; try again (a loaded runner).
	for attempt := 1; ; attempt++ {
		jump, ok := heldPoll(t, w, g, func() time.Time {
			at := clock()
			ahead.Add(int64(time.Hour))
			return at
		})
		if !ok {
			require.Less(t, attempt, 3, "the poll timed out before the release on every attempt: %s", g.Status().LastPollError)
			t.Logf("attempt %d: the poll timed out before the release (%s); again", attempt, g.Status().LastPollError)
			continue
		}
		g.mu.Lock()
		mono, wall := g.lastGoodMono, g.lastGoodWall
		g.mu.Unlock()
		require.False(t, mono.After(jump), "the lease is anchored after the poll was sent (monotonic %s past the moment the poll was seen waiting)", mono.Sub(jump))
		require.False(t, wall.After(jump.Round(0)), "the lease is anchored after the poll was sent (wall %s past the moment the poll was seen waiting)", wall.Sub(jump.Round(0)))
		return
	}
}

// heldPoll runs one pollOnce while a foreign transaction holds the epoch
// table's ACCESS EXCLUSIVE lock. Once the holder backend is seen waiting on
// that lock it calls during (which returns the instant it marks) and only then
// releases the lock. ok is false when the poll failed instead (its
// statement_timeout ran out before the release).
func heldPoll(t *testing.T, w *swWorld, g *Guard, during func() time.Time) (marked time.Time, ok bool) {
	t.Helper()
	locked, release := make(chan struct{}), make(chan struct{})
	txDone := make(chan error, 1)
	go func() {
		txDone <- w.foreign.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("LOCK TABLE " + EpochTable + " IN ACCESS EXCLUSIVE MODE").Error; err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-txDone:
		t.Fatalf("lock the epoch table: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the epoch table lock was never granted")
	}
	released := false
	defer func() {
		if !released {
			close(release)
		}
		require.NoError(t, <-txDone)
	}()

	polled := make(chan struct{})
	go func() { defer close(polled); g.pollOnce(context.Background()) }()
	waiting := func() bool {
		var n int64
		if err := w.foreign.Raw("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE pid = ? AND wait_event_type = 'Lock'", g.pid).Scan(&n).Error; err != nil {
			t.Logf("pg_stat_activity: %v", err)
			return false
		}
		return n > 0
	}
	for !waiting() {
		select {
		case <-polled:
			require.NotEmpty(t, g.Status().LastPollError, "the poll was answered while the epoch table was locked: it did not wait, the test proves nothing")
			return time.Time{}, false
		case <-time.After(2 * time.Millisecond):
		}
	}
	marked = during()
	released = true
	close(release)
	select {
	case <-polled:
	case <-time.After(5 * time.Second):
		t.Fatal("the poll did not return after the lock was released")
	}
	return marked, g.Status().LastPollError == ""
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
