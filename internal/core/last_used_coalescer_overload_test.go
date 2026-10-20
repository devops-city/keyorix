package core

// last_used_coalescer_overload_test.go — MERGE-FIX-3348C: the coalescer under a
// slow, blocked or failing database. The stamp is advisory, so under overload it
// must degrade (drop, back off, give up at the deadline) and never grow:
// no goroutine per request, no map beyond its cap, no retry storm, no shutdown
// stalled behind a stuck write.

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stopLastUsedTimer keeps a test's armed 30 s timer from firing after the test
// (and its database) is gone.
func stopLastUsedTimer(t *testing.T, a *lastUsedCoalescer) {
	t.Helper()
	t.Cleanup(func() { stopLastUsedTimerNow(a) })
}

func stopLastUsedTimerNow(a *lastUsedCoalescer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
}

func (a *lastUsedCoalescer) pendingLen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}

// blockedWrite is a write that blocks until released (or, if ctxAware, until
// its context ends) and counts its calls.
type blockedWrite struct {
	release  chan struct{}
	entered  chan struct{} // closed on the first call
	once     sync.Once
	relOnce  sync.Once
	calls    atomic.Int32
	ctxAware bool
}

func newBlockedWrite(t *testing.T, ctxAware bool) *blockedWrite {
	b := &blockedWrite{release: make(chan struct{}), entered: make(chan struct{}), ctxAware: ctxAware}
	t.Cleanup(b.unblock)
	return b
}

func (b *blockedWrite) unblock() { b.relOnce.Do(func() { close(b.release) }) }

func (b *blockedWrite) write(ctx context.Context, _ lastUsedKey, _ time.Time) error {
	b.calls.Add(1)
	b.once.Do(func() { close(b.entered) })
	if b.ctxAware {
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return errors.New("db unavailable")
	}
	<-b.release
	return errors.New("db unavailable")
}

// TestLastUsed_Overload_BlockedWriteKeepsGoroutinesAndMapBounded is the finding
// 1 + 2 proof. The database blocks every write; 5000 distinct credentials
// authenticate against a cap of 10. Before: every record() past the cap spawned
// a goroutine blocked on the flush lock (thousands here) and the map grew to
// 5000. Now: one flush goroutine, a map at most at its cap, and every stamp that
// did not fit is counted.
func TestLastUsed_Overload_BlockedWriteKeepsGoroutinesAndMapBounded(t *testing.T) {
	const maxKeys, total = 10, 5000
	a := newLastUsedCoalescer(time.Hour, maxKeys)
	stopLastUsedTimer(t, a)
	b := newBlockedWrite(t, false)
	a.write = b.write

	base := runtime.NumGoroutine()
	now := time.Now()
	for i := range total {
		a.record(lastUsedKey{lastUsedSession, uint(i + 1)}, now)
	}
	grown := runtime.NumGoroutine() - base

	assert.LessOrEqual(t, grown, 4, "goroutines started by %d record() calls past the cap", total)
	assert.LessOrEqual(t, a.pendingLen(), maxKeys, "the map must not grow past its cap")
	// The flush that started at the cap holds maxKeys in flight, the map holds at
	// most maxKeys more; everything else was dropped and counted.
	dropped := a.droppedCount()
	assert.GreaterOrEqual(t, dropped, uint64(total-2*maxKeys))
	assert.LessOrEqual(t, dropped, uint64(total-maxKeys))

	// A stamp for a credential already pending still advances.
	a.mu.Lock()
	var k lastUsedKey
	for pk := range a.pending {
		k = pk
		break
	}
	a.mu.Unlock()
	if k != (lastUsedKey{}) {
		later := now.Add(time.Minute)
		a.record(k, later)
		got, ok := a.pendingAt(k)
		require.True(t, ok)
		assert.True(t, got.Equal(later), "a pending key's stamp still advances at the cap")
	}
	b.unblock()
}

// TestLastUsed_Overload_FailedFlushMergeBackHonoursCap: keys that failed to
// write go back only while the cap has room; the rest are dropped and counted.
func TestLastUsed_Overload_FailedFlushMergeBackHonoursCap(t *testing.T) {
	const maxKeys = 4
	a := newLastUsedCoalescer(time.Hour, maxKeys)
	stopLastUsedTimer(t, a)
	now := time.Now()
	// Hold the early flush off (a backoff in force) so the flush below is the
	// explicit one.
	a.backoffUntil = now.Add(time.Hour)
	var once sync.Once
	a.write = func(context.Context, lastUsedKey, time.Time) error {
		once.Do(func() {
			for i := range maxKeys {
				a.record(lastUsedKey{lastUsedSession, uint(i + 1)}, now)
			}
		})
		return errors.New("db down")
	}
	for i := range maxKeys {
		a.record(lastUsedKey{lastUsedPAT, uint(i + 1)}, now)
	}
	a.flush(context.Background())

	assert.LessOrEqual(t, a.pendingLen(), maxKeys, "merge-back must respect the cap")
	assert.Equal(t, uint64(maxKeys), a.droppedCount(), "the failed keys that did not fit are counted")
}

// TestLastUsed_Overload_BackoffDelaysEarlyFlush is finding 3: after a failed
// flush the still-full map must not start another flush at once.
func TestLastUsed_Overload_BackoffDelaysEarlyFlush(t *testing.T) {
	const maxKeys = 3
	a := newLastUsedCoalescer(time.Hour, maxKeys)
	stopLastUsedTimer(t, a)
	var clockMu sync.Mutex
	fake := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a.clock = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return fake }
	a.backoffMin, a.backoffMax = 10*time.Second, 10*time.Second
	var calls atomic.Int32
	a.write = func(context.Context, lastUsedKey, time.Time) error { calls.Add(1); return errors.New("db down") }

	fill := func() {
		for i := range maxKeys {
			a.record(lastUsedKey{lastUsedSession, uint(i + 1)}, fake)
		}
	}
	fill() // reaches the cap: the first early flush runs and fails
	require.Eventually(t, func() bool { return calls.Load() >= 1 && !a.flushing.Load() }, 5*time.Second, 5*time.Millisecond)
	afterFirst := calls.Load()

	fill() // the failed keys are back, the map is full: no new flush inside the backoff
	require.Never(t, func() bool { return calls.Load() != afterFirst }, 300*time.Millisecond, 10*time.Millisecond,
		"an early flush ran inside the backoff window")

	clockMu.Lock()
	fake = fake.Add(11 * time.Second) // past the (jittered) backoff
	clockMu.Unlock()
	fill()
	require.Eventually(t, func() bool { return calls.Load() > afterFirst }, 5*time.Second, 5*time.Millisecond,
		"the early flush must resume once the backoff has passed")
}

func TestLastUsed_Overload_BackoffDelayDoublesWithJitterAndCeiling(t *testing.T) {
	a := newLastUsedCoalescer(time.Hour, 10)
	for _, tc := range []struct {
		n        int
		lo, hi   time.Duration
		describe string
	}{
		{1, 500 * time.Millisecond, 1 * time.Second, "starts at 1 s"},
		{2, 1 * time.Second, 2 * time.Second, "doubles"},
		{3, 2 * time.Second, 4 * time.Second, "doubles again"},
		{7, 30 * time.Second, 60 * time.Second, "capped at 60 s"},
		{40, 30 * time.Second, 60 * time.Second, "stays capped"},
	} {
		for range 50 {
			d := a.backoffDelay(tc.n)
			assert.GreaterOrEqual(t, d, tc.lo, "n=%d %s", tc.n, tc.describe)
			assert.LessOrEqual(t, d, tc.hi, "n=%d %s", tc.n, tc.describe)
		}
	}
}

// TestLastUsed_Overload_PeriodicFlushRespectsBackoffAndSuccessResetsIt: the
// timer flush waits out the backoff, and one successful flush clears it.
//
// It drives the timer callback (onTimer) by hand under a fake clock instead of
// waiting for real timers: the timer is armed for an hour and never fires, so
// every flush below runs synchronously on this goroutine. (An earlier version
// waited for the key to leave pending and then read failures/backoffUntil; flush
// empties pending BEFORE its writes, so that wait could end mid-flush, before
// finishFlush had reset the backoff.)
func TestLastUsed_Overload_PeriodicFlushRespectsBackoffAndSuccessResetsIt(t *testing.T) {
	a := newLastUsedCoalescer(time.Hour, 100)
	stopLastUsedTimer(t, a)
	var clockMu sync.Mutex
	fake := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a.clock = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return fake }
	// Jitter takes [d/2, d], so the backoff lasts at least 30 minutes.
	a.backoffMin, a.backoffMax = time.Hour, time.Hour
	var calls atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	a.write = func(context.Context, lastUsedKey, time.Time) error {
		calls.Add(1)
		if fail.Load() {
			return errors.New("db down")
		}
		return nil
	}
	k := lastUsedKey{lastUsedPAT, 1}
	a.record(k, fake)

	a.onTimer() // the periodic flush fails and starts the backoff
	require.Equal(t, int32(1), calls.Load())
	_, ok := a.pendingAt(k)
	require.True(t, ok, "the failed stamp goes back into pending")

	// The timer fires again with the clock still inside the backoff: no attempt.
	a.onTimer()
	assert.Equal(t, int32(1), calls.Load(), "the periodic flush must wait out the backoff")
	// Stop the timer that call re-armed (its delay is the remaining backoff), so
	// nothing fires on its own while the clock moves.
	stopLastUsedTimerNow(a)

	fail.Store(false)
	clockMu.Lock()
	fake = fake.Add(2 * time.Hour) // past the backoff
	clockMu.Unlock()
	a.onTimer() // after the backoff the periodic flush retries and succeeds
	assert.Equal(t, int32(2), calls.Load(), "after the backoff the periodic flush retries")
	_, ok = a.pendingAt(k)
	assert.False(t, ok, "the retried stamp was written")
	a.mu.Lock()
	defer a.mu.Unlock()
	assert.Zero(t, a.failures, "success resets the backoff")
	assert.True(t, a.backoffUntil.IsZero())
}

// TestLastUsed_Overload_ShutdownFlushReturnsWhenCtxExpiresBehindBlockedFlush is
// finding 4. A background flush is stuck in a write; the shutdown flush must
// give up when its own context ends instead of waiting for the stuck one.
func TestLastUsed_Overload_ShutdownFlushReturnsWhenCtxExpiresBehindBlockedFlush(t *testing.T) {
	a := newLastUsedCoalescer(time.Hour, 100)
	stopLastUsedTimer(t, a)
	b := newBlockedWrite(t, false)
	a.write = b.write
	a.record(lastUsedKey{lastUsedPAT, 1}, time.Now())
	go a.flush(context.Background()) // the stuck background flush
	select {
	case <-b.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the background flush never reached the write")
	}
	a.record(lastUsedKey{lastUsedPAT, 2}, time.Now())

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { a.flush(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the shutdown flush stalled behind a blocked flush instead of returning at its ctx deadline")
	}
	_, ok := a.pendingAt(lastUsedKey{lastUsedPAT, 2})
	assert.True(t, ok, "stamps the shutdown flush did not reach stay pending")
	b.unblock()
}

// TestLastUsed_Overload_ShutdownFlushIsBoundedWhileWriting: with the lock free
// but the database hanging, the flush stops at its ctx deadline.
func TestLastUsed_Overload_ShutdownFlushIsBoundedWhileWriting(t *testing.T) {
	a := newLastUsedCoalescer(time.Hour, 100)
	stopLastUsedTimer(t, a)
	b := newBlockedWrite(t, true)
	a.write = b.write
	a.record(lastUsedKey{lastUsedPAT, 1}, time.Now())

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	a.flush(ctx)
	assert.Less(t, time.Since(start), 3*time.Second)
	_, ok := a.pendingAt(lastUsedKey{lastUsedPAT, 1})
	assert.True(t, ok, "the unwritten stamp stays pending")
}

// TestLastUsed_Overload_BacklogDrainsInChunks is finding 5: a backlog goes out
// in transactions of lastUsedWriteChunk keys, in (kind, id) order, not one
// commit per key.
func TestLastUsed_Overload_BacklogDrainsInChunks(t *testing.T) {
	const n = 2*lastUsedWriteChunk + 34
	a := newLastUsedCoalescer(time.Hour, 10*n)
	stopLastUsedTimer(t, a)
	var perKey atomic.Int32
	a.write = func(context.Context, lastUsedKey, time.Time) error { perKey.Add(1); return nil }
	var sizes []int
	var prev lastUsedKey
	ordered := true
	a.writeBatch = func(_ context.Context, es []lastUsedEntry) error {
		sizes = append(sizes, len(es))
		for _, e := range es {
			if e.key.kind < prev.kind || (e.key.kind == prev.kind && e.key.id <= prev.id) {
				ordered = false
			}
			prev = e.key
		}
		return nil
	}
	now := time.Now()
	for i := range n {
		a.record(lastUsedKey{lastUsedSession, uint(n - i)}, now)
	}
	a.flush(context.Background())

	assert.Equal(t, []int{lastUsedWriteChunk, lastUsedWriteChunk, 34}, sizes)
	assert.True(t, ordered, "chunks are written in (kind, id) order")
	assert.Zero(t, perKey.Load(), "no per-key write when the transactions succeed")
	assert.Zero(t, a.pendingLen())
}

// TestLastUsed_Overload_FailedChunkFallsBackToPerKeySoOneBadRowDoesNotBlockTheRest.
func TestLastUsed_Overload_FailedChunkFallsBackToPerKeySoOneBadRowDoesNotBlockTheRest(t *testing.T) {
	a := newLastUsedCoalescer(time.Hour, 1000)
	stopLastUsedTimer(t, a)
	bad := lastUsedKey{lastUsedPAT, 7}
	var mu sync.Mutex
	written := map[lastUsedKey]bool{}
	a.writeBatch = func(context.Context, []lastUsedEntry) error { return errors.New("tx rolled back") }
	a.write = func(_ context.Context, k lastUsedKey, _ time.Time) error {
		if k == bad {
			return errors.New("bad row")
		}
		mu.Lock()
		written[k] = true
		mu.Unlock()
		return nil
	}
	now := time.Now()
	for i := range 20 {
		a.record(lastUsedKey{lastUsedPAT, uint(i + 1)}, now)
	}
	a.flush(context.Background())

	mu.Lock()
	assert.Len(t, written, 19, "every key but the bad row is written")
	mu.Unlock()
	_, stillPending := a.pendingAt(bad)
	assert.True(t, stillPending, "the bad row stays pending for the next attempt")
}

// TestLastUsed_Overload_DownDatabaseStopsAfterOneChunk: when nothing in a chunk
// lands the rest of the backlog is not tried one by one.
func TestLastUsed_Overload_DownDatabaseStopsAfterOneChunk(t *testing.T) {
	const n = 3 * lastUsedWriteChunk
	a := newLastUsedCoalescer(time.Hour, 10*n)
	stopLastUsedTimer(t, a)
	var calls atomic.Int32
	a.write = func(context.Context, lastUsedKey, time.Time) error { calls.Add(1); return errors.New("db down") }
	now := time.Now()
	for i := range n {
		a.record(lastUsedKey{lastUsedSession, uint(i + 1)}, now)
	}
	a.flush(context.Background())
	assert.Equal(t, int32(lastUsedWriteChunk), calls.Load(), "one chunk is attempted, then the flush stops")
	assert.Equal(t, n, a.pendingLen(), "nothing is lost: the whole backlog is pending again")
}
