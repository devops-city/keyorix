package core

// last_used_coalescer.go — keeps the "last used" bookkeeping stamps
// (personal_access_tokens.last_used_at, machine_identity_credentials.last_used_at,
// sessions.last_seen_at) off the request path.
//
// Before OPT-LASTUSED-1 every authenticated request ran a conditional
// UPDATE ... WHERE id = ? AND (last_used_at IS NULL OR last_used_at < now-30s)
// inline. Even when it matched no row it was one statement per request, and
// when the 30 s window rolled over, every concurrent request of the same
// credential queued on that row's lock behind the one that won (and behind its
// commit fsync under strict durability).
//
// Now the request only records the use in memory (one map write under a
// mutex). A timer armed by the first pending use flushes everything recorded
// since, once per lastUsedFlushInterval: at most one UPDATE per credential per
// interval, never on a request goroutine and never in a request's transaction.
//
// Monotonic across replicas: the flush reuses the store's conditional
// UPDATE with staleness 0, i.e. SET col = t WHERE id = ? AND (col IS NULL OR
// col < t). That is GREATEST(existing, t) in a form both SQLite and Postgres
// run, so a replica that flushes an older observation after another replica
// flushed a newer one leaves the column where it is. It is also the exact
// statement shape the single_writer tracker already classifies as a
// bookkeeping-only update (internal/solewriter FencedTables.UpdateIgnores).
//
// Staleness bound: a use at time t is in the database by t +
// lastUsedFlushInterval + one flush's duration. A crash (no graceful
// shutdown) loses at most the uses recorded since the last flush, i.e. at
// most one interval. FlushLastUsed runs on graceful shutdown.
//
// Overload behaviour (the stamp is advisory, so it yields to the database):
//   - At most one background flush runs at a time (the flushing flag); record()
//     never starts a goroutine while one is in flight.
//   - pending never holds more than maxKeys entries. A use of a credential that
//     is not already pending is dropped (and counted, with a rate-limited log
//     line) once the map is full; a credential already pending still advances.
//   - A flush that leaves any key unwritten (error or timeout) starts an
//     exponential backoff (1 s doubling to 60 s, jittered); no early or timer
//     flush runs before it has passed. Success resets it. A single permanently
//     failing row therefore holds the flush cadence at the backoff ceiling.
//   - Writes go out in chunks of lastUsedWriteChunk keys, one transaction per
//     chunk, so a backlog drains at one commit per chunk instead of one per key.
//   - The flush lock is a channel semaphore taken with the caller's ctx, so the
//     shutdown flush is bounded by its own deadline even if a background flush
//     is stuck in a write.
//
// No security decision reads these columns (inventory in the OPT-LASTUSED-1
// PR): inactivity suspension uses users.last_login_at (written at login, not
// here), and revocation/expiry never consult last use. The stale-credential
// and hygiene reports work in days. If a future feature ever bases an
// access decision on these columns, it must also consult the pending
// in-memory value (pendingAt), not the column alone.

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// lastUsedFlushInterval bounds how long a recorded use may wait in memory.
// It equals the 30 s throttle the inline stamps used before, so the column's
// staleness bound for readers is unchanged.
const lastUsedFlushInterval = 30 * time.Second

// lastUsedMaxPending caps the in-memory map. Reaching it starts a flush
// immediately instead of waiting for the timer, and a use of a credential not
// already pending is dropped (counted) while the map is full.
const lastUsedMaxPending = 50_000

// lastUsedFlushTimeout bounds one background flush.
const lastUsedFlushTimeout = 20 * time.Second

// lastUsedWriteChunk is how many keys one transaction writes.
const lastUsedWriteChunk = 500

// Backoff after a failed flush: start, double, ceiling. The delay actually
// used is jittered into [d/2, d].
const (
	lastUsedBackoffMin = 1 * time.Second
	lastUsedBackoffMax = 60 * time.Second
)

// lastUsedLogEvery is the minimum gap between two log lines of one kind
// (drops, failed flushes): an outage must not turn into a log flood.
const lastUsedLogEvery = time.Minute

type lastUsedKind uint8

const (
	lastUsedPAT lastUsedKind = iota + 1
	lastUsedMachineCredential
	lastUsedSession
)

type lastUsedKey struct {
	kind lastUsedKind
	id   uint
}

// lastUsedCoalescer holds the newest observed use per credential until the
// next flush.
type lastUsedCoalescer struct {
	interval time.Duration
	maxKeys  int
	// write persists one observation with GREATEST semantics. Set by
	// lastUsed(); a test may replace it.
	write func(ctx context.Context, k lastUsedKey, at time.Time) error
	// writeBatch persists many observations in one transaction (all or
	// nothing). Optional: when nil, or when it fails, the chunk is written key
	// by key through write.
	writeBatch func(ctx context.Context, entries []lastUsedEntry) error

	// Backoff bounds and clock; tests shorten them.
	backoffMin, backoffMax time.Duration
	clock                  func() time.Time

	// flushing is the single-flight flag for background flushes (the timer's
	// and the cap-triggered one).
	flushing atomic.Bool
	// flushSem (capacity 1) serializes every flush, background or shutdown, so
	// two flushes never write the same key out of order. It is a channel and
	// not a mutex so that acquiring it can honour a context.
	flushSem chan struct{}

	mu           sync.Mutex
	pending      map[lastUsedKey]time.Time
	timer        *time.Timer // armed while pending is non-empty and no flush is running
	failures     int         // consecutive failed flushes
	backoffUntil time.Time   // no background flush before this
	dropped      uint64      // stamps dropped over the cap, lifetime
	dropLog      rateLimitedLog
	failLog      rateLimitedLog
}

// lastUsedEntry is one observation to write.
type lastUsedEntry struct {
	key lastUsedKey
	at  time.Time
}

// rateLimitedLog allows one line per lastUsedLogEvery and counts what it
// suppressed. Used under lastUsedCoalescer.mu.
type rateLimitedLog struct {
	last       time.Time
	suppressed uint64
}

// allow adds n events and reports whether a line may be logged now; if so,
// events is how many happened since the previous line.
func (l *rateLimitedLog) allow(now time.Time, n uint64) (ok bool, events uint64) {
	l.suppressed += n
	if !l.last.IsZero() && now.Sub(l.last) < lastUsedLogEvery {
		return false, 0
	}
	l.last = now
	events, l.suppressed = l.suppressed, 0
	return true, events
}

func newLastUsedCoalescer(interval time.Duration, maxKeys int) *lastUsedCoalescer {
	return &lastUsedCoalescer{
		interval:   interval,
		maxKeys:    maxKeys,
		backoffMin: lastUsedBackoffMin,
		backoffMax: lastUsedBackoffMax,
		clock:      time.Now,
		flushSem:   make(chan struct{}, 1),
		pending:    map[lastUsedKey]time.Time{},
	}
}

// lastUsed returns this core's coalescer, creating it on first use.
func (c *KeyorixCore) lastUsed() *lastUsedCoalescer {
	c.lastUsedOnce.Do(func() {
		if c.lastUsedAgg == nil {
			c.lastUsedAgg = newLastUsedCoalescer(lastUsedFlushInterval, lastUsedMaxPending)
		}
		if c.lastUsedAgg.write == nil {
			c.lastUsedAgg.write = c.writeLastUsed
			c.lastUsedAgg.writeBatch = c.writeLastUsedBatch
		}
	})
	return c.lastUsedAgg
}

// touchLastUsed is the store's conditional UPDATE with staleness 0, so the
// stored value only ever moves forward.
func touchLastUsed(ctx context.Context, st storage.Storage, k lastUsedKey, at time.Time) error {
	switch k.kind {
	case lastUsedPAT:
		return st.TouchPersonalAccessToken(ctx, k.id, at, 0)
	case lastUsedMachineCredential:
		return st.TouchMachineIdentityCredential(ctx, k.id, at, 0)
	case lastUsedSession:
		return st.TouchSession(ctx, k.id, at, 0)
	}
	return nil
}

// writeLastUsed is the coalescer's single-key write.
func (c *KeyorixCore) writeLastUsed(ctx context.Context, k lastUsedKey, at time.Time) error {
	return touchLastUsed(ctx, c.storage, k, at)
}

// writeLastUsedBatch writes entries (already in (kind, id) order) in one
// transaction: one commit per chunk instead of one per key. Replicas flushing
// overlapping sets lock rows in the same order, so chunks cannot deadlock each
// other; a failure rolls the whole chunk back.
//
// nosemgrep: keyorix-unbounded-bulk-slice-param -- only caller is writeChunk, which passes at most lastUsedWriteChunk entries drawn from the coalescer's own capped map, never caller-supplied input
func (c *KeyorixCore) writeLastUsedBatch(ctx context.Context, entries []lastUsedEntry) error {
	return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		for _, e := range entries {
			if err := touchLastUsed(ctx, tx, e.key, e.at); err != nil {
				return err
			}
		}
		return nil
	})
}

// record notes a use at time at. It never touches the database.
func (a *lastUsedCoalescer) record(k lastUsedKey, at time.Time) {
	a.mu.Lock()
	prev, already := a.pending[k]
	switch {
	case already:
		if at.After(prev) {
			a.pending[k] = at
		}
	case len(a.pending) >= a.maxKeys:
		a.dropLocked(1)
	default:
		a.pending[k] = at
	}
	// An early flush only when the map is full and no backoff is running; the
	// flag in kick() keeps it to one flush at a time however often we get here.
	early := len(a.pending) >= a.maxKeys && !a.clock().Before(a.backoffUntil)
	if !early && a.timer == nil && len(a.pending) > 0 {
		a.armTimerLocked()
	}
	a.mu.Unlock()
	if early {
		a.kick()
	}
}

// dropLocked counts n stamps dropped because the map is full and logs at most
// once per lastUsedLogEvery. The caller holds a.mu.
func (a *lastUsedCoalescer) dropLocked(n uint64) {
	a.dropped += n
	if ok, since := a.dropLog.allow(a.clock(), n); ok {
		log.Printf("last-used: pending map at its cap of %d; dropped %d stamp(s) since the last notice (%d in total). Their last_used_at / last_seen_at will lag; no access decision reads those columns", a.maxKeys, since, a.dropped)
	}
}

// droppedCount is the number of stamps dropped over the cap so far.
func (a *lastUsedCoalescer) droppedCount() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropped
}

// armTimerLocked arms the periodic flush: after interval, or after the backoff
// if that ends later. The caller holds a.mu and has checked a.timer == nil.
func (a *lastUsedCoalescer) armTimerLocked() {
	delay := a.interval
	if wait := a.backoffUntil.Sub(a.clock()); wait > delay {
		delay = wait
	}
	a.timer = time.AfterFunc(delay, a.onTimer)
}

// onTimer is the periodic flush. It runs the flush on the timer's own
// goroutine, under the same single-flight flag as the early flush.
func (a *lastUsedCoalescer) onTimer() {
	a.mu.Lock()
	a.timer = nil
	if wait := a.backoffUntil.Sub(a.clock()); wait > 0 {
		if len(a.pending) > 0 {
			a.timer = time.AfterFunc(wait, a.onTimer)
		}
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()
	if a.flushing.CompareAndSwap(false, true) {
		defer a.flushing.Store(false)
		a.flushInBackground()
	}
	// else a flush is running; it re-arms the timer if anything is pending
	// when it ends.
}

// kick starts a background flush unless one is already in flight. It never
// starts more than one goroutine however many callers race here.
func (a *lastUsedCoalescer) kick() {
	if !a.flushing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer a.flushing.Store(false)
		a.flushInBackground()
	}()
}

// pendingAt returns the newest unflushed use of k, if any.
func (a *lastUsedCoalescer) pendingAt(k lastUsedKey) (time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.pending[k]
	return t, ok
}

func (a *lastUsedCoalescer) flushInBackground() {
	ctx, cancel := context.WithTimeout(context.Background(), lastUsedFlushTimeout)
	defer cancel()
	a.flush(ctx)
}

// acquireFlush takes the flush semaphore, giving up when ctx ends first.
func (a *lastUsedCoalescer) acquireFlush(ctx context.Context) bool {
	select {
	case a.flushSem <- struct{}{}:
		return true
	default:
	}
	select {
	case a.flushSem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// rearm arms the periodic timer if stamps are pending and none is armed.
func (a *lastUsedCoalescer) rearm() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.timer == nil && len(a.pending) > 0 {
		a.armTimerLocked()
	}
}

// flush writes every pending observation, in chunks of lastUsedWriteChunk keys
// in (kind, id) order, one transaction per chunk (see writeChunk for the
// per-key fallback). Whatever was not written goes back into pending, merged
// with anything newer recorded meanwhile and within the cap, and starts the
// backoff: a transient database error delays the stamp instead of dropping it.
// An explicit flush (shutdown, tests) ignores the backoff but not ctx: it gives
// up waiting for a running flush when ctx ends, and stops writing then.
func (a *lastUsedCoalescer) flush(ctx context.Context) {
	if !a.acquireFlush(ctx) {
		a.mu.Lock()
		n := len(a.pending)
		a.mu.Unlock()
		log.Printf("last-used flush: gave up waiting for the flush already running (%v); %d pending stamp(s) not written by this call", ctx.Err(), n)
		a.rearm()
		return
	}
	defer func() { <-a.flushSem }()

	a.mu.Lock()
	batch := a.pending
	a.pending = make(map[lastUsedKey]time.Time, len(batch))
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.mu.Unlock()
	if len(batch) == 0 {
		return
	}

	entries := make([]lastUsedEntry, 0, len(batch))
	for k, at := range batch {
		entries = append(entries, lastUsedEntry{k, at})
	}
	// Deterministic order (kind, id): replicas flushing overlapping sets
	// touch rows in the same order.
	slices.SortFunc(entries, func(x, y lastUsedEntry) int {
		if c := cmp.Compare(x.key.kind, y.key.kind); c != 0 {
			return c
		}
		return cmp.Compare(x.key.id, y.key.id)
	})

	var failed []lastUsedEntry
	var firstErr error
	for start := 0; start < len(entries); start += lastUsedWriteChunk {
		if ctx.Err() != nil {
			failed, firstErr = append(failed, entries[start:]...), cmp.Or(firstErr, ctx.Err())
			break
		}
		chunk := entries[start:min(start+lastUsedWriteChunk, len(entries))]
		chunkFailed, err := a.writeChunk(ctx, chunk)
		firstErr = cmp.Or(firstErr, err)
		failed = append(failed, chunkFailed...)
		if len(chunkFailed) == len(chunk) {
			// Nothing in this chunk landed: the database is down or stuck.
			// Do not try the rest one by one; they wait for the backoff.
			failed = append(failed, entries[start+len(chunk):]...)
			break
		}
	}
	a.finishFlush(len(entries), failed, firstErr)
}

// finishFlush records the outcome: resets the backoff on success, otherwise
// steps it, puts the unwritten keys back (cap permitting, the rest dropped and
// counted) and re-arms the timer.
func (a *lastUsedCoalescer) finishFlush(total int, failed []lastUsedEntry, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(failed) == 0 {
		a.failures, a.backoffUntil = 0, time.Time{}
	} else {
		a.failures++
		delay := a.backoffDelay(a.failures)
		a.backoffUntil = a.clock().Add(delay)
		var dropped uint64
		for _, e := range failed {
			if prev, ok := a.pending[e.key]; ok {
				if e.at.After(prev) {
					a.pending[e.key] = e.at
				}
				continue
			}
			if len(a.pending) >= a.maxKeys {
				dropped++
				continue
			}
			a.pending[e.key] = e.at
		}
		if dropped > 0 {
			a.dropLocked(dropped)
		}
		if ok, flushes := a.failLog.allow(a.clock(), 1); ok {
			log.Printf("last-used flush: %d of %d stamp(s) not written (%d failed flush(es) since the last notice, %d in a row); next background flush in %s: %v",
				len(failed), total, flushes, a.failures, delay.Round(time.Millisecond), err)
		}
	}
	if a.timer == nil && len(a.pending) > 0 {
		a.armTimerLocked()
	}
}

// backoffDelay is the wait after the n-th consecutive failed flush (n >= 1):
// backoffMin doubling up to backoffMax, then jittered into [d/2, d] so replicas
// that failed together do not retry together.
func (a *lastUsedCoalescer) backoffDelay(n int) time.Duration {
	d := a.backoffMin
	for i := 1; i < n && d < a.backoffMax; i++ {
		d *= 2
	}
	d = min(d, a.backoffMax)
	if d <= 0 {
		return 0
	}
	return d/2 + rand.N(d/2+1) // #nosec G404 -- retry jitter, not security-sensitive
}

// writeChunk writes one chunk and returns the entries that were not written
// plus the first error. It tries the chunk's single transaction first (one
// commit); if that fails, it writes the keys one by one so that a single bad
// row cannot hold back the rest of its chunk.
func (a *lastUsedCoalescer) writeChunk(ctx context.Context, chunk []lastUsedEntry) (failed []lastUsedEntry, firstErr error) {
	if a.writeBatch != nil {
		err := a.safeBatch(ctx, chunk)
		if err == nil {
			return nil, nil
		}
		firstErr = err
		if ctx.Err() != nil {
			return chunk, firstErr
		}
	}
	for i, e := range chunk {
		if ctx.Err() != nil {
			return append(failed, chunk[i:]...), cmp.Or(firstErr, ctx.Err())
		}
		if panicked, err := a.safeWrite(ctx, e.key, e.at); err != nil && !panicked {
			failed = append(failed, e)
			firstErr = cmp.Or(firstErr, err)
		}
	}
	return failed, firstErr
}

// safeBatch runs the chunk transaction and turns a panic into an error (the
// per-key fallback then isolates the panicking key).
func (a *lastUsedCoalescer) safeBatch(ctx context.Context, chunk []lastUsedEntry) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("last-used batch write panicked: %v", r)
		}
	}()
	return a.writeBatch(ctx, chunk)
}

// safeWrite runs one write and turns a panic into an error: the flush runs on
// a timer goroutine, where an unrecovered panic from storage would take the
// whole server down for a bookkeeping stamp. A panicking key is dropped, not
// retried (it would most likely panic again every interval).
func (a *lastUsedCoalescer) safeWrite(ctx context.Context, k lastUsedKey, at time.Time) (panicked bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("last-used flush: write for kind %d id %d panicked, dropping it: %v", k.kind, k.id, r)
			panicked, err = true, fmt.Errorf("last-used write panicked: %v", r)
		}
	}()
	return false, a.write(ctx, k, at)
}

// FlushLastUsed writes every recorded but not yet flushed last-used / last-seen
// stamp now. The server calls it on graceful shutdown so an orderly stop
// loses nothing; tests call it instead of waiting for the interval. It is
// bounded by ctx both while waiting for a background flush that is still
// running and while writing; stamps it did not reach stay pending (and are
// lost with the process).
func (c *KeyorixCore) FlushLastUsed(ctx context.Context) {
	c.lastUsed().flush(ctx)
}
