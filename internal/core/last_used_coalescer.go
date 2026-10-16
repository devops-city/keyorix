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
	"slices"
	"sync"
	"time"
)

// lastUsedFlushInterval bounds how long a recorded use may wait in memory.
// It equals the 30 s throttle the inline stamps used before, so the column's
// staleness bound for readers is unchanged.
const lastUsedFlushInterval = 30 * time.Second

// lastUsedMaxPending caps the in-memory map. Reaching it starts a flush
// immediately instead of waiting for the timer. Entries are only ever added
// for credentials that just authenticated, so the cap is a safety net.
const lastUsedMaxPending = 50_000

// lastUsedFlushTimeout bounds one background flush.
const lastUsedFlushTimeout = 20 * time.Second

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

	mu      sync.Mutex
	pending map[lastUsedKey]time.Time
	timer   *time.Timer // armed while pending is non-empty

	// flushMu serializes flushes so a timer flush and FlushLastUsed never
	// write the same key out of order.
	flushMu sync.Mutex
}

func newLastUsedCoalescer(interval time.Duration, maxKeys int) *lastUsedCoalescer {
	return &lastUsedCoalescer{interval: interval, maxKeys: maxKeys, pending: map[lastUsedKey]time.Time{}}
}

// lastUsed returns this core's coalescer, creating it on first use.
func (c *KeyorixCore) lastUsed() *lastUsedCoalescer {
	c.lastUsedOnce.Do(func() {
		if c.lastUsedAgg == nil {
			c.lastUsedAgg = newLastUsedCoalescer(lastUsedFlushInterval, lastUsedMaxPending)
		}
		if c.lastUsedAgg.write == nil {
			c.lastUsedAgg.write = c.writeLastUsed
		}
	})
	return c.lastUsedAgg
}

// writeLastUsed is the coalescer's write: the store's conditional UPDATE with
// staleness 0, so the stored value only ever moves forward.
func (c *KeyorixCore) writeLastUsed(ctx context.Context, k lastUsedKey, at time.Time) error {
	switch k.kind {
	case lastUsedPAT:
		return c.storage.TouchPersonalAccessToken(ctx, k.id, at, 0)
	case lastUsedMachineCredential:
		return c.storage.TouchMachineIdentityCredential(ctx, k.id, at, 0)
	case lastUsedSession:
		return c.storage.TouchSession(ctx, k.id, at, 0)
	}
	return nil
}

// record notes a use at time at. It never touches the database.
func (a *lastUsedCoalescer) record(k lastUsedKey, at time.Time) {
	a.mu.Lock()
	if prev, ok := a.pending[k]; !ok || at.After(prev) {
		a.pending[k] = at
	}
	full := len(a.pending) >= a.maxKeys
	if full {
		if a.timer != nil {
			a.timer.Stop()
			a.timer = nil
		}
	} else if a.timer == nil {
		a.timer = time.AfterFunc(a.interval, a.flushInBackground)
	}
	a.mu.Unlock()
	if full {
		go a.flushInBackground()
	}
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

// flush writes every pending observation, one UPDATE per key, each in its own
// autocommit statement (no transaction spans two rows, so a flush never holds
// one row's lock while waiting on another). A failed write goes back into
// pending, merged with anything newer recorded meanwhile, and the timer is
// re-armed: a transient database error delays the stamp by an interval
// instead of dropping it.
func (a *lastUsedCoalescer) flush(ctx context.Context) {
	a.flushMu.Lock()
	defer a.flushMu.Unlock()

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

	keys := make([]lastUsedKey, 0, len(batch))
	for k := range batch {
		keys = append(keys, k)
	}
	// Deterministic order (kind, id): replicas flushing overlapping sets
	// touch rows in the same order.
	slices.SortFunc(keys, func(x, y lastUsedKey) int {
		if c := cmp.Compare(x.kind, y.kind); c != 0 {
			return c
		}
		return cmp.Compare(x.id, y.id)
	})

	var failed map[lastUsedKey]time.Time
	for i, k := range keys {
		if ctx.Err() != nil {
			if failed == nil {
				failed = map[lastUsedKey]time.Time{}
			}
			for _, rest := range keys[i:] {
				failed[rest] = batch[rest]
			}
			break
		}
		if panicked, err := a.safeWrite(ctx, k, batch[k]); err != nil && !panicked {
			if failed == nil {
				failed = map[lastUsedKey]time.Time{}
			}
			failed[k] = batch[k]
		}
	}
	if len(failed) == 0 {
		return
	}
	a.mu.Lock()
	for k, t := range failed {
		if prev, ok := a.pending[k]; !ok || t.After(prev) {
			a.pending[k] = t
		}
	}
	if a.timer == nil {
		a.timer = time.AfterFunc(a.interval, a.flushInBackground)
	}
	a.mu.Unlock()
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
// loses nothing; tests call it instead of waiting for the interval.
func (c *KeyorixCore) FlushLastUsed(ctx context.Context) {
	c.lastUsed().flush(ctx)
}
