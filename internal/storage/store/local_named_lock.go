// local_named_lock.go — general-purpose cross-replica serialization for check-then-act
// invariants that don't warrant their own bespoke WithXLock method (#1646).
package store

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"sync"
)

// namedLockRegistry hands out one *sync.Mutex per lock key, creating it on
// first use, so the non-Postgres WithNamedLock fallback (SQLite,
// single-process by construction) serializes callers per-key exactly like
// PostgreSQL's pg_advisory_lock does -- not one shared mutex serializing every
// unrelated key against every other. FIX-5 (adversarial review run 2): this
// replaces a single process-wide *sync.Mutex that WAS shared across every
// lock key -- with the reentrancy guard now keyed on lockKey (see
// namedLockHeldCtxKey), a nested WithNamedLock call under a DIFFERENT key
// must actually be able to acquire its OWN lock rather than either
// (old, wrong) silently skipping it, or (a naive per-key reentrancy fix atop
// the OLD single shared mutex) self-deadlocking by re-locking the same mutex
// the outer call already holds.
//
// #1690 regression (Part 2 regression audit, 2026-09-04): FIX-5's own map
// (originally map[string]*sync.Mutex) never deleted an entry once created --
// lockKey's key space is per-entity (sodGrantLockKey("user"/"group", ID),
// projectAdminGuardLockKey(projectID)), so on a long-uptime SQLite/
// single-process deployment the map grows by one entry per distinct
// user/group/project ID ever role-managed and never shrinks: an unbounded
// memory-growth surface the old single-mutex design had no way to exhibit,
// by construction. Fixed with a refcounted entry: acquire increments refs
// under r.mu before locking the entry's own mutex; release decrements refs
// (also under r.mu) after unlocking it and deletes the map entry only once
// refs reaches zero -- i.e. only once no goroutine anywhere in the process is
// still holding or waiting on that specific entry. A racing acquire for the
// same key between another caller's unlock and its release either sees the
// entry still in the map (bumps refs, reuses the SAME mutex object -- no
// correctness gap) or finds it already deleted (creates a fresh one for a
// genuinely uncontended key) -- there is never a window where two different
// mutex objects are live for the same key at once.
// #2853: the entry is an explicit FIFO ticket queue, not a sync.Mutex. Three
// properties the mutex could not give, each load-bearing:
//
//   - CONTEXT-AWARENESS. A waiter whose ctx is cancelled must leave the queue
//     and return, having touched no pooled connection. sync.Mutex.Lock cannot
//     be cancelled, so a caller abandoned by its request context stayed queued.
//   - FIFO. sync.Mutex deliberately allows barging (a newly arriving goroutine
//     can win over one already waiting) and only falls back to a FIFO-ish
//     starvation mode after 1ms. For a lock that guards a cross-replica
//     check-then-act sequence, "first to ask is first served" is the behaviour
//     an operator expects, and it bounds worst-case latency per waiter.
//   - A CHECKABLE held/queued STATE. The Postgres path below must be entered by
//     at most one goroutine per key per process (see WithNamedLock's connection
//     budget note), which means the gate has to be inspectable, not implicit in
//     a mutex's internals.
//
// held is true while some caller owns the key. Release hands ownership to the
// head of the queue by closing its ticket WITHOUT clearing held, so no third
// goroutine can slip in between a release and its successor's wake-up.
type namedLockEntry struct {
	mu    sync.Mutex
	held  bool
	queue []chan struct{} // FIFO; guarded by mu
	refs  int             // guarded by namedLockRegistry.mu, not by mu above
}

type namedLockRegistry struct {
	mu    sync.Mutex
	locks map[string]*namedLockEntry
}

func newNamedLockRegistry() *namedLockRegistry {
	return &namedLockRegistry{locks: make(map[string]*namedLockEntry)}
}

// acquire blocks until this caller owns lockKey, or ctx is done, creating the
// entry if this is the first caller to ever name it (or if a prior entry was
// already reclaimed). On success the caller MUST pass the returned entry to
// release(lockKey, entry) exactly once, after its critical section. On error
// nothing is owed: acquire has already undone its own bookkeeping.
func (r *namedLockRegistry) acquire(ctx context.Context, lockKey string) (*namedLockEntry, error) {
	r.mu.Lock()
	e, ok := r.locks[lockKey]
	if !ok {
		e = &namedLockEntry{}
		r.locks[lockKey] = e
	}
	e.refs++
	r.mu.Unlock()

	e.mu.Lock()
	if !e.held {
		e.held = true
		e.mu.Unlock()
		return e, nil
	}
	ticket := make(chan struct{})
	e.queue = append(e.queue, ticket)
	e.mu.Unlock()

	select {
	case <-ticket:
		return e, nil
	case <-ctx.Done():
		e.mu.Lock()
		for i, c := range e.queue {
			if c != ticket {
				continue
			}
			// Still queued: drop out. Nothing was ever owned, and no
			// connection was ever taken.
			e.queue = append(e.queue[:i], e.queue[i+1:]...)
			e.mu.Unlock()
			r.unref(lockKey, e)
			return nil, ctx.Err()
		}
		e.mu.Unlock()
		// Not in the queue any more: a release dequeued this ticket and is
		// committed to closing it, so ownership is being handed to US even
		// though our ctx has fired. Take it and pass it straight on —
		// returning here without releasing would leave held=true forever and
		// wedge the key for the life of the process.
		<-ticket
		r.release(lockKey, e)
		return nil, ctx.Err()
	}
}

// release hands ownership of lockKey to the longest-waiting caller, or marks
// the key free if nobody is waiting, and then lets the registry reclaim the
// entry once no one is holding or waiting on it (#1690: the map must not grow
// by one permanent entry per distinct ID ever locked).
func (r *namedLockRegistry) release(lockKey string, e *namedLockEntry) {
	e.mu.Lock()
	if len(e.queue) > 0 {
		next := e.queue[0]
		e.queue = e.queue[1:]
		// held stays true: ownership transfers directly to next.
		e.mu.Unlock()
		close(next)
	} else {
		e.held = false
		e.mu.Unlock()
	}
	r.unref(lockKey, e)
}

// unref drops this caller's reference and reclaims the entry once the last
// holder/waiter is gone. refs counts live acquire calls (owner plus queued
// waiters), so refs==0 implies held==false and an empty queue.
func (r *namedLockRegistry) unref(lockKey string, e *namedLockEntry) {
	r.mu.Lock()
	e.refs--
	if e.refs == 0 {
		delete(r.locks, lockKey)
	}
	r.mu.Unlock()
}

// namedLockKey derives a stable int64 advisory-lock key from an arbitrary lockKey
// string via FNV-1a (Go-side, not a Postgres SQL function, so the same key always
// hashes identically regardless of which connection computes it).
func namedLockKey(lockKey string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(lockKey)) // fnv.Write never errors
	return int64(h.Sum64())         // #nosec G115 -- advisory-lock key, not a security boundary -- truncation to int64 range is fine
}

// namedLockHeldCtxKey marks a context as already running inside a WithNamedLock
// closure for one or more SPECIFIC lock keys (see heldNamedLockKeys). WithNamedLock
// is meant to guard against concurrent OTHER callers racing the same check-then-act
// sequence for a given lockKey; it is not meant to serialize a single call chain
// against itself reacquiring that SAME key. Without this guard, one guarded core
// method calling another under the identical key (e.g. SetProjectMemberRole →
// guardLastProjectAdmin's own re-entry, both keyed on projectAdminGuardLockKey)
// self-deadlocks: the SQLite/single-process path re-locks ls.namedLockMu (not
// reentrant), and the Postgres path pulls a SECOND connection from the pool and
// blocks it on pg_advisory_lock behind the first connection's own held lock —
// which, under a small pool, also starves connectionOpener into a permanent
// select (reproduced: internal/core's suite hung 600s on exactly this shape).
//
// FIX-5 (adversarial review run 2): the marker used to be a single untyped
// boolean, so ANY already-held lock -- regardless of key -- caused a nested
// WithNamedLock call under a DIFFERENT key to skip acquiring it entirely. That is
// the wrong invariant: WithNamedLock's whole point is per-key cross-replica
// serialization, and a nested call under a different key still needs its own
// lock actually taken (e.g. SetProjectMemberRole holds projectAdminGuardLockKey
// and calls AssignUserRole, which must still acquire its own
// sodGrantLockKey("user", userID) -- a different resource, not covered by the
// outer lock at all). The marker is now the SET of keys currently held by this
// call chain, so only a re-entrant acquisition of the SAME key is skipped.
type namedLockHeldCtxKey struct{}

// heldNamedLockKeys reads the set of lock keys already held by this call chain,
// or nil if none.
func heldNamedLockKeys(ctx context.Context) map[string]bool {
	held, _ := ctx.Value(namedLockHeldCtxKey{}).(map[string]bool)
	return held
}

// namedLockConnCtxKey carries the lock session (advisoryLockSession) an outer WithNamedLock call
// checked out of the pool, so a nested call under a DIFFERENT key (Postgres
// path only) reuses it instead of checking out a second connection.
//
// Part 2 regression audit (adversarial review run 2), found in FIX-5 itself:
// PostgreSQL advisory locks are SESSION-scoped, not per-acquisition -- one
// connection can hold pg_advisory_lock on any number of distinct keys at
// once. Before this, every WithNamedLock call (nested or not) pulled its own
// connection via sqlDB.Conn(ctx), so a call chain nesting N distinct keys
// needed N simultaneous pooled connections. Under a constrained pool (e.g.
// max_open_conns: 1 or 2, unenforced by internal/config), the outer call
// holds the pool's only connection for the ENTIRE duration of fn -- which is
// itself the blocked inner call waiting on sqlDB.Conn(ctx) for a connection
// only the outer call could release. Verified: an indefinite deadlock (not
// contention -- it never resolved on its own; only an artificial context
// timeout ended it), reproduced against real Postgres with MaxOpenConns(1).
// Reusing the outer call's connection for every nested key removes the
// per-chain connection-count dependency entirely: a chain nesting any number
// of distinct keys still needs only ONE pooled connection.
type namedLockConnCtxKey struct{}

func heldNamedLockSession(ctx context.Context) *advisoryLockSession {
	sess, _ := ctx.Value(namedLockConnCtxKey{}).(*advisoryLockSession)
	return sess
}

// WithNamedLock runs fn with every OTHER caller using the identical lockKey
// serialized against it, in two layers:
//
//  1. a per-key in-process FIFO queue (namedLockRegistry), which every caller
//     passes through FIRST, on every dialect;
//  2. on PostgreSQL only, a session-scoped advisory lock (pg_advisory_lock)
//     keyed by lockKey's FNV-1a hash, which extends the guarantee across
//     processes/replicas (ADR-039 HA). SQLite is single-instance by
//     construction, so layer 1 is the whole guarantee there.
//
// Two DIFFERENT lock keys never serialize against each other in either layer.
//
// Like WithBootstrapLock/WithAuditCheckpointLock, this BLOCKS until the lock is
// acquired rather than skipping on contention — a caller that loses the race must
// actually re-run its check under the lock and observe the winner's now-committed
// state, not silently no-op. It now also honours ctx while blocked: a caller whose
// context is cancelled or times out while queued returns that error instead of
// waiting indefinitely, and does so without ever having taken a connection.
//
// # Connection budget (#2853, NAMEDLOCK-POOL-1)
//
// A lock holder needs at most ONE request-pool connection at a time: the one
// fn's own queries use. The advisory-lock session comes from the dedicated
// named-lock pool (SetNamedLockDB, wired by the storage factory), never from the
// request pool, so the request pool always drains whatever the number of keys
// held at once. Callers beyond that pool's cap queue and run a little later.
// Two rules keep the lock pool's own use bounded and free of hold-and-wait:
//
//   - Layer 1, top-level calls only: at most one top-level goroutine per key
//     per process is ever past the queue, so at most one NEW lock session per
//     key is ever parked on pg_advisory_lock. Queued waiters hold nothing; a
//     cancelled waiter leaves the queue having touched no connection at all.
//     (Before layer 1, every waiter parked a connection for its whole wait; M
//     callers on one key exhausted a pool of M and the holder could not
//     finish.)
//   - A nested call under a different key reuses the outer call's lock session
//     (namedLockConnCtxKey), so a call chain needs one lock session however
//     many keys it nests, and it waits for the inner key in Postgres on that
//     session, never in the layer-1 queue (#3358). Waiting in-process while
//     holding a lock session was hold-and-wait: the top-level owner of the
//     inner key in-process waited for a lock session, and with every session
//     held by nested callers, nothing moved. So no caller ever waits in layer
//     1 holding a lock session, and a caller waiting for a lock session holds
//     only layer-1 ownership, which no session holder waits for.
//     Guard: TestWithNamedLock_NestedCallerHoldingEveryLockSession_DoesNotDeadlock.
//
// Before NAMEDLOCK-POOL-1 the lock session came from the request pool: one key
// held per pool connection, each holder's fn waiting for one more, a permanent
// hang. Without SetNamedLockDB (tests building a LocalStorage directly) that is
// still the shape: two request-pool connections per held key.
//
// Guards: TestWithNamedLock_Postgres_SmallPool_DistinctKeysAndReadsComplete
// (internal/storage, factory-built), TestWithNamedLock_LockPool_HolderRunsOnAOneConnectionRequestPool,
// TestWithNamedLock_ManyWaitersOnOneKey_DoNotExhaustPool,
// TestWithNamedLock_HolderCompletesUnderPoolSmallerThanWaiters,
// TestWithNamedLock_CancelledWhileQueued_ReleasesAndTakesNoConnection.
//
// Never call WithNamedLock while holding a request-pool connection (inside a
// WithTransaction or other pinned session): that caller would hold one request
// connection while it waits for a lock session, and holders of lock sessions
// wait for request connections. Run the transaction inside fn instead.
// Nothing inside fn may hold one request-pool connection while asking for another.
// Lock ordering across DIFFERENT keys is unchanged and still the caller's
// responsibility: two call chains taking keys A then B and B then A deadlock,
// exactly as they did when both layers were advisory locks — layer 1 just makes
// such a cycle resolve in-process rather than in Postgres.
//
// fn receives the (possibly lock-marked) context so that a nested WithNamedLock
// call made from within fn, under the SAME lockKey, sees the marker via
// namedLockHeldCtxKey and runs directly instead of re-acquiring: the outer lock
// already gives this call chain exclusivity over every other goroutine/replica
// for that key. A nested call under a DIFFERENT lockKey is not covered by the
// outer lock at all and still acquires its own. Callers that thread ctx through
// to further WithNamedLock calls MUST use the ctx passed to fn, not whatever ctx
// they closed over — otherwise the marker never propagates and a same-key nested
// call self-deadlocks (see namedLockHeldCtxKey).
func (ls *LocalStorage) WithNamedLock(ctx context.Context, lockKey string, fn func(ctx context.Context) error) error {
	held := heldNamedLockKeys(ctx)
	if held[lockKey] {
		return fn(ctx)
	}
	ctx = checkNamedLockOrder(ctx, lockKey) // C-GUARD-3: test builds panic on an out-of-order acquisition
	next := make(map[string]bool, len(held)+1)
	for k := range held {
		next[k] = true
	}
	next[lockKey] = true
	ctx = context.WithValue(ctx, namedLockHeldCtxKey{}, next)

	// Reuse an outer call's already-checked-out lock session if this call chain
	// has one (see namedLockConnCtxKey) -- a nested call under a different key
	// must still acquire its OWN advisory lock, but never needs a SECOND
	// lock session to do it.
	//
	// #3358: a nested call does NOT pass through the in-process queue. It
	// already holds a lock session, and waiting in-process while holding one
	// is hold-and-wait: the top-level owner of this key in-process may itself
	// be waiting for a lock session, and with every session of the pool held
	// by nested callers like this one, neither side can move (and every other
	// key in the process waits for a session too). Blocking in Postgres on the
	// session we already hold takes nothing new, and pg_advisory_lock still
	// excludes every other holder of the key, in this process or any other.
	// heldNamedLockSession is only ever set on the Postgres path below.
	if sess := heldNamedLockSession(ctx); sess != nil {
		key := namedLockKey(lockKey)
		if err := sess.lock(ctx, key); err != nil {
			return fmt.Errorf("failed to acquire named advisory lock %q: %w", lockKey, err)
		}
		defer sess.unlock(ctx, key, "named lock")
		return fn(ctx)
	}

	// #2853: a top-level call queues IN-PROCESS FIRST, before any pooled
	// connection is taken, on Postgres as well as SQLite. This is what bounds
	// the connection cost of contention — see the connection budget note above.
	entry, err := ls.namedLockMu.acquire(ctx, lockKey)
	if err != nil {
		return fmt.Errorf("failed to acquire named lock %q: %w", lockKey, err)
	}
	defer ls.namedLockMu.release(lockKey, entry)

	if ls.db.Dialector.Name() != "postgres" {
		return fn(ctx)
	}

	key := namedLockKey(lockKey)

	// The lock session comes from the dedicated named-lock pool (SetNamedLockDB),
	// never from the request pool fn's own queries use: see the connection
	// budget note above.
	lockDB := ls.namedLockDB
	if lockDB == nil {
		sqlDB, err := ls.db.DB()
		if err != nil {
			return err
		}
		lockDB = sqlDB
	}
	conn, err := lockDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // returns the conn to the pool (after the unlock below)

	sess, err := openAdvisoryLockSession(ctx, conn, ls.transactionPooling)
	if err != nil {
		return fmt.Errorf("failed to acquire named advisory lock %q: %w", lockKey, err)
	}
	defer sess.close(ctx)
	if err := sess.lock(ctx, key); err != nil {
		return fmt.Errorf("failed to acquire named advisory lock %q: %w", lockKey, err)
	}
	// Release before the deferred Close so the pooled connection carries no
	// lock. The unlock ignores ctx's cancellation: a caller whose request was
	// cancelled inside fn must still unlock, or the session would go back to
	// the pool still holding the lock and every later caller for that key, on
	// any replica, would block on it. If the unlock fails anyway, the session
	// is discarded, which ends the Postgres backend and every advisory lock it
	// held (same rule as WithSchedulerLock).
	defer sess.unlock(ctx, key, "named lock")

	// Make this lock session available to any nested WithNamedLock call under
	// a different key, for the remainder of this call chain.
	ctx = context.WithValue(ctx, namedLockConnCtxKey{}, sess)
	return fn(ctx)
}

// SetNamedLockDB gives WithNamedLock a pool of its own for the advisory-lock
// sessions, separate from the request pool and from the scheduler lock pool. A
// lock session is pinned for the whole critical section while fn's queries need
// a connection of their own; on the request pool, as many distinct keys held at
// once as the pool has connections pinned every connection, each waiting for one
// more (hold-and-wait; NAMEDLOCK-POOL-1). It is not the scheduler lock pool
// because scheduler jobs call WithNamedLock from inside their own lock-held
// section: on one capped pool, enough jobs doing that at once would pin every
// session and wait for one more. Lock semantics are unchanged: one session
// advisory lock per key, in the same database, released before the session is
// pooled again.
//
// Without one (a LocalStorage built directly by tests or examples), the request
// pool is used as before. Call it before serving traffic.
func (ls *LocalStorage) SetNamedLockDB(db *sql.DB) {
	ls.namedLockDB = db
}
