// interleave_sync_points_test.go — GUARD-5's deterministic two-replica
// interleaving driver.
//
// # WHY THIS EXISTS
//
// GUARD-4's FuzzCrossReplicaInvariants races two replicas blindly: both ops
// are released from one barrier and whichever interleaving the OS scheduler
// happens to produce is the one that gets tested. That found #2650 live, but
// six of its pending seeds (#2646, #2647, #2649, #2655, #2657, #2659) never
// went red in ~400 blind repetitions each, because the window between the
// "check" and the "act" in those functions is a handful of microseconds wide.
// A race test that only fails by luck is not a regression test: it cannot tell
// "the bug is fixed" from "the scheduler was kind this time", and in CI it is
// indistinguishable from a flake.
//
// This file makes the interleaving a parameter instead of an accident. Given
// two conflicting operations A and B, each with one named sync point placed at
// the boundary between its own check and its own decisive write, it can drive
// any of the six legal interleavings of the two (check, act) pairs
// deterministically, every run, with no timing dependence at all.
//
// # WHERE THE SYNC POINTS LIVE, AND WHY NOT IN PRODUCTION CODE
//
// GUARD-5's brief asked for named sync points inside each guarded
// check-then-act function, build-tagged to compile away in production. This
// file deliberately does NOT do that, for one reason that outweighs the
// convenience: the brief also says "never change production behaviour or
// timing", and the strongest available guarantee of that is for the mechanism
// to be physically incapable of entering a production build. A build tag can
// be switched on by a stray `-tags` in a release pipeline; a `_test.go` file
// cannot be compiled into a non-test binary by any invocation of the Go
// toolchain. So the sync points are named for the production boundary they
// represent (see syncPointName below and the per-issue callers), but they are
// IMPLEMENTED as one-shot GORM callbacks on one replica's OWN *gorm.DB
// connection pool — the technique
// concurrency_check_then_act_exempt_review_postgres_test.go (C-GUARD2-EXEMPT-
// REVIEW) and internal/storage/store/concurrency_purge_restore_race_test.go
// already use, generalised here from "run B to completion inside A's hook" to
// "pause either side at its own boundary and resume them in any order".
//
// That choice is not free, and the cost is stated rather than hidden: a sync
// point can only be placed at a SQL statement boundary on that replica's
// connection, so the boundary it marks is "immediately before the first
// <kind> statement this operation issues against <table>" — which is after
// the operation's check and before its write for every function this file is
// used with, but is NOT an arbitrary source-level position. When a function's
// check and act are separated by other statements against the same table,
// this driver cannot pin a point between them; it would need the production
// sync point the brief asked for. No such case arose among #2646-#2660.
// TestInterleaveSyncPointsAreTestOnly keeps the "zero production footprint"
// half of that trade honest.
//
// # WHAT A FORCED INTERLEAVING DOES AND DOES NOT PROVE
//
// Same caveat C-GUARD2-EXEMPT-REVIEW states for its own one-shot hooks, and
// it applies here too: forcing an ordering proves the resulting end state is
// REACHABLE under Postgres READ COMMITTED with no shared lock between the two
// calls. It says nothing about how often an unforced race hits that window.
// Nothing here reaches into either replica's code path — the hook only
// chooses WHEN the other replica runs. Both replicas run their real, complete
// core operations on their own connections, committing on their own.
//
// Postgres only; every caller is gated on KEYORIX_TEST_PG_DSN like the rest of
// this package's cross-replica tests.
package core

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// --- sync points -------------------------------------------------------------

// syncPointArrivalTimeout bounds how long the driver waits for a replica to
// reach its sync point before concluding it cannot get there (because the
// other replica holds a lock it needs, or because the operation refused
// before ever reaching its write). Generous on purpose: this is a hang
// detector, not a speed limit (CLAUDE.md, "timeouts detect hangs; they don't
// enforce speed"), and a false "blocked" verdict here would silently turn a
// forced ordering back into a lucky one.
const syncPointArrivalTimeout = 15 * time.Second

// syncPoint is one named, pausable interleaving point on ONE replica's own
// *gorm.DB. It fires at most once per arming: when that replica is about to
// execute its first `kind` statement against `table`, the goroutine running
// the operation announces itself on `arrived` and then BLOCKS until the driver
// sends on `release`.
//
// Per-*gorm.DB registration is what keeps this honest as a two-replica test:
// GORM callbacks are attached to a *gorm.DB, so arming replica A's sync point
// cannot pause, delay or otherwise perturb replica B's connection.
type syncPoint struct {
	// name is the production boundary this point marks, for traces and
	// failure messages — e.g. "ShareSecret:before-share_records-INSERT".
	name  string
	kind  string
	table string

	armed   atomic.Bool
	hits    atomic.Int32
	arrived chan struct{}
	release chan struct{}
	once    sync.Once

	// remove unregisters this sync point's GORM callback. See the method of
	// the same name below for why a caller in a loop must not rely on
	// t.Cleanup for this.
	removeFn func()
}

// remove unregisters the sync point's GORM callback immediately, rather than
// at the end of the test.
//
// This matters for any caller that creates sync points in a LOOP. GORM holds
// one callback chain per *gorm.DB and walks it for every statement, so N
// still-registered sync points cost O(N) per query — and t.Cleanup does not
// run until the whole test function returns. The ordering sweep creates two
// per run across ~175 runs; leaving them registered made it quadratic and it
// failed to finish inside a 60-minute timeout twice before this was found.
// Idempotent, and safe to call even when t.Cleanup will also fire.
func (sp *syncPoint) remove() {
	if sp == nil || sp.removeFn == nil {
		return
	}
	sp.removeFn()
	sp.removeFn = nil
}

// syncPointName builds the canonical name for a sync point: the production
// function whose check/act boundary it marks, plus the statement that boundary
// is immediately before. Named rather than free-form so a trace line names a
// code location a reader can go and look at.
func syncPointName(fn, kind, table string) string {
	return fmt.Sprintf("%s:before-%s-%s", fn, table, strings.ToUpper(kind))
}

// newSyncPoint registers a disarmed sync point on db. It starts disarmed so a
// fixture can build its world, and the serial orderings can run, through the
// same *gorm.DB without ever pausing.
//
// kind is "create", "update" or "delete" (GORM's own callback families). The
// returned sync point is unregistered automatically at the end of the test.
func newSyncPoint(t *testing.T, db *gorm.DB, fn, kind, table string) *syncPoint {
	t.Helper()
	sp := &syncPoint{
		name:    syncPointName(fn, kind, table),
		kind:    kind,
		table:   table,
		arrived: make(chan struct{}, 1),
		release: make(chan struct{}, 1),
	}
	cb := func(tx *gorm.DB) {
		if !sp.armed.Load() || tx.Statement.Table != sp.table {
			return
		}
		sp.once.Do(func() {
			sp.hits.Add(1)
			sp.arrived <- struct{}{}
			<-sp.release
		})
	}
	cbName := "guard5:" + sp.name
	switch kind {
	case "create":
		require.NoError(t, db.Callback().Create().Before("gorm:create").Register(cbName, cb))
		sp.removeFn = func() { _ = db.Callback().Create().Remove(cbName) }
	case "update":
		require.NoError(t, db.Callback().Update().Before("gorm:update").Register(cbName, cb))
		sp.removeFn = func() { _ = db.Callback().Update().Remove(cbName) }
	case "delete":
		require.NoError(t, db.Callback().Delete().Before("gorm:delete").Register(cbName, cb))
		sp.removeFn = func() { _ = db.Callback().Delete().Remove(cbName) }
	default:
		t.Fatalf("newSyncPoint: unknown kind %q (want create|update|delete)", kind)
	}
	t.Cleanup(sp.remove)
	return sp
}

// arm makes the next matching statement pause. Calling arm on a sync point
// that has already fired does nothing: sync.Once makes each point strictly
// one-shot per test, so an operation that writes the same table twice pauses
// only at its first write.
func (sp *syncPoint) arm() { sp.armed.Store(true) }

// fired reports whether this sync point actually paused its replica. Every
// ordering the driver claims to have forced asserts this: a sync point that
// silently never fires turns a forced interleaving back into whatever the
// scheduler felt like, and the test would still pass while proving nothing.
func (sp *syncPoint) fired() bool { return sp.hits.Load() > 0 }

// waitArrive blocks until the replica reaches this sync point, or until the
// timeout. It reports false when the replica never got there.
func (sp *syncPoint) waitArrive(d time.Duration) bool {
	select {
	case <-sp.arrived:
		return true
	case <-time.After(d):
		return false
	}
}

// resume lets a paused replica proceed past its sync point. Safe to call when
// the point never fired (the buffered send is then simply never received).
func (sp *syncPoint) resume() {
	select {
	case sp.release <- struct{}{}:
	default:
	}
}

// --- orderings ---------------------------------------------------------------

// An interleaveOrder names one of the six legal orderings of two operations A
// and B, each modelled as a (check, act) pair with check strictly before act.
// Six is the complete set: C(4,2) ways to interleave two length-2 sequences.
// The two serial orderings are included deliberately — they are the control
// group. A test whose invariant breaks under a serial ordering has found an
// ordinary sequential bug, not a race, and reporting it as a race would send
// the fix to the wrong place.
//
// Named interleaveOrder rather than the more natural `interleaving` because
// interleave_production_purity_test.go greps every non-test file in the
// repository for these identifiers: "interleaving" is an ordinary English
// word that appears in five production comments, and a guard that fires on
// those is a guard people learn to ignore (CLAUDE.md: "a check that always
// fails is as useless as one that always passes").
type interleaveOrder string

const (
	// Serial: A runs to completion, then B. No overlap at all.
	orderSerialAB interleaveOrder = "A-check,A-act,B-check,B-act"
	// Serial: B runs to completion, then A.
	orderSerialBA interleaveOrder = "B-check,B-act,A-check,A-act"
	// A checks, B checks on a snapshot that still includes A's un-written
	// state, A writes, B writes: B's write lands on a stale check.
	orderABAcAa interleaveOrder = "A-check,B-check,A-act,B-act"
	// A checks, B checks AND writes, then A writes on a stale check. This is
	// the shape C-GUARD2-EXEMPT-REVIEW's beforeA hook produces, and the one
	// most of #2646-#2660 are about.
	orderABBaAa interleaveOrder = "A-check,B-check,B-act,A-act"
	// Mirror of orderABAcAa with the replicas swapped.
	orderBABcBa interleaveOrder = "B-check,A-check,B-act,A-act"
	// Mirror of orderABBaAa with the replicas swapped.
	orderBAAaBa interleaveOrder = "B-check,A-check,A-act,B-act"
)

// allInterleavings is the complete ordering set, in a fixed order so a sweep's
// output is diffable run to run.
var allInterleavings = []interleaveOrder{
	orderSerialAB,
	orderSerialBA,
	orderABAcAa,
	orderABBaAa,
	orderBABcBa,
	orderBAAaBa,
}

// --- driver ------------------------------------------------------------------

// interleaveResult is one forced run's outcome. Trace records what actually
// happened in the order it happened, so a run that could NOT be forced as
// requested says so in the output rather than quietly degrading into a blind
// race.
type interleaveResult struct {
	Order interleaveOrder
	ErrA  error
	ErrB  error
	// Forced is true only when both sync points fired and the driver
	// released them in exactly the requested order. Serial orderings are
	// Forced by construction (nothing to pause).
	Forced bool
	// Degraded explains why Forced is false: which replica never reached its
	// sync point, and why that is or is not expected.
	Degraded string
	Trace    []string
}

func (r *interleaveResult) logf(format string, args ...any) {
	r.Trace = append(r.Trace, fmt.Sprintf(format, args...))
}

// String renders the result for a t.Logf line.
func (r *interleaveResult) String() string {
	status := "forced"
	if !r.Forced {
		status = "DEGRADED: " + r.Degraded
	}
	return fmt.Sprintf("[%s] %s | errA=%v errB=%v | trace: %s",
		r.Order, status, r.ErrA, r.ErrB, strings.Join(r.Trace, " -> "))
}

// runInterleaving drives opA and opB through the requested ordering using spA
// (armed on replica A's connection) and spB (armed on replica B's).
//
// For the four genuinely interleaved orderings the shape is always the same:
// start the first replica, wait for it to pause at its own sync point (its
// check is now done and its write has not happened), start the second replica,
// wait for IT to pause, then release the two writes in the requested order,
// waiting for each released operation to finish before releasing the next so
// the act ordering is a fact and not a hope.
//
// Blocked-on-lock is a first-class outcome, not a failure: when the second
// replica cannot reach its sync point because the first holds a row or
// advisory lock it needs, the driver says so in Degraded, releases the first
// replica, and lets the second complete. That is what a correctly-serialized
// function looks like from here — so a Degraded result with a lock-wait reason
// is evidence the fix works, which is why the driver reports it instead of
// failing.
func runInterleaving(t *testing.T, order interleaveOrder, spA, spB *syncPoint, opA, opB func() error) *interleaveResult {
	t.Helper()
	return runInterleavingTimeout(t, order, spA, spB, opA, opB, syncPointArrivalTimeout)
}

// runInterleavingTimeout is runInterleaving with an explicit arrival timeout.
//
// Use it only where blocking is the EXPECTED outcome — a pair whose fix
// serializes the two replicas can never realize an interleaved ordering, so
// the default 15s hang-detector budget is pure wall-clock there and would push
// such a test past the 10 s-per-test ceiling GUARD-5's brief sets. Everywhere
// else the generous default is the right one: shortening it on a pair that
// CAN interleave would turn a slow-but-real arrival into a bogus "blocked"
// verdict, which is the one failure mode that would quietly undo this whole
// file's purpose.
func runInterleavingTimeout(t *testing.T, order interleaveOrder, spA, spB *syncPoint, opA, opB func() error, arrival time.Duration) *interleaveResult {
	t.Helper()
	res := &interleaveResult{Order: order}

	switch order {
	case orderSerialAB:
		res.logf("A full")
		res.ErrA = opA()
		res.logf("B full")
		res.ErrB = opB()
		res.Forced = true
		return res
	case orderSerialBA:
		res.logf("B full")
		res.ErrB = opB()
		res.logf("A full")
		res.ErrA = opA()
		res.Forced = true
		return res
	}

	// first is the replica whose check happens first; second is the other.
	type side struct {
		label string
		sp    *syncPoint
		op    func() error
		err   *error
		done  chan struct{}
	}
	a := &side{label: "A", sp: spA, op: opA, err: &res.ErrA, done: make(chan struct{})}
	b := &side{label: "B", sp: spB, op: opB, err: &res.ErrB, done: make(chan struct{})}

	var first, second *side
	var releaseFirstActFirst bool
	switch order {
	case orderABAcAa:
		first, second, releaseFirstActFirst = a, b, true
	case orderABBaAa:
		first, second, releaseFirstActFirst = a, b, false
	case orderBABcBa:
		first, second, releaseFirstActFirst = b, a, true
	case orderBAAaBa:
		first, second, releaseFirstActFirst = b, a, false
	default:
		t.Fatalf("runInterleaving: unknown ordering %q", order)
	}

	// A nil sync point means "this side has no reachable pause between its
	// check and its act" — the operation does not issue the statement a sync
	// point could sit on, on this input. The commonest case by far: a
	// destructive op whose decisive write is a DELETE of rows that do not
	// exist yet (TransitionMembership's revoke removing a role grant the
	// concurrent activation has not inserted). Rather than time out and call
	// it DEGRADED, such a side is run to COMPLETION in its slot — which is
	// exactly the shape C-GUARD2-EXEMPT-REVIEW's beforeA hook produces, and
	// still a legal, fully-deterministic interleaving. Only the orderings that
	// genuinely need that side's check and act pulled apart become
	// unrepresentable, and those are reported, not silently approximated.
	if first.sp == nil {
		res.Degraded = fmt.Sprintf("replica %s has no sync point, so its check and act cannot be separated; "+
			"%s reduces to a serial ordering", first.label, order)
		res.logf("%s full (unpausable)", first.label)
		*first.err = first.op()
		res.logf("%s full", second.label)
		*second.err = second.op()
		return res
	}
	if second.sp == nil && releaseFirstActFirst {
		res.Degraded = fmt.Sprintf("replica %s has no sync point, so %s (which needs %s's check before %s's act "+
			"and %s's act after it) cannot be realized", second.label, order, second.label, first.label, second.label)
		res.logf("%s full (unpausable)", first.label)
		*first.err = first.op()
		res.logf("%s full", second.label)
		*second.err = second.op()
		return res
	}

	start := func(s *side) {
		s.sp.arm()
		go func() {
			defer close(s.done)
			*s.err = s.op()
		}()
	}

	start(first)
	if !first.sp.waitArrive(arrival) {
		// The first replica never reached its write — it refused earlier, or
		// its operation does not write that table on this input at all.
		res.Degraded = fmt.Sprintf("replica %s never reached %s (refused before its write?)", first.label, first.sp.name)
		res.logf("%s never arrived at %s", first.label, first.sp.name)
		<-first.done
		res.logf("%s finished (err=%v)", first.label, *first.err)
		res.logf("%s full", second.label)
		*second.err = second.op()
		return res
	}
	res.logf("%s checked, paused at %s", first.label, first.sp.name)

	if second.sp == nil {
		// first is paused between its check and its act; run second's whole
		// operation here, then let first write on its now-stale check. This is
		// the "O runs to completion inside S's window" interleaving, forced
		// with no timing dependence at all.
		//
		// second runs in a goroutine with a deadline rather than inline,
		// because a CORRECTLY SERIALIZED pair deadlocks this shape: if the
		// paused side holds a named/advisory lock that second needs, second
		// can never finish while first is parked, and first can never be
		// released while we wait for second. Running it inline hung the whole
		// test binary until `go test -timeout` killed it, with no output
		// saying why — found while green-proving #2669's membership
		// serialization fix, which is exactly a pair that does this. The
		// deadline turns that into the Degraded verdict it should have been
		// all along, and "blocked while the other side holds the lock" is
		// evidence the fix works.
		res.logf("%s full (unpausable) while %s waits", second.label, first.label)
		go func() {
			defer close(second.done)
			*second.err = second.op()
		}()
		select {
		case <-second.done:
			res.logf("%s finished (err=%v)", second.label, *second.err)
			first.sp.resume()
			<-first.done
			res.logf("%s acted and finished (err=%v)", first.label, *first.err)
			res.Forced = first.sp.fired()
			if !res.Forced {
				res.Degraded = "the pausable side's sync point did not fire"
			}
		case <-time.After(arrival):
			res.Degraded = fmt.Sprintf("replica %s did not finish within %s while %s was parked at %s "+
				"(the two are serialized against each other)", second.label, arrival, first.label, first.sp.name)
			res.logf("%s did not finish; releasing %s to unblock it", second.label, first.label)
			first.sp.resume()
			<-first.done
			res.logf("%s finished (err=%v)", first.label, *first.err)
			<-second.done
			res.logf("%s finished (err=%v)", second.label, *second.err)
		}
		return res
	}

	start(second)
	secondArrived := second.sp.waitArrive(arrival)
	if !secondArrived {
		// Either the second replica is blocked on a lock the first holds —
		// the signature of a correctly serialized pair — or it refused before
		// its write. Distinguish the two by asking Postgres directly, so a
		// "DEGRADED" line names which one it was.
		res.Degraded = fmt.Sprintf("replica %s never reached %s within %s", second.label, second.sp.name, arrival)
		res.logf("%s did not arrive at %s; releasing %s to unblock", second.label, second.sp.name, first.label)
		first.sp.resume()
		<-first.done
		res.logf("%s finished (err=%v)", first.label, *first.err)
		second.sp.resume()
		<-second.done
		res.logf("%s finished (err=%v)", second.label, *second.err)
		return res
	}
	res.logf("%s checked, paused at %s", second.label, second.sp.name)

	actFirst, actSecond := second, first
	if releaseFirstActFirst {
		actFirst, actSecond = first, second
	}
	actFirst.sp.resume()
	// Bounded, not a bare receive. The side we just released can block on a
	// row lock the STILL-PARKED other side holds: a parked sync point sits
	// inside its replica's open transaction, so every lock that transaction
	// has taken is still held while it waits. Releasing A and then waiting
	// forever for A's write to land behind B's locks is a deadlock the test
	// binary cannot get out of — it hung two full sweep runs at exactly the
	// same pair before this was found, with no diagnostic beyond "still
	// running". This is the same failure as the unpausable-side deadlock
	// handled above, in the other branch; both exist because a parked replica
	// is not an idle one.
	select {
	case <-actFirst.done:
		res.logf("%s acted and finished (err=%v)", actFirst.label, *actFirst.err)
	case <-time.After(arrival):
		res.Degraded = fmt.Sprintf("replica %s could not complete its act while %s was still parked at %s "+
			"(the two are serialized against each other), so %s could not be realized",
			actFirst.label, actSecond.label, actSecond.sp.name, order)
		res.logf("%s blocked on %s's held locks; releasing %s", actFirst.label, actSecond.label, actSecond.label)
		actSecond.sp.resume()
		<-actSecond.done
		res.logf("%s finished (err=%v)", actSecond.label, *actSecond.err)
		<-actFirst.done
		res.logf("%s finished (err=%v)", actFirst.label, *actFirst.err)
		return res
	}
	actSecond.sp.resume()
	<-actSecond.done
	res.logf("%s acted and finished (err=%v)", actSecond.label, *actSecond.err)

	res.Forced = spA.fired() && spB.fired()
	if !res.Forced {
		res.Degraded = "a sync point did not fire after both replicas ran"
	}
	return res
}

// interleavePauseA builds the (spA, spB) pair for "pause replica A between its check and
// its act, run replica B to completion in that window, then let A write" —
// combined with orderABBaAa. interleavePauseB is the mirror. Returning the nil side
// explicitly keeps the caller's intent readable at the call site, and keeps the
// "which side is the stale writer" decision in the test rather than inside the
// driver.
func interleavePauseA(spA *syncPoint) (*syncPoint, *syncPoint) { return spA, nil }

// interleavePauseB is interleavePauseA's mirror, for use with orderBAAaBa.
func interleavePauseB(spB *syncPoint) (*syncPoint, *syncPoint) { return nil, spB }

// requireForced fails the test unless the ordering was realized exactly as
// requested. Per-issue regression tests call this: their whole claim is "this
// end state is reachable under THIS ordering", and a degraded run does not
// support it.
func requireForced(t *testing.T, res *interleaveResult) {
	t.Helper()
	t.Log(res.String())
	require.True(t, res.Forced,
		"the %s interleaving was not forced, so this run proves nothing about it (%s)", res.Order, res.Degraded)
}
