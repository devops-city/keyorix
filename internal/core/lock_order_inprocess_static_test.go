// lock_order_inprocess_static_test.go — #2694: one declared acquisition order
// for every lock a call chain can hold while it takes another, in-process
// mutexes included, checked statically over every call site.
//
// storage.NamedLockOrder (C-GUARD-3) orders WithNamedLock key families only,
// and its runtime check sees only nestings a test drives. An ABBA between a
// sync.Mutex and a named lock (mutex, then WithNamedLock, in one function; the
// named lock, then the mutex, in another) deadlocks within one process — the
// named lock's layer 1 is an in-process FIFO queue — and neither half saw it.
// TestLockOrder_InProcessLocksFollowDeclaredOrder builds the static
// acquisition graph (lock_order_graph_test.go) of internal/core,
// internal/core/storage and internal/storage/store and requires every edge
// A -> B ("B is acquired while A is held") to go DOWN lockOrderTable.
//
// # Which in-process locks exist (how the list is known to be complete)
//
// The idioms that can make one goroutine wait for another, and how each is
// handled. Derived from the language and the packages' imports, then checked
// with `rg` over the three packages' non-test files on 2026-10-17:
//
//   - sync.Mutex / sync.RWMutex fields, package variables, array shards and
//     returned pointers (Lock, RLock, TryLock, TryRLock): recognised by the
//     callee's type, so every receiver shape is a node.
//   - sync.Once.Do and singleflight.Group.Do: concurrent callers wait for the
//     one running fn, so they are nodes too (fn runs under them).
//   - sync.Map (rotationBackendLocks, impersonationCeilingCache, three SQL
//     memo caches): never blocks; only rotationBackendLocks stores mutexes,
//     and those are found through rotationBackendLock()'s return value.
//   - channels used as locks or hand-offs: the SQLite write gate (a
//     chan struct{} of capacity 1, internal/storage — what WithTransaction
//     takes, so it is the WithTransaction node); the named-lock ticket queue
//     (inside WithNamedLock, so the named node); the audit flusher hand-off
//     (submitAuditBatchItem waits for runAuditFlusher's batch transaction) —
//     declared in lockOrderHandoffs; the audit broker's signal channels
//     (audit_stream.go, non-blocking sends). No other buffered channel of
//     capacity N is acquired-then-released in these packages.
//   - DB locks: WithNamedLock families, WithTransaction (SQLite write gate,
//     Postgres request connection), WithBootstrapLock,
//     WithAuditCheckpointLock, WithSchedulerLock. Row locks (SELECT … FOR
//     UPDATE) live inside a transaction and are not nodes of their own.
//   - errgroup / WaitGroup.Go / time.AfterFunc / context.AfterFunc: run fn on
//     another goroutine, which starts holding nothing.
//
// semaphore.Weighted, sync.Cond and atomic spin locks: none in these packages
// (`rg 'semaphore\.|sync\.Cond|CompareAndSwap'`: one CompareAndSwap, a
// generation counter in audit_verify_state.go, not a lock).
//
// # What the scan does not see (say so, per CLAUDE.md)
//
//   - Callers outside the three packages (server/*, internal/notifychan): a
//     server-side mutex held across a core call is not a node. A one-off scan
//     with KEYORIX_LOCK_ORDER_EXTRA="../../server/... ../notifychan"
//     (2026-10-17) found none — server mutexes are only ever acquired last;
//     the only server-side holder is WithSchedulerLock, whose row is below.
//     A new one would be invisible to this test.
//   - Calls through function values stored in struct fields, and through
//     interfaces other than storage.Storage (notifiers, KMS providers): the
//     callee is unknown, so nothing it acquires is an edge.
//   - Which receiver a store method runs on: a gorm Transaction inside a
//     store method is a new transaction on the root store and a SAVEPOINT on
//     a transaction-scoped one; the scan cannot tell, which is why
//     lockOrderEdgeExemptions exists.
//   - Path feasibility: a hold region is the union over branches, so a lock
//     released on every real path before some call can still produce an
//     edge. A false edge fails loudly here; it never hides a real one.
//   - Same-family named-lock nesting with different IDs: that is
//     NamedLockOrder's Nestable rule, checked at runtime.
package core

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// lockOrderEntry is one row of the declared order.
type lockOrderEntry struct {
	Class  string
	Reason string
}

// lockOrderNamedFamilies stands for every storage.NamedLockOrder family, in
// that order, at its place in lockOrderTable (the named order is declared
// once, there).
const lockOrderNamedFamilies = "<storage.NamedLockOrder>"

// lockOrderTable is the ONE declared acquisition order, outermost first. A
// chain holding a class may only acquire classes BELOW it. Classes that are
// only ever acquired last (nothing is acquired while they are held: caches,
// clock watermarks, the audit head cache) cannot be part of a cycle and are
// deliberately not listed; the test reports any class that has an outgoing
// edge and no row.
//
// If the test reports an inversion, fix the acquisition order in the code (or
// file it); do not move a row to make it legal — the row's other edges then
// break, exactly as with NamedLockOrder.
var lockOrderTable = []lockOrderEntry{
	{"core.KeyorixCore.auditVerifyJobMu", "TryLock only (never waited on): one incremental audit verification at a time; the job then takes the scheduler/checkpoint locks and transactions"},
	{"core.KeyorixCore.accessReviewDecisionMu", "in-process fast path held for all of DecideAccessReviewItem, whose revoke path takes the removal-guard named locks; no lock is ever held when it is taken"},
	{"WithSchedulerLock", "server/main.go's scheduler jobs run under it and call into core (which may take named locks inside it: SetNamedLockDB's doc)"},
	{"WithBootstrapLock", "one-time install seeding; wraps its own transactions"},
	{"WithAuditCheckpointLock", "checkpoint writer; takes the audit watermark mutex and transactions inside"},
	{lockOrderNamedFamilies, "cross-replica named locks, in storage.NamedLockOrder's order: taken before any in-process guard mutex and before the transaction they guard (INV-CORE-41: named lock OUTSIDE, transaction INSIDE)"},
	{"core.KeyorixCore.accountStateMu", "taken inside last-admin-guard (SuspendUser, SCIM, DeleteUser); held across the account-state read-modify-write transaction"},
	{"core.KeyorixCore.globalAdminGuardMu", "taken inside last-admin-guard (RemoveUserRole's global-admin branch); held across the guarded removal's transaction"},
	{"core.KeyorixCore.secretDependencyMu", "taken inside secret-dependency-graph; held across the cycle check and the edge insert"},
	{"core.KeyorixCore.setupResendMu", "held across the resend throttle count and the token write (transactional)"},
	{"core.KeyorixCore.webauthnCredentialMu", "held across the signature-counter read-validate-write (row lock in a transaction)"},
	{"(*github.com/keyorixhq/keyorix/internal/core.KeyorixCore).loginFailureLock()", "per-user shard of loginFailureMu, held across the failed-login counter transaction"},
	{"core.HTTPJWKSResolver.group", "singleflight JWKS fetch; takes only the resolver's own cache mutex"},
	{"core.mfaUpgradeGrace.mu", "ADR-112 grace evaluation: held across the marker/admin reads, the grace-ended audit write and the marker write (each its own short transaction, 5 s context); nothing in those takes it back, and it is never taken inside a transaction"},
	{lockClassTx, "a transaction holds the SQLite write gate / a Postgres request connection: nothing that can wait on another request may be acquired inside it"},
	{"store.LocalStorage.auditChainMu", "the transaction-scoped audit append (logAuditEventDirect) takes it inside the caller's transaction"},
}

// lockOrderEdgeExemptions are edges the scan reports but that cannot happen,
// each with the reason; a row whose edge is no longer reported fails the test.
var lockOrderEdgeExemptions = []struct{ From, To, Reason string }{
	{"store.LocalStorage.auditChainMu", lockClassTx,
		"logAuditEventDirect runs only on a transaction-scoped LocalStorage (logAuditEvent dispatches there when auditFlusher is nil, and only WithTransaction's clones have a nil flusher), so its ls.db.Transaction is a SAVEPOINT on the transaction already held, not a new one"},
}

// lockOrderHandoffs: a call to the key blocks until the value's goroutine has
// run (lock_order_graph_test.go's buildLockGraph).
var lockOrderHandoffs = map[string]string{
	"(*internal/storage/store.LocalStorage).submitAuditBatchItem": "(*internal/storage/store.LocalStorage).runAuditFlusher",
}

// lockOrderRanks expands table into class -> rank.
func lockOrderRanks(table []lockOrderEntry) map[string]int {
	rank := map[string]int{}
	for _, e := range table {
		if e.Class == lockOrderNamedFamilies {
			for _, fam := range storage.NamedLockOrder {
				rank[lockClassNamedPrefix+fam.Prefix] = len(rank)
			}
			continue
		}
		rank[e.Class] = len(rank)
	}
	return rank
}

// checkLockOrder returns one message per edge that goes against table, per
// class held across another acquisition without a row, and per stale row or
// exemption.
func checkLockOrder(g *lockGraph, table []lockOrderEntry, exempt []struct{ From, To, Reason string }) []string {
	rank := lockOrderRanks(table)
	exempted := map[lockEdge]bool{}
	var msgs []string
	for _, x := range exempt {
		e := lockEdge{x.From, x.To}
		exempted[e] = true
		if _, ok := g.edges[e]; !ok {
			msgs = append(msgs, fmt.Sprintf("lockOrderEdgeExemptions: %s -> %s is no longer reported — delete the exemption", x.From, x.To))
		}
	}
	for _, p := range g.unresolved {
		msgs = append(msgs, fmt.Sprintf("%s: WithNamedLock key family not resolvable statically — use a *LockKey const or constructor", p))
	}
	used := map[string]bool{}
	edges := slices.SortedFunc(maps.Keys(g.edges), func(x, y lockEdge) int {
		return strings.Compare(x.from+"\x00"+x.to, y.from+"\x00"+y.to)
	})
	for _, e := range edges {
		used[e.from], used[e.to] = true, true
		if exempted[e] {
			continue
		}
		where := lockShortKey(g.witnessChain(e))
		if e.from == e.to {
			if !lockClassReentrant(e.from) {
				msgs = append(msgs, fmt.Sprintf("self-deadlock: %s is acquired while already held [%s]", e.from, where))
			}
			continue
		}
		rf, okf := rank[e.from]
		if !okf {
			msgs = append(msgs, fmt.Sprintf("%s is held while acquiring %s but has no row in lockOrderTable — declare its place (with a one-line reason) [%s]", e.from, e.to, where))
			continue
		}
		rt, okt := rank[e.to]
		if !okt {
			continue // a leaf: nothing is acquired under it (or it has its own missing-row message)
		}
		if rf > rt {
			msgs = append(msgs, fmt.Sprintf("lock-order violation: %s is acquired while holding %s, but lockOrderTable requires the reverse [%s]", e.to, e.from, where))
		}
	}
	for _, e := range table {
		if e.Class != lockOrderNamedFamilies && !used[e.Class] {
			msgs = append(msgs, fmt.Sprintf("lockOrderTable row %q matches no edge — delete the stale row", e.Class))
		}
		if strings.TrimSpace(e.Reason) == "" {
			msgs = append(msgs, fmt.Sprintf("lockOrderTable row %q has no reason", e.Class))
		}
	}
	return msgs
}

func TestLockOrder_InProcessLocksFollowDeclaredOrder(t *testing.T) {
	fset, pkgs := loadLockOrderPackages(t, ".", "./storage", "../storage/store")
	g := buildLockGraph(t, fset, pkgs, lockOrderHandoffs)

	// The scan must still be seeing what #2694 is about; an empty graph would
	// pass every check below.
	for _, want := range []lockEdge{
		{"named:last-admin-guard", "core.KeyorixCore.accountStateMu"},
		{"named:last-admin-guard", "core.KeyorixCore.globalAdminGuardMu"},
		{"named:secret-dependency-graph:", "core.KeyorixCore.secretDependencyMu"},
		{"core.KeyorixCore.accessReviewDecisionMu", "named:last-admin-guard"},
		{"named:project-admin-guard:", "named:sod-grant:user:"},
		{"core.KeyorixCore.accountStateMu", lockClassTx},
	} {
		if _, ok := g.edges[want]; !ok {
			t.Errorf("lock-order scan no longer sees %s -> %s — the scan stopped seeing call chains it must see", want.from, want.to)
		}
	}
	if len(g.edges) < 50 {
		t.Fatalf("lock-order scan found only %d edges — it stopped following calls", len(g.edges))
	}
	for _, m := range checkLockOrder(g, lockOrderTable, lockOrderEdgeExemptions) {
		t.Error(m)
	}
}

// TestLockOrder_PlantedABBAIsCaught calibrates the guard both ways on
// testdata/lockorder: abba/ holds a mutex and then takes a named lock in one
// function, and takes the named lock and then (through a helper) the mutex in
// another; ok/ only ever takes the mutex inside the named lock. Whichever
// place abba's mutex gets in the table, one of its two edges goes against it;
// ok/ passes with the matching table and fails with the reverse one.
func TestLockOrder_PlantedABBAIsCaught(t *testing.T) {
	fset, pkgs := loadLockOrderPackages(t, "./testdata/lockorder/abba", "./testdata/lockorder/ok")
	for _, p := range pkgs {
		g := buildLockGraph(t, fset, []*packages.Package{p}, nil)
		mu := p.Name + ".svc.mu"
		muFirst := []lockOrderEntry{{mu, "planted: before the named locks"}, {lockOrderNamedFamilies, "named"}}
		muLast := []lockOrderEntry{{lockOrderNamedFamilies, "named"}, {mu, "planted: after the named locks"}}
		violations := func(table []lockOrderEntry) (int, []string) {
			msgs := checkLockOrder(g, table, nil)
			n := 0
			for _, m := range msgs {
				if strings.HasPrefix(m, "lock-order violation") {
					n++
				}
			}
			return n, msgs
		}
		switch p.Name {
		case "abba":
			for _, table := range [][]lockOrderEntry{muFirst, muLast} {
				if n, msgs := violations(table); n == 0 {
					t.Errorf("planted ABBA not caught with %s first; messages: %v", table[0].Class, msgs)
				} else {
					t.Logf("planted ABBA, %s first: %v", table[0].Class, msgs)
				}
			}
		case "ok":
			if _, msgs := violations(muLast); len(msgs) != 0 {
				t.Errorf("consistent nesting reported with the matching table: %v", msgs)
			}
			if n, msgs := violations(muFirst); n == 0 {
				t.Errorf("mutex-inside-named-lock not reported against a table that puts the mutex first: %v", msgs)
			}
		default:
			t.Fatalf("unexpected testdata package %q", p.Name)
		}
	}
}

// TestLockOrder_DumpGraph writes the whole graph, with witness chains, to the
// file KEYORIX_LOCK_ORDER_DUMP names — for placing a new lock in the table.
// KEYORIX_LOCK_ORDER_EXTRA adds space-separated package patterns to the scan
// (e.g. "../../server/..." for the one-off caller scan the header mentions).
func TestLockOrder_DumpGraph(t *testing.T) {
	out := os.Getenv("KEYORIX_LOCK_ORDER_DUMP")
	if out == "" {
		t.Skip("set KEYORIX_LOCK_ORDER_DUMP=<file> to write the lock graph")
	}
	patterns := append([]string{".", "./storage", "../storage/store"}, strings.Fields(os.Getenv("KEYORIX_LOCK_ORDER_EXTRA"))...)
	fset, pkgs := loadLockOrderPackages(t, patterns...)
	g := buildLockGraph(t, fset, pkgs, lockOrderHandoffs)
	edges := slices.SortedFunc(maps.Keys(g.edges), func(x, y lockEdge) int {
		return strings.Compare(x.from+"\x00"+x.to, y.from+"\x00"+y.to)
	})
	var b strings.Builder
	for _, e := range edges {
		fmt.Fprintf(&b, "%s -> %s   [%s]\n", e.from, e.to, strings.ReplaceAll(g.witnessChain(e), lockModule, ""))
	}
	fmt.Fprintf(&b, "unresolved: %v\nclasses: %v\n", g.unresolved, slices.Sorted(maps.Keys(g.classes)))
	if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
