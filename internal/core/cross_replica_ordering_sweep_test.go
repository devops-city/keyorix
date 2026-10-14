// cross_replica_ordering_sweep_test.go — GUARD-5 item 3: enumerate the hook
// ORDERINGS for every conflicting operation pair the fuzzer knows, rather than
// hoping random timing lands on the bad one.
//
// # WHAT THIS ADDS OVER THE OTHER TWO FILES
//
// cross_replica_forced_interleaving_test.go forces ONE ordering per KNOWN
// issue — the one that issue's own report describes. That is the right shape
// for a regression test and the wrong shape for discovery: it can only ever
// confirm what someone already wrote down. This file inverts it. For each
// conflicting pair it runs all SIX legal interleavings of the two (check, act)
// pairs and reports every one that breaks an invariant, against a registry of
// the orderings already explained by an open issue. Anything outside that
// registry is a finding.
//
// Including the two SERIAL orderings is deliberate and load-bearing: an
// invariant that breaks under "A runs completely, then B runs completely" is
// an ordinary sequential bug, not a race, and reporting it as a race would
// send the fix to the wrong layer. The sweep labels them separately.
//
// # WHY IT IS ENV-GATED AND NOT IN THE DEFAULT CI RUN
//
// 33 pairs x 6 orderings = 198 forced runs, each needing a full world reset,
// plus a multi-second wait on every ordering a correctly-serialized pair makes
// unreachable. That is minutes, not seconds, and its value is DISCOVERY, which
// is a thing you want nightly and on demand — not on every PR, where the
// twelve per-issue regression tests are the right cost/benefit. So it is gated
// on KEYORIX_INTERLEAVE_SWEEP=1 and wired into the nightly rig
// (scripts/fuzzing/nightly-cross-replica.sh).
//
// Being honest about what that costs: an env-gated test contributes nothing to
// an ordinary CI run, which is normally an anti-pattern in this repo ("a guard
// nobody has watched fail is not a guard"). It is not acting as a guard here —
// g5KnownOrderingViolations is the finding ledger, the per-issue tests are the
// guard, and the nightly run is what watches this one. If the nightly stops
// running, this file stops being worth anything, which is why item 4's script
// sends an ntfy line on failure rather than writing to a log nobody reads.
//
// Postgres only; skipped cleanly when KEYORIX_TEST_PG_DSN is unset.
package core

import (
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// --- the conflicting-pair catalog -------------------------------------------

// g5ConflictFamily is one resource whose lifecycle two ops can disagree about:
// a set of DESTRUCTIVE ops (delete/revoke/suspend/disable) and a set of
// CONSTRUCTIVE ops (create/restore/grant/enable/update) over the same
// resource. The sweep crosses the two sets.
//
// COMPLETENESS, STATED RATHER THAN ASSUMED. This catalog is derived from
// g5OpSyncPoints (the ops a sync point can be placed on) grouped by the
// resource whose liveness or state the two ops contend over. It is NOT the
// full 40x40 product, and the three exclusions are deliberate:
//
//   - ops with no sync-point spec (9 of the 40 kinds) cannot be forced at all,
//     so including them would silently degrade to a blind race. They are
//     listed in g5OpsWithoutSyncPoints below and reported by
//     TestOrderingSweep_CatalogCoversEveryForceableOp so the gap stays
//     visible instead of becoming folklore.
//   - pairs from different families (e.g. DeleteSecret against SuspendUser)
//     touch disjoint rows and have nothing to contend over. Including them
//     would multiply the runtime by ~20x for no reachable violation.
//   - destructive-against-destructive and constructive-against-constructive
//     pairs are excluded EXCEPT where both directions genuinely matter
//     (the admin-removal pair 36/37, and the dependency-cycle pair 28/29),
//     which are listed explicitly as their own family.
//
// A reviewer who disagrees with any of those three should add the family here;
// the sweep will then cover it, and this comment is the thing to argue with.
type g5ConflictFamily struct {
	name         string
	destructive  []byte
	constructive []byte
}

var g5ConflictFamilies = []g5ConflictFamily{
	{
		name:        "secret-lifecycle",
		destructive: []byte{0}, // DeleteSecret
		// RestoreSecret, both share paths, the share-permission update, the ACL
		// grant, the full-row auto-rotate Save, and both dependency adds — every
		// op whose write lands on a row the delete cascade sweeps.
		constructive: []byte{1, 6, 7, 8, 10, 38, 28},
	},
	{
		name:         "project-lifecycle",
		destructive:  []byte{2}, // DeleteProject
		constructive: []byte{3, 5, 12, 30, 33, 39},
	},
	{
		name:         "environment-lifecycle",
		destructive:  []byte{4}, // DeleteEnvironment
		constructive: []byte{5},
	},
	{
		name:         "share-grant",
		destructive:  []byte{9},    // RevokeShare
		constructive: []byte{6, 8}, // re-share, permission update
	},
	{
		name:         "acl-grant",
		destructive:  []byte{11}, // RevokeSecretACL
		constructive: []byte{10},
	},
	{
		name:        "user-account-state",
		destructive: []byte{21}, // SuspendUser
		// Every write path that persists a full user row and can therefore
		// revert the suspension or the password change.
		constructive: []byte{22, 23, 24, 25},
	},
	{
		name:         "membership",
		destructive:  []byte{14}, // TransitionMembership(revoke)
		constructive: []byte{12, 13},
	},
	{
		name:         "mfa-enrolment",
		destructive:  []byte{26}, // BeginMFAEnrollment (supersedes the pending secret)
		constructive: []byte{27}, // ActivateMFA
	},
	{
		name:         "dynamic-secret-config",
		destructive:  []byte{32}, // disable
		constructive: []byte{30, 33, 39},
	},
	{
		name:         "global-admin-ceiling",
		destructive:  []byte{36}, // remove admin 1's global role
		constructive: []byte{37}, // ... concurrently with admin 2's
	},
	{
		name:         "dependency-graph",
		destructive:  []byte{29}, // add the reverse edge (the cycle attempt)
		constructive: []byte{28}, // add the forward edge
	},
}

// g5OpsWithoutSyncPoints are the op kinds this sweep cannot force, because no
// g5OpSyncPoints entry says where their check/act boundary is. Recorded so the
// sweep's coverage claim is checkable rather than asserted; see
// TestOrderingSweep_CatalogCoversEveryForceableOp.
var g5OpsWithoutSyncPoints = []byte{15, 16, 17, 18, 19, 20, 31, 34, 35}

// g5ConflictPair is one (destructive, constructive) pair with its family.
type g5ConflictPair struct {
	family string
	a, b   g4Op
}

func (p g5ConflictPair) key() string {
	sa, _ := g5SpecFor(p.a)
	sb, _ := g5SpecFor(p.b)
	return fmt.Sprintf("%s/%s||%s", p.family, sa.fn, sb.fn)
}

// g5EnumerateConflictPairs flattens the families into the pair list, in a
// fixed order so the sweep's output is diffable run to run.
func g5EnumerateConflictPairs() []g5ConflictPair {
	var out []g5ConflictPair
	for _, fam := range g5ConflictFamilies {
		for _, d := range fam.destructive {
			for _, c := range fam.constructive {
				out = append(out, g5ConflictPair{family: fam.name, a: g4Op{kind: d}, b: g4Op{kind: c}})
			}
		}
	}
	return out
}

// --- the known-violation ledger ---------------------------------------------

// g5KnownOrderingViolations maps a (pair key, ordering) the sweep is EXPECTED
// to find broken on main to the open issue that explains it. The sweep fails
// on anything not listed — that is the whole point: a violation nobody has
// written down is a finding.
//
// Keys are "<family>/<opA fn>||<opB fn>" exactly as g5ConflictPair.key()
// renders them, so a typo'd key shows up as an unexplained violation (loud)
// rather than as a silently excused one (quiet). The value is the issue
// number; delete a row when its fix lands, in the same PR.
//
// Populated from an actual full sweep run on main, not from reading the
// issues: every row here was observed. See the PR body for the raw output.
// #2831 landed the fixes for 2646, 2647, 2649, 2652, 2653, 2654, 2655, 2656
// and 2657 and promoted their seeds into the live corpus, so their rows are
// deleted here per the rule above: a row kept past its fix would excuse a
// regression of that ordering forever. The sweep is now expected to find
// those orderings clean, and will report them loudly if it does not.
// #2891 likewise promoted #2650's seed (its fix landed via #2668), so its two
// rows are deleted here too, for the same reason. #2659's fix landed via
// #2669 and its seed was promoted (see #2852, which also replaced invariant
// 6's cross-row-join check with the INV-CORE-44 one), so its two rows are
// deleted here as well. #2884 promoted #2651's seed (its fix landed via
// #2675), so its two rows are deleted here too.
// #2806's three rows are deleted by the PR that fixed it (the parent-liveness
// check in SetDynamicSecretConfigEnabled), leaving the ledger empty.
var g5KnownOrderingViolations = map[string]string{}

// g5LedgerIssuesWithoutASeed documents every g5KnownOrderingViolations issue
// that legitimately has no entry in pendingSeedFix, and why.
//
// The default rule is the strict one:
// TestOrderingSweep_KnownViolationKeysAreWellFormed demands that a ledger
// row's issue still be listed in pendingSeedFix, so that when a fix lands and
// its seed is promoted, the matching ledger row has to be deleted too —
// otherwise the sweep would go on excusing that ordering forever, which is a
// silenced regression rather than a known bug. A blanket exception would
// defeat that; an enumerated one with a reason per entry does not.
var g5LedgerIssuesWithoutASeed = map[string]string{
	// Empty, and that is the correct steady state: every ledger row should be
	// traceable to a pending fuzzer seed, so that promoting the seed forces
	// the row to be deleted with it. #2806 lived here while its fix was
	// pending (the sweep found it serially, so it never had a seed); the fix
	// landed in the same PR as this deletion.
}

// --- the sweep ---------------------------------------------------------------

// g5SweepOutcome is one (pair, ordering) result.
type g5SweepOutcome struct {
	key       string
	order     interleaveOrder
	forced    bool
	degraded  string
	violation string
	issue     string
	serial    bool
	// baselineDirty is set when the reset baseline was ALREADY violating an
	// invariant before this run's ordering was applied, so nothing the run
	// observed can be attributed to the ordering. The run is skipped, not
	// failed; see g5SweepOne.
	baselineDirty string
}

// TestOrderingSweep_Postgres runs every conflicting pair through every
// ordering and fails on any invariant break not explained by an open issue.
//
// Gated on KEYORIX_INTERLEAVE_SWEEP=1 — see this file's header for why, and
// why that is a considered trade rather than an oversight.
func TestOrderingSweep_Postgres(t *testing.T) {
	if os.Getenv("KEYORIX_INTERLEAVE_SWEEP") != "1" {
		t.Skip("KEYORIX_INTERLEAVE_SWEEP != 1 — the full 198-run ordering sweep is nightly/on-demand; " +
			"the per-issue regression tests in cross_replica_forced_interleaving_test.go are the CI-resident half")
	}
	w := buildG4World(t)
	pairs := g5EnumerateConflictPairs()
	t.Logf("sweeping %d conflicting pairs x %d orderings = %d forced runs",
		len(pairs), len(allInterleavings), len(pairs)*len(allInterleavings))

	var outcomes []g5SweepOutcome
	for _, p := range pairs {
		for _, order := range allInterleavings {
			outcomes = append(outcomes, g5SweepOne(t, w, p, order))
		}
	}

	// The audit-chain invariant is checked ONCE, here, rather than after each
	// of the 174 runs: it re-hashes the whole audit log, which grows
	// monotonically for the life of the world, so per-run checking made the
	// sweep quadratic and it blew a 60-minute timeout without finishing (first
	// real run, 2026-10-05). The per-issue regression tests and the fuzz
	// target still check it per pair, which is where attributing a chain break
	// to one operation actually matters.
	if v := g4FindAuditChainViolation(t, w); v != "" {
		t.Errorf("audit chain broken at the end of the sweep: %s "+
			"(not attributable to one ordering — re-run the per-issue tests to localize it)", v)
	}

	var unexplained, explained, serialBreaks, knownSerial, skipped []g5SweepOutcome
	for _, o := range outcomes {
		if o.baselineDirty != "" {
			skipped = append(skipped, o)
			continue
		}
		if o.violation == "" {
			continue
		}
		// Ledger membership is checked FIRST, including for the serial
		// orderings. A serial break is a louder kind of finding — no amount
		// of locking fixes it — but once it has an issue and a ledger row, it
		// is acknowledged, and reporting it as an error every run would make
		// this test permanently red. "A check that always fails is as useless
		// as one that always passes, and worse, because it teaches people to
		// ignore it" (CLAUDE.md). An UNLEDGERED serial break still errors,
		// separately from an unledgered interleaved one, so the distinction
		// survives where it matters.
		switch {
		case o.issue != "" && o.serial:
			knownSerial = append(knownSerial, o)
		case o.issue != "":
			explained = append(explained, o)
		case o.serial:
			serialBreaks = append(serialBreaks, o)
		default:
			unexplained = append(unexplained, o)
		}
	}

	t.Logf("%d/%d runs broke an invariant: %d explained by an open issue (%d of them SEQUENTIAL, not races), "+
		"%d UNEXPLAINED, %d unledgered SEQUENTIAL; %d runs not tested (dirty baseline)",
		len(explained)+len(knownSerial)+len(serialBreaks)+len(unexplained), len(outcomes),
		len(explained)+len(knownSerial), len(knownSerial), len(unexplained), len(serialBreaks), len(skipped))
	for _, o := range explained {
		t.Logf("  [known #%s] %s %s: %s", o.issue, o.key, o.order, o.violation)
	}
	for _, o := range knownSerial {
		t.Logf("  [known #%s, SEQUENTIAL — not a race] %s %s: %s", o.issue, o.key, o.order, o.violation)
	}

	// Skipped runs are a COVERAGE GAP, reported as a failure rather than a
	// log line: the sweep's whole claim is "every ordering of every
	// conflicting pair was tried", and a skipped run means it was not. The
	// fix is in g4ResetIteration (the reset does not clean whatever row the
	// previous run left), not here.
	for _, o := range skipped {
		t.Errorf("NOT TESTED — %s under %s: the reset baseline was already violating (%s). "+
			"g4ResetIteration does not clean up after some earlier run; this ordering was never exercised.",
			o.key, o.order, o.baselineDirty)
	}

	// A serial break is NOT a race: it means the invariant fails even when the
	// two operations never overlap. Reported separately and loudly, because
	// the fix belongs in the operation itself, not in a lock.
	for _, o := range serialBreaks {
		t.Errorf("SEQUENTIAL (not a race) invariant break — %s under %s: %s\n"+
			"Both operations ran to completion without overlapping, so no amount of locking fixes this.",
			o.key, o.order, o.violation)
	}
	for _, o := range unexplained {
		t.Errorf("UNEXPLAINED invariant break — %s under %s: %s\n"+
			"No g5KnownOrderingViolations row covers this (forced=%v degraded=%q). "+
			"Either file an issue and add the row, or it is a new bug.",
			o.key, o.order, o.violation, o.forced, o.degraded)
	}
}

// g5SweepOne forces one (pair, ordering) from a fresh baseline and reports
// what happened.
func g5SweepOne(t *testing.T, w *g4World, p g5ConflictPair, order interleaveOrder) g5SweepOutcome {
	t.Helper()
	out := g5SweepOutcome{
		key:    p.key(),
		order:  order,
		serial: order == orderSerialAB || order == orderSerialBA,
	}
	out.issue = g5KnownOrderingViolations[out.key+":"+string(order)]

	campaignID := g4ResetIteration(t, w)
	w.mu.Lock()
	w.campaignID = campaignID
	w.mu.Unlock()
	// The membership family needs a `provisioned` membership for the activate
	// op to do anything (see g5SeedProvisionedMembership) — but ONLY for the
	// activate pair: seeding it for the invite pair makes the invite refuse.
	if sb, ok := g5SpecFor(p.b); ok && sb.fn == "TransitionMembership(activate)" {
		g5SeedProvisionedMembership(t, w)
	}
	// Non-fatal on purpose. require.Empty here would FailNow and discard
	// every result the sweep had already collected — 170-odd forced runs
	// thrown away because one earlier run left a row the reset does not
	// clean. For a discovery tool that is the wrong trade: record the run as
	// unusable, skip it, and report the count at the end so the coverage gap
	// is visible rather than silently absorbed.
	if base := g4FindStateViolation(t, w); base != "" {
		out.baselineDirty = base
		return out
	}

	// Both sides get a sync point here, unlike the per-issue tests: the sweep
	// does not know in advance which side writes stale data, and that is the
	// question it is asking. A side that cannot reach its sync point is
	// reported as Degraded by the driver, not silently raced.
	spA := g5NewSyncPoint(t, w.db0, p.a, "A")
	spB := g5NewSyncPoint(t, w.db1, p.b, "B")
	// Unregister as soon as this run is done, NOT at the end of the test:
	// GORM walks one callback chain per *gorm.DB for every statement, so
	// leaving 2 x 174 sync points registered makes the sweep quadratic. See
	// syncPoint.remove.
	defer func() { spA.remove(); spB.remove() }()

	res := runInterleavingTimeout(t, order, spA, spB,
		func() error { g4RunOp(t, w, w.c0, p.a); return nil },
		func() error { g4RunOp(t, w, w.c1, p.b); return nil },
		g5SweepArrivalTimeout,
	)
	out.forced, out.degraded = res.Forced, res.Degraded
	out.violation = g4FindStateViolation(t, w)
	return out
}

// g5SweepArrivalTimeout is deliberately short. The sweep's dominant cost is
// waiting on orderings that are unreachable — a destructive op whose DELETE
// has no rows to remove never reaches its sync point, and 198 runs x 15 s of
// the driver's default would be 50 minutes of pure waiting. 2 s is ~6x the
// slowest observed real arrival (0.35 s) in this package.
//
// The risk this accepts, stated: a slow arrival misread as "unreachable" turns
// a would-be forced run into a Degraded one, and a Degraded run that then
// shows no violation is indistinguishable from a clean pass — so the sweep
// could MISS a finding. It cannot invent one. That is the right direction for
// a discovery tool whose results are all hand-read anyway, and the nightly
// run's own invocation uses a longer budget.
//
// Lowered from 2s to 1s after the first real run: 174 runs x up to 2 s of
// waiting on unreachable orderings was a large part of why that run did not
// finish inside a 60-minute timeout. 1 s is still ~3x the slowest real
// arrival observed in this package (0.35 s).
const g5SweepArrivalTimeout = 1 * time.Second

// TestOrderingSweep_CatalogCoversEveryForceableOp keeps the sweep's coverage
// claim checkable: every op kind that HAS a sync-point spec must either appear
// in a conflict family or be listed in g5OpsWithoutSyncPoints. Needs no
// Postgres, so it runs in the no-DSN quick CI path — which matters, because it
// is the only part of this file CI exercises.
//
// This is the check that would have caught the share/ACL family being dead
// (#2768) one level up: a family whose ops exist but are never crossed with
// anything reads, from the outside, exactly like a family that was covered.
func TestOrderingSweep_CatalogCoversEveryForceableOp(t *testing.T) {
	t.Parallel()
	inFamily := map[byte]bool{}
	for _, fam := range g5ConflictFamilies {
		for _, k := range fam.destructive {
			inFamily[k] = true
		}
		for _, k := range fam.constructive {
			inFamily[k] = true
		}
	}
	noSpec := map[byte]bool{}
	for _, k := range g5OpsWithoutSyncPoints {
		noSpec[k] = true
	}

	var uncovered []int
	for kind := range byte(g4NumOpKinds) {
		_, hasSpec := g5OpSyncPoints[kind]
		switch {
		case hasSpec && !inFamily[kind]:
			uncovered = append(uncovered, int(kind))
		case !hasSpec && !noSpec[kind]:
			t.Errorf("op kind %d has no g5OpSyncPoints entry and is not listed in g5OpsWithoutSyncPoints — "+
				"the sweep's coverage claim does not account for it", kind)
		case hasSpec && noSpec[kind]:
			t.Errorf("op kind %d is listed in g5OpsWithoutSyncPoints but DOES have a sync-point spec — "+
				"it should be in a conflict family instead", kind)
		}
	}
	sort.Ints(uncovered)
	require.Empty(t, uncovered,
		"these op kinds can be forced but appear in no conflict family, so the sweep never crosses them with anything: %v. "+
			"Add them to a family, or move them to g5OpsWithoutSyncPoints with a reason.", uncovered)
}

// TestOrderingSweep_KnownViolationKeysAreWellFormed catches a typo'd ledger
// row before it can silently excuse a real finding: every key in
// g5KnownOrderingViolations must name a pair the sweep actually enumerates and
// an ordering the driver actually knows. A key that matches nothing would make
// the ledger row dead and the corresponding violation unexplained — loud, but
// confusingly so.
//
// It also catches the opposite, which is the dangerous direction: a row whose
// pair/ordering IS enumerated but whose issue number no longer has a
// pendingSeedFix entry (i.e. the fix landed) is a row that should have been
// deleted, and leaving it would excuse a regression forever.
func TestOrderingSweep_KnownViolationKeysAreWellFormed(t *testing.T) {
	t.Parallel()
	valid := map[string]bool{}
	for _, p := range g5EnumerateConflictPairs() {
		for _, o := range allInterleavings {
			valid[p.key()+":"+string(o)] = true
		}
	}
	for key, issue := range g5KnownOrderingViolations {
		require.True(t, valid[key],
			"g5KnownOrderingViolations key %q names no (pair, ordering) the sweep enumerates — "+
				"check the family name and the two function names against g5ConflictPair.key()", key)
		if _, hasSeed := pendingSeedFix[issue]; !hasSeed {
			require.Contains(t, g5LedgerIssuesWithoutASeed, issue,
				"g5KnownOrderingViolations row %q is attributed to #%s, which has no pendingSeedFix entry and no "+
					"g5LedgerIssuesWithoutASeed reason — either its fix landed (delete the row, or the sweep will "+
					"excuse a regression of it forever) or it needs a documented reason here", key, issue)
		}
	}
}
