// besteffort_guard_test.go — internal/core's run of the best-effort-after-commit
// structural guard (GUARD-1; v2 per #2561's coordinator review).
//
// The scanner, its documented blind spots, and its own planted-positive
// calibration all live in internal/besteffortguard. This file is just the
// per-package invocation: scan ".", classify against docs/besteffort-exempt.tsv,
// and assert five things rather than one.
//
// Why five. v1 asserted only "no unclassified hits" and was green in all three
// packages, which established nothing about whether it could ever be red:
// delete the matcher and it stays green forever ("a guard nobody has watched
// fail is not a guard"). Measured afterwards, v1 found 5 hits in this package,
// all of one single callee, behind 12 exemption rows — 7 of which pardoned
// nothing at all.
//
// This package now also has ZERO hits, and the route there matters: the 42
// post-commit discards of writeAuditEventFull/writeAuditEventDiff that #2561's
// bare-call widening surfaced were FIXED (both now recover their own panic),
// not exempted — so their safety is derived from source rather than vouched for
// in a row. docs/besteffort-exempt.tsv consequently has no rows at all, which
// is why the assertions below lean on the scan's preconditions.
package guards

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/besteffortguard"
)

const (
	// besteffortExemptKey disambiguates this package's rows in the shared TSV.
	besteffortExemptKey  = "internal/core"
	besteffortExemptPath = "../../../docs/besteffort-exempt.tsv"

	// Floors below which a green result means the SCANNER broke, not that the
	// package got cleaner. Current values: 350 write-containing functions of
	// 1430, 172 discard sites, 51 post-write discards cleared as panic-safe.
	// Set well under those so ordinary refactoring doesn't trip them, but far
	// enough above zero that a matcher silently matching nothing — the exact way
	// a guard rots into a no-op — fails loudly.
	//
	// There is deliberately NO floor on HITS. With protection derived rather
	// than exempted, zero hits is the correct steady state, so a hit floor would
	// have to be zero and would assert nothing. ProtectedDiscards is the number
	// that carries that weight instead: it is non-zero only if the scanner is
	// still resolving callees AND still finding their deferred recovers.
	//
	// A floor is a blunt instrument and deliberately so: it cannot tell you
	// WHICH matcher broke, only that the scan's output collapsed. The planted
	// fixture in internal/besteffortguard is what pins the individual shapes.
	besteffortMinFuncsWithWrite    = 250
	besteffortMinDiscardSites      = 120
	besteffortMinProtectedDiscards = 35
)

// besteffortDerivedSafeCallees are the callees this package's correctness
// depends on the scanner RECOGNISING as already panic-safe. They used to be
// exemption rows (or, for the audit pair, would have become ones); they are now
// derived — the scanner reads their deferred recover() out of the source.
//
// Asserted by name because that derivation is a precondition, not a conclusion.
// If the scanner stopped recognising them, their call sites would become
// unclassified hits and the guard above would fail. But if it started
// recognising them for the WRONG reason — an over-broad safety rule, which an
// earlier draft of this change really did have: it marked 365 of 1430 functions
// safe by treating "calls something that recovers" as sufficient — nothing
// would fail at all. This names the ones that must be there, so the count
// floor is not the only thing standing behind the verdict.
var besteffortDerivedSafeCallees = []string{
	// account.go: recovers its own panic and persists
	// EventSessionRevocationPanicked for the affected user.
	"deleteSessionsForUserAndEvict",
	// account.go: recovers its own panic and logs.
	"evictUserSessionCache",
	// service.go: the single choke point every audit write funnels through.
	"emitAudit",
	// audit.go: both gained their own recover in #2561, which is what removed
	// the two exemption rows this change's first draft needed for their 42
	// post-commit call sites.
	"writeAuditEventFull",
	"writeAuditEventDiff",
}

func besteffortScan(t *testing.T) *besteffortguard.Result {
	t.Helper()
	res, err := besteffortguard.Scan("..", besteffortguard.Options{})
	if err != nil {
		t.Fatalf("besteffort guard: %v", err)
	}
	return res
}

func besteffortExemptions(t *testing.T) map[besteffortguard.Key]besteffortguard.Exemption {
	t.Helper()
	exempt, err := besteffortguard.LoadExemptions(besteffortExemptPath, besteffortExemptKey)
	if err != nil {
		t.Fatalf("besteffort guard: %v", err)
	}
	return exempt
}

// TestBestEffortGuard_UnprotectedPostWriteDiscard is the guard proper: every
// function in this package that drops a call's result after a committed storage
// write must either route it through besteffort.Run, land on a callee that
// recovers its own panic, or carry a reviewed exemption.
func TestBestEffortGuard_UnprotectedPostWriteDiscard(t *testing.T) {
	unclassified := besteffortguard.Unclassified(besteffortScan(t).Hits, besteffortExemptions(t))
	if len(unclassified) > 0 {
		t.Fatalf("besteffort guard: %d (function, callee) pair(s) drop a call's result after a storage write and are not "+
			"panic-protected. Prefer FIXING it — give the callee its own deferred recover(), or wrap the call in "+
			"besteffort.Run (see internal/besteffort) — over adding an %q row, because a derived fact goes red when it "+
			"stops being true and an exemption does not. Unclassified:\n  %s",
			len(unclassified), besteffortExemptKey+":<function>#<callee>", strings.Join(unclassified, "\n  "))
	}
}

// TestBestEffortGuard_NoStaleExemptions: every exemption must still pardon a
// real hit. A row matching nothing is the failure mode the coordinator caught
// on evictUserSessionCache (and six siblings) — it inflates the file's apparent
// coverage, and a row left behind after its hit was FIXED silently pre-approves
// the shape coming back.
func TestBestEffortGuard_NoStaleExemptions(t *testing.T) {
	stale := besteffortguard.StaleExemptions(besteffortScan(t).Hits, besteffortExemptions(t))
	if len(stale) > 0 {
		t.Fatalf("besteffort guard: %d exemption(s) in %s match no current hit. Delete them: a pardon for nothing "+
			"reads exactly like a load-bearing one, and if its hit was fixed, the fix is now un-guarded.\n  %s",
			len(stale), besteffortExemptPath, strings.Join(stale, "\n  "))
	}
}

// TestBestEffortGuard_ExemptionGuardsHoldInSource re-derives each exemption's
// OWN claim from the source on every run: a callee-recovers row's callee must
// really defer a recover(), and a callee-recovers-via row's named choke point
// must really recover AND really be reachable from the callee. Without this the
// guard column would be the same unverified prose as v1's reason string.
//
// Vacuous today (there are no rows), and kept for exactly that reason: the next
// row added must not be the first one anybody checks by hand.
func TestBestEffortGuard_ExemptionGuardsHoldInSource(t *testing.T) {
	problems, err := besteffortguard.VerifyExemptionGuards("..", besteffortExemptions(t))
	if err != nil {
		t.Fatalf("besteffort guard: %v", err)
	}
	if len(problems) > 0 {
		t.Fatalf("besteffort guard: %d exemption(s) in %s assert panic-safety the source does not show:\n  %s",
			len(problems), besteffortExemptPath, strings.Join(problems, "\n  "))
	}
}

// TestBestEffortGuard_ScanPreconditionHolds guards the CONDITION the three
// tests above depend on. Each of them passes trivially when the scan returns
// nothing, so a matcher that quietly stops matching turns all three green at
// once — indistinguishable from a clean package, and worse, because it looks
// like evidence.
func TestBestEffortGuard_ScanPreconditionHolds(t *testing.T) {
	res := besteffortScan(t)
	if res.Stats.FuncsWithWrite < besteffortMinFuncsWithWrite {
		t.Errorf("besteffort guard: scan detected writes in only %d function(s) of %d, floor is %d -- the write-verb "+
			"matcher has stopped recognising storage writes, so every \"post-write\" verdict above is vacuous",
			res.Stats.FuncsWithWrite, res.Stats.Funcs, besteffortMinFuncsWithWrite)
	}
	if res.Stats.DiscardSites < besteffortMinDiscardSites {
		t.Errorf("besteffort guard: scan found only %d discard site(s) anywhere in the package, floor is %d -- the "+
			"discard matcher has stopped matching", res.Stats.DiscardSites, besteffortMinDiscardSites)
	}
	if res.Stats.ProtectedDiscards < besteffortMinProtectedDiscards {
		t.Errorf("besteffort guard: scan classified only %d post-write discard(s) as already panic-safe, floor is %d -- "+
			"the panicSafetyIndex has stopped deriving protection. Since this package's hit count is legitimately zero, "+
			"this number is the main thing standing between \"clean\" and \"the scanner resolved nothing\".",
			res.Stats.ProtectedDiscards, besteffortMinProtectedDiscards)
	}
}

// TestBestEffortGuard_DerivedSafeCalleesAreRecognised asserts the scanner still
// reads the deferred recover() out of the specific callees whose protection is
// derived rather than exempted. See besteffortDerivedSafeCallees for why a
// count floor alone is not enough here.
func TestBestEffortGuard_DerivedSafeCalleesAreRecognised(t *testing.T) {
	safe := map[string]bool{}
	for _, name := range besteffortScan(t).SafeCallees {
		safe[name] = true
	}
	for _, want := range besteffortDerivedSafeCallees {
		if !safe[want] {
			t.Errorf("besteffort guard: %s is no longer derived as panic-safe. Either its deferred recover() was removed "+
				"(a real regression: its callers discard its result after a committed write, so a panic in it would now "+
				"misreport success as failure), or the scanner's panicSafetyIndex stopped recognising the shape.", want)
		}
	}
}
