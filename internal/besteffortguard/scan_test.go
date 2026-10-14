// scan_test.go — the best-effort guard's own calibration (#2561).
//
// The guard shipped with no demonstration that it could ever go red. Three
// packages ran it, all three were green, and nothing anywhere established
// whether that green meant "the codebase is clean" or "the scanner matches
// nothing". CLAUDE.md is blunt about which of those to assume: "a guard nobody
// has watched fail is not a guard", and "a check that always passes" is
// indistinguishable from no check at all.
//
// So this file runs the scanner against a planted fixture
// (testdata/planted/planted.go.txt) whose functions are NAMED for the verdict
// the scanner must reach, and asserts both directions: every MustFlag* appears
// and every MustNotFlag* does not. A matcher deleted from scan.go fails here,
// not silently-passes everywhere.
package besteffortguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plantedRoot copies the .txt fixture into a temp dir as a .go file, so the
// scanner's own directory walk (which skips _test.go and anything containing
// "generated") sees it exactly as it would see a real source file. The fixture
// is stored as .txt in-repo so the Go toolchain never tries to build or vet
// deliberately-broken code.
func plantedRoot(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", "planted", "planted.go.txt"))
	if err != nil {
		t.Fatalf("reading planted fixture: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "planted.go"), src, 0o600); err != nil {
		t.Fatalf("writing planted fixture: %v", err)
	}
	return dir
}

// TestScan_PlantedFixtureIsFlagged is the red-proof: the scanner must flag
// every function the fixture names MustFlag*, and must NOT flag any it names
// MustNotFlag*.
//
// Deriving the expectation from the fixture's own function names, rather than
// hardcoding a list here, means adding a case to the fixture automatically
// adds it to this assertion -- there is no second list to forget to update.
func TestScan_PlantedFixtureIsFlagged(t *testing.T) {
	t.Parallel()
	root := plantedRoot(t)

	res, err := Scan(root, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	flagged := map[string]Hit{}
	for _, h := range res.Hits {
		flagged[h.Func] = h
	}

	src, err := os.ReadFile(filepath.Join("testdata", "planted", "planted.go.txt"))
	if err != nil {
		t.Fatalf("reading planted fixture: %v", err)
	}
	var wantFlagged, wantClean []string
	for line := range strings.SplitSeq(string(src), "\n") {
		name, ok := plantedFuncName(line)
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(name, "MustFlag"):
			wantFlagged = append(wantFlagged, "(*svc)."+name)
		case strings.HasPrefix(name, "MustNotFlag"):
			wantClean = append(wantClean, "(*svc)."+name)
		}
	}
	if len(wantFlagged) < 6 || len(wantClean) < 10 {
		t.Fatalf("planted fixture parsed as %d positive / %d negative case(s); the fixture itself is broken or was gutted",
			len(wantFlagged), len(wantClean))
	}

	for _, fn := range wantFlagged {
		if _, ok := flagged[fn]; !ok {
			t.Errorf("planted positive %s was NOT flagged -- the scanner no longer catches the shape this case plants", fn)
		}
	}
	for _, fn := range wantClean {
		if h, ok := flagged[fn]; ok {
			t.Errorf("planted negative %s WAS flagged (%s discard of %s@%d) -- the scanner over-reports; a guard that flags everything is as useless as one that flags nothing",
				fn, h.Kind, h.DiscardCall, h.DiscardLine)
		}
	}
}

// plantedFuncName extracts "Name" from a `func (s *svc) Name() error {` line.
func plantedFuncName(line string) (string, bool) {
	const prefix = "func (s *svc) "
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(line, prefix)
	name, _, found := strings.Cut(rest, "(")
	if !found || name == "" {
		return "", false
	}
	return name, true
}

// TestScan_BothDiscardKindsAreProduced pins that the two kinds are genuinely
// distinguished, so a regression collapsing KindBare back into "not scanned"
// (the v1 behaviour) shows up as a missing kind rather than as a slightly
// smaller hit count nobody notices.
func TestScan_BothDiscardKindsAreProduced(t *testing.T) {
	t.Parallel()
	res, err := Scan(plantedRoot(t), Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	kinds := map[DiscardKind]int{}
	for _, h := range res.Hits {
		kinds[h.Kind]++
	}
	if kinds[KindBlank] == 0 {
		t.Error("no KindBlank hits: the scanner stopped seeing `_ = f()` entirely")
	}
	if kinds[KindBare] == 0 {
		t.Error("no KindBare hits: the scanner stopped seeing a bare `f()` whose result is dropped (#2561's widening)")
	}
}

// TestScan_WriteReceiverFieldRestriction pins the Options knob the three
// callers differ on, in both directions: with the restriction set to a field
// the fixture does not use, the fixture's writes stop counting as writes and
// EVERY hit disappears. A knob that silently does nothing is how
// server/http/handlers would end up scanning for writes it never finds.
func TestScan_WriteReceiverFieldRestriction(t *testing.T) {
	t.Parallel()
	root := plantedRoot(t)

	unrestricted, err := Scan(root, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(unrestricted.Hits) == 0 {
		t.Fatal("unrestricted scan found nothing; the rest of this test proves nothing")
	}

	// The fixture writes via `s.storage.CreateThing()`, so "storage" matches...
	matching, err := Scan(root, Options{WriteReceiverField: "storage"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(matching.Hits) != len(unrestricted.Hits) {
		t.Errorf("WriteReceiverField=%q found %d hits, want the same %d as unrestricted -- the fixture's writes all go through that field",
			"storage", len(matching.Hits), len(unrestricted.Hits))
	}

	// ...and a field nothing uses matches no write, so nothing is post-write.
	none, err := Scan(root, Options{WriteReceiverField: "noSuchField"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(none.Hits) != 0 {
		t.Errorf("WriteReceiverField=%q found %d hits, want 0 -- the restriction is not being applied", "noSuchField", len(none.Hits))
	}
	if none.Stats.FuncsWithWrite != 0 {
		t.Errorf("WriteReceiverField=%q reported %d functions with writes, want 0", "noSuchField", none.Stats.FuncsWithWrite)
	}
}

// TestStaleExemptions_FlagsAPardonForNothing is the direct unit test for the
// check whose absence let evictUserSessionCache sit in the exemption file
// pardoning zero hits.
func TestStaleExemptions_FlagsAPardonForNothing(t *testing.T) {
	t.Parallel()
	hits := []Hit{{Func: "(*T).Live", Callee: "callee"}}
	exempt := map[Key]Exemption{
		{Func: "(*T).Live", Callee: "callee"}:  {Reason: "live", Line: 1},
		{Func: "(*T).Gone", Callee: "callee"}:  {Reason: "stale", Line: 2},
		{Func: "(*T).Live", Callee: "other"}:   {Reason: "stale: right fn, wrong callee", Line: 3},
		{Func: "(*T).Live2", Callee: "callee"}: {Reason: "stale: right callee, wrong fn", Line: 4},
	}
	stale := StaleExemptions(hits, exempt)
	if len(stale) != 3 {
		t.Fatalf("StaleExemptions = %v, want exactly the 3 non-matching rows", stale)
	}
	for _, want := range []string{"(*T).Gone#callee", "(*T).Live#other", "(*T).Live2#callee"} {
		found := false
		for _, s := range stale {
			if strings.HasPrefix(s, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("StaleExemptions missing %s; got %v", want, stale)
		}
	}
}

// TestUnclassified_ExemptionIsPerCalleeNotPerFunction is the unit test for the
// key change: an exemption for one callee must NOT absorb a new, unprotected
// discard of a different callee added to the same function later. That
// absorption is what the whole-function key did, and why `ActivateMFA` could
// have grown a second discard invisibly.
func TestUnclassified_ExemptionIsPerCalleeNotPerFunction(t *testing.T) {
	t.Parallel()
	hits := []Hit{
		{Func: "(*C).ActivateMFA", Callee: "deleteSessionsForUserAndEvict", File: "mfa.go"},
		{Func: "(*C).ActivateMFA", Callee: "somethingNewAndUnprotected", File: "mfa.go"},
	}
	exempt := map[Key]Exemption{
		{Func: "(*C).ActivateMFA", Callee: "deleteSessionsForUserAndEvict"}: {Reason: "callee recovers its own panic", Line: 1},
	}
	unclassified := Unclassified(hits, exempt)
	if len(unclassified) != 1 {
		t.Fatalf("Unclassified = %v, want exactly the one unexempted callee", unclassified)
	}
	if !strings.Contains(unclassified[0], "somethingNewAndUnprotected") {
		t.Errorf("Unclassified = %v, want the NEW callee, not the exempted one", unclassified)
	}
}

// TestLoadExemptions_RejectsFunctionOnlyKey: the old whole-function key format
// must be rejected outright, not silently accepted as a function with an empty
// callee -- otherwise a stale v1 row would keep pardoning a whole function.
func TestLoadExemptions_RejectsFunctionOnlyKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "exempt.tsv")
	if err := os.WriteFile(path, []byte("internal/core:(*C).Foo\tsome reason\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if _, err := LoadExemptions(path, "internal/core"); err == nil {
		t.Fatal("LoadExemptions accepted a function-only key; a v1 row must be rejected, not silently honoured")
	}
}

// TestLoadExemptions_RejectsMissingReason: a row with no reason is not a
// reviewed exemption, it is a suppression.
func TestLoadExemptions_RejectsMissingReason(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "exempt.tsv")
	if err := os.WriteFile(path, []byte("internal/core:(*C).Foo#bar\tsite-reviewed\t\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if _, err := LoadExemptions(path, "internal/core"); err == nil {
		t.Fatal("LoadExemptions accepted a row with an empty reason")
	}
}

// TestLoadExemptions_RejectsCalleeWildcard: wildcarding the CALLEE would
// reproduce exactly the v1 whole-function pardon this format replaced.
func TestLoadExemptions_RejectsCalleeWildcard(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "exempt.tsv")
	row := "internal/core:(*C).Foo#*\tsite-reviewed\ta reason that is comfortably longer than the minimum length\n"
	if err := os.WriteFile(path, []byte(row), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if _, err := LoadExemptions(path, "internal/core"); err == nil {
		t.Fatal("LoadExemptions accepted a callee wildcard, which pardons every discard in that function")
	}
}

// TestLoadExemptions_RejectsUnknownGuard: the guard column must be one of the
// three kinds, or a typo would silently become an unverified claim.
func TestLoadExemptions_RejectsUnknownGuard(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "exempt.tsv")
	row := "internal/core:(*C).Foo#bar\tprobably-fine\ta reason that is comfortably longer than the minimum length\n"
	if err := os.WriteFile(path, []byte(row), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if _, err := LoadExemptions(path, "internal/core"); err == nil {
		t.Fatal("LoadExemptions accepted an unknown guard kind")
	}
}

// verifyFixture writes a tiny package into a temp dir for
// VerifyExemptionGuards to analyse.
func verifyFixture(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("package x\n"+src), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return dir
}

// TestVerifyExemptionGuards checks the check: an exemption that CLAIMS its
// callee recovers must be rejected when it doesn't, accepted when it does, and
// the "via" form must insist the named choke point is both real and actually
// reachable from the callee.
//
// Without this, the guard column would be the same kind of unverified prose as
// v1's reason string -- which is the specific failure this whole PR is about.
func TestVerifyExemptionGuards(t *testing.T) {
	t.Parallel()
	const src = `
func recovers() error { defer func() { _ = recover() }(); return nil }
func doesNotRecover() error { return nil }
func wrapper() error { return chokePoint() }
func chokePoint() error { defer func() { _ = recover() }(); return nil }
func unrelatedRecoverer() error { defer func() { _ = recover() }(); return nil }
`
	root := verifyFixture(t, src)

	for _, tc := range []struct {
		name      string
		key       Key
		guard     string
		wantProbs bool
	}{
		{"callee really recovers", Key{Func: "(*T).F", Callee: "recovers"}, GuardCalleeRecovers, false},
		{"callee does not recover", Key{Func: "(*T).F", Callee: "doesNotRecover"}, GuardCalleeRecovers, true},
		{"callee not declared here", Key{Func: "(*T).F", Callee: "noSuchFunc"}, GuardCalleeRecovers, true},
		{"via a real, reachable choke point", Key{Func: "(*T).F", Callee: "wrapper"}, GuardCalleeRecoversViaPrefix + "chokePoint", false},
		{"via a choke point that does not recover", Key{Func: "(*T).F", Callee: "wrapper"}, GuardCalleeRecoversViaPrefix + "doesNotRecover", true},
		{"via a recoverer the callee never calls", Key{Func: "(*T).F", Callee: "wrapper"}, GuardCalleeRecoversViaPrefix + "unrelatedRecoverer", true},
		{"via a function that does not exist", Key{Func: "(*T).F", Callee: "wrapper"}, GuardCalleeRecoversViaPrefix + "nope", true},
		{"site-reviewed is never derived-checked", Key{Func: "(*T).F", Callee: "doesNotRecover"}, GuardSiteReviewed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probs, err := VerifyExemptionGuards(root, map[Key]Exemption{
				tc.key: {Key: tc.key, Guard: tc.guard, Reason: "x", Line: 1},
			})
			if err != nil {
				t.Fatalf("VerifyExemptionGuards: %v", err)
			}
			if tc.wantProbs && len(probs) == 0 {
				t.Errorf("guard %q on callee %q was accepted; want a problem reported", tc.guard, tc.key.Callee)
			}
			if !tc.wantProbs && len(probs) != 0 {
				t.Errorf("guard %q on callee %q reported %v; want none", tc.guard, tc.key.Callee, probs)
			}
		})
	}
}

// TestScan_DerivedSafetyIsNotTransitive is the regression test for a draft of
// #2561 that got this wrong. The rule "safe if it CALLS something that
// recovers" cleared 365 of internal/core's 1430 functions, because almost
// everything eventually reaches an audit helper -- and it is false: a recover()
// in a callee protects only that callee.
func TestScan_DerivedSafetyIsNotTransitive(t *testing.T) {
	t.Parallel()
	res, err := Scan(plantedRoot(t), Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	safe := map[string]bool{}
	for _, n := range res.SafeCallees {
		safe[n] = true
	}
	for _, want := range []string{"genuinelyRecovers", "recoversViaBestEffort"} {
		if !safe[want] {
			t.Errorf("%s defers a recover() in its own body but was not derived as panic-safe", want)
		}
	}
	for _, notWant := range []string{"delegatesToRecoverer", "selfRecoveringHelper", "doesNotRecoverAtAll"} {
		if safe[notWant] {
			t.Errorf("%s has no deferred recover() in its OWN body but was derived as panic-safe -- the safety rule has "+
				"become transitive again, which silently suppresses exactly the reports this guard exists to make", notWant)
		}
	}
	if res.Stats.ProtectedDiscards == 0 {
		t.Error("no discards were classified as protected; the derived-safety path is not running at all")
	}
}

// TestScan_NameCollisionResolvesToUnsafe is #2561 round 2's BLOCKER 2 proving
// test: "collidingName" is declared on BOTH *svc (genuinely recovers) and
// *otherSvc (does not) in the planted fixture. The bare-name index must
// resolve the whole name as UNSAFE -- a name is safe only if EVERY
// declaration sharing it is safe. The pre-fix version kept only the first
// declaration ENCOUNTERED while building the index (map iteration over the
// scanned files has no defined order), so which one "won" was
// nondeterministic, and a genuinely-unsafe method could be silently credited
// as safe whenever its same-named, safe sibling happened to be visited first.
func TestScan_NameCollisionResolvesToUnsafe(t *testing.T) {
	t.Parallel()
	res, err := Scan(plantedRoot(t), Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, n := range res.SafeCallees {
		if n == "collidingName" {
			t.Fatal("collidingName was derived as panic-safe, but one of its two same-named declarations " +
				"(*otherSvc) does not recover -- a collision must resolve toward unsafe, not toward whichever " +
				"declaration the index happened to see first")
		}
	}
}
