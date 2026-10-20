// TestEffectThenErrorExclusions_AreLoadBearing is the staleness check for
// effectThenErrorExtraExclusions, the sibling of TestOracleAByDesign_RowsAreLoadBearing
// and TestKnownOpenTolerances_AreLoadBearing (oracle_a_by_design_test.go).
//
// Each row narrows oracle (d) for one (op, method). A row that no longer matters
// (the op stopped writing the downstream table, an earlier layer now accepts the
// case, the op never reaches the error branch) is decoration that tells a reader
// oracle (d) still sees something it does not. So every row is driven by name,
// as an effect-then-error fault at its first call (the ordinal the rows were
// traced at), and must satisfy both halves through the REAL oracle:
//   - without the row, oracle (d) reports a violation;
//   - with the row, it reports nothing.
//
// A case that cannot be driven FAILS: a row that was never exercised has not been
// shown to exclude anything, and a skipped subtest reads like a passing one.
//
// Not covered: a row is driven at nth=1 only. A row that is load-bearing only at
// a later ordinal would be reported as stale here; give it a field for the
// ordinal rather than weakening this check.
package faultops

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// withoutEffectThenErrorRow removes the row at index i (not every row with the
// same op/method: a duplicate that the first-match lookup shadows must be
// reported dead, so identity is the index) and returns the restore.
func withoutEffectThenErrorRow(i int) func() {
	saved := effectThenErrorExtraExclusions
	kept := make([]effectThenErrorExclusion, 0, len(saved))
	kept = append(kept, saved[:i]...)
	kept = append(kept, saved[i+1:]...)
	effectThenErrorExtraExclusions = kept
	return func() { effectThenErrorExtraExclusions = saved }
}

func oracleDFindings(findings []string) []string {
	var d []string
	for _, f := range findings {
		if strings.Contains(f, "ORACLE (d)") {
			d = append(d, f)
		}
	}
	return d
}

// effectThenErrorRowProblem returns why row i is not load-bearing, or "" if it is.
func effectThenErrorRowProblem(t *testing.T, i int) string {
	t.Helper()
	e := effectThenErrorExtraExclusions[i]
	in, outcome, reason := driveFaultCase(t, e.op, e.method, 1, faultstorage.KindEffectThenError)
	if outcome != driveObserved {
		return fmt.Sprintf("its own (op, method) could not be driven as an effect-then-error fault at call 1 (%s: %s); "+
			"fix the row, or fix whatever made the case unreachable", outcome, reason)
	}
	if in.result.Success {
		return "the op reported SUCCESS under effect-then-error, so it never reaches oracle (d)'s error branch " +
			"(the behaviour changed: remove the row, or the row names the wrong case)"
	}
	if f := oracleDFindings(oracleFindingsWithout(t, in, func() func() { return withoutEffectThenErrorRow(i) })); len(f) == 0 {
		return "with the row removed oracle (d) reports nothing for this case, so the row is stale " +
			"(an earlier layer accepts it, or the op no longer produces the diff). Remove it"
	}
	if f := oracleDFindings(oracleFindingsWithout(t, in, func() func() { return func() {} })); len(f) > 0 {
		return fmt.Sprintf("with the row in place oracle (d) still reports: %v. The row does not cover the real diff "+
			"(NOT widened automatically: an unexplained table or column is a different finding)", f)
	}
	return ""
}

func TestEffectThenErrorExclusions_AreLoadBearing(t *testing.T) {
	if len(effectThenErrorExtraExclusions) == 0 {
		t.Fatal("effectThenErrorExtraExclusions is empty: the registry files " +
			"(effect_then_error_exclusion_entry_*_test.go) did not register, or every row was removed " +
			"and this guard should be removed with them")
	}
	for i := range effectThenErrorExtraExclusions {
		e := effectThenErrorExtraExclusions[i]
		label := fmt.Sprintf("%s/%s", e.op, e.method)
		t.Run(label, func(t *testing.T) {
			if p := effectThenErrorRowProblem(t, i); p != "" {
				t.Fatalf("effectThenErrorExclusion %q: %s", label, p)
			}
		})
	}
}
