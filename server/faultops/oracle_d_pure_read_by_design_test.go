// oracle_d_pure_read_by_design_test.go — FUZZ-RULES-2 (#3091): oracle (d) may
// consult a reviewed oracle (a) KindError row for an effect-then-error fault on
// the same (op, method, nth) when the faulted method is a pure read.
//
// Why this is the same decision, not a new one
// --------------------------------------------
// effect-then-error runs the real storage call and then reports an error. For
// a call that writes, that is a different state from the error kind's (the
// write happened), and oracle (d) rightly demands old-or-new. For a pure read
// there is no effect to apply: the caller sees the same error after the same
// (absent) state change, so the run ends in exactly the state the KindError
// fault leaves. When that error-kind state is already reviewed and registered
// as by design (oracleAByDesignErrors), refusing the identical state under the
// other kind label only re-reports a decided case.
// #3091 is that case: REST POST /auth/webauthn/login/finish,
// GetUserPermissions#1/effect-then-error leaves [LoginAttempt AuditEvent],
// exactly the post_auth_webauthn_login_finish_getuserpermissions row's state
// (#2880 / #2894 / #2841).
//
// What it checks, per run (oracleDPureReadByDesign)
//   - kind is effect-then-error, the op reported an error, and the method is in
//     pureReadMethods;
//   - a KindError row for the same op, method and nth exists AND opts in
//     (pureReadEffectThenError); every other row is ignored;
//   - the diff vs the pre-fault state is EXACTLY that row's tables plus
//     outcomeLogs (not merely a subset: the slot was kept and the audit
//     written, as in the error-kind run).
//
// What it checks, per row (TestOracleDPureRead_RowsAreLoadBearing)
//   - the row's own tuple, driven with BOTH kinds, gives the same response and
//     the same differing tables: the "pure read" premise, observed, not assumed;
//   - the effect-then-error case passes the real oracle with the opt-in and is
//     reported by oracle (d) without it (load-bearing);
//   - the same case relabelled to another op or another nth is reported.
//
// What it does NOT do
//   - It does not classify storage methods as reads by itself. pureReadMethods
//     is a reviewed list; the per-row drive above is what confirms it for each
//     tuple that uses it.
//   - It does not extend to a row with wrongCredentialResponse or consumedBy
//     (those carry their own effect-then-error rows) nor to panic.
package faultops

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// pureReadMethods are the storage methods reviewed as pure reads for this
// rule. GetUserPermissions resolves a user's permission names with SELECTs
// only (#3091 review, SESSION-FUZZ-FIX-A). Add a method only with the same
// review; the per-row check still drives every tuple that relies on it.
var pureReadMethods = map[string]bool{
	"GetUserPermissions": true,
}

// oracleDPureReadByDesign returns the opted-in KindError row that accounts for
// an effect-then-error run's whole diff, or nil.
func oracleDPureReadByDesign(in oracleInput, diff []string) *oracleAByDesignError {
	if in.kind != faultstorage.KindEffectThenError || in.result.Success || !pureReadMethods[in.method] || len(diff) == 0 {
		return nil
	}
	for i := range oracleAByDesignErrors {
		e := &oracleAByDesignErrors[i]
		if !e.pureReadEffectThenError || e.kind != faultstorage.KindError ||
			e.op != in.op || e.method != in.method || e.nth != in.nth {
			continue
		}
		allowed := append(append([]string{}, e.tables...), e.outcomeLogs...)
		if diffSubsetOf(diff, allowed) && diffSubsetOf(allowed, diff) {
			return e
		}
	}
	return nil
}

// TestOracleDPureRead_RowsAreScoped: an opted-in row is a pinned KindError row
// on a reviewed pure read, with no post-verdict or class-B fields (those rows
// have their own effect-then-error rows), and its proving test exists.
func TestOracleDPureRead_RowsAreScoped(t *testing.T) {
	t.Parallel()
	n := 0
	for _, e := range oracleAByDesignErrors {
		if !e.pureReadEffectThenError {
			continue
		}
		n++
		label := fmt.Sprintf("%s/%s/%s#%d", e.op, e.method, e.kind, e.nth)
		if e.kind != faultstorage.KindError {
			t.Errorf("%s: pureReadEffectThenError is only meaningful on a KindError row", label)
		}
		if !pureReadMethods[e.method] {
			t.Errorf("%s: %s is not in pureReadMethods", label, e.method)
		}
		if e.nth <= 0 {
			t.Errorf("%s: nth must be pinned", label)
		}
		if e.wrongCredentialResponse != "" || e.consumedBy != "" {
			t.Errorf("%s: a post-verdict or class-B row carries its own effect-then-error row; do not opt it in", label)
		}
		if err := provingTestExists(e.provingTest); err != nil {
			t.Errorf("%s: %v", label, err)
		}
	}
	if n == 0 {
		t.Fatal("no row opts in to pureReadEffectThenError: oracleDPureReadByDesign is dead, remove it with its call in oracle (d)")
	}
}

// TestOracleDPureRead_RowsAreLoadBearing drives every opted-in row's tuple with
// both kinds through the real harness and the real oracle.
func TestOracleDPureRead_RowsAreLoadBearing(t *testing.T) {
	n := 0
	for _, e := range oracleAByDesignErrors {
		if !e.pureReadEffectThenError {
			continue
		}
		n++
		e := e
		label := fmt.Sprintf("%s/%s#%d", e.op, e.method, e.nth)
		t.Run(strings.ReplaceAll(label, "/", "_"), func(t *testing.T) {
			asErr, outcome, reason := driveFaultCase(t, e.op, e.method, e.nth, faultstorage.KindError)
			if outcome != driveObserved {
				t.Fatalf("error kind could not be driven (%s: %s)", outcome, reason)
			}
			ete, outcome, reason := driveFaultCase(t, e.op, e.method, e.nth, faultstorage.KindEffectThenError)
			if outcome != driveObserved {
				t.Fatalf("effect-then-error could not be driven (%s: %s)", outcome, reason)
			}
			// The pure-read premise, observed for this tuple.
			if asErr.result != ete.result {
				t.Fatalf("premise: effect-then-error answered %+v, the error kind %+v -- not a pure read here", ete.result, asErr.result)
			}
			errDiff, eteDiff := sortedCopy(diffTables(asErr.before, asErr.after)), sortedCopy(diffTables(ete.before, ete.after))
			if strings.Join(errDiff, ",") != strings.Join(eteDiff, ",") {
				t.Fatalf("premise: effect-then-error diverges in %v, the error kind in %v -- not the same state", eteDiff, errDiff)
			}
			// Load-bearing, both directions, through the real oracle.
			if f := oracleFindingsWithout(t, ete, func() func() { return func() {} }); len(f) > 0 {
				t.Fatalf("with the opt-in the oracle still reports: %v", f)
			}
			f := oracleFindingsWithout(t, ete, func() func() { return withoutPureReadOptIn(e) })
			if len(f) == 0 || !strings.Contains(f[0], "ORACLE (d)") {
				t.Fatalf("without the opt-in oracle (d) must report this case; got %v", f)
			}
			// Op- and nth-scoped: the same run relabelled is not accepted.
			for _, relabel := range []func(*oracleInput){
				func(in *oracleInput) { in.op = "REST POST /auth/login" },
				func(in *oracleInput) { in.nth = e.nth + 1 },
			} {
				in := ete
				relabel(&in)
				if oracleDPureReadByDesign(in, diffTables(in.before, in.after)) != nil {
					t.Errorf("accepted the case relabelled as (%s, nth %d)", in.op, in.nth)
				}
			}
			t.Logf("load-bearing: %s effect-then-error == error (%s, diff %v)", label, ete.result.Detail, eteDiff)
		})
	}
	if n == 0 {
		t.Fatal("no row opts in to pureReadEffectThenError")
	}
}

// withoutPureReadOptIn clears e's opt-in and returns the restore.
func withoutPureReadOptIn(e oracleAByDesignError) func() {
	saved := oracleAByDesignErrors
	cp := append([]oracleAByDesignError(nil), saved...)
	for i := range cp {
		if cp[i].op == e.op && cp[i].method == e.method && cp[i].kind == e.kind && cp[i].nth == e.nth {
			cp[i].pureReadEffectThenError = false
		}
	}
	oracleAByDesignErrors = cp
	return func() { oracleAByDesignErrors = saved }
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// provingTestExists resolves a "<repo dir>/<TestName>[/subtest...]" citation
// and reports an error unless that directory has a `func <TestName>(`.
func provingTestExists(cite string) error {
	i := strings.Index(cite, "/Test")
	if i < 0 {
		return fmt.Errorf("provingTest %q is not <dir>/<TestName>", cite)
	}
	dir, name := cite[:i], cite[i+1:]
	if j := strings.Index(name, "/"); j >= 0 {
		name = name[:j]
	}
	files, err := filepath.Glob(filepath.Join("..", "..", dir, "*_test.go"))
	if err != nil || len(files) == 0 {
		return fmt.Errorf("provingTest %q: no test files in %s", cite, dir)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "func "+name+"(") {
			return nil
		}
	}
	return fmt.Errorf("provingTest %q: no func %s in %s", cite, name, dir)
}
