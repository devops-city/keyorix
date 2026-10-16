// login_fault_classes_test.go guards the ORPHAN-2 follow-ups to the #2844
// login fault sweep, one class each:
//
//   - class A (#2880 post-verdict accounting): the oracleAByDesignErrors rows
//     that carry wrongCredentialResponse. Their pinned response is re-derived
//     here from a REAL wrong-credential run of the same op, and so is the
//     rest of "answered, counted and audited like a wrong credential".
//   - class B (consume-first, docs/atomicity-exempt.tsv): oracle (d) now
//     consults consumeFirstExemptions, the same list oracle (a)'s error branch
//     already used. Pinned in both directions: an exempt op's real tuples pass,
//     and they fail again without the entry. The same diff on an op the ledger
//     does not tie to a consumption still fails.
//   - class D (FinishWebAuthnLogin's best-effort step-up grant): the
//     opScopedBestEffortTables entries that carry pinnedKinds must stay
//     load-bearing.
//
// Every load-bearing check here goes through the real checkOraclesReporting,
// once with the exemption and once without it. Nothing re-derives the oracle's
// layer order, so a check cannot pass while the real oracle disagrees.
package faultops

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// wrongCredentialRequests send a WRONG credential to a class-A op, after the
// op's own catalog Setup (so the fixture is exactly the one the fault runs use).
// A wrongCredentialResponse row on an op with no entry here fails
// TestOracleAByDesign_WrongCredentialOutcomesAreReal: its pinned response
// would be an assertion nobody derived.
var wrongCredentialRequests = map[string]func(ctx context.Context, w *faultWorld, state any) (opResult, error){
	"REST POST /auth/login": func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
		st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/login", map[string]any{
			"username": "faultadmin", "password": faultAdminPassword + "-wrong",
		})
		if err != nil {
			return opResult{}, err
		}
		return httpResult(st, body), nil
	},
	"REST POST /auth/mfa/verify": func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
		st2 := state.([2]string)
		code, err := totpCodeOutsideWindow(st2[0], time.Now())
		if err != nil {
			return opResult{}, err
		}
		st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/mfa/verify", map[string]any{
			"mfa_challenge": st2[1], "code": code,
		})
		if err != nil {
			return opResult{}, err
		}
		return httpResult(st, body), nil
	},
}

// totpCodeOutsideWindow returns a six-digit code that is not valid for secret
// at any step within +/-2 of now, so it is wrong on purpose and not by luck.
func totpCodeOutsideWindow(secret string, now time.Time) (string, error) {
	valid := map[string]bool{}
	for step := -2; step <= 2; step++ {
		c, err := totp.GenerateCode(secret, now.Add(time.Duration(step)*30*time.Second))
		if err != nil {
			return "", err
		}
		valid[c] = true
	}
	for d := range 10 {
		c := strings.Repeat(fmt.Sprint(d), 6)
		if !valid[c] {
			return c, nil
		}
	}
	return "", fmt.Errorf("no repeated-digit code outside the window")
}

// wrongCredentialRun is one fault-free run of op with a wrong credential.
type wrongCredentialRun struct {
	result        opResult
	before, after dbSnapshot
}

func runWrongCredential(t *testing.T, w *faultWorld, op string) wrongCredentialRun {
	t.Helper()
	send, ok := wrongCredentialRequests[op]
	if !ok {
		t.Fatalf("op %q has wrongCredentialResponse rows but no wrongCredentialRequests entry: its pinned "+
			"response cannot be derived, so it is an assertion. Add a request that sends a wrong credential", op)
	}
	var entry *operation
	for i := range opCatalog {
		if opCatalog[i].Key == op {
			entry = &opCatalog[i]
		}
	}
	if entry == nil {
		t.Fatalf("op %q is not in opCatalog", op)
	}
	ctx := context.Background()
	w.resetForReuse(t, nil)
	var state any
	if entry.Setup != nil {
		var err error
		if state, err = entry.Setup(ctx, w); err != nil {
			t.Fatalf("%s: setup: %v", op, err)
		}
	}
	drainAllBackgroundGoroutines()
	before, err := snapshotDB(w.db)
	if err != nil {
		t.Fatal(err)
	}
	w.faulty.Arm(nil)
	res, err := send(ctx, w, state)
	if err != nil {
		t.Fatalf("%s: wrong-credential request: %v", op, err)
	}
	drainAllBackgroundGoroutines()
	after, err := snapshotDB(w.db)
	if err != nil {
		t.Fatal(err)
	}
	return wrongCredentialRun{result: res, before: before, after: after}
}

// TestOracleAByDesign_WrongCredentialOutcomesAreReal derives, per class-A op,
// what a WRONG credential actually gets, and holds every wrongCredentialResponse
// row to it:
//   - the pinned response is byte-identical to the wrong-credential response;
//   - a wrong credential is itself counted (one LoginAttempt row) and audited
//     (an AuditEvent row), so "like a wrong credential" means counted and
//     audited, and the row requires both (postVerdictOutcomeHolds);
//   - the row's tables cover every business table the wrong credential
//     changes (charged at least as much), and every table it adds beyond those
//     is a class-B consumption: named in consumedColumns, with consumedBy a
//     function docs/atomicity-exempt.tsv classifies B.
func TestOracleAByDesign_WrongCredentialOutcomesAreReal(t *testing.T) {
	byOp := map[string][]oracleAByDesignError{}
	for _, e := range oracleAByDesignErrors {
		if e.wrongCredentialResponse != "" {
			byOp[e.op] = append(byOp[e.op], e)
		}
	}
	if len(byOp) == 0 {
		t.Fatal("no wrongCredentialResponse rows at all -- this check would pass while checking nothing")
	}
	classes := atomicityLedgerClasses(t)
	w := buildReusableFaultWorld(t, nil)
	ops := make([]string, 0, len(byOp))
	for op := range byOp {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		run := runWrongCredential(t, w, op)
		if run.result.Success {
			t.Fatalf("%s: the wrong-credential request SUCCEEDED (%s) -- the request is not wrong", op, run.result.Detail)
		}
		if n := addedRows(run.before, run.after, "LoginAttempt"); n != 1 {
			t.Errorf("%s: a wrong credential added %d LoginAttempt rows, want 1 -- the baseline these rows call "+
				"\"counted\" is not what they assume", op, n)
		}
		if addedRows(run.before, run.after, "AuditEvent") == 0 {
			t.Errorf("%s: a wrong credential wrote no AuditEvent -- the baseline these rows call \"audited\" is "+
				"not what they assume", op)
		}
		var wrongBusiness []string
		for _, tb := range diffTables(run.before, run.after) {
			if !isOutcomeLogTable(tb) {
				wrongBusiness = append(wrongBusiness, tb)
			}
		}
		for _, e := range byOp[op] {
			label := fmt.Sprintf("%s/%s#%d/%s", e.op, e.method, e.nth, e.kind)
			if e.wrongCredentialResponse != run.result.Detail {
				t.Errorf("%s: pinned wrongCredentialResponse %q, but a real wrong credential gets %q", label,
					e.wrongCredentialResponse, run.result.Detail)
			}
			if !diffSubsetOf(wrongBusiness, e.tables) {
				t.Errorf("%s: a wrong credential changes %v, the row's tables are %v -- the fault would be charged "+
					"LESS than a wrong credential", label, wrongBusiness, e.tables)
			}
			if !diffSubsetOf([]string{"AuditEvent"}, e.outcomeLogs) {
				t.Errorf("%s: outcomeLogs %v does not require the AuditEvent a wrong credential writes -- the row "+
					"would accept an unaudited fault", label, e.outcomeLogs)
			}
			for _, tb := range e.tables {
				if diffSubsetOf([]string{tb}, wrongBusiness) {
					continue
				}
				if len(e.consumedColumns[tb]) == 0 {
					t.Errorf("%s: table %q is in the row but a wrong credential does not change it, and the row "+
						"declares no class-B consumption for it -- unexplained divergence", label, tb)
				}
			}
			if e.consumedBy != "" && classes[e.consumedBy] != "B" {
				t.Errorf("%s: consumedBy %q is classified %q in docs/atomicity-exempt.tsv, not B", label,
					e.consumedBy, classes[e.consumedBy])
			}
		}
		t.Logf("%s: wrong credential -> %q, business diff %v; %d row(s) checked", op,
			strings.TrimSpace(run.result.Detail), wrongBusiness, len(byOp[op]))
	}
}

// TestPostVerdictOutcome_Calibration: the per-run check must refuse each way
// the decided outcome can be missed, on a real driven case. Green first, so a
// refusal below is about the mutation and not about the case.
func TestPostVerdictOutcome_Calibration(t *testing.T) {
	login, outcome, reason := driveFaultCase(t, "REST POST /auth/login", "GetUserRoles", 1, faultstorage.KindError)
	if outcome != driveObserved {
		t.Fatalf("calibration case could not be driven (%s: %s)", outcome, reason)
	}
	mfa, outcome, reason := driveFaultCase(t, "REST POST /auth/mfa/verify", "GetUserRoles", 1, faultstorage.KindError)
	if outcome != driveObserved {
		t.Fatalf("calibration case could not be driven (%s: %s)", outcome, reason)
	}
	match := func(in oracleInput) bool { return oracleAErrorByDesign(in, diffTables(in.before, in.after)) != nil }

	t.Run("green: the real post-verdict faults match", func(t *testing.T) {
		if !match(login) || !match(mfa) {
			t.Fatalf("the real cases did not match their rows: login %q %v, mfa %q %v",
				login.result.Detail, diffTables(login.before, login.after), mfa.result.Detail, diffTables(mfa.before, mfa.after))
		}
	})
	t.Run("red: answered differently from a wrong credential", func(t *testing.T) {
		in := login
		in.result.Detail = `HTTP 500: {"code":500,"error":"Internal","message":"Login could not be completed. Please try again.","success":false}` + "\n"
		if match(in) {
			t.Fatal("accepted a 500 -- the response is the oracle #2888 is about")
		}
	})
	t.Run("red: the slot was handed back (not counted)", func(t *testing.T) {
		in := login
		in.after = withTable(in.after, "LoginAttempt", in.before.Tables["LoginAttempt"])
		if match(in) {
			t.Fatal("accepted a post-verdict fault that kept no LoginAttempt row -- #3048's shape")
		}
	})
	t.Run("red: no audit event", func(t *testing.T) {
		in := login
		in.after = withTable(in.after, "AuditEvent", in.before.Tables["AuditEvent"])
		if match(in) {
			t.Fatal("accepted an unaudited post-verdict fault")
		}
	})
	t.Run("red: the consumed table moved outside its declared column", func(t *testing.T) {
		in := mfa
		rows := append([]string{}, in.after.Tables["MFASecret"].Rows...)
		if len(rows) == 0 {
			t.Fatal("calibration premise: the MFA case has an MFASecret row")
		}
		rows[0] = strings.Replace(rows[0], `"ID":`, `"Extra":1,"ID":`, 1)
		in.after = withTable(in.after, "MFASecret", tableSnapshot{Table: "MFASecret", Hash: "edited", Rows: rows})
		if match(in) {
			t.Fatal("accepted an MFASecret change outside LastUsedStep -- not the class-B consumption")
		}
	})
	t.Run("red: success", func(t *testing.T) {
		in := login
		in.result.Success = true
		if match(in) {
			t.Fatal("accepted a reported success")
		}
	})
}

// withTable returns a copy of snap with table replaced.
func withTable(snap dbSnapshot, table string, ts tableSnapshot) dbSnapshot {
	out := dbSnapshot{Hash: snap.Hash + "+" + table, Tables: make(map[string]tableSnapshot, len(snap.Tables))}
	maps.Copy(out.Tables, snap.Tables)
	out.Tables[table] = ts
	return out
}

// classBOracleCases are the real class-B tuples the consume-first lookup
// accepts on the error branch (panic) and on oracle (d) (effect-then-error).
// Each one failed the oracle before ORPHAN-2 (the #2844 sweep).
var classBOracleCases = []struct {
	op, method string
	kind       faultstorage.FaultKind
}{
	{"REST POST /api/v1/auth/mfa/stepup", "CreateMFAStepUpGrant", faultstorage.KindError},
	{"REST POST /api/v1/auth/mfa/stepup", "CreateMFAStepUpGrant", faultstorage.KindPanic},
	{"REST POST /api/v1/auth/mfa/stepup", "MarkTOTPStepUsed", faultstorage.KindEffectThenError},
	{"REST POST /api/v1/auth/mfa/activate", "ActivateMFASecret", faultstorage.KindEffectThenError},
	{"REST POST /api/v1/auth/mfa/activate", "CreateMFARecoveryCodes", faultstorage.KindEffectThenError},
	{"REST POST /api/v1/auth/mfa/activate", "MarkTOTPStepUsed", faultstorage.KindEffectThenError},
	{"REST POST /api/v1/auth/mfa/activate", "SetUserMFAEnabled", faultstorage.KindEffectThenError},
}

// TestConsumeFirst_ClassBTuplesAreAcceptedOnlyThroughTheLedger: each case
// passes the real oracle, and fails it again with its op's consume-first
// entry removed. That is both the staleness check for those entries and the
// proof that the ledger lookup is what accepts them.
func TestConsumeFirst_ClassBTuplesAreAcceptedOnlyThroughTheLedger(t *testing.T) {
	for _, c := range classBOracleCases {
		t.Run(strings.ReplaceAll(fmt.Sprintf("%s/%s/%s", c.op, c.method, c.kind), "/", "_"), func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, c.op, c.method, 1, c.kind)
			if outcome != driveObserved {
				t.Fatalf("case could not be driven (%s: %s)", outcome, reason)
			}
			if in.result.Success {
				t.Fatalf("the op reported SUCCESS (%s): not the consume-first error shape", in.result.Detail)
			}
			if f := oracleFindingsWithout(t, in, func() func() { return func() {} }); len(f) > 0 {
				t.Fatalf("the oracle reports this class-B case: %v", f)
			}
			f := oracleFindingsWithout(t, in, func() func() { return withoutConsumeFirstEntry(c.op) })
			if len(f) == 0 {
				t.Fatalf("with %s's consume-first entry removed the oracle STILL accepts the case -- something "+
					"else covers it, so the entry is not what makes it pass (dead for this tuple)", c.op)
			}
			t.Logf("accepted only through the ledger: diff vs before %v; without the entry: %s",
				diffTables(in.before, in.after), f[0])
		})
	}
}

// TestConsumeFirst_NonExemptOpStillFailsTheOracle: the classification is
// per op, through consumeFirstExemptions, not "any diff that looks like a
// consumption". Two directions:
//   - a real exempt class-B case (stepup MarkTOTPStepUsed#1/effect-then-error,
//     whose diff IS the consumption alone) relabelled as a non-exempt op fails
//     the real oracle. /auth/mfa/verify is the sharpest choice, because its
//     VerifyMFACredentials is class B in the ledger too. A global "looks
//     consume-shaped" rule would accept it.
//   - a real post-verdict PANIC on /auth/mfa/verify (#3048's tuple, its diff
//     MFASecret's consumption plus the slot and the audit) is refused by the
//     consume-first lookup. Since #3277 core denies it like its error, which is
//     the decided outcome, so the oracle accepts it, but only through its own
//     reviewed KindPanic by-design row: with that row removed it fails again.
func TestConsumeFirst_NonExemptOpStillFailsTheOracle(t *testing.T) {
	exempt, outcome, reason := driveFaultCase(t, "REST POST /api/v1/auth/mfa/stepup", "MarkTOTPStepUsed", 1, faultstorage.KindEffectThenError)
	if outcome != driveObserved {
		t.Fatalf("case could not be driven (%s: %s)", outcome, reason)
	}
	if f := oracleFindingsWithout(t, exempt, func() func() { return func() {} }); len(f) > 0 {
		t.Fatalf("calibration: the exempt op's own case must pass, got %v", f)
	}
	if atomicityLedgerClasses(t)["(*KeyorixCore).VerifyMFACredentials"] != "B" {
		t.Fatal("premise: VerifyMFACredentials is class B in docs/atomicity-exempt.tsv")
	}
	for _, op := range []string{"REST POST /auth/mfa/verify", "REST POST /api/v1/secrets/"} {
		in := exempt
		in.op = op
		if _, ok := consumeFirstAccountsForDiff(in); ok {
			t.Errorf("%s: consume-first accepted a diff on an op with no consumeFirstExemptions entry", op)
		}
		if f := oracleFindingsWithout(t, in, func() func() { return func() {} }); len(f) == 0 {
			t.Errorf("%s: the oracle ACCEPTED the consumption-only effect-then-error diff %v on a non-exempt op",
				op, diffTables(in.before, in.after))
		}
	}

	real, outcome, reason := driveFaultCase(t, "REST POST /auth/mfa/verify", "CreateSession", 1, faultstorage.KindPanic)
	if outcome != driveObserved {
		t.Fatalf("case could not be driven (%s: %s)", outcome, reason)
	}
	if !diffSubsetOf([]string{"MFASecret"}, diffTables(real.before, real.after)) {
		t.Fatalf("premise: the post-verdict panic leaves the burned step, diff %v", diffTables(real.before, real.after))
	}
	if _, ok := consumeFirstAccountsForDiff(real); ok {
		t.Error("consume-first accepted /auth/mfa/verify's post-verdict panic")
	}
	if f := oracleFindingsWithout(t, real, func() func() { return func() {} }); len(f) > 0 {
		t.Errorf("calibration: /auth/mfa/verify CreateSession#1/panic is denied like its error since #3277 and has "+
			"a reviewed by-design row, but the oracle reports it: %v", f)
	}
	row := oracleAByDesignError{op: "REST POST /auth/mfa/verify", method: "CreateSession", kind: faultstorage.KindPanic, nth: 1}
	if f := oracleFindingsWithout(t, real, func() func() { return withoutByDesignRow(row) }); len(f) == 0 {
		t.Errorf("with its KindPanic by-design row removed the oracle STILL accepts /auth/mfa/verify CreateSession#1/panic "+
			"(diff %v, %q): something other than the reviewed row (consume-first?) covers a post-verdict panic",
			diffTables(real.before, real.after), real.result.Detail)
	}
}

// withoutConsumeFirstEntry removes op's consume-first entries and returns the
// restore.
func withoutConsumeFirstEntry(op string) func() {
	saved := consumeFirstExemptions
	kept := make([]consumeFirstExemption, 0, len(saved))
	for _, e := range saved {
		if e.op != op {
			kept = append(kept, e)
		}
	}
	consumeFirstExemptions = kept
	return func() { consumeFirstExemptions = saved }
}

// TestOpScopedBestEffort_PinnedEntriesAreLoadBearing drives every
// opScopedBestEffortTables entry that carries pinnedKinds, once per kind, and
// requires the real oracle to accept the case with the entry and to report it
// without the entry. Entries without pinnedKinds predate this check and are
// not covered, said here rather than implied.
func TestOpScopedBestEffort_PinnedEntriesAreLoadBearing(t *testing.T) {
	pinned := 0
	for i, e := range opScopedBestEffortTables {
		for _, kind := range e.pinnedKinds {
			pinned++
			i, e, kind := i, e, kind
			nth := max(e.minNthCall, 1)
			t.Run(strings.ReplaceAll(fmt.Sprintf("%s/%s#%d/%s", e.op, e.method, nth, kind), "/", "_"), func(t *testing.T) {
				in, outcome, reason := driveFaultCase(t, e.op, e.method, nth, kind)
				if outcome != driveObserved {
					t.Fatalf("entry's own case could not be driven (%s: %s)", outcome, reason)
				}
				if f := oracleFindingsWithout(t, in, func() func() { return func() {} }); len(f) > 0 {
					t.Fatalf("the oracle reports the entry's own case: %v", f)
				}
				f := oracleFindingsWithout(t, in, func() func() { return withoutBestEffortEntry(i) })
				if len(f) == 0 {
					t.Fatalf("with the entry removed the oracle STILL accepts the case: the entry is dead. Remove it")
				}
				t.Logf("load-bearing: diff vs reference %v; without the entry: %s", diffTables(in.refAfter, in.after), f[0])
			})
		}
	}
	if pinned == 0 {
		t.Fatal("no opScopedBestEffortTables entry carries pinnedKinds -- this check is checking nothing")
	}
}

// withoutBestEffortEntry removes opScopedBestEffortTables[i] and returns the
// restore.
func withoutBestEffortEntry(i int) func() {
	saved := opScopedBestEffortTables
	kept := append(saved[:i:i], saved[i+1:]...)
	opScopedBestEffortTables = kept
	return func() { opScopedBestEffortTables = saved }
}
