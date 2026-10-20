// undelivered_session_oracle_test.go — #2844, oracle (f): an operation that
// reports FAILURE must not leave a NEW Session row behind.
//
// A session row the client never received is live: it appears in the owner's
// session list, outlives the failure until it expires, and a revocation sweep
// has to find it. The exhaustive login-op sweep (AUTH-AUDIT-1, posted on #2844)
// found it twice in oracle (a)'s output (a panic in the identity read after the
// session insert on /auth/login; a panic in the ambient step-up grant write on
// /auth/webauthn/login/finish). Widening the sweep to every session-issuing op
// found a third shape oracles (a) and (d) cannot see at all: CreateSession or
// RotateSession effect-then-error leaves the row behind while the post-state
// still matches the fault-free reference modulo outcome-log tables, so (d)
// accepted it. Seven ops, ten tuples, listed in undeliveredSessionPins.
//
// Why a separate oracle and not a stricter (a)/(d): those compare whole tables
// against "before" and "reference", and a failed login legitimately keeps
// other rows (the counted LoginAttempt, #2880). Whether a NEW session survived
// a reported failure is a narrower, never-acceptable fact, so it has no
// tolerance and no by-design table: checkNoUndeliveredSession reports through
// Errorf directly, never through checkOraclesReporting's tolerance-aware
// report().
//
// "New" is a multiset difference over canonical rows, not a table diff: an op
// that DELETES a session and then reports failure (end-impersonation,
// DeleteSession effect-then-error) changes the table without leaving anything
// live, and must not trip this.
//
// What it does not see: a session that existed BEFORE the op and that a failed
// op should have deleted (a different property: revocation, not issuance), and
// the two session-issuing paths that are not in opCatalog (passwordless WebAuthn
// finish, setup-token consume). Those are covered at their own boundaries:
// internal/core/login_undelivered_session_test.go (the shared createSession and
// the mint ordering) and server/http/handlers/login_undelivered_session_test.go
// (ConsumeSetup's completeLogin).
package faultops

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// checkNoUndeliveredSession is oracle (f). Called from checkOraclesReporting,
// so it runs on every input the fuzzer and every deterministic driver feeds the
// harness.
func checkNoUndeliveredSession(t fuzzVerdict, label string, in oracleInput) {
	t.Helper()
	if in.result.Success {
		return
	}
	if n := addedRows(in.before, in.after, "Session"); n > 0 {
		t.Errorf("%s: ORACLE (f) VIOLATION (#2844) — the operation reported FAILURE (%s) but left %d new Session row(s) "+
			"behind: a live session the client never received. A session-creating write that errored may have "+
			"committed (deliver it or delete it, internal/core/session_undelivered.go), and nothing fallible may run "+
			"after the insert unless it is panic-safe best-effort", label, in.result.Detail, n)
	}
}

// addedRows counts rows of table present in after but not in before, as a
// multiset over canonical rows (two sessions for the same user from the same
// client canonicalize identically, so a set would miss the second).
func addedRows(before, after dbSnapshot, table string) int {
	seen := map[string]int{}
	for _, r := range before.Tables[table].Rows {
		seen[r]++
	}
	n := 0
	for _, r := range after.Tables[table].Rows {
		if seen[r] > 0 {
			seen[r]--
			continue
		}
		n++
	}
	return n
}

// sessionIssuingOps are the opCatalog ops whose fault-free run writes a new
// session. Derived from the session-insert sites, not guessed: every
// storage.CreateSession and storage.RotateSession call in internal/core
// (mintSession's callers, StartImpersonation, RefreshSession, and the setup
// consume's in-transaction insert), mapped to
// the ops that reach them. TestUndeliveredSessionSweep's calibration fails if
// one of these stops issuing a session, so the list cannot rot into a set of ops
// that test nothing.
var sessionIssuingOps = []string{
	"REST POST /auth/login",
	"REST POST /auth/mfa/verify",
	"REST POST /auth/webauthn/login/finish",
	"REST POST /auth/saml/{provider}/acs",
	"REST GET /auth/sso/{provider}/callback",
	"REST POST /api/v1/admin/impersonate",
	"REST POST /auth/refresh",
	"REST POST /auth/setup/consume", // AUTH-2 item 1 (#3298): its session is inserted in the consume's transaction
}

// undeliveredSessionPins are every tuple that left an undelivered session on
// origin/main @ cc8e3dbe. Each must now be observed AND leave no new session.
var undeliveredSessionPins = []struct {
	op, method string
	kind       faultstorage.FaultKind
}{
	{"REST POST /auth/login", "GetUserPermissions", faultstorage.KindPanic},
	{"REST POST /auth/login", "GetUserRoles", faultstorage.KindPanic},
	{"REST POST /auth/login", "CreateSession", faultstorage.KindEffectThenError},
	{"REST POST /auth/mfa/verify", "CreateSession", faultstorage.KindEffectThenError},
	{"REST POST /auth/webauthn/login/finish", "CreateMFAStepUpGrant", faultstorage.KindPanic},
	{"REST POST /auth/webauthn/login/finish", "CreateSession", faultstorage.KindEffectThenError},
	{"REST POST /auth/saml/{provider}/acs", "CreateSession", faultstorage.KindEffectThenError},
	{"REST GET /auth/sso/{provider}/callback", "CreateSession", faultstorage.KindEffectThenError},
	{"REST POST /api/v1/admin/impersonate", "CreateSession", faultstorage.KindEffectThenError},
	{"REST POST /auth/refresh", "RotateSession", faultstorage.KindEffectThenError},
}

func TestUndeliveredSession_PinnedTuplesLeaveNoSession(t *testing.T) {
	for _, p := range undeliveredSessionPins {
		t.Run(p.op+"/"+p.method+"/"+p.kind.String(), func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, p.op, p.method, 1, p.kind)
			if outcome != driveObserved {
				t.Fatalf("could not drive the pinned tuple (%s: %s): a pin that cannot run proves nothing", outcome, reason)
			}
			sink := &driveSink{t: t}
			checkNoUndeliveredSession(sink, p.op, in)
			for _, f := range sink.findings {
				t.Error(f)
			}
		})
	}
}

// TestUndeliveredSession_OracleCalibration proves oracle (f) fires on the shape
// it exists for and stays quiet on the two neighbours it must not confuse with
// it: a successful issuance, and a failed op that removed a session.
func TestUndeliveredSession_OracleCalibration(t *testing.T) {
	row := `{"UserID":1}`
	snap := func(rows ...string) dbSnapshot {
		return dbSnapshot{Tables: map[string]tableSnapshot{"Session": {Table: "Session", Rows: rows}}}
	}
	cases := []struct {
		name          string
		success       bool
		before, after dbSnapshot
		wantFinding   bool
	}{
		{"failure that added a session", false, snap(row), snap(row, row), true},
		{"failure that added the first session", false, snap(), snap(row), true},
		{"success that added a session", true, snap(row), snap(row, row), false},
		{"failure that deleted a session", false, snap(row, row), snap(row), false},
		{"failure that changed nothing", false, snap(row), snap(row), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sink := &driveSink{t: t}
			checkNoUndeliveredSession(sink, c.name, oracleInput{
				result: opResult{Success: c.success, Detail: "x"}, before: c.before, after: c.after,
			})
			if got := len(sink.findings) > 0; got != c.wantFinding {
				t.Errorf("finding=%v, want %v (%v)", got, c.wantFinding, sink.findings)
			}
		})
	}
}

// TestUndeliveredSessionSweep drives EVERY (storage method, nth 1-3, kind) that
// fires during each session-issuing op, not a random sample, and requires
// oracle (f) to hold on all of them. ~360 faults, ~12s on SQLite with reused
// worlds; run by the repo-guards job (every Test...Sweep, no DSN, no -short).
// Skipped under -short, and when KEYORIX_TEST_PG_DSN is set: on Postgres every
// world is a fresh schema and the same sweep takes ~8 minutes (measured
// locally, before -race), which the test-suite legs that carry the DSN cannot
// afford. The pinned tuples above still run there, against Postgres.
func TestUndeliveredSessionSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive sweep; run without -short (repo-guards runs it)")
	}
	if os.Getenv("KEYORIX_TEST_PG_DSN") != "" {
		t.Skip("exhaustive sweep runs on SQLite (repo-guards); on Postgres it takes ~8 min, so only the pinned tuples run here")
	}
	ctx := context.Background()
	kinds := []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}
	ref := buildReusableFaultWorld(t, nil)
	w := buildReusableFaultWorld(t, nil)
	for _, key := range sessionIssuingOps {
		opIdx := -1
		for i, e := range opCatalog {
			if e.Key == key {
				opIdx = i
			}
		}
		if opIdx < 0 {
			t.Fatalf("session-issuing op %q is not in opCatalog: update sessionIssuingOps", key)
		}
		op := opCatalog[opIdx]

		// Profile the fault-free run: which methods it calls, and how often.
		// Calibration: it must actually write a new session.
		w.resetForReuse(t, nil)
		var state any
		var err error
		if op.Setup != nil {
			if state, err = op.Setup(ctx, w); err != nil {
				t.Fatalf("%s: setup: %v", key, err)
			}
		}
		drainAllBackgroundGoroutines()
		before, err := snapshotDB(w.db)
		if err != nil {
			t.Fatal(err)
		}
		start := len(w.faulty.Calls())
		w.faulty.Arm(nil)
		res, err := op.Execute(ctx, w, state)
		if err != nil || !res.Success {
			t.Fatalf("%s: fault-free run did not succeed (%v, %q)", key, err, res.Detail)
		}
		drainAllBackgroundGoroutines()
		after, err := snapshotDB(w.db)
		if err != nil {
			t.Fatal(err)
		}
		if addedRows(before, after, "Session") == 0 {
			t.Fatalf("calibration: %s no longer writes a session when it succeeds; it does not belong in sessionIssuingOps", key)
		}
		counts := map[string]int{}
		for _, c := range w.faulty.Calls()[start:] {
			counts[c.Method]++
		}
		methods := make([]string, 0, len(counts))
		for m := range counts {
			methods = append(methods, m)
		}
		sort.Strings(methods)

		methodIdx := map[string]int{}
		for i, m := range storageInterfaceMethodNames() {
			methodIdx[m] = i
		}
		fired, violated := 0, 0
		for _, m := range methods {
			mi, ok := methodIdx[m]
			if !ok {
				continue // WithTransaction and other non-interface wrappers
			}
			for nth := 1; nth <= counts[m] && nth <= 3; nth++ {
				for _, k := range kinds {
					data := []byte{byte(opIdx), byte(mi >> 8), byte(mi), byte(nth - 1), fuzzKindSelector(k)}
					sink := &driveSink{t: t}
					var seen *oracleInput
					func() {
						defer func() { rethrowUnlessDriveAbort(recover()) }()
						runOneFuzzIterationReporting(t, sink, data, ref, w, func(in oracleInput) { seen = &in })
					}()
					if seen == nil {
						continue // never fired, or the harness skipped (reported by other tests)
					}
					fired++
					oracle := &driveSink{t: t}
					checkNoUndeliveredSession(oracle, key, *seen)
					for _, f := range oracle.findings {
						t.Error(f)
					}
					if len(oracle.findings) > 0 {
						violated++
					}
				}
			}
		}
		if fired == 0 {
			t.Fatalf("%s: no fault fired; the sweep checked nothing", key)
		}
		t.Logf("%s: %d faults fired, %d left an undelivered session", key, fired, violated)
	}
}
