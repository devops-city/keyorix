// zz_sso_class_c_oracle_test.go: the oracle (a)/(d) by-design rule for the SSO
// login ops' class-C step set (#2910).
//
// WHAT IT ACCEPTS. A login that REPORTED FAILURE may leave behind state the
// fault-free login would also have produced, and nothing else. Andrei's #2839
// decision classifies CompleteSAML's JIT provisioning and group/role reconcile
// as class C (docs/atomicity-exempt.tsv, the JIT:(*KeyorixCore).CompleteSAML
// row, whose reconcile claims cover CompleteSSO since #2907). Each step is
// independent, idempotent and converges on the next successful login, and
// nothing is rolled back. That is sound only together with condition 1: no
// session is minted over a reconcile that did not fully apply. So on a
// reported failure the fault world may legitimately hold:
//   - the login state consumed (single-use, replay protection: the class-B half
//     of the same op);
//   - a JIT-provisioned account (condition 3: audited even when the login then
//     fails);
//   - SOME of the reconcile's membership/grant changes.
//
// The fault-free run would produce every one of these too. The rule is a
// soundness check, not a table carve-out. For every table that changed, each
// row the fault world ADDED must also have been added by the fault-free
// reference run, and each row it REMOVED must also have been removed by it.
// The fault world's change has to be a sub-transition of the correct one, so a
// row the correct login would never write, or a removal the correct login would
// not make, still fails the oracle. Only these tables may change at all:
// SSOLoginState, User, UserGroup and UserRole, plus the outcome logs the oracle
// always ignores. A Session row behind a reported failure is never accepted.
//
// WHAT IT DOES NOT CHECK.
//   - It assumes the reference world's pre-op state equals this world's
//     (deterministic Setup: the ops persist no random values, see their Setup
//     comments). If that ever stops holding, rows stop matching and the rule
//     refuses, so it fails closed, not open.
//   - User.LastLoginAt is ignored when matching rows. RecordLogin stamps it
//     only after a successful mint, so the reference's JIT row always has it
//     and a refused run's never does. Nothing else on User is ignored.
//   - It does not re-derive condition 1 (no session over a partial
//     reconcile). internal/core's reconcile-refusal tests own that. This rule
//     only refuses a Session row on the error path.
package faultops

import (
	"encoding/json"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// ssoClassCLedgerKey is the atomicity-ledger row this rule rests on.
// TestSSOClassCRule_MatchesAtomicityLedger requires it to say C.
const ssoClassCLedgerKey = "JIT:(*KeyorixCore).CompleteSAML"

// ssoClassCOp: jitBaselineRole is the role provisionSSOUser grants a NEW
// account (the provider's DefaultRole), for an op whose world JIT-provisions.
// The SAML world's GroupRoleMap revokes that same role (a managed role conferred
// by an unasserted group), so a correct login grants it and then revokes it,
// and the net change does not contain it. A run refused between those two steps
// keeps the grant. That is a class-C intermediate state, the JIT step's own
// output, so it is accepted, but only as that exact row: this role, at global
// scope, held by an account created in this same run.
type ssoClassCOp struct {
	jitBaselineRole string
}

var ssoClassCOps = map[string]ssoClassCOp{
	"REST POST /auth/saml/{provider}/acs":    {jitBaselineRole: "system_viewer"},
	"REST GET /auth/sso/{provider}/callback": {},
}

// ssoClassCTables may change on a reported failure. Anything else changing is
// refused outright.
var ssoClassCTables = map[string]bool{
	"SSOLoginState": true, "User": true, "UserGroup": true, "UserRole": true,
}

// ssoClassCIgnoredColumns are removed from rows before matching. See the file
// comment for why each is here.
var ssoClassCIgnoredColumns = map[string][]string{"User": {"LastLoginAt"}}

// ssoClassCAccountsForDiff reports whether a REPORTED-FAILURE run's change from
// before to after is a sub-transition of the reference run's change from before
// to refAfter, confined to ssoClassCTables.
func ssoClassCAccountsForDiff(in oracleInput) bool {
	opCfg, ok := ssoClassCOps[in.op]
	if !ok || in.result.Success {
		return false
	}
	newUsers, _ := rowDelta(in.before.Tables["User"].Rows, in.after.Tables["User"].Rows)
	outcome := make(map[string]bool, len(outcomeLogTables))
	for _, t := range outcomeLogTables {
		outcome[t] = true
	}
	changed := false
	for name, b := range in.before.Tables {
		a := in.after.Tables[name]
		if a.Hash == b.Hash || outcome[name] {
			continue
		}
		if !ssoClassCTables[name] {
			return false
		}
		strip := ssoClassCIgnoredColumns[name]
		bRows, aRows, rRows := stripRows(b.Rows, strip), stripRows(a.Rows, strip), stripRows(in.refAfter.Tables[name].Rows, strip)
		added, removed := rowDelta(bRows, aRows)
		refAdded, refRemoved := rowDelta(bRows, rRows)
		extra := multisetMinus(added, refAdded)
		if name == "UserRole" {
			extra = dropJITBaselineGrants(extra, opCfg.jitBaselineRole, in.before.Tables["Role"].Rows, newUsers)
		}
		if len(extra) > 0 || !multisetSubset(removed, refRemoved) {
			return false
		}
		if len(added)+len(removed) > 0 {
			changed = true
		}
	}
	return changed
}

func stripRows(rows []string, cols []string) []string {
	if len(cols) == 0 {
		return rows
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(r), &m); err != nil {
			out = append(out, r) // not JSON: compare as-is (fails closed on mismatch)
			continue
		}
		for _, c := range cols {
			delete(m, c)
		}
		b, err := json.Marshal(m) // map keys marshal sorted: canonical
		if err != nil {
			out = append(out, r)
			continue
		}
		out = append(out, string(b))
	}
	return out
}

// rowDelta returns the multiset difference: rows in to and not in from (added),
// and rows in from and not in to (removed).
func rowDelta(from, to []string) (added, removed []string) {
	count := make(map[string]int, len(from))
	for _, r := range from {
		count[r]++
	}
	for _, r := range to {
		if count[r] > 0 {
			count[r]--
			continue
		}
		added = append(added, r)
	}
	for r, n := range count {
		for ; n > 0; n-- {
			removed = append(removed, r)
		}
	}
	return added, removed
}

// multisetMinus returns the rows of a not matched by a row of b.
func multisetMinus(a, b []string) []string {
	have := make(map[string]int, len(b))
	for _, r := range b {
		have[r]++
	}
	var out []string
	for _, r := range a {
		if have[r] > 0 {
			have[r]--
			continue
		}
		out = append(out, r)
	}
	return out
}

// dropJITBaselineGrants removes from rows every UserRole row that is exactly
// the JIT baseline grant: RoleID = the role named roleName, global scope, held
// by one of the accounts in newUsers (User rows added in this run). Anything
// unparseable is kept, so it fails closed.
func dropJITBaselineGrants(rows []string, roleName string, roleRows, newUsers []string) []string {
	if roleName == "" || len(rows) == 0 {
		return rows
	}
	var roleID float64 = -1
	for _, r := range roleRows {
		var m struct {
			ID   float64
			Name string
		}
		if json.Unmarshal([]byte(r), &m) == nil && m.Name == roleName {
			roleID = m.ID
		}
	}
	created := map[float64]bool{}
	for _, u := range newUsers {
		var m struct{ ID float64 }
		if json.Unmarshal([]byte(u), &m) == nil {
			created[m.ID] = true
		}
	}
	var out []string
	for _, r := range rows {
		var m struct {
			UserID, RoleID, ProjectID, EnvironmentID float64
		}
		if json.Unmarshal([]byte(r), &m) == nil && roleID >= 0 && m.RoleID == roleID &&
			created[m.UserID] && m.ProjectID == 0 && m.EnvironmentID == 0 {
			continue
		}
		out = append(out, r)
	}
	return out
}

func multisetSubset(sub, super []string) bool {
	have := make(map[string]int, len(super))
	for _, r := range super {
		have[r]++
	}
	for _, r := range sub {
		if have[r] == 0 {
			return false
		}
		have[r]--
	}
	return true
}

// ── Proving tests ──────────────────────────────────────────────────────────

func TestSSOClassCRule_MatchesAtomicityLedger(t *testing.T) {
	classes := atomicityLedgerClasses(t)
	if got := classes[ssoClassCLedgerKey]; got != "C" {
		t.Fatalf("docs/atomicity-exempt.tsv classifies %q as %q, not C -- the SSO class-C oracle rule rests on that "+
			"row and must not outlive it", ssoClassCLedgerKey, got)
	}
}

func TestSSOClassCRule_OpsExist(t *testing.T) {
	for op := range ssoClassCOps {
		found := false
		for _, o := range opCatalog {
			if o.Key == op {
				found = true
			}
		}
		if !found {
			t.Errorf("ssoClassCOps names %q, which is not in opCatalog", op)
		}
	}
}

func classCSnap(tables map[string][]string) dbSnapshot {
	s := dbSnapshot{Tables: map[string]tableSnapshot{}}
	for _, name := range []string{"SSOLoginState", "User", "UserGroup", "UserRole", "Session", "AuditEvent", "Role"} {
		rows := tables[name]
		b, _ := json.Marshal(rows)
		s.Tables[name] = tableSnapshot{Table: name, Rows: rows, Hash: string(b)}
	}
	return s
}

// TestSSOClassCRule_Calibration: the shape it exists for is accepted, and each
// nearby shape that is NOT a sub-transition of the correct login is refused.
func TestSSOClassCRule_Calibration(t *testing.T) {
	const op = "REST GET /auth/sso/{provider}/callback"
	state := `{"ID":1,"State":"s"}`
	user := `{"ID":2,"Username":"u","LastLoginAt":null}`
	userStamped := `{"ID":2,"Username":"u","LastLoginAt":"set"}`
	inEng := `{"UserID":2,"GroupID":41}`
	inContr := `{"UserID":2,"GroupID":42}`
	roleEng := `{"UserID":2,"RoleID":51}`
	roleAdmin := `{"UserID":2,"RoleID":60}`
	inOps := `{"UserID":2,"GroupID":43}` // asserted and already held: the correct login keeps it
	session := `{"ID":9,"UserID":2}`

	before := classCSnap(map[string][]string{"SSOLoginState": {state}, "User": {user}, "UserGroup": {inContr, inOps}})
	// The correct login: state consumed, +engineers, -contractors, +engineer role,
	// a session, the last-login stamp.
	ref := classCSnap(map[string][]string{"User": {userStamped}, "UserGroup": {inEng, inOps}, "UserRole": {roleEng}, "Session": {session}})
	failed := opResult{Success: false}

	cases := []struct {
		name   string
		in     oracleInput
		accept bool
	}{
		{"green: consumed state + the add applied, the removal not (refused login)", oracleInput{op: op, result: failed, before: before, refAfter: ref,
			after: classCSnap(map[string][]string{"User": {user}, "UserGroup": {inContr, inOps, inEng}})}, true},
		{"green: consume-first only", oracleInput{op: op, result: failed, before: before, refAfter: ref,
			after: classCSnap(map[string][]string{"User": {user}, "UserGroup": {inContr, inOps}})}, true},
		{"green: whole reconcile applied, then the mint failed", oracleInput{op: op, result: failed, before: before, refAfter: ref,
			after: classCSnap(map[string][]string{"User": {user}, "UserGroup": {inEng, inOps}, "UserRole": {roleEng}})}, true},
		{"red: a grant the correct login never makes", oracleInput{op: op, result: failed, before: before, refAfter: ref,
			after: classCSnap(map[string][]string{"User": {user}, "UserGroup": {inContr, inOps}, "UserRole": {roleAdmin}})}, false},
		{"red: a removal the correct login does not make", oracleInput{op: op, result: failed, before: before, refAfter: ref,
			after: classCSnap(map[string][]string{"User": {user}, "UserGroup": {inContr}})}, false},
		{"red: a session behind a reported failure", oracleInput{op: op, result: failed, before: before, refAfter: ref,
			after: classCSnap(map[string][]string{"User": {user}, "UserGroup": {inEng, inOps}, "UserRole": {roleEng}, "Session": {session}})}, false},
		{"red: reported SUCCESS is not this rule's business", oracleInput{op: op, result: opResult{Success: true}, before: before, refAfter: ref,
			after: classCSnap(map[string][]string{"User": {user}, "UserGroup": {inContr, inOps, inEng}})}, false},
		{"red: another op gets no exemption", oracleInput{op: "REST POST /api/v1/secrets/", result: failed, before: before, refAfter: ref,
			after: classCSnap(map[string][]string{"User": {user}, "UserGroup": {inContr, inOps, inEng}})}, false},
		{"red: nothing changed is not an acceptance", oracleInput{op: op, result: failed, before: before, refAfter: ref, after: before}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ssoClassCAccountsForDiff(tc.in); got != tc.accept {
				t.Fatalf("ssoClassCAccountsForDiff = %v, want %v", got, tc.accept)
			}
		})
	}
}

// TestSSOClassCRule_JITBaselineCalibration: the one row allowed beyond the
// reference's net change is the JIT baseline grant to an account created in
// this run, and nothing that merely resembles it.
func TestSSOClassCRule_JITBaselineCalibration(t *testing.T) {
	const saml = "REST POST /auth/saml/{provider}/acs"
	const oidc = "REST GET /auth/sso/{provider}/callback"
	roles := []string{`{"ID":5,"Name":"system_viewer"}`, `{"ID":60,"Name":"admin"}`}
	state := `{"ID":1,"State":"s"}`
	existing := `{"ID":1,"Username":"old","LastLoginAt":null}`
	jit := `{"ID":2,"Username":"new","LastLoginAt":null}`
	jitStamped := `{"ID":2,"Username":"new","LastLoginAt":"set"}`
	baseline := `{"UserID":2,"RoleID":5,"ProjectID":0,"EnvironmentID":0}`
	baselineOld := `{"UserID":1,"RoleID":5,"ProjectID":0,"EnvironmentID":0}`
	baselineProj := `{"UserID":2,"RoleID":5,"ProjectID":7,"EnvironmentID":0}`
	adminGrant := `{"UserID":2,"RoleID":60,"ProjectID":0,"EnvironmentID":0}`
	eng := `{"UserID":2,"RoleID":51,"ProjectID":0,"EnvironmentID":0}`
	session := `{"ID":9,"UserID":2}`

	before := classCSnap(map[string][]string{"SSOLoginState": {state}, "User": {existing}, "Role": roles})
	// Correct login: JIT account, baseline granted then revoked (net: absent),
	// engineer role granted, session.
	ref := classCSnap(map[string][]string{"User": {existing, jitStamped}, "UserRole": {eng}, "Session": {session}, "Role": roles})
	failed := opResult{Success: false}
	after := func(userRoles ...string) dbSnapshot {
		return classCSnap(map[string][]string{"User": {existing, jit}, "UserRole": userRoles, "Role": roles})
	}

	cases := []struct {
		name   string
		in     oracleInput
		accept bool
	}{
		{"green: refused after JIT, before the baseline revocation", oracleInput{op: saml, result: failed, before: before, refAfter: ref, after: after(baseline)}, true},
		{"green: baseline kept plus a grant the correct login also makes", oracleInput{op: saml, result: failed, before: before, refAfter: ref, after: after(baseline, eng)}, true},
		{"red: an admin grant to the new account", oracleInput{op: saml, result: failed, before: before, refAfter: ref, after: after(baseline, adminGrant)}, false},
		{"red: the baseline role at a project scope", oracleInput{op: saml, result: failed, before: before, refAfter: ref, after: after(baselineProj)}, false},
		{"red: the baseline role to an account that already existed", oracleInput{op: saml, result: failed, before: before, refAfter: ref, after: after(baselineOld)}, false},
		{"red: the OIDC op declares no JIT baseline", oracleInput{op: oidc, result: failed, before: before, refAfter: ref, after: after(baseline)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ssoClassCAccountsForDiff(tc.in); got != tc.accept {
				t.Fatalf("ssoClassCAccountsForDiff = %v, want %v", got, tc.accept)
			}
		})
	}
}

// TestSSOClassCRule_IsLoadBearing drives real cases from both SSO ops, the way
// TestOracleAByDesign_RowsAreLoadBearing drives its rows. For each one it
// asserts that the oracle really does see a business-state change on the
// error path, that NO other mechanism already accepts it (so this rule is not
// dead weight), and that this rule does. The cases are the headline revocation
// refusal (OIDC: the stale membership's removal fails) and the JIT-baseline
// intermediate (SAML: the baseline role's revocation fails after
// provisioning).
func TestSSOClassCRule_IsLoadBearing(t *testing.T) {
	cases := []struct{ op, method string }{
		{"REST GET /auth/sso/{provider}/callback", "RemoveUserFromGroup"},
		{"REST POST /auth/saml/{provider}/acs", "RemoveRole"},
	}
	for _, c := range cases {
		t.Run(c.op+"/"+c.method, func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, c.op, c.method, 1, faultstorage.KindError)
			if outcome != driveObserved {
				t.Fatalf("case could not be driven (%s: %s)", outcome, reason)
			}
			if in.result.Success {
				t.Fatalf("the login reported SUCCESS under a failed revocation -- condition 1 (#2839/#2907) is broken: %s", in.result.Detail)
			}
			diff := diffTables(in.before, in.after)
			if len(diff) == 0 || onlyOutcomeLogTables(diff) {
				t.Fatalf("diff %v: the oracle would not flag this case, so the rule is not load-bearing for it", diff)
			}
			if _, ok := consumeFirstAccountsForDiff(in); ok {
				t.Fatalf("consume-first already accepts %v -- this rule is dead for the case", diff)
			}
			if e := oracleAErrorByDesign(in, diff); e != nil {
				t.Fatalf("an oracleAByDesignErrors row already accepts %v -- this rule is dead for the case", diff)
			}
			if !ssoClassCAccountsForDiff(in) {
				t.Fatalf("the SSO class-C rule refused a real class-C refusal: diff %v", diff)
			}
			t.Logf("load-bearing: %s %s#1/error diverges in %v, accepted only by the SSO class-C rule", c.op, c.method, diff)
		})
	}
}
