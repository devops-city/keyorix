// by_design_seed_counterfactuals_test.go — FUZZ-RULES-2: the committed seeds
// for #3091, #3093 (x2), #3094 and #3101 each pass the oracle through exactly
// one reviewed rule, and are reported again without it.
//
// The seeds are legacy-encoded (index-addressed), so their bytes re-point when
// opCatalog or the storage method list changes; seedIntent records what each
// is for, and TestReportSeedIntentDrift reports drift. These tests therefore
// drive each tuple BY NAME (driveFaultCase), which does not drift, and only
// check that the seed file is committed.
package faultops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

var byDesignSeedCases = []struct {
	seed       string
	op, method string
	nth        int
	kind       faultstorage.FaultKind
	rule       string
	// remove takes the one rule out and returns the restore.
	remove func(t *testing.T) func()
	// oracle is the oracle that must report the case without the rule.
	oracle string
}{
	{
		seed: "3091_webauthn_loginfinish_getuserpermissions_effect_then_error",
		op:   "REST POST /auth/webauthn/login/finish", method: "GetUserPermissions", nth: 1, kind: faultstorage.KindEffectThenError,
		rule: "pureReadEffectThenError on post_auth_webauthn_login_finish_getuserpermissions",
		remove: func(t *testing.T) func() {
			return withoutPureReadOptIn(mustByDesignRow(t, "REST POST /auth/webauthn/login/finish", "GetUserPermissions", faultstorage.KindError, 1))
		},
		oracle: "d",
	},
	{
		seed: "3106_webauthn_loginfinish_getuserroles_effect_then_error",
		op:   "REST POST /auth/webauthn/login/finish", method: "GetUserRoles", nth: 1, kind: faultstorage.KindEffectThenError,
		rule: "pureReadEffectThenError on post_auth_webauthn_login_finish_getuserroles",
		remove: func(t *testing.T) func() {
			return withoutPureReadOptIn(mustByDesignRow(t, "REST POST /auth/webauthn/login/finish", "GetUserRoles", faultstorage.KindError, 1))
		},
		oracle: "d",
	},
	{
		seed: "3093_grpc_createuser_getuserrolescopes_error",
		op:   "GRPC keyorix.v1.UserService.CreateUser", method: "GetUserRoleScopes", nth: 1, kind: faultstorage.KindError,
		rule: "nonLoadBearingAuthzRead grpc_userservice_createuser_getuserrolescopes_1",
		remove: func(*testing.T) func() {
			return withoutNonLoadBearingAuthzRead("GRPC keyorix.v1.UserService.CreateUser", "GetUserRoleScopes", 1)
		},
		oracle: "c",
	},
	{
		seed: "3093_grpc_updateuser_getuserrolescopes_nth2_error",
		op:   "GRPC keyorix.v1.UserService.UpdateUser", method: "GetUserRoleScopes", nth: 2, kind: faultstorage.KindError,
		rule: "nonLoadBearingAuthzRead grpc_userservice_updateuser_getuserrolescopes_2",
		remove: func(*testing.T) func() {
			return withoutNonLoadBearingAuthzRead("GRPC keyorix.v1.UserService.UpdateUser", "GetUserRoleScopes", 2)
		},
		oracle: "c",
	},
	{
		seed: "3094_recoverycodes_regenerate_marktotpstepused_effect_then_error",
		op:   "REST POST /api/v1/auth/mfa/recovery-codes/regenerate", method: "MarkTOTPStepUsed", nth: 1, kind: faultstorage.KindEffectThenError,
		rule: "consumeFirstExemptions entry for /mfa/recovery-codes/regenerate (requireReauth, class B), consulted by oracle (d) since #3065",
		remove: func(*testing.T) func() {
			return withoutConsumeFirstEntry("REST POST /api/v1/auth/mfa/recovery-codes/regenerate")
		},
		oracle: "d",
	},
	{
		seed: "3101_mfa_verify_getuserpermissions_error",
		op:   "REST POST /auth/mfa/verify", method: "GetUserPermissions", nth: 1, kind: faultstorage.KindError,
		rule: "oracleAByDesign post_auth_mfa_verify_getuserpermissions (#2880 post-verdict, since #3065)",
		remove: func(t *testing.T) func() {
			return withoutByDesignRow(mustByDesignRow(t, "REST POST /auth/mfa/verify", "GetUserPermissions", faultstorage.KindError, 1))
		},
		oracle: "a",
	},
}

// TestByDesignSeeds_AcceptedOnlyThroughTheirRule: green with the rule, red
// (by the named oracle) without it.
func TestByDesignSeeds_AcceptedOnlyThroughTheirRule(t *testing.T) {
	for _, c := range byDesignSeedCases {
		c := c
		t.Run(c.seed, func(t *testing.T) {
			if _, err := os.Stat(filepath.Join(fuzzCorpusDir, c.seed)); err != nil {
				t.Fatalf("seed %s is not committed: %v", c.seed, err)
			}
			if in, ok := seedIntent[c.seed]; !ok || in.op != c.op || in.method != c.method {
				t.Fatalf("seedIntent[%q] = %+v, want (%q, %q): the re-encoder would target the wrong tuple", c.seed, in, c.op, c.method)
			}
			in, outcome, reason := driveFaultCase(t, c.op, c.method, c.nth, c.kind)
			if outcome != driveObserved {
				t.Fatalf("case could not be driven (%s: %s)", outcome, reason)
			}
			if f := oracleFindingsWithout(t, in, func() func() { return func() {} }); len(f) > 0 {
				t.Fatalf("with %s the oracle still reports: %v", c.rule, f)
			}
			f := oracleFindingsWithout(t, in, func() func() { return c.remove(t) })
			want := fmt.Sprintf("ORACLE (%s)", c.oracle)
			if len(f) == 0 || !strings.Contains(f[0], want) {
				t.Fatalf("without %s, %s must report this case; got %v", c.rule, want, f)
			}
			t.Logf("accepted only through %s; without it: %.200s", c.rule, f[0])
		})
	}
}

// TestNonLoadBearingAuthzRead_GRPCUserServiceRowsAreExact: the #3093 rows
// match their traced (op, method, nth) and nothing next to it. UpdateUser's
// call #1 is the admin-rank ceiling read and must stay load-bearing.
func TestNonLoadBearingAuthzRead_GRPCUserServiceRowsAreExact(t *testing.T) {
	t.Parallel()
	const create, update, m = "GRPC keyorix.v1.UserService.CreateUser", "GRPC keyorix.v1.UserService.UpdateUser", "GetUserRoleScopes"
	for _, c := range []struct {
		op, method string
		nth        int
		want       bool
	}{
		{create, m, 1, true},
		{update, m, 2, true},
		{update, m, 1, false}, // the ceiling read
		{create, m, 2, false},
		{update, m, 3, false},
		{create, "GetUserPermissions", 1, false},
		{"REST POST /api/v1/users/", m, 1, false},
		{"GRPC keyorix.v1.UserService.GetUser", m, 1, false},
	} {
		if got := nonLoadBearingAuthzRead(c.op, c.method, c.nth); got != c.want {
			t.Errorf("nonLoadBearingAuthzRead(%q, %q, %d) = %v, want %v", c.op, c.method, c.nth, got, c.want)
		}
	}
}

// TestNonLoadBearingAuthzRead_AttributedRows: a row that carries any of
// designComment / provingTest / why carries all three, its why is a reason,
// and its proving test exists.
func TestNonLoadBearingAuthzRead_AttributedRows(t *testing.T) {
	t.Parallel()
	attributed := 0
	for _, e := range nonLoadBearingAuthzReadExceptions {
		label := fmt.Sprintf("%s/%s#%d", e.op, e.method, e.nth)
		if e.designComment == "" && e.provingTest == "" && e.why == "" {
			continue
		}
		attributed++
		if e.designComment == "" || e.provingTest == "" || len(e.why) < 80 {
			t.Errorf("%s: designComment, provingTest and a why of 80+ chars come together", label)
			continue
		}
		if err := provingTestExists(e.provingTest); err != nil {
			t.Errorf("%s: %v", label, err)
		}
	}
	if attributed == 0 {
		t.Fatal("no attributed nonLoadBearingAuthzRead row: this check verifies nothing")
	}
}

func mustByDesignRow(t *testing.T, op, method string, kind faultstorage.FaultKind, nth int) oracleAByDesignError {
	t.Helper()
	for _, e := range oracleAByDesignErrors {
		if e.op == op && e.method == method && e.kind == kind && e.nth == nth {
			return e
		}
	}
	t.Fatalf("no oracleAByDesignError row for %s/%s/%s#%d", op, method, kind, nth)
	return oracleAByDesignError{}
}

// withoutNonLoadBearingAuthzRead removes exactly one row and returns the
// restore.
func withoutNonLoadBearingAuthzRead(op, method string, nth int) func() {
	saved := nonLoadBearingAuthzReadExceptions
	kept := make([]nonLoadBearingException, 0, len(saved))
	for _, e := range saved {
		if e.op == op && e.method == method && e.nth == nth {
			continue
		}
		kept = append(kept, e)
	}
	nonLoadBearingAuthzReadExceptions = kept
	return func() { nonLoadBearingAuthzReadExceptions = saved }
}
