// post_verdict_identity_read_panic_test.go — #3267: a PANIC in a login's
// post-verdict identity read (GetUserRoles, GetUserPermissions) is answered
// exactly like the same read's ERROR, on every login op that has one.
//
// Found by FuzzStorageFaultOperations on /auth/mfa/verify GetUserPermissions#1
// panic (oracle (a): failure reported, LoginAttempt and MFASecret changed).
// Driven through this package's real router, Recovery middleware included,
// the panic was answered with the Recovery 500 while the same fault as an
// error gets the wrong-credential 401. A wrong credential never reaches the
// identity read, so the 500 itself answered "was the credential correct?";
// the lockout went uncounted and nothing was audited, while the TOTP step
// stayed burned and the per-IP slot stayed spent. Every login op had the same
// shape for both halves of the read (six tuples); the fuzzer had found one.
//
// The fix is in the one function every login path reads its identity through,
// core's resolveLoginIdentityBeforeMint: a panic there becomes its error, so
// the existing post-verdict denial (already proven against a wrong credential
// for the error kind) runs. The rows registered in
// oracle_a_by_design_entry_*_panic_test.go accept the resulting state for the
// panic kind; the test below is what keeps them honest as a family.
package faultops

import (
	"fmt"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

const (
	identityReadPanicDesign = "internal/core/webauthn.go resolveLoginIdentityBeforeMint: a panic in the post-verdict " +
		"identity read is returned as its ErrLoginIdentityUnavailable error (#3267), so every login path denies it " +
		"through the same denyAfterCredentialMatched / LoginCompletion.Failed branch as the error kind"
	identityReadPanicWhy = "The credential matched before the identity read panicked, so the panic is the same " +
		"post-verdict fault as the read's error and gets the same decided outcome (#2880, #2894, #3267): the " +
		"wrong-credential response, the LoginAttempt slot kept, the lockout counted, auth.login_error audited, no " +
		"session. A 500 instead would tell the caller the credential was right. Any credential consumption the " +
		"error row keeps (the burned TOTP step) is kept here too, for the same reason."
	identityReadPanicFamilyTest = "server/faultops/TestPostVerdictIdentityReadPanic_AnsweredLikeItsError"
)

// identityReadMethods are the two storage reads GetUserIdentity makes.
var identityReadMethods = []string{"GetUserRoles", "GetUserPermissions"}

// TestPostVerdictIdentityReadPanic_AnsweredLikeItsError takes its population
// from the registry, not from a list here: every reviewed KindError row for a
// login identity read. For each, the panic kind of the same (op, method, nth)
// must
//   - have its own reviewed KindPanic row (so the fuzzer accepts exactly this
//     outcome and nothing wider), and
//   - when driven through the real router, produce the error kind's response
//     byte for byte, diverge in the same tables, add the same number of
//     AuditEvent rows and add no Session.
//
// What it does not see: the lockout columns (dbSnapshot does not carry them)
// and the audit event TYPE. Those are compared against a wrong credential by
// server/http/handlers' TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword,
// TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode and
// TestVerifyMFA_IdentityReadPanicAuditsLoginErrorAndKeepsTheCodeBurned (panic
// subtests through middleware.Recovery), and for WebAuthn by internal/core's
// TestLoginIdentityReadPanic_DeniedLikeItsError.
func TestPostVerdictIdentityReadPanic_AnsweredLikeItsError(t *testing.T) {
	var population []oracleAByDesignError
	for _, e := range oracleAByDesignErrors {
		if e.kind == faultstorage.KindError && slices.Contains(identityReadMethods, e.method) {
			population = append(population, e)
		}
	}
	// Calibration: the three login ops in opCatalog that read the identity
	// after the verdict (/auth/login, /auth/mfa/verify, /auth/webauthn/login/finish),
	// both halves of the read. Fewer means a row went missing and this test
	// would quietly check less.
	if len(population) < 6 {
		t.Fatalf("only %d identity-read KindError rows registered, want at least 6 (3 login ops x 2 reads)", len(population))
	}
	for _, e := range population {
		t.Run(fmt.Sprintf("%s/%s", e.op, e.method), func(t *testing.T) {
			requirePanicKindAnsweredLikeErrorKind(t, e, true)
		})
	}
}

// requirePanicKindAnsweredLikeErrorKind drives e's (op, method, nth) as an
// error and as a panic through the real router and requires the panic kind to
// report failure, answer byte for byte like the error kind, diverge in the
// same tables, add the same number of AuditEvent rows and add no Session, and
// (requireRow) to have its own reviewed KindPanic row. Shared by the
// identity-read (#3267) and write (#3277) families.
func requirePanicKindAnsweredLikeErrorKind(t *testing.T, e oracleAByDesignError, requireRow bool) {
	t.Helper()
	if requireRow && !hasByDesignRow(e.op, e.method, e.nth, faultstorage.KindPanic) {
		t.Errorf("no KindPanic oracleAByDesignError row for %s %s#%d: the panic kind must be reviewed "+
			"alongside the error kind", e.op, e.method, e.nth)
	}
	errIn, outcome, reason := driveFaultCase(t, e.op, e.method, e.nth, faultstorage.KindError)
	if outcome != driveObserved {
		t.Fatalf("error kind could not be driven (%s: %s)", outcome, reason)
	}
	panicIn, outcome, reason := driveFaultCase(t, e.op, e.method, e.nth, faultstorage.KindPanic)
	if outcome != driveObserved {
		t.Fatalf("panic kind could not be driven (%s: %s)", outcome, reason)
	}
	if panicIn.result.Success {
		t.Fatalf("the panic kind reported success: %q", panicIn.result.Detail)
	}
	if panicIn.result.Detail != errIn.result.Detail {
		t.Errorf("response differs: panic got %q, the same fault as an error got %q -- the status code "+
			"answers whether the credential was correct (#3267)", panicIn.result.Detail, errIn.result.Detail)
	}
	errDiff, panicDiff := diffTables(errIn.before, errIn.after), diffTables(panicIn.before, panicIn.after)
	slices.Sort(errDiff)
	slices.Sort(panicDiff)
	if !slices.Equal(errDiff, panicDiff) {
		t.Errorf("diverged tables differ: panic %v, error %v", panicDiff, errDiff)
	}
	if n := addedRows(panicIn.before, panicIn.after, "Session"); n != 0 {
		t.Errorf("the panic kind left %d new Session row(s)", n)
	}
	if p, e := addedRows(panicIn.before, panicIn.after, "AuditEvent"), addedRows(errIn.before, errIn.after, "AuditEvent"); p != e {
		t.Errorf("the panic kind wrote %d AuditEvent row(s), the error kind %d -- the audit record "+
			"must not depend on how the fault surfaced", p, e)
	}
}

func hasByDesignRow(op, method string, nth int, kind faultstorage.FaultKind) bool {
	for _, e := range oracleAByDesignErrors {
		if e.op == op && e.method == method && e.nth == nth && e.kind == kind {
			return true
		}
	}
	return false
}
