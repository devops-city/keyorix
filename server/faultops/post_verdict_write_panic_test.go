// post_verdict_write_panic_test.go — #3277: a PANIC in a login's post-verdict
// storage WRITE (the TOTP anti-replay mark, the session insert) is answered
// exactly like the same write's ERROR, on every login op that has one.
//
// The write-side sibling of #3267 (post_verdict_identity_read_panic_test.go).
// Driven through this package's real router, Recovery middleware included,
// each of these panics was answered with the Recovery 500 while the same fault
// as an error gets the wrong-credential 401. A wrong credential never reaches
// these writes, so the 500 told the caller the credential was correct; the
// lockout went uncounted and nothing was audited.
//
// A write, unlike the identity read, may have committed before it panicked, so
// core settles that per write before it denies (internal/core
// mfa.go markTOTPStepUsedAfterMatch, session_undelivered.go mintLoginSession):
//   - MarkTOTPStepUsed: the step is never given back, so a code whose mark did
//     land stays burned; one whose mark did not land was never accepted.
//   - CreateSession: createSession deletes a row that landed before the panic
//     continues, and the token is never returned. On /auth/mfa/verify the
//     consumed TOTP step is NOT released (the error kind releases it, because
//     there the row is known to be absent): a code that was accepted stays used.
package faultops

import (
	"fmt"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

const (
	writePanicDesign = "internal/core: a panic in a post-verdict login write is returned as that write's error (#3277): " +
		"mfa.go markTOTPStepUsedAfterMatch for the anti-replay mark (VerifyMFACredentials then denies it through the " +
		"same codeMatched branch as the error kind), session_undelivered.go mintLoginSession for the session insert " +
		"(createSession has already deleted a row that landed; the caller denies through the same " +
		"LoginCompletion.Failed / ErrLoginPostVerdict branch as the error kind)"
	writePanicWhy = "The credential matched before the write panicked, so the panic is the same post-verdict fault " +
		"as the write's error and gets the same decided outcome (#2880, #2894, #3277): the wrong-credential " +
		"response, the LoginAttempt slot kept, the lockout counted, the same audit record as the error kind, no " +
		"session. A 500 instead would tell the caller the credential was right. Commit-aware: a session row that " +
		"landed before the panic is deleted and its token never returned, and a consumed TOTP step is never " +
		"given back after a panic, so an accepted code stays used."
	writePanicFamilyTest = "server/faultops/TestPostVerdictWritePanic_AnsweredLikeItsError"
)

// postVerdictLoginWriteMethods are the storage writes every login op in
// opCatalog makes after the credential matched and before it is delivered.
var postVerdictLoginWriteMethods = []string{"MarkTOTPStepUsed", "CreateSession"}

// postVerdictLoginOps are the opCatalog login ops whose post-verdict writes
// this family covers.
var postVerdictLoginOps = []string{
	"REST POST /auth/login",
	"REST POST /auth/mfa/verify",
	"REST POST /auth/webauthn/login/finish",
}

// TestPostVerdictWritePanic_AnsweredLikeItsError takes its population from the
// registry: every reviewed KindError row for a post-verdict login write. For
// each, the panic kind of the same (op, method, nth) must have its own
// KindPanic row and, driven through the real router, match the error kind's
// response, diverged tables and AuditEvent count, and add no Session (see
// requirePanicKindAnsweredLikeErrorKind).
//
// What it does not see: the lockout columns, the audit event TYPE, and which
// TOTP step the MFASecret row holds (a released step and a kept one both show
// as "MFASecret diverged"). Those are compared against a wrong credential by
// server/http/handlers' TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword
// and TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode (panic subtests
// through middleware.Recovery) and TestVerifyMFA_WritePanicKeepsTheCodeBurned,
// and for WebAuthn and the after-commit panics by internal/core's
// TestLoginWritePanic_DeniedLikeItsError.
func TestPostVerdictWritePanic_AnsweredLikeItsError(t *testing.T) {
	var population []oracleAByDesignError
	for _, e := range oracleAByDesignErrors {
		if e.kind == faultstorage.KindError && slices.Contains(postVerdictLoginWriteMethods, e.method) &&
			slices.Contains(postVerdictLoginOps, e.op) {
			population = append(population, e)
		}
	}
	// Calibration: CreateSession on all three login ops, MarkTOTPStepUsed on
	// /auth/mfa/verify. Fewer means a row went missing and this test would
	// quietly check less.
	if len(population) < 4 {
		t.Fatalf("only %d post-verdict write KindError rows registered, want at least 4", len(population))
	}
	for _, e := range population {
		t.Run(fmt.Sprintf("%s/%s", e.op, e.method), func(t *testing.T) {
			requirePanicKindAnsweredLikeErrorKind(t, e, true)
		})
	}
	// #3277 follow-up: post-verdict writes whose error kind needs no registry
	// row, so the registry cannot supply them. The step-up's diff is accepted
	// for every kind by its consume-first entry (verifyMFAStepUpCode) plus the
	// mfa.error outcome log, and impersonation start writes nothing on
	// failure, so oracle (a) never compares their RESPONSE with anything: a
	// panic answered with the Recovery 500 passed the fuzzer. This list is
	// hand-written; it does not discover a new write on these ops by itself.
	for _, e := range postVerdictWritesWithoutRows {
		t.Run(fmt.Sprintf("%s/%s", e.op, e.method), func(t *testing.T) {
			if hasByDesignRow(e.op, e.method, e.nth, faultstorage.KindError) {
				t.Fatalf("%s %s#%d now has a KindError row: move it to the registry population", e.op, e.method, e.nth)
			}
			requirePanicKindAnsweredLikeErrorKind(t, e, false)
		})
	}
}

// postVerdictWritesWithoutRows: see TestPostVerdictWritePanic_AnsweredLikeItsError.
// Setup consume (/auth/setup/consume) is not in opCatalog; its family guard is
// server/http/handlers' TestConsumeSetup_PostVerdictPanicAnsweredLikeItsError.
var postVerdictWritesWithoutRows = []oracleAByDesignError{
	{op: "REST POST /api/v1/auth/mfa/stepup", method: "MarkTOTPStepUsed", nth: 1},
	{op: "REST POST /api/v1/auth/mfa/stepup", method: "CreateMFAStepUpGrant", nth: 1},
	{op: "REST POST /api/v1/admin/impersonate", method: "CreateSession", nth: 1},
}
