// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3277: the panic kind of the TOTP anti-replay write. Same decided outcome
	// as the error row (MarkTOTPStepUsed#1/error), checked per run by
	// wrongCredentialResponse. FaultyStorage panics in place of the call, so
	// the mark never lands here; a mark that lands and THEN panics is
	// internal/core's TestLoginWritePanic_DeniedLikeItsError (the step stays
	// burned, a replay is refused).
	registerOracleAByDesign("post_auth_mfa_verify_marktotpstepused_panic", oracleAByDesignError{
		op: "REST POST /auth/mfa/verify", method: "MarkTOTPStepUsed", kind: faultstorage.KindPanic, nth: 1,
		tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongTOTPCodeResponse,
		designComment:           writePanicDesign,
		provingTest: "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/MarkTOTPStepUsed/panic " +
			"(through middleware.Recovery); server/http/handlers/TestVerifyMFA_WritePanicKeepsTheCodeBurned/MarkTOTPStepUsed; " +
			writePanicFamilyTest,
		why: writePanicWhy + " The AuditEvent is mfa.error, as for the error kind.",
	})
}
