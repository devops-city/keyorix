// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	registerOracleAByDesign("post_auth_mfa_verify_createsession", oracleAByDesignError{
		op:          "REST POST /auth/mfa/verify",
		method:      "CreateSession",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt", "MFASecret"},
		outcomeLogs: []string{"AuditEvent"},
		designComment: "internal/core/mfa.go VerifyMFALoginPending: on a mintSession failure the consumed TOTP " +
			"step is given back with ReleaseTOTPStepIfUnchanged (#2567; last_used_step -> step-1, see its " +
			"interface doc), the attempt is counted (lc.Failed) and the error is ErrLoginPostVerdict, so " +
			"\"the per-IP login-attempt slot stays CONSUMED\" and VerifyMFA audits auth.login_error",
		provingTest: "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/CreateSession/error " +
			"(slot, lockout, response parity, no session); server/http/handlers/" +
			"TestVerifyMFA_MintFailureAfterCorrectCodeAuditsLoginError (audit); internal/core/" +
			"TestVerifyMFALogin_CreateSessionFailure_ReleasesTOTPStepForRetry (MFASecret)",
		why: "The code matched and the session write failed. No session exists, the slot stays counted exactly " +
			"as for a wrong code (#2880/#2894), and MFASecret differs only because the step release writes " +
			"last_used_step = step-1 rather than the row's pre-mark value -- which re-permits exactly this one " +
			"step so the user can retry the same code, and cannot re-open any step a later request consumed " +
			"(CAS-guarded). The AuditEvent is the auth.login_error record.",
	})
}
