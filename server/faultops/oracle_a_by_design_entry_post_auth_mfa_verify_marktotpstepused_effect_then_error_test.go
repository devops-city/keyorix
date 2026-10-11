// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// The anti-replay write itself, effect-then-error: the step WAS marked used
	// (the effect landed), then the call reported an error. Same outcome as
	// the error-kind row above (MarkTOTPStepUsed#1/error), plus the consumption
	// that did land.
	registerOracleAByDesign("post_auth_mfa_verify_marktotpstepused_effect_then_error", oracleAByDesignError{
		op: "REST POST /auth/mfa/verify", method: "MarkTOTPStepUsed", kind: faultstorage.KindEffectThenError, nth: 1,
		tables: []string{"LoginAttempt", "MFASecret"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongTOTPCodeResponse,
		consumedBy:              "(*KeyorixCore).VerifyMFACredentials",
		consumedColumns:         map[string][]string{"MFASecret": {"LastUsedStep"}},
		designComment: "internal/core/mfa.go VerifyMFACredentials: \"the code WAS confirmed correct here -- only the " +
			"anti-replay consumption write (MarkTOTPStepUsed) failed. This must still count toward the lockout " +
			"exactly like a wrong code would\" (#2888); not ErrMFAVerificationUnavailable, the handler's only " +
			"release condition (server/http/handlers/mfa.go)",
		provingTest: "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/MarkTOTPStepUsed/effect-then-error",
		why: "The code matched and the step was marked used, but the write reported an error, so the login is refused. " +
			"It keeps its LoginAttempt slot and is audited mfa.error exactly as the error kind is (#2894). The burned " +
			"step is VerifyMFACredentials' class-B anti-replay consumption: rolling it back would make the same code " +
			"replayable. No session, grant or step-up token is written.",
	})
}
