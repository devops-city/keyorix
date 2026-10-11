// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #2880 / #2894: post-verdict faults on /auth/mfa/verify. Both are reached
	// only AFTER the TOTP code matched, so the request is charged exactly like
	// a wrong code -- lockout counter, per-IP LoginAttempt slot and a 401
	// byte-identical to a wrong code -- because doing anything cheaper for a
	// correct code is a side channel confirming correctness. Found untolerated
	// on #2894's head by LOGIN-ACCT-1 (pass on main, where the slot used to be
	// released). Pinned per method; never a wildcard.
	registerOracleAByDesign("post_auth_mfa_verify_marktotpstepused", oracleAByDesignError{
		op:          "REST POST /auth/mfa/verify",
		method:      "MarkTOTPStepUsed",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt"},
		outcomeLogs: []string{"AuditEvent"},
		designComment: "internal/core/mfa.go VerifyMFACredentials: \"the code WAS confirmed correct here -- " +
			"only the anti-replay consumption write (MarkTOTPStepUsed) failed. This must still count toward " +
			"the lockout exactly like a wrong code would\" (#2888); the error wraps " +
			"ErrMFAVerificationStorageFailure but NOT ErrMFAVerificationUnavailable, the handler's only " +
			"release condition (server/http/handlers/mfa.go)",
		provingTest: "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/MarkTOTPStepUsed/error " +
			"(slot, lockout, response parity); internal/core/" +
			"TestVerifyMFALogin_MarkTOTPStepUsedErrorAfterMatch_StillCountsTowardLockout (lockout, mfa.error audit)",
		why: "The code matched; only the anti-replay write failed, so the login is refused (the step could not " +
			"be recorded as used) and the request keeps its LoginAttempt slot like a wrong code does. Releasing " +
			"the slot here would make a correct guess cheaper than a wrong one, observable as when the per-IP " +
			"429s start (#2894). The AuditEvent is the mfa.error record that keeps the storage fault " +
			"distinguishable from a wrong code for an operator. No session, grant or step is left behind.",
	})
}
