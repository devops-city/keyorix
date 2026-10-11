// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	registerOracleAByDesign("post_auth_mfa_verify_getuserroles_effect_then_error", oracleAByDesignError{
		op: "REST POST /auth/mfa/verify", method: "GetUserRoles", kind: faultstorage.KindEffectThenError, nth: 1,
		tables: []string{"LoginAttempt", "MFASecret"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongTOTPCodeResponse,
		consumedBy:              "(*KeyorixCore).VerifyMFACredentials",
		consumedColumns:         map[string][]string{"MFASecret": {"LastUsedStep"}},
		designComment:           mfaVerifyPostVerdictDesign,
		provingTest:             "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/GetUserRoles/effect-then-error",
		why:                     mfaVerifyPostVerdictWhy,
	})
}
