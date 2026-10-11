// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	registerOracleAByDesign("post_auth_mfa_verify_getuserpermissions", oracleAByDesignError{
		op: "REST POST /auth/mfa/verify", method: "GetUserPermissions", kind: faultstorage.KindError, nth: 1,
		tables: []string{"LoginAttempt", "MFASecret"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongTOTPCodeResponse,
		consumedBy:              "(*KeyorixCore).VerifyMFACredentials",
		consumedColumns:         map[string][]string{"MFASecret": {"LastUsedStep"}},
		designComment:           mfaVerifyPostVerdictDesign,
		provingTest:             "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/GetUserPermissions/error",
		why:                     mfaVerifyPostVerdictWhy,
	})
}
