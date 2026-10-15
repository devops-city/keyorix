// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3267: the panic kind of the post-verdict identity read, the fuzzer's own
	// finding for GetUserPermissions (input fe6c11ccaf78dcc3593231, seed
	// testdata/fuzz/FuzzStorageFaultOperations/48f5b7ad020f2e32). It replaces
	// the expiring knownOpenTolerance #3269 added. Same decided outcome as the
	// error row, checked per run by wrongCredentialResponse.
	registerOracleAByDesign("post_auth_mfa_verify_getuserroles_panic", oracleAByDesignError{
		op: "REST POST /auth/mfa/verify", method: "GetUserRoles", kind: faultstorage.KindPanic, nth: 1,
		tables: []string{"LoginAttempt", "MFASecret"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongTOTPCodeResponse,
		consumedBy:              "(*KeyorixCore).VerifyMFACredentials",
		consumedColumns:         map[string][]string{"MFASecret": {"LastUsedStep"}},
		designComment:           identityReadPanicDesign,
		provingTest: "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/GetUserRoles/panic " +
			"(through middleware.Recovery); server/http/handlers/TestVerifyMFA_IdentityReadPanicAuditsLoginErrorAndKeepsTheCodeBurned/GetUserRoles; " +
			identityReadPanicFamilyTest,
		why: identityReadPanicWhy,
	})
}
