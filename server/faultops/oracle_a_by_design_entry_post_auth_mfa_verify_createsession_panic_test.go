// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3277: the panic kind of the session insert on /auth/mfa/verify. Unlike
	// the error row, the consumed TOTP step is NOT released: after a panic the
	// row's absence is only as good as createSession's best-effort delete, so
	// the accepted code stays used (the step is the class-B consumption the
	// identity-read panic rows keep too).
	registerOracleAByDesign("post_auth_mfa_verify_createsession_panic", oracleAByDesignError{
		op: "REST POST /auth/mfa/verify", method: "CreateSession", kind: faultstorage.KindPanic, nth: 1,
		tables: []string{"LoginAttempt", "MFASecret"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongTOTPCodeResponse,
		consumedBy:              "(*KeyorixCore).VerifyMFACredentials",
		consumedColumns:         map[string][]string{"MFASecret": {"LastUsedStep"}},
		designComment:           writePanicDesign,
		provingTest: "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/CreateSession/panic " +
			"(through middleware.Recovery); server/http/handlers/TestVerifyMFA_WritePanicKeepsTheCodeBurned/CreateSession; " +
			writePanicFamilyTest,
		why: writePanicWhy + " The AuditEvent is auth.login_error, as for the error kind.",
	})
}
