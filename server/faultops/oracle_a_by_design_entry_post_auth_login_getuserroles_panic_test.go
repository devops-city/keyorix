// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3267 family: the panic kind of the post-verdict identity read. Same
	// decided outcome as the error row, checked per run by
	// wrongCredentialResponse.
	registerOracleAByDesign("post_auth_login_getuserroles_panic", oracleAByDesignError{
		op: "REST POST /auth/login", method: "GetUserRoles", kind: faultstorage.KindPanic, nth: 1,
		tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongPasswordResponse,
		designComment:           identityReadPanicDesign,
		provingTest: "server/http/handlers/TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword/GetUserRoles/panic " +
			"(through middleware.Recovery); " + identityReadPanicFamilyTest,
		why: identityReadPanicWhy,
	})
}
