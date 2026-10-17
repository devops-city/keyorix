// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3277: the panic kind of the session insert on /auth/login. Same decided
	// outcome as the error row, checked per run by wrongCredentialResponse.
	registerOracleAByDesign("post_auth_login_createsession_panic", oracleAByDesignError{
		op: "REST POST /auth/login", method: "CreateSession", kind: faultstorage.KindPanic, nth: 1,
		tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongPasswordResponse,
		designComment:           writePanicDesign,
		provingTest: "server/http/handlers/TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword/CreateSession/panic " +
			"(through middleware.Recovery); internal/core/TestLogin_SessionWritePanicsAfterCommit_RevokesTheRowAndDenies; " +
			writePanicFamilyTest,
		why: writePanicWhy + " The AuditEvent is auth.login_error, as for the error kind.",
	})
}
