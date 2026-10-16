// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3277: the panic kind of the session insert on WebAuthn login finish.
	// Like the error row it carries no wrongCredentialResponse (faultops has no
	// failed-assertion request); TestPostVerdictWritePanic_AnsweredLikeItsError
	// requires it to match the error kind, and internal/core's
	// TestLoginWritePanic_DeniedLikeItsError compares it with a failed assertion.
	registerOracleAByDesign("post_auth_webauthn_login_finish_createsession_panic", oracleAByDesignError{
		op: "REST POST /auth/webauthn/login/finish", method: "CreateSession", kind: faultstorage.KindPanic, nth: 1,
		tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
		designComment: writePanicDesign,
		provingTest: "internal/core/TestLoginWritePanic_DeniedLikeItsError/FinishWebAuthnLogin; " +
			"server/http/handlers/TestFinishWebAuthnLogin_PanicKeepsTheSlotOnlyAfterTheVerdict/CreateSession; " +
			writePanicFamilyTest,
		why: writePanicWhy + " The AuditEvent is auth.login_error, as for the error kind.",
	})
}
