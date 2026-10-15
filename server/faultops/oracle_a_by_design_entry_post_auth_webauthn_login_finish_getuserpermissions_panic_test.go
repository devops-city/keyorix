// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3267 family: the panic kind of the post-verdict identity read. Mirrors
	// the error row, which has no wrongCredentialResponse either: this package
	// has no wrong-assertion request to derive one from
	// (wrongCredentialRequests). So, like the error row, this row alone would
	// also accept the pre-#3267 shape (the Recovery 500, diff [LoginAttempt]);
	// what refuses that shape is TestPostVerdictIdentityReadPanic_AnsweredLikeItsError,
	// which runs in default CI and requires the panic's response, diff and
	// AuditEvent count to equal the error kind's (red on main for this tuple).
	registerOracleAByDesign("post_auth_webauthn_login_finish_getuserpermissions_panic", oracleAByDesignError{
		op: "REST POST /auth/webauthn/login/finish", method: "GetUserPermissions", kind: faultstorage.KindPanic, nth: 1,
		tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
		designComment: identityReadPanicDesign,
		provingTest: "internal/core/TestLoginIdentityReadPanic_DeniedLikeItsError/FinishWebAuthnLogin/GetUserPermissions; " +
			identityReadPanicFamilyTest + " (response byte-identical to the error kind's, through the real router)",
		why: identityReadPanicWhy,
	})
}
