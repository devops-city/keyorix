// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// Same #2880 decision, the other half of the identity read (roles, then
	// permissions). #2949 (TOL-1) pins this tuple with tables [LoginAttempt]
	// only, from main's pre-#2894 shape; with #2894's auth.login_error audit the
	// diff is [AuditEvent LoginAttempt]. Whichever merges second keeps ONE row
	// for this tuple -- this one, the superset.
	registerOracleAByDesign("post_auth_webauthn_login_finish_getuserpermissions", oracleAByDesignError{
		op:          "REST POST /auth/webauthn/login/finish",
		method:      "GetUserPermissions",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt"},
		outcomeLogs: []string{"AuditEvent"},
		// #3091 (FUZZ-RULES-2): GetUserPermissions is a pure read, so its
		// effect-then-error ends in this same state; oracle (d) may consult this
		// row for it (oracle_d_pure_read_by_design_test.go).
		pureReadEffectThenError: true,
		designComment: "internal/core/webauthn.go FinishWebAuthnLoginPending: an identity-read failure after the " +
			"assertion verified is denied via denyAfterCredentialMatched (ErrLoginPostVerdict wrapping " +
			"ErrLoginIdentityUnavailable, never ErrWebAuthnLoginNotEvaluated); server/http/handlers/webauthn.go " +
			"releases the reservation only on ErrWebAuthnLoginNotEvaluated and audits auth.login_error",
		provingTest: "internal/core/TestFinishWebAuthnLogin_PermissionsReadFailureLeavesNoSessionOrGrant",
		why: "The assertion has passed when the permissions read fails, so the request keeps the IP slot it " +
			"reserved (#2880) -- releasing it would make post-verification failures free -- and the login is " +
			"refused before any session, step-up grant or step-up token is written (#2841). The AuditEvent is " +
			"the auth.login_error record (#2894).",
	})
}
