// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// Same #2880 decision on REST POST /auth/webauthn/login/finish. On main this
	// tuple's diff is [LoginAttempt], absorbed by #2565's wildcard
	// knownOpenTolerance; #2894 adds the auth.login_error audit for a
	// post-verdict fault, so the diff becomes [AuditEvent LoginAttempt] and the
	// wildcard (tables [LoginAttempt]) no longer covers it. TOL-1 (#2949) pins
	// the main-side shape of this same tuple without the AuditEvent: whichever of
	// the two merges second keeps ONE row for this tuple -- this one, since it
	// is the superset -- and TestOracleAByDesign_RowsAreLoadBearing fails on the
	// narrower one if both survive.
	registerOracleAByDesign("post_auth_webauthn_login_finish_createsession", oracleAByDesignError{
		op:          "REST POST /auth/webauthn/login/finish",
		method:      "CreateSession",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt"},
		outcomeLogs: []string{"AuditEvent"},
		designComment: "server/http/handlers/webauthn.go FinishWebAuthnLogin releases the per-IP reservation " +
			"ONLY on core.ErrWebAuthnLoginNotEvaluated, and audits a core.ErrLoginPostVerdict failure as " +
			"auth.login_error (#2894); internal/core/webauthn.go ErrWebAuthnLoginNotEvaluated is reserved " +
			"for storage errors BEFORE any verdict on the assertion, and mintSession runs after it passed",
		provingTest: "internal/core/TestFinishWebAuthnLogin_MintFailureAfterAssertion_StillCountsTheLoginAttempt " +
			"(slot); internal/core/TestFinishWebAuthnLogin_PostVerdictFaultCostsTheSameAsAFailedAssertion " +
			"(ErrLoginPostVerdict, lockout parity)",
		why: "The WebAuthn assertion was evaluated and passed before CreateSession failed, so the request is a " +
			"genuine login attempt and keeps the IP slot it reserved -- releasing it would let an attacker " +
			"drive unlimited post-verification failures without spending budget (#2880). No session is " +
			"minted. The AuditEvent is the auth.login_error record that keeps the storage fault " +
			"distinguishable from a failed assertion for an operator.",
	})
}
