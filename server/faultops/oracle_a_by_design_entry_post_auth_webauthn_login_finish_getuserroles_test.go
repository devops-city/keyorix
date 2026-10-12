// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #2880 (auth owner's decision: a post-verdict storage fault keeps the
	// per-IP login attempt counted), GetUserRoles half. Pinned, never a
	// wildcard: only the one post-assertion read is covered, and only for the
	// [LoginAttempt] residue. Before #2841's fix this same tuple also left an
	// MFAStepUpGrant and a login AuditEvent behind (#2807/#2841, tolerated
	// twice in knownOpenTolerances); those halves were the bug and are gone —
	// a diff naming MFAStepUpGrant or Session again is not covered by this row
	// and fails oracle (a) loudly.
	// With #2894 the failure is post-verdict (ErrLoginPostVerdict wrapping
	// ErrLoginIdentityUnavailable): answered like a failed assertion and
	// audited as auth.login_error, hence the AuditEvent outcome log.
	registerOracleAByDesign("post_auth_webauthn_login_finish_getuserroles", oracleAByDesignError{
		op:          "REST POST /auth/webauthn/login/finish",
		method:      "GetUserRoles",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt"},
		outcomeLogs: []string{"AuditEvent"},
		// #3106 (FUZZ-RULES-3): same decision as #3091. GetUserRoles is a pure
		// read, so its effect-then-error ends in this same state; oracle (d) may
		// consult this row for it (oracle_d_pure_read_by_design_test.go).
		pureReadEffectThenError: true,
		designComment: "internal/core/webauthn.go: ErrLoginIdentityUnavailable (\"deliberately NOT " +
			"ErrWebAuthnLoginNotEvaluated: the assertion WAS evaluated and passed, so the per-IP " +
			"login-attempt reservation must stay counted\"); server/http/handlers/webauthn.go " +
			"FinishWebAuthnLogin releases the reservation only on ErrWebAuthnLoginNotEvaluated",
		provingTest: "internal/core/TestFinishWebAuthnLogin_IdentityReadFailureLeavesNoSessionOrGrant",
		why: "The WebAuthn assertion has already been evaluated and passed when the response identity " +
			"read fails, so the request is a genuine login attempt and keeps the IP slot it reserved. " +
			"Releasing it would let an attacker drive unlimited post-verification failures against an " +
			"IP without spending budget (#2880). The login itself is refused with no session, no step-up " +
			"grant and no step-up token written (#2841), so the kept LoginAttempt row is the only state " +
			"left, and it is the rate-limit enforcement, not a partial commit.",
	})
}
