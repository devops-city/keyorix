// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// ---- ORPHAN-2: #2844 triage class A, the #2880 decision on /auth/login and
	// /auth/mfa/verify (coordinator, 2026-10-10 23:50). A storage fault after a
	// CORRECT credential is answered like a wrong one, audited and counted. One
	// row per op x method x kind, each carrying wrongCredentialResponse, so every
	// fuzz input re-checks the whole outcome: the response byte-identical to a
	// wrong credential's, the LoginAttempt slot kept, the auth.login_error /
	// mfa.error audit written. The effect-then-error rows are oracle (d)'s; for a
	// read the "effect" is the read itself, so the state is the error kind's.
	//
	// NOT pinned here: the PANIC kind of the same tuples. A post-verdict panic
	// reaches the Recovery middleware and answers 500 with no audit event (and on
	// /auth/mfa/verify also hands the slot back, #3048), which is not the decided
	// outcome. Those tuples still fail the oracle on purpose (NEEDS ANDREI in
	// SESSION-ORPHAN-2.md).
	registerOracleAByDesign("post_auth_login_createsession", oracleAByDesignError{
		op: "REST POST /auth/login", method: "CreateSession", kind: faultstorage.KindError, nth: 1,
		tables: []string{"LoginAttempt"}, outcomeLogs: []string{"AuditEvent"},
		wrongCredentialResponse: wrongPasswordResponse,
		designComment:           loginPostVerdictDesign,
		provingTest: "server/http/handlers/TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword/CreateSession/error " +
			"(response, lockout, slot, no session); server/http/handlers/TestLogin_PostVerdictFaultAuditsLoginErrorNotLoginFailed",
		why: loginPostVerdictWhy,
	})
}
