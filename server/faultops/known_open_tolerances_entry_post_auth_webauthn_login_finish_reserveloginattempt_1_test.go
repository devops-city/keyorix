// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// The fifth #2549 entry (op="REST POST /api/v1/auth/mfa/stepup",
	// method=CreateMFAStepUpGrant#1, tables=[MFASecret]) MOVED to
	// oracleAByDesignErrors (oracle_a_by_design_test.go). Unlike the four bulk-op
	// entries above it was genuinely load-bearing — MFASecret is business state,
	// not an outcome log, so no existing exemption reached it — but a
	// knownOpenTolerance was the wrong instrument: this list means "a filed,
	// not-yet-fixed bug, tolerated until someone fixes it", and the entry's own
	// comment said the opposite ("NOT a bug ... the intended fail-closed
	// design"). An expiring bug tolerance over intended behaviour can only be
	// re-filed forever. It now sits in a mechanism whose rows assert
	// by-design-ness and are required to cite the production comment and the
	// proving test that establish it.
	//
	// (#2554's row — REST PATCH /api/v1/secrets/{id}/classification,
	// CreateSecretAccessLog, panic, nth 1 — is GONE, not expired. Its entry
	// said "remove this entry once PR #2560 merges"; it merged and nobody did,
	// which is precisely the decay TestKnownOpenTolerances_AreLoadBearing was
	// added to catch. writeAccessLog (internal/core/audit.go) now recovers from
	// a PANIC in CreateSecretAccessLog, not just a returned error. Same three
	// signals as the deletions at the end of this list: issue CLOSED, the
	// recover() present in the tree, and the row reported dead.)
	// #2565's two wildcard rows on REST POST /auth/webauthn/login/finish
	// (blank method, error and panic, [LoginAttempt]) are settled by TOL-1
	// (QUEUE-FIX-1), re-verified by driving every storage method on the op at
	// nth 1, error and panic, against origin/main @ ff1c2439:
	//
	//   - The pre-verdict triggers #2565 was filed for (ListWebAuthnCredentials,
	//     ConsumeMFAChallenge, ConsumeWebAuthnSession, GetUser) no longer consult
	//     any row: ErrWebAuthnLoginNotEvaluated releases the reservation.
	//   - PANIC row: DELETED, dead (no panic tuple yields a LoginAttempt-only
	//     diff).
	//   - CreateSession#1/error, [LoginAttempt]: post-verdict, by design (#2880)
	//     -- MOVED to oracleAByDesignErrors, pinned (oracle_a_by_design_test.go).
	//     Its GetUserRoles sibling is pinned there by #2876, the PR that makes
	//     that tuple's diff [LoginAttempt]; on main it is still #2807's bug shape.
	//   - ReserveLoginAttempt#1/error: the same #2837 shape as /auth/mfa/verify's
	//     row above (reservation write fails, login succeeds best-effort, run
	//     lacks only the LoginAttempt row). Kept, re-pointed to #2837, pinned to
	//     that method. Expiry deliberately NOT moved.
	registerKnownOpenTolerance("post_auth_webauthn_login_finish_reserveloginattempt_1", knownOpenTolerance{
		op: "REST POST /auth/webauthn/login/finish", method: "ReserveLoginAttempt", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2837", expires: "2026-10-17",
		tables:     []string{"LoginAttempt"},
		findingDoc: "#2837",
	})
}
