// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// REFRESH-ROW-1/2 (#3082's red, FuzzStorageFaultOperations seed "\xa3y#200000"):
	// a storage fault AFTER the token verdict keeps the per-IP login-attempt slot
	// (Andrei, 2026-10-11, under the #2880 rule): a valid token must never be cheaper
	// than a wrong one, or the slot count would tell an attacker which guess hit a
	// live session. RotateSession runs only after RefreshSession found the token,
	// saw it unrotated, inside its absolute ceiling, not impersonated, and its
	// owner active -- every refusal before that is a verdict. The row is pinned to
	// this one method and kind. The one PRE-verdict read (GetSessionAny) is NOT
	// covered: it releases the slot (core.ErrRefreshNotEvaluated) and leaves no
	// diff, and a diff there would fail oracle (a) loudly. The owner read GetUser
	// is post-verdict too and has its own row (post_auth_refresh_getuser).
	registerOracleAByDesign("post_auth_refresh_rotatesession", oracleAByDesignError{
		op:     "REST POST /auth/refresh",
		method: "RotateSession",
		kind:   faultstorage.KindError,
		nth:    1,
		tables: []string{"LoginAttempt"},
		designComment: "internal/core/auth.go RefreshSession: RotateSession runs after the token was found, " +
			"unrotated, inside its ceiling and its owner active -- the token verdict -- and its error is " +
			"\"failed to rotate session\", not ErrRefreshNotEvaluated (which wraps only the GetSessionAny " +
			"lookup before the verdict); server/http/handlers/auth.go RefreshToken returns the per-IP slot " +
			"only for a DELIVERED session (returnLoginSlot, #2936) and for ErrRefreshNotEvaluated",
		provingTest: "server/http/handlers/TestRefresh_RotateSessionFaultKeepsSlotAndMatchesFailureShape " +
			"(slot kept, response byte-identical to a wrong token's); " +
			"server/http/handlers/TestRefresh_StorageFaultSlotPolicy (every storage call refresh makes, classified pre/post verdict)",
		why: "The token was accepted and the rotation write failed, so the refresh is refused with the same 401 a " +
			"dead token gets and keeps the LoginAttempt slot it reserved. Returning it would make a valid token " +
			"cheaper than a wrong one, observable as when the per-IP 429s start (#2880). The rotation is one " +
			"transaction, so nothing else is written: no new session, the old row is not retired, and the " +
			"kept LoginAttempt row is the rate-limit enforcement, not a partial commit.",
	})
}
