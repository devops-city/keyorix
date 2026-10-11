// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// FIX-3065 (REVIEW-AUTH-1 point at 3d340933): the owner read on /auth/refresh is
	// POST-verdict. RefreshSession reads the owner (GetUser) only after GetSessionAny
	// matched a live token and the reuse, ceiling and impersonation verdicts ran, so
	// a fault there keeps the per-IP login-attempt slot (Andrei, #2880 and the
	// RotateSession row): a correct token must never be cheaper than a wrong one.
	// Only the GetSessionAny fault is pre-verdict (core.ErrRefreshNotEvaluated,
	// slot released, no diff).
	registerOracleAByDesign("post_auth_refresh_getuser", oracleAByDesignError{
		op:     "REST POST /auth/refresh",
		method: "GetUser",
		kind:   faultstorage.KindError,
		nth:    1,
		tables: []string{"LoginAttempt"},
		designComment: "internal/core/auth.go RefreshSession: GetUser runs after GetSessionAny found the token, " +
			"unrotated, inside its ceiling and not impersonated -- the token verdict is already reached -- and its " +
			"error is \"failed to read account\", not ErrRefreshNotEvaluated (which wraps only the GetSessionAny " +
			"lookup); server/http/handlers/auth.go RefreshToken returns the per-IP slot only for a DELIVERED " +
			"session (returnLoginSlot, #2936) and for ErrRefreshNotEvaluated",
		provingTest: "server/http/handlers/TestRefresh_GetUserFaultKeepsSlotAndMatchesFailureShape " +
			"(slot kept, response byte-identical to a wrong token's, token still usable); " +
			"server/http/handlers/TestRefresh_StorageFaultSlotPolicy (every storage call refresh makes, classified pre/post verdict)",
		why: "The token matched a live session and the owner read failed, so the refresh is refused with the same " +
			"401 a dead token gets and keeps the LoginAttempt slot it reserved. Returning it would make a valid " +
			"token cheaper than a wrong one, observable as when the per-IP 429s start (#2880). The read writes " +
			"nothing: the session is untouched and the only diff is the kept LoginAttempt row, which is the " +
			"rate-limit enforcement, not a partial commit.",
	})
}
