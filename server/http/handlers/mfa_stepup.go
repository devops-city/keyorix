// mfa_stepup.go — HTTP handler for explicit MFA step-up re-verification.
// POST /api/v1/auth/mfa/stepup lets an already-authenticated user re-verify
// their TOTP code (or a recovery code) to open a 15-minute window for reading
// "restricted" classified secrets without going through a full re-login.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// MFAStepUp handles POST /api/v1/auth/mfa/stepup. The caller must be
// authenticated (session or PAT). On success, a short-lived MFAStepupToken is
// recorded server-side, enabling the classification gate to permit reads of
// "restricted" secrets for the configured window (default 15 minutes).
func (h *AuthHandler) MFAStepUp(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	if strings.TrimSpace(body.Code) == "" {
		sendError(w, "BadRequest", "code is required", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.VerifyMFAStepUp(r.Context(), userCtx.UserID, body.Code); err != nil {
		if errors.Is(err, core.ErrMFAVerificationUnavailable) {
			// FIX-1 (#2548 sibling) + #2740 review: no code was evaluated, so
			// "retry" leaks nothing. See errMFAVerificationUnavailable (mfa.go).
			sendError(w, "ServiceUnavailable", errMFAVerificationUnavailable, http.StatusServiceUnavailable, nil)
			return
		}
		if errors.Is(err, core.ErrMFAVerificationStorageFailure) || errors.Is(err, core.ErrLoginPostVerdict) {
			// Storage failed AFTER the code was found correct (the anti-replay
			// mark, the lock recheck, the grant write): answer exactly like a
			// wrong code (same status, same text) so a correct guess is never
			// confirmed, and never echo the wrapped storage error. Core has
			// already counted it and audited mfa.error (#2894 review).
			sendError(w, "Unauthorized", "invalid code", http.StatusUnauthorized, nil)
			return
		}
		sendError(w, "Unauthorized", stepUpRefusalMessage(err), http.StatusUnauthorized, nil)
		return
	}
	sendSuccess(w, nil, "MFA step-up verified. Restricted secrets are accessible for 15 minutes.")
}

// stepUpRefusalMessage is the client text for every other step-up refusal. The
// messages core returns on those branches are fixed strings about the caller's
// own account (not active, locked, MFA not enrolled) or "invalid code", none of
// which wraps a cause. Anything else (a new branch that wraps a storage error)
// gets "invalid code" rather than its err.Error(), so a future wrap cannot
// leak driver text or a post-verdict hint through this fallthrough.
func stepUpRefusalMessage(err error) string {
	if errors.Unwrap(err) != nil {
		return "invalid code"
	}
	return err.Error()
}
