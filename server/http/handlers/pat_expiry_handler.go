// pat_expiry_handler.go — HTTP handlers for the caller's expired personal access tokens.
//
// Routes (all under /api/v1/auth/tokens/expired, authenticated, self-scoped):
//
//	GET    /auth/tokens/expired  — list the caller's expired (non-revoked) PATs
//	DELETE /auth/tokens/expired  — bulk-revoke all the caller's expired PATs
package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// PATExpiryHandler handles self-service expired-token cleanup.
type PATExpiryHandler struct {
	coreService *core.KeyorixCore
}

// NewPATExpiryHandler constructs a PATExpiryHandler.
func NewPATExpiryHandler(coreService *core.KeyorixCore) *PATExpiryHandler {
	return &PATExpiryHandler{coreService: coreService}
}

// ListExpiredPATs handles GET /auth/tokens/expired — returns the caller's
// non-revoked PATs whose ExpiresAt is in the past.
func (h *PATExpiryHandler) ListExpiredPATs(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetHumanUser(w, r)
	if !ok {
		return
	}
	tokens, err := h.coreService.ListExpiredOwnPATs(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "InternalError", "Failed to list expired tokens", http.StatusInternalServerError, nil)
		return
	}
	out := make([]patResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, toPATResponse(t))
	}
	sendSuccess(w, out, "")
}

// BulkRevokeExpiredPATs handles DELETE /auth/tokens/expired — bulk-revokes all
// the caller's non-revoked, expired PATs and returns 204 No Content on success.
func (h *PATExpiryHandler) BulkRevokeExpiredPATs(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetHumanUser(w, r)
	if !ok {
		return
	}
	_, err := h.coreService.BulkRevokeExpiredOwnPATs(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "InternalError", "Failed to revoke expired tokens", http.StatusInternalServerError, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
