// secret_ownership_history.go — OwnershipHistory handler: the chain of ownership
// transfers for a single secret, derived from the audit log.
package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// OwnershipHistory handles GET /api/v1/secrets/{id}/ownership-history — the ordered
// list of ownership transfers for a secret (oldest first). Requires secrets.read at
// the secret's scope; core re-checks read access. Returns an empty array when no
// transfers have occurred.
func (h *SecretHandler) OwnershipHistory(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	records, err := h.coreService.GetSecretOwnershipHistory(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "not found"):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized"):
			h.sendError(w, "Forbidden", "Not authorized to view this secret's ownership history", http.StatusForbidden, nil)
		default:
			h.sendError(w, "InternalError", "Failed to retrieve ownership history", http.StatusInternalServerError, nil)
		}
		return
	}

	if records == nil {
		records = []core.OwnershipRecord{}
	}
	h.sendSuccess(w, map[string]any{"ownership_history": records, "total": len(records)}, "")
}
