// secrets_access_list.go — ListAccessors handler: the effective access list for a
// secret (who can read it).
package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListAccessors handles GET /api/v1/secrets/{id}/access — returns the distinct users
// who can read the secret (owner + direct + group shares). Scoped secrets.read is
// enforced by the router; core re-checks the caller's read access.
func (h *SecretHandler) ListAccessors(w http.ResponseWriter, r *http.Request) {
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

	result, err := h.coreService.ListSecretAccessors(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "not found"):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized"):
			h.sendError(w, "Forbidden", "Not authorized to view this secret's access", http.StatusForbidden, nil)
		default:
			h.sendError(w, "InternalError", "Failed to list accessors", http.StatusInternalServerError, nil)
		}
		return
	}
	// #417: degraded/degraded_reasons must reach API consumers — a report that
	// silently dropped a group's members would look identical to a fully-resolved
	// one otherwise.
	h.sendSuccess(w, map[string]any{
		"accessors":        result.Accessors,
		"total":            len(result.Accessors),
		"degraded":         result.Degraded,
		"degraded_reasons": result.DegradedReasons,
	}, "")
}
