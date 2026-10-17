// secrets_reassign_owner.go — bulk owner reassignment: re-home a departed user's
// secrets in a project to a new owner (offboarding).
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ReassignOwner handles POST /api/v1/projects/{id}/secrets/reassign-owner with
// {"from_owner_id":N,"to_owner_id":M} — transfers every secret in the project owned by
// from_owner_id to to_owner_id (offboarding). Scoped secrets.write (project) is enforced
// by the router; the per-secret transfer re-checks ownership/owner-gone authorization.
func (h *SecretHandler) ReassignOwner(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		FromOwnerID uint `json:"from_owner_id"`
		ToOwnerID   uint `json:"to_owner_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	n, err := h.coreService.ReassignOwnedSecrets(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), uint(id), reqBody.FromOwnerID, reqBody.ToOwnerID)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "required"), strings.Contains(err.Error(), "must differ"), strings.Contains(err.Error(), "not found"):
			status = http.StatusBadRequest
		case strings.Contains(err.Error(), "permission"), strings.Contains(err.Error(), "not authorized"):
			status = http.StatusForbidden
		}
		h.sendError(w, "Error", errorMessageFor(status, err), status, nil)
		return
	}
	h.sendSuccess(w, map[string]any{"reassigned": n}, "")
}
