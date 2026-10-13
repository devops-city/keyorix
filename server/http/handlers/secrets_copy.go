// secrets_copy.go — CopySecret handler: copy a secret into another environment.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// CopySecret handles POST /api/v1/secrets/{id}/copy with {"environment_id":N,"name":"…"}
// — creates a new secret in the target environment (same project) with the source's
// value and metadata. The route gates secrets.read on the source ({id}); this handler
// additionally authorizes secrets.write at the target environment's scope, so the
// caller must be allowed both to read the source and to create in the target.
func (h *SecretHandler) CopySecret(w http.ResponseWriter, r *http.Request) {
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
	var reqBody struct {
		EnvironmentID uint   `json:"environment_id"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if reqBody.EnvironmentID == 0 {
		h.sendError(w, "BadRequest", "environment_id is required", http.StatusBadRequest, nil)
		return
	}

	// Authorize creating in the target environment (same project as the source).
	source, err := h.coreService.GetSecret(r.Context(), uint(id))
	if err != nil {
		h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		return
	}
	scope := core.Scope{ProjectID: source.ProjectID, EnvironmentID: reqBody.EnvironmentID}
	if allowed, aerr := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "secrets.write", scope); aerr != nil || !allowed {
		h.sendError(w, "Forbidden", "Insufficient permissions for the target environment", http.StatusForbidden, nil)
		return
	}

	created, err := h.coreService.CopySecret(r.Context(), uint(id), reqBody.EnvironmentID, reqBody.Name, userCtx.Username, userCtx.UserID, clientIP(r), r.Header.Get("User-Agent"))
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "same project") || strings.Contains(msg, "already exists") || strings.Contains(msg, "validation") || strings.Contains(msg, "required"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "permission") || strings.Contains(msg, "not authorized"):
			status = http.StatusForbidden
		default:
			log.Printf("Error copying secret %d to environment %d: %v", id, reqBody.EnvironmentID, err) // NOSONAR
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, newSecretNodeWire(created), "Secret copied")
}
