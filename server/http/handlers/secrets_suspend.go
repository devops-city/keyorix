// secrets_suspend.go — SuspendSecret / ResumeSecret handlers: freeze or restore value
// reads of a secret (incident response).
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SuspendSecret handles POST /api/v1/secrets/{id}/suspend with an optional body
// {"reason": "...", "clear_synced_copies": true}. clear_synced_copies asks the operator
// and k8s-sync to also empty the copies synced to Kubernetes clusters for this suspension
// (a compromise response; resume removes the request). Scoped secrets.write is enforced
// by the router; the flag needs no further permission.
func (h *SecretHandler) SuspendSecret(w http.ResponseWriter, r *http.Request) {
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
		Reason            string `json:"reason"`
		ClearSyncedCopies bool   `json:"clear_synced_copies"`
	}
	_ = json.NewDecoder(r.Body).Decode(&reqBody) // body is optional

	secret, err := h.coreService.SuspendSecretWithOptions(r.Context(), uint(id), userCtx.UserID, reqBody.Reason,
		core.SuspendOptions{ClearSyncedCopies: reqBody.ClearSyncedCopies})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to suspend secret", http.StatusInternalServerError, nil)
		}
		return
	}
	h.sendSuccess(w, newSecretNodeWire(secret), "Secret suspended")
}

// ResumeSecret handles POST /api/v1/secrets/{id}/resume. Scoped secrets.write is
// enforced by the router.
func (h *SecretHandler) ResumeSecret(w http.ResponseWriter, r *http.Request) {
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
	secret, err := h.coreService.ResumeSecret(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to resume secret", http.StatusInternalServerError, nil)
		}
		return
	}
	h.sendSuccess(w, newSecretNodeWire(secret), "Secret resumed")
}
