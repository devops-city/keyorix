// secrets_bulk_delete.go — BulkDeleteSecrets handler: delete multiple secrets in
// one call. Scoped secrets.delete (project) is enforced by the router.
// Each deletion calls the same DeleteSecret logic as the single-delete path
// (audit log, dependency events, etc.) so no cleanup is bypassed.
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

// BulkDeleteSecrets handles POST /api/v1/projects/{id}/secrets/bulk-delete with
// {"secret_ids":[1,2,3]}. Each ID is deleted via the normal single-secret delete
// path; partial success is allowed — failures are collected in the response rather
// than aborting the entire batch.
func (h *SecretHandler) BulkDeleteSecrets(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}

	var req core.BulkDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	ip, ua := clientIP(r), r.Header.Get("User-Agent")
	result, err := h.coreService.BulkDeleteSecrets(r.Context(), req, uint(projectID), userCtx.Username, userCtx.UserID, ip, ua)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "exceeds the maximum batch size") {
			status = http.StatusBadRequest
		}
		h.sendError(w, "Error", err.Error(), status, nil)
		return
	}

	h.sendSuccess(w, result, "")
}
