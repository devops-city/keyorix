// secrets_bulk_rename.go — BulkRenameSecrets handler: rename a project's secrets toward
// naming-policy conformance in one call (the remediation for the name-conformance
// report). Scoped secrets.write (project) is enforced by the router. Never touches values.
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

// BulkRenameSecrets handles POST /api/v1/projects/{id}/secrets/bulk-rename with
// {"renames":[{"id":N,"new_name":"..."}],"dry_run":false}. Each new name must satisfy
// the current naming policy and not collide with a sibling; entries failing a check are
// skipped (with a reason) while the rest proceed. dry_run validates and reports without
// changing anything. Returns the BulkRenameReport. Never reads or changes a value.
func (h *SecretHandler) BulkRenameSecrets(w http.ResponseWriter, r *http.Request) {
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
		Renames []core.SecretRename `json:"renames"`
		DryRun  bool                `json:"dry_run"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	ip, ua := clientIP(r), r.Header.Get("User-Agent")
	report, err := h.coreService.BulkRenameSecrets(r.Context(), uint(id), reqBody.Renames, reqBody.DryRun, userCtx.Username, userCtx.UserID, ip, ua)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "exceeds the maximum batch size") {
			status = http.StatusBadRequest
		}
		h.sendError(w, "Error", errorMessageFor(status, err), status, nil)
		return
	}
	h.sendSuccess(w, report, "")
}
