// secrets_bulk_rotate.go — BulkRotateSecrets handler: trigger rotation for multiple
// secrets in a single project call — the HTTP transport for core.BulkRotateSecrets.
// Scoped secrets.write (project) is enforced by the router.
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

// BulkRotateSecrets handles POST /api/v1/projects/{id}/secrets/bulk-rotate.
//
// Request body (all fields optional):
//
//	{
//	  "secret_ids":       [1, 2, 3],       // explicit list; if omitted, rotate all matching
//	  "environment_id":   4,               // optional env filter (ignored when secret_ids set)
//	  "classification":   "confidential"   // optional classification filter (ignored when secret_ids set)
//	}
//
// Returns a BulkRotateResult JSON object with triggered/failed counts. Individual secret
// failures never abort the run — partial results are always returned.
func (h *SecretHandler) BulkRotateSecrets(w http.ResponseWriter, r *http.Request) {
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
		SecretIDs      []uint `json:"secret_ids"`
		EnvironmentID  uint   `json:"environment_id"`
		Classification string `json:"classification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	req := core.BulkRotateRequest{
		ProjectID:      uint(id),
		SecretIDs:      reqBody.SecretIDs,
		EnvID:          reqBody.EnvironmentID,
		Classification: strings.TrimSpace(reqBody.Classification),
		RotatedBy:      userCtx.Username,
	}

	result, err := h.coreService.BulkRotateSecrets(r.Context(), req)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "exceeds the maximum batch size") {
			status = http.StatusBadRequest
		}
		h.sendError(w, "Error", errorMessageFor(status, err), status, nil)
		return
	}
	h.sendSuccess(w, result, "")
}
