// secrets_retention_override.go — SetRetentionOverride handler.
//
// PATCH /api/v1/secrets/{id}/retention
// Body:    {"retention_override_days": N}  (0 = clear override)
// Success: 200 {"data": {"secret_id": N, "retention_override_days": N}}
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SetRetentionOverride handles PATCH /api/v1/secrets/{id}/retention.
// Gated by secrets.manage at the secret scope (wired in router.go).
func (h *SecretHandler) SetRetentionOverride(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	rawID := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(rawID, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
		RetentionOverrideDays int `json:"retention_override_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	if err := h.coreService.SetSecretRetentionOverride(
		r.Context(), userCtx.UserID, uint(id), reqBody.RetentionOverrideDays,
	); err != nil {
		if errors.Is(err, core.ErrInvalidRetentionDays) {
			h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
			return
		}
		h.sendError(w, "InternalError", "Failed to set retention override", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, map[string]any{
		"secret_id":               uint(id),
		"retention_override_days": reqBody.RetentionOverrideDays,
	}, "Retention override updated")
}
