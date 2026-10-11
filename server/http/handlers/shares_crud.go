// shares_crud.go — ShareSecret, UpdateSharePermission, RevokeShare.
//
// Handles creating, updating, and revoking share records.
// For list/query operations see shares_query.go.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ShareSecret handles POST /api/v1/secrets/{id}/share
func (h *ShareHandler) ShareSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
		RecipientID uint       `json:"recipient_id" validate:"required"`
		IsGroup     bool       `json:"is_group"`
		Permission  string     `json:"permission" validate:"required,oneof=read write"`
		ExpiresAt   *time.Time `json:"expires_at"` // optional: time-bound (JIT) share
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	var shareErr error
	var shareRecord *models.ShareRecord

	if reqBody.IsGroup {
		shareRecord, shareErr = h.coreService.ShareSecretWithGroup(r.Context(), &core.GroupShareSecretRequest{
			SecretID:   uint(id),
			GroupID:    reqBody.RecipientID,
			Permission: reqBody.Permission,
			SharedBy:   userCtx.UserID,
			ExpiresAt:  reqBody.ExpiresAt,
		})
	} else {
		shareRecord, shareErr = h.coreService.ShareSecret(r.Context(), &core.ShareSecretRequest{
			SecretID:    uint(id),
			RecipientID: reqBody.RecipientID,
			IsGroup:     false,
			Permission:  reqBody.Permission,
			SharedBy:    userCtx.UserID,
			ExpiresAt:   reqBody.ExpiresAt,
		})
	}

	if shareErr != nil {
		log.Printf("Error sharing secret: %v", shareErr)
		if strings.Contains(shareErr.Error(), errNotFound) {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if reason, ok := core.ShareRefusalMessage(shareErr); ok {
			h.sendError(w, "Forbidden", reason, http.StatusForbidden, nil)
		} else if strings.Contains(shareErr.Error(), errPermissionDenied) {
			h.sendError(w, "Forbidden", "Not authorized to share this secret", http.StatusForbidden, nil)
		} else if strings.Contains(shareErr.Error(), "expiry must be in the future") {
			h.sendError(w, "ValidationError", "Share expiry must be in the future", http.StatusBadRequest, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to share secret", http.StatusInternalServerError, nil)
		}
		return
	}

	sendCreated(w, newShareRecordWire(shareRecord), i18n.T("SuccessSecretShared", nil))
}

// UpdateSharePermission handles PUT /api/v1/shares/{id}
func (h *ShareHandler) UpdateSharePermission(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid share ID", http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
		Permission  string     `json:"permission" validate:"required,oneof=read write"`
		ExpiresAt   *time.Time `json:"expires_at"`   // optional: set/extend/shorten the time-bound expiry
		ClearExpiry bool       `json:"clear_expiry"` // optional: make the share permanent
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	shareRecord, err := h.coreService.UpdateSharePermission(r.Context(), &core.UpdateShareRequest{
		ShareID:     uint(id),
		Permission:  reqBody.Permission,
		UpdatedBy:   userCtx.UserID,
		ExpiresAt:   reqBody.ExpiresAt,
		ClearExpiry: reqBody.ClearExpiry,
	})
	if err != nil {
		log.Printf("Error updating share permission: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", "Share not found", http.StatusNotFound, nil)
		} else if reason, ok := core.ShareRefusalMessage(err); ok {
			h.sendError(w, "Forbidden", reason, http.StatusForbidden, nil)
		} else if strings.Contains(err.Error(), errPermissionDenied) {
			h.sendError(w, "Forbidden", "Not authorized to update this share", http.StatusForbidden, nil)
		} else if strings.Contains(err.Error(), "expiry must be in the future") {
			h.sendError(w, "ValidationError", "Share expiry must be in the future", http.StatusBadRequest, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to update share permission", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, newShareRecordWire(shareRecord), i18n.T("SuccessShareUpdated", nil))
}

// RevokeShare handles DELETE /api/v1/shares/{id}
func (h *ShareHandler) RevokeShare(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid share ID", http.StatusBadRequest, nil)
		return
	}

	if err := h.coreService.RevokeShare(r.Context(), uint(id), userCtx.UserID); err != nil {
		log.Printf("Error revoking share: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", "Share not found", http.StatusNotFound, nil)
		} else if reason, ok := core.ShareRefusalMessage(err); ok {
			h.sendError(w, "Forbidden", reason, http.StatusForbidden, nil)
		} else if strings.Contains(err.Error(), errPermissionDenied) {
			h.sendError(w, "Forbidden", "Not authorized to revoke this share", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to revoke share", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
