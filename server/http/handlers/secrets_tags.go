// secrets_tags.go — GetTags / SetTags handlers: free-form tags on a secret.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetTags handles GET /api/v1/secrets/{id}/tags — the secret's tags. Scoped
// secrets.read is enforced by the router; core re-checks read access.
func (h *SecretHandler) GetTags(w http.ResponseWriter, r *http.Request) {
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
	tags, err := h.coreService.GetSecretTags(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		h.tagError(w, err, "Failed to list tags")
		return
	}
	if tags == nil {
		tags = []string{}
	}
	h.sendSuccess(w, map[string]any{"tags": tags}, "")
}

// SetTags handles PUT /api/v1/secrets/{id}/tags with {"tags":[...]} — replaces the
// secret's tag set. Scoped secrets.write is enforced by the router; core re-checks
// write access and normalizes the tags. Returns the stored set.
func (h *SecretHandler) SetTags(w http.ResponseWriter, r *http.Request) {
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
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	tags, err := h.coreService.SetSecretTags(r.Context(), uint(id), userCtx.UserID, body.Tags)
	if err != nil {
		h.tagError(w, err, "Failed to set tags")
		return
	}
	if tags == nil {
		tags = []string{}
	}
	h.sendSuccess(w, map[string]any{"tags": tags}, "")
}

// tagError maps a core error to the right status for the tag endpoints.
func (h *SecretHandler) tagError(w http.ResponseWriter, err error, fallback string) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
	case strings.Contains(msg, "permission") || strings.Contains(msg, "not authorized"):
		h.sendError(w, "Forbidden", "Not authorized for this secret", http.StatusForbidden, nil)
	case strings.Contains(msg, "validation") || strings.Contains(msg, "exceeds") || strings.Contains(msg, "at most"):
		h.sendError(w, "BadRequest", msg, http.StatusBadRequest, nil)
	default:
		h.sendError(w, "InternalError", fallback, http.StatusInternalServerError, nil)
	}
}
