// secrets_expiring.go — ExpiringSecrets handler: a project's secrets expiring (or
// already expired) within a window, soonest-first, for proactive renewal.
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

type expiringSecretEntry struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Classification string `json:"classification,omitempty"`
	EnvironmentID  uint   `json:"environment_id"`
	Expiration     string `json:"expiration,omitempty"`
	Expired        bool   `json:"expired"`
}

// ExpiringSecrets handles GET /api/v1/projects/{id}/secrets/expiring?days=N — the
// project's secrets expiring (or already expired) within the window, soonest-first.
// Scoped secrets.read (project) is enforced by the router. days defaults to 30, cap 3650.
func (h *SecretHandler) ExpiringSecrets(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	days := 0
	if v := r.URL.Query().Get("days"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil {
			days = n
		}
	}

	secrets, truncated, err := h.coreService.ListExpiringSecrets(r.Context(), uint(id), days)
	if err != nil {
		h.sendError(w, "InternalError", "Failed to list expiring secrets", http.StatusInternalServerError, nil)
		return
	}

	now := time.Now()
	entries := make([]expiringSecretEntry, 0, len(secrets))
	for _, s := range secrets {
		e := expiringSecretEntry{
			ID: s.ID, Name: s.Name, Type: s.Type, Classification: s.Classification, EnvironmentID: s.EnvironmentID,
		}
		if s.Expiration != nil {
			e.Expiration = s.Expiration.UTC().Format(time.RFC3339)
			e.Expired = s.Expiration.Before(now)
		}
		entries = append(entries, e)
	}
	// #G24: "total" reflects the returned sample size, not necessarily the true
	// count of matching secrets — "truncated" tells the caller/UI whether more
	// exist beyond expiringScanPageSize (soonest-expiring are still guaranteed
	// to be included, since storage orders by expiration ascending).
	h.sendSuccess(w, map[string]any{"expiring": entries, "total": len(entries), "truncated": truncated}, "")
}
