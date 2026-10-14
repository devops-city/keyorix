// secrets_extend_expiring.go — ExtendExpiringSecrets handler: bulk-renew the expiry of
// a project's expiring/expired secrets in one call. Scoped secrets.write (project) is
// enforced by the router.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ExtendExpiringSecrets handles POST /api/v1/projects/{id}/secrets/extend-expiring with
// {"within_days":N,"new_window_days":M} — sets a new expiration of now+new_window_days
// (default 90) on every secret expiring within within_days (default 30, already-expired
// included). Returns {extended}. Only pushes expiry out, never in. Never touches values.
func (h *SecretHandler) ExtendExpiringSecrets(w http.ResponseWriter, r *http.Request) {
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
		WithinDays    int `json:"within_days"`
		NewWindowDays int `json:"new_window_days"`
	}
	// An empty body is valid — both windows fall back to their defaults.
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			h.sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
			return
		}
	}

	n, truncated, err := h.coreService.ExtendExpiringSecrets(r.Context(), uint(id), reqBody.WithinDays, reqBody.NewWindowDays, userCtx.Username, userCtx.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, "required") {
			status = http.StatusBadRequest
		} else {
			log.Printf("Error extending expiring secrets for project %d: %v", id, err)
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	// #G24: "truncated" tells the caller more secrets matched the window than the
	// scan cap covered — the soonest-expiring ones were still renewed first
	// (storage orders by expiration ascending), but not every matching secret was.
	h.sendSuccess(w, map[string]any{"extended": n, "truncated": truncated}, "")
}
