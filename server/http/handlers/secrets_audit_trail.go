// secrets_audit_trail.go — AuditTrail handler: the lifecycle events of a single secret.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// secretAuditEntry is the wire format for one lifecycle event of a secret. It exposes
// only non-sensitive metadata — never a plaintext value (the stored diff records a
// {"changed":true} marker for value changes, not the value itself).
type secretAuditEntry struct {
	ID            uint            `json:"id"`
	EventType     string          `json:"event_type"`
	Timestamp     string          `json:"timestamp"`
	UserID        *uint           `json:"user_id,omitempty"`
	ActorType     string          `json:"actor_type"`
	Description   string          `json:"description"`
	Success       bool            `json:"success"`
	Diff          json.RawMessage `json:"diff,omitempty"`
	Impersonation bool            `json:"impersonation,omitempty"`
}

// AuditTrail handles GET /api/v1/secrets/{id}/audit?limit=N — the secret's lifecycle
// events (created, rotated, rolled-back, suspended/resumed, shared, owner-transferred,
// reclassified, …) newest-first. Scoped secrets.read is enforced by the router; core
// re-checks the caller's read access. limit defaults to 50 and is capped at 500.
func (h *SecretHandler) AuditTrail(w http.ResponseWriter, r *http.Request) {
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

	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil {
			limit = n
		}
	}

	events, err := h.coreService.ListSecretAuditEvents(r.Context(), uint(id), userCtx.UserID, limit)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "not found"):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized"):
			h.sendError(w, "Forbidden", "Not authorized to view this secret's audit trail", http.StatusForbidden, nil)
		default:
			h.sendError(w, "InternalError", "Failed to list audit trail", http.StatusInternalServerError, nil)
		}
		return
	}

	entries := make([]secretAuditEntry, 0, len(events))
	for _, e := range events {
		entries = append(entries, toSecretAuditEntry(e))
	}
	h.sendSuccess(w, map[string]any{"audit": entries, "total": len(entries)}, "")
}

func toSecretAuditEntry(e *models.AuditEvent) secretAuditEntry {
	entry := secretAuditEntry{
		ID:            e.ID,
		EventType:     e.EventType,
		Timestamp:     e.EventTime.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UserID:        e.UserID,
		ActorType:     storage.AuditActorKind(e),
		Description:   e.Description,
		Success:       e.Success == nil || *e.Success,
		Impersonation: e.Impersonation,
	}
	if e.Diff != "" {
		entry.Diff = json.RawMessage(e.Diff)
	}
	return entry
}
