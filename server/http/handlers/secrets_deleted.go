// secrets_deleted.go — DeletedSecrets handler: the recycle bin, a project's
// soft-deleted (restorable) secrets.
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// deletedSecretEntry is the wire format for one trashed secret. Metadata only — no
// value, ever.
type deletedSecretEntry struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Classification string `json:"classification,omitempty"`
	EnvironmentID  uint   `json:"environment_id"`
	OwnerID        uint   `json:"owner_id"`
	DeletedAt      string `json:"deleted_at,omitempty"`
	// PurgeAt is the UTC instant (RFC 3339) before which the purge job will not
	// hard-delete this secret: the restore deadline. See core.SecretPurgeAt.
	PurgeAt string `json:"purge_at,omitempty"`
}

// purgeAtHeader carries the same instant on the DELETE /secrets/{id} response, which
// stays 204 No Content so existing clients that check the status keep working.
const purgeAtHeader = "Keyorix-Purge-At"

// formatPurgeAt renders a purge instant the way every API timestamp is rendered:
// RFC 3339, UTC.
func formatPurgeAt(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// DeletedSecrets handles GET /api/v1/projects/{id}/secrets/deleted?limit=N — the
// project's recycle bin (soft-deleted secrets, most-recently-deleted first), so an
// operator can find a secret's ID to POST /secrets/{id}/restore. Scoped secrets.read
// (project) is enforced by the router. limit defaults to 100, capped at 500.
func (h *SecretHandler) DeletedSecrets(w http.ResponseWriter, r *http.Request) {
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

	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil {
			limit = n
		}
	}

	secrets, err := h.coreService.ListDeletedSecrets(r.Context(), uint(id), limit)
	if err != nil {
		h.sendError(w, "InternalError", "Failed to list deleted secrets", http.StatusInternalServerError, nil)
		return
	}

	entries := make([]deletedSecretEntry, 0, len(secrets))
	for _, s := range secrets {
		e := toDeletedSecretEntry(s)
		if at, ok := h.coreService.SecretPurgeAt(s); ok {
			e.PurgeAt = formatPurgeAt(at)
		}
		entries = append(entries, e)
	}
	h.sendSuccess(w, map[string]interface{}{"deleted": entries, "total": len(entries)}, "")
}

func toDeletedSecretEntry(s *models.SecretNode) deletedSecretEntry {
	e := deletedSecretEntry{
		ID:             s.ID,
		Name:           s.Name,
		Type:           s.Type,
		Classification: s.Classification,
		EnvironmentID:  s.EnvironmentID,
		OwnerID:        s.OwnerID,
	}
	if s.DeletedAt.Valid {
		e.DeletedAt = s.DeletedAt.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return e
}
