// secrets_orphaned.go — OrphanedSecrets handler: a project's secrets whose owner is no
// longer a live user (offboarding hygiene; re-assign with transfer-ownership).
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// orphanedSecretEntry is the wire format for one secret with a departed owner. Metadata
// only — no value, ever.
type orphanedSecretEntry struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Classification string `json:"classification,omitempty"`
	EnvironmentID  uint   `json:"environment_id"`
	OwnerID        uint   `json:"owner_id"`
}

// OrphanedSecrets handles GET /api/v1/projects/{id}/secrets/orphaned — the project's
// live secrets whose owner is no longer a live user, so an admin can transfer
// ownership (POST /secrets/{id}/transfer-ownership). Scoped secrets.read (project) is
// enforced by the router.
func (h *SecretHandler) OrphanedSecrets(w http.ResponseWriter, r *http.Request) {
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

	secrets, err := h.coreService.ListOrphanedSecrets(r.Context(), uint(id))
	if err != nil {
		h.sendError(w, "InternalError", "Failed to list orphaned secrets", http.StatusInternalServerError, nil)
		return
	}

	entries := make([]orphanedSecretEntry, 0, len(secrets))
	for _, s := range secrets {
		entries = append(entries, orphanedSecretEntry{
			ID:             s.ID,
			Name:           s.Name,
			Type:           s.Type,
			Classification: s.Classification,
			EnvironmentID:  s.EnvironmentID,
			OwnerID:        s.OwnerID,
		})
	}
	h.sendSuccess(w, map[string]any{"orphaned": entries, "total": len(entries)}, "")
}
