// machine_token_hygiene.go — MachineTokenHygiene handler: deployment-wide stale /
// expired-but-active machine credentials an admin should revoke (token sprawl).
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// machineTokenHygieneEntry is the safe wire shape for one flagged machine credential —
// metadata + flags only, never the token hash.
type machineTokenHygieneEntry struct {
	ID                uint   `json:"id"`
	MachineIdentityID uint   `json:"machine_identity_id"`
	Name              string `json:"name"`
	TokenPrefix       string `json:"token_prefix"`
	LastUsedAt        string `json:"last_used_at,omitempty"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	Expired           bool   `json:"expired"`
	Stale             bool   `json:"stale"`
}

// MachineTokenHygiene handles GET /api/v1/machine-token-hygiene?days=N — the
// deployment-wide non-revoked machine credentials that are expired-but-active or stale.
// Global audit.read is enforced by the router, not the universal system_viewer
// baseline. days defaults to 90, cap 3650.
func (h *CatalogHandler) MachineTokenHygiene(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	days := 90
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	if days > 3650 {
		days = 3650
	}

	entries, err := h.coreService.ListMachineTokenHygiene(r.Context(), time.Duration(days)*24*time.Hour)
	if err != nil {
		sendError(w, "InternalError", "Failed to list machine-token hygiene", http.StatusInternalServerError, nil)
		return
	}
	out := make([]machineTokenHygieneEntry, 0, len(entries))
	for _, e := range entries {
		row := machineTokenHygieneEntry{
			ID:                e.Credential.ID,
			MachineIdentityID: e.Credential.MachineIdentityID,
			Name:              e.Credential.Name,
			TokenPrefix:       e.Credential.TokenPrefix,
			Expired:           e.Expired,
			Stale:             e.Stale,
		}
		if e.Credential.LastUsedAt != nil {
			row.LastUsedAt = e.Credential.LastUsedAt.UTC().Format(time.RFC3339)
		}
		if e.Credential.ExpiresAt != nil {
			row.ExpiresAt = e.Credential.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, row)
	}
	sendSuccess(w, map[string]any{"tokens": out, "total": len(out)}, "")
}
