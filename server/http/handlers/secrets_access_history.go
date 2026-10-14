// secrets_access_history.go — AccessHistory handler: recent reads of a secret.
package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// secretAccessLogEntry is the wire format for one row of a secret's access
// history. IPAddress/UserAgent are metadata about the READER's own session, not
// about the secret -- every caller who can reach this route holds only
// secrets.read (the route's gate), which authorizes seeing that reads happened,
// not where OTHER users read from. Both are populated only when the caller
// separately holds audit.read (see AccessHistory); omitted (not zero-valued)
// otherwise, mirroring secretAuditEntry's omitempty convention.
type secretAccessLogEntry struct {
	ID              uint      `json:"id"`
	SecretVersionID uint      `json:"secret_version_id"`
	AccessedBy      string    `json:"accessed_by"`
	Action          string    `json:"action"`
	AccessTime      time.Time `json:"access_time"`
	IPAddress       string    `json:"ip_address,omitempty"`
	UserAgent       string    `json:"user_agent,omitempty"`
}

func toSecretAccessLogEntry(l models.SecretAccessLog, includeIPAndUA bool) secretAccessLogEntry {
	e := secretAccessLogEntry{
		ID:              l.ID,
		SecretVersionID: l.SecretVersionID,
		AccessedBy:      l.AccessedBy,
		Action:          l.Action,
		AccessTime:      l.AccessTime,
	}
	if includeIPAndUA {
		// Rows written before #3141 stored r.RemoteAddr as ip:port; show the
		// bare IP for those too (the stored row and the export stay untouched).
		e.IPAddress = core.CanonicalIP(l.IPAddress)
		e.UserAgent = l.UserAgent
	}
	return e
}

// AccessHistory handles GET /api/v1/secrets/{id}/access-log?days=N — the secret's
// recent access-log entries (who read it, when, from where). Scoped secrets.read is
// enforced by the router; core re-checks the caller's read access. days defaults to
// 30 and is capped at 365.
//
// IP/user-agent are included only for a caller who separately holds audit.read,
// checked globally (unscoped) to match /api/v1/audit/*'s own gate
// (server/http/router.go's permAuditRead) -- an ordinary secrets.read-only reader
// sees accessor/action/time, never another user's originating IP. Mirrors
// GetDashboardStats' established hasAuditRead gating pattern
// (internal/core/dashboard.go) and fails closed: an authorization-check error
// is treated as "no", never as "yes".
func (h *SecretHandler) AccessHistory(w http.ResponseWriter, r *http.Request) {
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

	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			days = n
		}
	}
	if days > 365 {
		days = 365
	}
	since := time.Now().AddDate(0, 0, -days)

	logs, err := h.coreService.ListSecretAccessHistory(r.Context(), uint(id), userCtx.UserID, since)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "not found"):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized"):
			h.sendError(w, "Forbidden", "Not authorized to view this secret's access log", http.StatusForbidden, nil)
		default:
			h.sendError(w, "InternalError", "Failed to list access history", http.StatusInternalServerError, nil)
		}
		return
	}

	includeIPAndUA, aerr := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "audit.read", core.Scope{})
	if aerr != nil {
		includeIPAndUA = false
	}

	entries := make([]secretAccessLogEntry, 0, len(logs))
	for _, l := range logs {
		entries = append(entries, toSecretAccessLogEntry(l, includeIPAndUA))
	}
	h.sendSuccess(w, map[string]any{"access_log": entries, "total": len(entries)}, "")
}
