// audit_retention_handler.go — on-demand audit log retention purge job.
//
// POST /api/v1/admin/jobs/purge-audit-logs deletes audit events older
// than the requested retention window. Gated by system.write (enforced by the
// admin jobs subrouter in router.go).
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// purgeAuditLogsRequest is the JSON body accepted by PurgeAuditLogsJob.
type purgeAuditLogsRequest struct {
	RetentionDays int `json:"retention_days"`
}

// PurgeAuditLogsJob handles
//
//	POST /api/v1/admin/jobs/purge-audit-logs
//
// Body:     {"retention_days": N}   (N must be >= 7)
// Response: {"data": {"deleted_count": N, "cutoff_time": "..."}}
func (h *AdminJobsHandler) PurgeAuditLogsJob(w http.ResponseWriter, r *http.Request) {
	uc := middleware.GetUserFromContext(r.Context())
	if uc == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	var req purgeAuditLogsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Bad Request", "invalid request body", http.StatusBadRequest, nil)
		return
	}

	result, err := h.coreService.PurgeAuditLogs(r.Context(), core.AuditLogRetentionConfig{
		RetentionDays: req.RetentionDays,
		ActorID:       uc.UserID,
	})
	if err != nil {
		if errors.Is(err, core.ErrInvalidAuditRetentionDays) {
			sendError(w, "Bad Request", clientSafe(err), http.StatusBadRequest, nil)
			return
		}
		log.Printf("Error running purge-audit-logs job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, map[string]any{
		"deleted_count": result.DeletedCount,
		"cutoff_time":   result.CutoffTime,
	}, "")
}
