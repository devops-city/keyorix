// inactivity_suspend.go — on-demand admin job handler for user inactivity
// auto-suspension.  POST /api/v1/system/admin/jobs/suspend-inactive-users
// suspends every non-admin user whose last login exceeds the configured
// threshold.  Gated by system.write (enforced by the admin jobs subrouter).
package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// suspendInactiveUsersRequest is the JSON body accepted by the endpoint.
type suspendInactiveUsersRequest struct {
	InactiveDays int  `json:"inactive_days"`
	DryRun       bool `json:"dry_run"`
}

// SuspendInactiveUsers handles
//
//	POST /api/v1/system/admin/jobs/suspend-inactive-users
//
// Body: {"inactive_days": N}
// Response: {"suspended": [...], "skipped": N, "total": N}
func (h *AdminJobsHandler) SuspendInactiveUsers(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	var req suspendInactiveUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Bad Request", "invalid request body", http.StatusBadRequest, nil)
		return
	}

	if req.InactiveDays <= 0 {
		sendError(w, "Bad Request", "inactive_days must be greater than 0", http.StatusBadRequest, nil)
		return
	}
	if req.InactiveDays > core.MaxInactiveDays {
		sendError(w, "Bad Request", fmt.Sprintf("inactive_days exceeds the maximum of %d", core.MaxInactiveDays), http.StatusBadRequest, nil)
		return
	}

	result, err := h.coreService.SuspendInactiveUsers(core.WithAuditActor(r.Context(), u.UserID), core.InactivitySuspendConfig{
		InactiveDays: req.InactiveDays,
		DryRun:       req.DryRun,
	})
	if err != nil {
		log.Printf("Error running suspend-inactive-users job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, map[string]any{
		"suspended": result.Suspended,
		"skipped":   result.Skipped,
		"total":     result.Total,
	}, "")
}
