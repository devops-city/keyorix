// projects_suspend.go — project-wide suspend/resume: freeze or restore value reads of
// every secret in a project (incident response).
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SuspendProjectSecrets handles POST /api/v1/projects/{id}/secrets/suspend-all with an
// optional {"reason": "...", "clear_synced_copies": true}. clear_synced_copies is the same
// per-suspension choice POST /secrets/{id}/suspend takes, applied to every secret the
// request suspends. Scoped secrets.write (project) is enforced by the router, as for a
// single-secret suspend; the flag needs no further permission.
func (h *SecretHandler) SuspendProjectSecrets(w http.ResponseWriter, r *http.Request) {
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
		Reason            string `json:"reason"`
		ClearSyncedCopies bool   `json:"clear_synced_copies"`
	}
	_ = json.NewDecoder(r.Body).Decode(&reqBody) // optional

	n, err := h.coreService.SuspendProjectSecretsWithOptions(r.Context(), uint(id), userCtx.UserID, reqBody.Reason,
		core.SuspendOptions{ClearSyncedCopies: reqBody.ClearSyncedCopies})
	if err != nil {
		if errors.Is(err, core.ErrBulkSuspendAuditUnavailable) {
			h.sendError(w, "InternalError", "The audit event for this request could not be recorded; no secret was suspended. Retry, or "+core.SuspendWithoutClearingHint, http.StatusInternalServerError, nil)
			return
		}
		if partial, ok := errors.AsType[*core.BulkSuspendPartialError](err); ok {
			// Already-suspended secrets stay suspended; the counts let the operator retry.
			msg := "Some secrets could not be suspended and are still readable; retry"
			if partial.AuditRefused {
				msg = "An audit event could not be recorded; the suspension stopped early. Retry, or " + core.SuspendWithoutClearingHint
			}
			h.sendError(w, "InternalError", msg,
				http.StatusInternalServerError,
				map[string]int{"suspended": partial.Suspended, "failed": partial.Failed})
			return
		}
		h.sendError(w, "InternalError", "Failed to suspend project secrets", http.StatusInternalServerError, nil)
		return
	}
	data := map[string]any{"suspended": n}
	if reqBody.ClearSyncedCopies {
		data["clear_synced_copies"] = true
	}
	h.sendSuccess(w, data, "")
}

// ResumeProjectSecrets handles POST /api/v1/projects/{id}/secrets/resume-all.
func (h *SecretHandler) ResumeProjectSecrets(w http.ResponseWriter, r *http.Request) {
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
	n, err := h.coreService.ResumeProjectSecrets(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		h.sendError(w, "InternalError", "Failed to resume project secrets", http.StatusInternalServerError, nil)
		return
	}
	h.sendSuccess(w, map[string]any{"resumed": n}, "")
}
