// bulk_access_requests.go — bulk approve/reject endpoints for access requests
// and CRUD endpoints for rejection-reason templates (ADR-024 extension).
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// ── Bulk approve/reject ───────────────────────────────────────────────────────

// BulkApproveAccessRequests handles
// POST /api/v1/access-requests/bulk-approve
// Body: {"request_ids": [1, 2, 3]}
func (h *CatalogHandler) BulkApproveAccessRequests(w http.ResponseWriter, r *http.Request) {
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	var body struct {
		RequestIDs []uint `json:"request_ids"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	result, err := h.coreService.BulkApproveAccessRequests(r.Context(), body.RequestIDs, actor.UserID, machineID(r))
	if err != nil {
		msg := err.Error()
		status := http.StatusBadRequest
		if !strings.Contains(msg, "required") && !strings.Contains(msg, "exceeds the maximum batch size") {
			log.Printf("Error bulk-approving access requests: %v", err)
			msg = clientSafe(err)
			status = http.StatusInternalServerError
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, map[string]any{"result": result}, "Bulk approve complete")
}

// BulkRejectAccessRequests handles
// POST /api/v1/access-requests/bulk-reject
// Body: {"request_ids": [1, 2, 3], "reason": "..."}
func (h *CatalogHandler) BulkRejectAccessRequests(w http.ResponseWriter, r *http.Request) {
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	var body struct {
		RequestIDs []uint `json:"request_ids"`
		Reason     string `json:"reason"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	result, err := h.coreService.BulkRejectAccessRequests(r.Context(), body.RequestIDs, actor.UserID, machineID(r), body.Reason)
	if err != nil {
		msg := err.Error()
		status := http.StatusBadRequest
		if !strings.Contains(msg, "required") && !strings.Contains(msg, "exceeds the maximum batch size") {
			log.Printf("Error bulk-rejecting access requests: %v", err)
			msg = clientSafe(err)
			status = http.StatusInternalServerError
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, map[string]any{"result": result}, "Bulk reject complete")
}

// ── Rejection reason templates ────────────────────────────────────────────────

// CreateRejectionReasonTemplate handles
// POST /api/v1/rejection-reason-templates
// Body: {"name": "...", "reason": "..."}
func (h *CatalogHandler) CreateRejectionReasonTemplate(w http.ResponseWriter, r *http.Request) {
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	var body struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	t, err := h.coreService.CreateRejectionReasonTemplate(r.Context(), actor.UserID, body.Name, body.Reason)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		if strings.Contains(msg, "required") {
			status = http.StatusBadRequest
		} else {
			log.Printf("Error creating rejection reason template: %v", err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendCreated(w, map[string]any{"template": t}, "Template created")
}

// ListRejectionReasonTemplates handles
// GET /api/v1/rejection-reason-templates
func (h *CatalogHandler) ListRejectionReasonTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := h.coreService.ListRejectionReasonTemplates(r.Context())
	if err != nil {
		log.Printf("Error listing rejection reason templates: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"templates": templates}, "")
}

// DeleteRejectionReasonTemplate handles
// DELETE /api/v1/rejection-reason-templates/{id}
func (h *CatalogHandler) DeleteRejectionReasonTemplate(w http.ResponseWriter, r *http.Request) {
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid template ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteRejectionReasonTemplate(r.Context(), actor.UserID, uint(id)); err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		if strings.Contains(msg, errNotFound) {
			status = http.StatusNotFound
		} else {
			log.Printf("Error deleting rejection reason template %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
