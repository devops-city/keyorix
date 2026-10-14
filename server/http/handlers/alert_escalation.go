// alert_escalation.go — CRUD endpoints for alert escalation policies and the
// on-demand job trigger. All routes are admin-only (system.write).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

const (
	escalationNotFound        = "not found"
	escalationNotFoundMessage = "Alert escalation policy not found"
)

// AlertEscalationHandler serves the alert escalation policy CRUD endpoints and the
// run-alert-escalation admin job trigger.
type AlertEscalationHandler struct {
	coreService *core.KeyorixCore
}

// NewAlertEscalationHandler constructs an AlertEscalationHandler.
func NewAlertEscalationHandler(coreService *core.KeyorixCore) *AlertEscalationHandler {
	return &AlertEscalationHandler{coreService: coreService}
}

// policyToAPI converts an AlertEscalationPolicy model to the API wire shape.
func policyToAPI(p *models.AlertEscalationPolicy) map[string]any {
	return map[string]any{
		"id":                     p.ID,
		"name":                   p.Name,
		"min_severity":           p.MinSeverity,
		"escalate_after_minutes": p.EscalateAfterMinutes,
		"channel_ids":            p.ChannelIDs,
		"enabled":                p.Enabled,
		"created_by":             p.CreatedBy,
		"created_at":             p.CreatedAt,
		"updated_at":             p.UpdatedAt,
	}
}

// isEscalationValidationError reports whether err came from core escalation validation.
func isEscalationValidationError(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "alert escalation policy") ||
		strings.HasPrefix(msg, "invalid min_severity") ||
		strings.HasPrefix(msg, "escalate_after_minutes")
}

// Create handles POST /api/v1/alert-escalation-policies.
func (h *AlertEscalationHandler) Create(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name                 string `json:"name"`
		MinSeverity          string `json:"min_severity"`
		EscalateAfterMinutes int    `json:"escalate_after_minutes"`
		ChannelIDs           string `json:"channel_ids"`
		Enabled              *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	p := &models.AlertEscalationPolicy{
		Name:                 body.Name,
		MinSeverity:          body.MinSeverity,
		EscalateAfterMinutes: body.EscalateAfterMinutes,
		ChannelIDs:           body.ChannelIDs,
		CreatedBy:            u.UserID,
	}
	if body.Enabled != nil {
		p.Enabled = *body.Enabled
	} else {
		p.Enabled = true
	}
	created, err := h.coreService.CreateAlertEscalationPolicy(r.Context(), p)
	if err != nil {
		if isEscalationValidationError(err) {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
			return
		}
		log.Printf("Error creating alert escalation policy: %v", err)
		sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	h.coreService.LogAlertEscalationPolicyCreated(r.Context(), u.UserID, created)
	sendCreated(w, policyToAPI(created), "")
}

// List handles GET /api/v1/alert-escalation-policies.
func (h *AlertEscalationHandler) List(w http.ResponseWriter, r *http.Request) {
	policies, err := h.coreService.ListAlertEscalationPolicies(r.Context())
	if err != nil {
		log.Printf("Error listing alert escalation policies: %v", err)
		sendError(w, "InternalError", "Failed to list alert escalation policies", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]any, 0, len(policies))
	for i := range policies {
		out = append(out, policyToAPI(&policies[i]))
	}
	sendSuccess(w, map[string]any{"policies": out}, "")
}

// Get handles GET /api/v1/alert-escalation-policies/{id}.
func (h *AlertEscalationHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	p, err := h.coreService.GetAlertEscalationPolicy(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), escalationNotFound) {
			sendError(w, "NotFound", escalationNotFoundMessage, http.StatusNotFound, nil)
			return
		}
		log.Printf("Error getting alert escalation policy %d: %v", id, err)
		sendError(w, "InternalError", "Failed to get alert escalation policy", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, policyToAPI(p), "")
}

// Update handles PUT /api/v1/alert-escalation-policies/{id}.
func (h *AlertEscalationHandler) Update(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	// Fetched BEFORE the mutation so the audit event can carry a real diff --
	// UpdateAlertEscalationPolicy mutates the row in place, so this is the
	// only chance to observe the pre-update state (coordinator review, PR
	// #2249). Best-effort: a failure here must not block the update itself,
	// it only means the audit event's before side is empty.
	before, _ := h.coreService.GetAlertEscalationPolicy(r.Context(), id)
	updated, err := h.coreService.UpdateAlertEscalationPolicy(r.Context(), id, body)
	if err != nil {
		if strings.Contains(err.Error(), escalationNotFound) {
			sendError(w, "NotFound", escalationNotFoundMessage, http.StatusNotFound, nil)
			return
		}
		if isEscalationValidationError(err) {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
			return
		}
		log.Printf("Error updating alert escalation policy %d: %v", id, err)
		sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	h.coreService.LogAlertEscalationPolicyUpdated(r.Context(), u.UserID, before, updated)
	sendSuccess(w, policyToAPI(updated), "")
}

// Delete handles DELETE /api/v1/alert-escalation-policies/{id}.
func (h *AlertEscalationHandler) Delete(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	if err := h.coreService.DeleteAlertEscalationPolicy(r.Context(), id); err != nil {
		if strings.Contains(err.Error(), escalationNotFound) {
			sendError(w, "NotFound", escalationNotFoundMessage, http.StatusNotFound, nil)
			return
		}
		log.Printf("Error deleting alert escalation policy %d: %v", id, err)
		sendError(w, "InternalError", "Failed to delete alert escalation policy", http.StatusInternalServerError, nil)
		return
	}
	h.coreService.LogAlertEscalationPolicyDeleted(r.Context(), u.UserID, id)
	w.WriteHeader(http.StatusNoContent)
}

// RunEscalation handles POST /api/v1/system/admin/jobs/run-alert-escalation.
func (h *AlertEscalationHandler) RunEscalation(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	result, err := h.coreService.RunAlertEscalation(core.WithAuditActor(r.Context(), u.UserID))
	if err != nil {
		log.Printf("Error running alert escalation job: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"evaluated": result.Evaluated,
		"escalated": result.Escalated,
		"skipped":   result.Skipped,
	}, "")
}
