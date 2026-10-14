// access_review_campaigns.go — endpoints for periodic access-review campaigns
// (ISO 27001 A.5.18). All are project-scoped; gets need roles.read and mutations
// roles.assign (wired in router.go).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// campaignStatusForError maps a core error to an HTTP status (shared shape).
func campaignStatusForError(msg string) int {
	switch {
	case strings.Contains(msg, "not found"):
		return http.StatusNotFound
	case strings.Contains(msg, "required") || strings.Contains(msg, "must be") ||
		strings.Contains(msg, "still pending") || strings.Contains(msg, "already closed") ||
		strings.Contains(msg, "campaign is closed") || strings.Contains(msg, "ownership cannot be revoked"):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// sendCampaignError classifies err via campaignStatusForError and writes the
// response. The message is only echoed back for the recognized, deliberately
// user-facing outcomes above; the unclassified/500 fallback is assumed to be a
// raw error from a lower layer (storage, etc.), so it is logged server-side
// and replaced with a generic client-safe message (backlog #116).
func sendCampaignError(w http.ResponseWriter, context string, err error) {
	msg := err.Error()
	status := campaignStatusForError(msg)
	if status == http.StatusInternalServerError {
		log.Printf("Error %s: %v", context, err)
		msg = clientSafe(err)
	}
	sendError(w, "Error", msg, status, nil)
}

// OpenAccessReviewCampaign handles POST /api/v1/projects/{id}/access-review/campaigns.
func (h *CatalogHandler) OpenAccessReviewCampaign(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	// Body is optional; ignore decode errors on an empty body.
	_ = json.NewDecoder(r.Body).Decode(&body)
	result, err := h.coreService.OpenAccessReviewCampaign(r.Context(), userCtx.UserID, machineID(r), uint(projectID), body.Name)
	if err != nil {
		sendCampaignError(w, "opening access-review campaign", err)
		return
	}
	sendCreated(w, map[string]any{"campaign": result.Campaign, "progress": result.Progress}, "Campaign opened")
}

// ListAccessReviewCampaigns handles GET /api/v1/projects/{id}/access-review/campaigns.
func (h *CatalogHandler) ListAccessReviewCampaigns(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	campaigns, err := h.coreService.ListAccessReviewCampaigns(r.Context(), uint(projectID))
	if err != nil {
		log.Printf("Error listing access-review campaigns for project %d: %v", projectID, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"campaigns": campaigns, "count": len(campaigns)}, "")
}

// GetAccessReviewCampaign handles GET /api/v1/projects/{id}/access-review/campaigns/{campaignId}.
func (h *CatalogHandler) GetAccessReviewCampaign(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "campaignId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidCampaignID, http.StatusBadRequest, nil)
		return
	}
	detail, err := h.coreService.GetAccessReviewCampaign(r.Context(), uint(projectID), uint(campaignID))
	if err != nil {
		sendCampaignError(w, "getting access-review campaign", err)
		return
	}
	sendSuccess(w, map[string]any{
		"campaign": detail.Campaign, "items": detail.Items, "progress": detail.Progress,
	}, "")
}

// DecideAccessReviewCampaignItem handles
// POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide.
func (h *CatalogHandler) DecideAccessReviewCampaignItem(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "campaignId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidCampaignID, http.StatusBadRequest, nil)
		return
	}
	itemID, err := strconv.ParseUint(chi.URLParam(r, "itemId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid item ID", http.StatusBadRequest, nil)
		return
	}
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Action == "" {
		sendError(w, "ValidationError", "action is required (attest|revoke)", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DecideAccessReviewItem(r.Context(), userCtx.UserID, uint(projectID), uint(campaignID), uint(itemID), body.Action, body.Reason); err != nil {
		sendCampaignError(w, "deciding access-review campaign item", err)
		return
	}
	sendSuccess(w, nil, "Decision recorded")
}

// CloseAccessReviewCampaign handles
// POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/close.
func (h *CatalogHandler) CloseAccessReviewCampaign(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "campaignId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidCampaignID, http.StatusBadRequest, nil)
		return
	}
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Force bool `json:"force"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	result, err := h.coreService.CloseAccessReviewCampaign(r.Context(), userCtx.UserID, machineID(r), uint(projectID), uint(campaignID), body.Force)
	if err != nil {
		sendCampaignError(w, "closing access-review campaign", err)
		return
	}
	sendSuccess(w, map[string]any{"campaign": result.Campaign, "progress": result.Progress}, "Campaign closed")
}
