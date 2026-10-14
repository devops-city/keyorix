// risk_exceptions.go — the risk register / exceptions endpoints (ISO 27001 A.5.8
// risk treatment). Listing discloses free-text Reference/Justification (which may
// itself name a secret) deployment-wide, so it needs audit.read, not the universal
// system_viewer baseline; create/revoke need system.write (wired in router.go).
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListRiskExceptions handles GET /api/v1/risk-exceptions — the register. ?all=true
// includes expired exceptions (history); default is active only.
func (h *DashboardHandler) ListRiskExceptions(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("all") != "true"
	exceptions, err := h.coreService.ListRiskExceptions(r.Context(), activeOnly)
	if err != nil {
		log.Printf("Error listing risk exceptions: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"exceptions": exceptions}, "")
}

// CreateRiskException handles POST /api/v1/risk-exceptions — accept a control gap for
// a bounded time with a justification.
func (h *DashboardHandler) CreateRiskException(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Title         string `json:"title"`
		Category      string `json:"category"`
		Reference     string `json:"reference"`
		Justification string `json:"justification"`
		ExpiresAt     string `json:"expires_at"` // RFC3339
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		sendError(w, "InvalidParameter", "expires_at must be an RFC3339 timestamp", http.StatusBadRequest, nil)
		return
	}
	exc, err := h.coreService.CreateRiskException(r.Context(), actor.UserID, isMachineActor(r), body.Title, body.Category, body.Reference, body.Justification, expiresAt)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "required") || strings.Contains(msg, "must be"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error creating risk exception: %v", err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendCreated(w, map[string]any{"exception": exc}, "Risk exception recorded")
}

// ApproveRiskException handles POST /api/v1/risk-exceptions/{id}/approve — dual
// control (#170): the exception only suppresses its matched violation from the
// compliance posture once a DIFFERENT system.write holder than the creator
// approves it.
func (h *DashboardHandler) ApproveRiskException(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid exception ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.ApproveRiskException(r.Context(), actor.UserID, isMachineActor(r), uint(id)); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "dual control"):
			status = http.StatusForbidden
		case strings.Contains(msg, "concurrently"):
			status = http.StatusConflict
		case strings.Contains(msg, "cannot approve") || strings.Contains(msg, "already approved"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Risk exception approved")
}

// RevokeRiskException handles DELETE /api/v1/risk-exceptions/{id} — withdraw early.
func (h *DashboardHandler) RevokeRiskException(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid exception ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RevokeRiskException(r.Context(), actor.UserID, uint(id)); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "already revoked"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "concurrently"):
			status = http.StatusConflict
		case errors.Is(err, core.ErrRiskExceptionNotFoundPublic):
			status = http.StatusNotFound
		case errors.Is(err, core.ErrRiskExceptionPermissionDenied):
			status = http.StatusForbidden
		default:
			log.Printf("Error revoking risk exception %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Risk exception revoked")
}
