// sod.go — separation-of-duties endpoints (ISO 27001 A.5.3 / SOX). Deployment-wide:
// listing policy DEFINITIONS (name/permission pair, no PII) needs only the universal
// system_viewer baseline system.read; listing VIOLATIONS discloses violator
// names/emails deployment-wide, so it needs audit.read; creating/deleting policies
// needs system.write (wired in router.go).
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListSoDPolicies handles GET /api/v1/sod/policies.
func (h *CatalogHandler) ListSoDPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.coreService.ListSoDPolicies(r.Context())
	if err != nil {
		log.Printf("Error listing SoD policies: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"policies": policies, "count": len(policies)}, "")
}

// CreateSoDPolicy handles POST /api/v1/sod/policies.
func (h *CatalogHandler) CreateSoDPolicy(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		PermissionA string `json:"permission_a"`
		PermissionB string `json:"permission_b"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	policy, err := h.coreService.CreateSoDPolicy(r.Context(), actor.UserID, body.Name, body.Description, body.PermissionA, body.PermissionB)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case errors.Is(err, core.ErrSoDValidation):
			status = http.StatusBadRequest
		case errors.Is(err, core.ErrSoDPermissionDenied):
			status = http.StatusForbidden
		default:
			log.Printf("Error creating SoD policy: %v", err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendCreated(w, map[string]any{"policy": policy}, "Policy created")
}

// DeleteSoDPolicy handles DELETE /api/v1/sod/policies/{id}.
func (h *CatalogHandler) DeleteSoDPolicy(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid policy ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteSoDPolicy(r.Context(), actor.UserID, uint(id)); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case errors.Is(err, core.ErrSoDNotFound):
			status = http.StatusNotFound
		case errors.Is(err, core.ErrSoDPermissionDenied):
			status = http.StatusForbidden
		default:
			log.Printf("Error deleting SoD policy %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Policy deleted")
}

// ListSoDViolations handles GET /api/v1/sod/violations.
func (h *CatalogHandler) ListSoDViolations(w http.ResponseWriter, r *http.Request) {
	report, err := h.coreService.DetectSoDViolations(r.Context())
	if err != nil {
		log.Printf("Error detecting SoD violations: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	// #420: degraded/degraded_reasons must reach API consumers — a scan that silently
	// skipped a principal whose permissions couldn't be read would otherwise look
	// identical to one that scanned everyone and found nothing for them.
	sendSuccess(w, map[string]any{
		"violations":       report.Violations,
		"count":            len(report.Violations),
		"degraded":         report.Degraded,
		"degraded_reasons": report.DegradedReasons,
	}, "")
}
