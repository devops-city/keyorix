// secret_certificate.go — certificate inspection handler (ADR-054).
//
// Route (under /api/v1/secrets, project-scoped from the {id} secret):
//
//	GET /{id}/certificate — public X.509 metadata of a certificate-valued secret
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetSecretCertificate handles GET /api/v1/secrets/{id}/certificate
func (h *SecretHandler) GetSecretCertificate(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}
	info, err := h.coreService.InspectCertificate(r.Context(), userCtx.UserID, uint(id))
	if err != nil {
		// Same mapping as the value routes (ERRMAP-1): schedule 403, expired and
		// suspended 409, each with its stable code. InspectCertificate authorizes the
		// caller (EnforceSecretReadPermission) before it evaluates any secret-state
		// guard, so a refusal reaching here is only ever returned to an authorized
		// reader; an unauthorized caller's error is a permission error that never
		// classifies, and falls through to the 403 below exactly as before.
		if h.sendSecretReadRefusal(w, err) {
			return
		}
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "not a parseable"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "permission") || strings.Contains(msg, "not authorized"):
			status = http.StatusForbidden
		default:
			log.Printf("Error inspecting certificate for secret %d: %v", id, err)
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, info, "")
}
