// secrets_copy_environment.go — CopyEnvironmentSecrets handler: bulk-promote every
// secret from one environment to another (same project).
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

// CopyEnvironmentSecrets handles POST /api/v1/projects/{id}/environments/{envId}/copy-secrets
// with {"target_environment_id":N} — copies every secret in {envId} into the target
// environment (same project), skipping name clashes. Scoped secrets.write (project) is
// enforced by the router; core verifies both environments belong to the project.
func (h *SecretHandler) CopyEnvironmentSecrets(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	sourceEnvID, err := strconv.ParseUint(chi.URLParam(r, "envId"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid environment ID", http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		TargetEnvironmentID uint `json:"target_environment_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if reqBody.TargetEnvironmentID == 0 {
		h.sendError(w, "BadRequest", "target_environment_id is required", http.StatusBadRequest, nil)
		return
	}

	copied, skipped, err := h.coreService.CopyEnvironmentSecrets(r.Context(), uint(projectID), uint(sourceEnvID), reqBody.TargetEnvironmentID, userCtx.Username, userCtx.UserID, clientIP(r), r.Header.Get("User-Agent"))
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, "must ") || strings.Contains(msg, "required") || strings.Contains(msg, "belong") || strings.Contains(msg, "validation") {
			status = http.StatusBadRequest
		} else {
			log.Printf("Error copying secrets from environment %d to %d (project %d): %v", sourceEnvID, reqBody.TargetEnvironmentID, projectID, err) // NOSONAR
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, map[string]interface{}{"copied": copied, "skipped": skipped}, "")
}
