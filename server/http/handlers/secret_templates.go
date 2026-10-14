// secret_templates.go — HTTP handlers for secret template management.
//
// Routes (under /api/v1/secret-templates):
//
//	POST   /                — create a template (secrets.write)
//	GET    /                — list all templates (secrets.read)
//	GET    /{id}            — get template by ID (secrets.read)
//	PUT    /{id}            — update a template (secrets.write)
//	DELETE /{id}            — delete a template (secrets.write)
//	POST   /{id}/apply      — apply template to a preview/dry-run, return merged fields (secrets.read)
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SecretTemplateHandler handles secret template HTTP requests.
type SecretTemplateHandler struct {
	coreService *core.KeyorixCore
}

// NewSecretTemplateHandler creates a new SecretTemplateHandler.
func NewSecretTemplateHandler(coreService *core.KeyorixCore) *SecretTemplateHandler {
	return &SecretTemplateHandler{coreService: coreService}
}

// Create handles POST /api/v1/secret-templates.
func (h *SecretTemplateHandler) Create(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name                  string `json:"name"`
		Description           string `json:"description"`
		DefaultClassification string `json:"default_classification"`
		DefaultTags           string `json:"default_tags"`
		DescriptionPattern    string `json:"description_pattern"`
		RotationHintDays      int    `json:"rotation_hint_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}

	req := &core.CreateSecretTemplateRequest{
		Name:                  body.Name,
		Description:           body.Description,
		DefaultClassification: body.DefaultClassification,
		DefaultTags:           body.DefaultTags,
		DescriptionPattern:    body.DescriptionPattern,
		RotationHintDays:      body.RotationHintDays,
		CreatedBy:             actor.UserID,
	}

	tmpl, err := h.coreService.CreateSecretTemplate(r.Context(), req)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, "name is required"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "invalid classification"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error creating secret template: %v", err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendCreated(w, tmpl, "Secret template created")
}

// List handles GET /api/v1/secret-templates.
func (h *SecretTemplateHandler) List(w http.ResponseWriter, r *http.Request) {
	templates, err := h.coreService.ListSecretTemplates(r.Context())
	if err != nil {
		log.Printf("Error listing secret templates: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"templates": templates}, "")
}

// Get handles GET /api/v1/secret-templates/{id}.
func (h *SecretTemplateHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidTemplateID, http.StatusBadRequest, nil)
		return
	}
	tmpl, err := h.coreService.GetSecretTemplate(r.Context(), uint(id))
	if err != nil {
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errSecretTemplateNotFound, http.StatusNotFound, nil)
			return
		}
		log.Printf("Error getting secret template: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, tmpl, "")
}

// Update handles PUT /api/v1/secret-templates/{id}.
func (h *SecretTemplateHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidTemplateID, http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Name                  string `json:"name"`
		Description           string `json:"description"`
		DefaultClassification string `json:"default_classification"`
		DefaultTags           string `json:"default_tags"`
		DescriptionPattern    string `json:"description_pattern"`
		RotationHintDays      int    `json:"rotation_hint_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	req := &core.UpdateSecretTemplateRequest{
		Name:                  body.Name,
		Description:           body.Description,
		DefaultClassification: body.DefaultClassification,
		DefaultTags:           body.DefaultTags,
		DescriptionPattern:    body.DescriptionPattern,
		RotationHintDays:      body.RotationHintDays,
	}
	tmpl, err := h.coreService.UpdateSecretTemplate(r.Context(), uint(id), req)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "name is required"), strings.Contains(msg, "invalid classification"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error updating secret template: %v", err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	h.coreService.LogSecretTemplateUpdated(r.Context(), actor.UserID, tmpl.ID, tmpl.Name)
	sendSuccess(w, tmpl, "Secret template updated")
}

// Delete handles DELETE /api/v1/secret-templates/{id}.
func (h *SecretTemplateHandler) Delete(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidTemplateID, http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteSecretTemplate(r.Context(), uint(id)); err != nil {
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errSecretTemplateNotFound, http.StatusNotFound, nil)
			return
		}
		log.Printf("Error deleting secret template: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	h.coreService.LogSecretTemplateDeleted(r.Context(), actor.UserID, uint(id))
	w.WriteHeader(http.StatusNoContent)
}

// Apply handles POST /api/v1/secret-templates/{id}/apply — a preview/dry-run
// that merges the template's defaults into the caller's supplied fields and
// returns the merged result without creating any secret.
func (h *SecretTemplateHandler) Apply(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidTemplateID, http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Classification string   `json:"classification"`
		Description    string   `json:"description"`
		Tags           []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	result, err := h.coreService.ApplyTemplate(r.Context(), uint(id), body.Classification, body.Description, body.Tags)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			sendError(w, "NotFound", errSecretTemplateNotFound, http.StatusNotFound, nil)
			return
		case strings.Contains(msg, "invalid classification"):
			sendError(w, "Error", msg, http.StatusBadRequest, nil)
			return
		default:
			log.Printf("Error applying secret template: %v", err)
			sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
			return
		}
	}
	h.coreService.LogSecretTemplateApplied(r.Context(), actor.UserID, uint(id))
	sendSuccess(w, result, "")
}
