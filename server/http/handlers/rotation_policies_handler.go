// rotation_policies_handler.go — HTTP handlers for the rotation policies domain.
//
// Routes (all under /api/v1/rotation-policies):
//
//	GET    /                — List (with optional project_id / environment_id query params)
//	POST   /                — Create
//	GET    /evaluate        — Evaluate (with optional project_id query param)
//	GET    /{id}            — Get
//	PUT    /{id}            — Update
//	DELETE /{id}            — Delete (204 No Content)
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
	"github.com/keyorixhq/keyorix/server/validation"
)

// RotationPolicyHandler handles rotation policy HTTP requests.
type RotationPolicyHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewRotationPolicyHandler creates a new RotationPolicyHandler.
func NewRotationPolicyHandler(coreService *core.KeyorixCore) *RotationPolicyHandler {
	return &RotationPolicyHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}
}

func (h *RotationPolicyHandler) sendSuccess(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := encodeJSONResponse(w, SuccessResponse{Success: true, Data: data, Message: message}); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// sendCreated writes a 201 Created JSON success response with correctly ordered
// headers -- mirrors helpers.go's package-level sendCreated (used by every OTHER
// handler's own 201 path). Calling w.WriteHeader(http.StatusCreated) before
// sendSuccess's Header().Set() calls (Create's previous shape) silently drops the
// Content-Type header: net/http only flushes headers set BEFORE the first
// WriteHeader/Write call, so a caller that inspects the response's Content-Type to
// decide whether to parse it as JSON (as ADR-108 PR 1's generated CLI client does)
// received no signal at all that this actually was JSON -- confirmed live: the new
// CLI's CreateRotationPolicyWithResponse got a nil JSON201 despite an HTTP 201 with
// a genuinely JSON body, because oapi-codegen's response parser gates JSON
// decoding on the Content-Type header. Found via scripts/cli-parity-check.sh
// against a real running server, not a unit test -- see docs/cli-split-
// inventory.md §7 PR 1's test notes.
func (h *RotationPolicyHandler) sendCreated(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusCreated)
	if err := encodeJSONResponse(w, SuccessResponse{Success: true, Data: data, Message: message}); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

func (h *RotationPolicyHandler) sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	if err := encodeJSONResponse(w, ErrorResponse{
		Error:   errorType,
		Message: message,
		Code:    statusCode,
		Details: details,
	}); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}

// List handles GET /api/v1/rotation-policies
func (h *RotationPolicyHandler) List(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	var projectID *uint
	var environmentID *uint

	if v := r.URL.Query().Get("project_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			h.sendError(w, "InvalidParameter", errInvalidProjectIDField, http.StatusBadRequest, nil)
			return
		}
		uid := uint(id)
		projectID = &uid
	}
	if v := r.URL.Query().Get("environment_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			h.sendError(w, "InvalidParameter", errInvalidEnvIDField, http.StatusBadRequest, nil)
			return
		}
		uid := uint(id)
		environmentID = &uid
	}

	policies, err := h.coreService.ListRotationPolicies(r.Context(), projectID, environmentID)
	if err != nil {
		log.Printf("Error listing rotation policies: %v", err)
		h.sendError(w, "InternalError", "Failed to list rotation policies", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, policies, "")
}

// Create handles POST /api/v1/rotation-policies
func (h *RotationPolicyHandler) Create(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	var reqBody struct {
		Name            string `json:"name" validate:"required,min=1,max=255"`
		Description     string `json:"description"`
		Scope           string `json:"scope" validate:"required,oneof=project environment"`
		ProjectID       *uint  `json:"project_id"`
		EnvironmentID   *uint  `json:"environment_id"`
		IntervalDays    int    `json:"interval_days" validate:"required,min=1,max=365"`
		AlertDaysBefore int    `json:"alert_days_before" validate:"min=0,max=90"`
		NotifyOnBreach  bool   `json:"notify_on_breach"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Authorize against the policy's target scope from the body.
	var pid, eid uint
	if reqBody.ProjectID != nil {
		pid = *reqBody.ProjectID
	}
	if reqBody.EnvironmentID != nil {
		eid = *reqBody.EnvironmentID
	}
	scope := core.Scope{ProjectID: pid, EnvironmentID: eid}
	if allowed, err := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "secrets.write", scope); err != nil || !allowed {
		h.sendError(w, "Forbidden", "Insufficient permissions", http.StatusForbidden, nil)
		return
	}
	// Per-project MFA policy (ADR-037), same as the scoped-permission middleware.
	if middleware.ProjectMFABlocked(r, h.coreService, scope.ProjectID) {
		middleware.WriteProjectMFARequired(w)
		return
	}

	req := &core.CreateRotationPolicyRequest{
		Name:            reqBody.Name,
		Description:     reqBody.Description,
		Scope:           reqBody.Scope,
		ProjectID:       reqBody.ProjectID,
		EnvironmentID:   reqBody.EnvironmentID,
		IntervalDays:    reqBody.IntervalDays,
		AlertDaysBefore: reqBody.AlertDaysBefore,
		NotifyOnBreach:  reqBody.NotifyOnBreach,
		CreatedBy:       userCtx.Username,
	}

	policy, err := h.coreService.CreateRotationPolicy(r.Context(), userCtx.UserID, req)
	if err != nil {
		log.Printf("Error creating rotation policy: %v", err)
		if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "must be less than") {
			h.sendError(w, "ValidationError", err.Error(), http.StatusUnprocessableEntity, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to create rotation policy", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendCreated(w, policy, "Rotation policy created successfully")
}

// Get handles GET /api/v1/rotation-policies/{id}
func (h *RotationPolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidRotationPolicyID, http.StatusBadRequest, nil)
		return
	}

	policy, err := h.coreService.GetRotationPolicy(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error getting rotation policy: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", errRotationPolicyNotFound, http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get rotation policy", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, policy, "")
}

// Update handles PUT /api/v1/rotation-policies/{id}
func (h *RotationPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidRotationPolicyID, http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
		Name            string `json:"name" validate:"required,min=1,max=255"`
		Description     string `json:"description"`
		IntervalDays    int    `json:"interval_days" validate:"required,min=1,max=365"`
		AlertDaysBefore int    `json:"alert_days_before" validate:"min=0,max=90"`
		NotifyOnBreach  bool   `json:"notify_on_breach"`
		IsActive        bool   `json:"is_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.UpdateRotationPolicyRequest{
		ID:              uint(id),
		Name:            reqBody.Name,
		Description:     reqBody.Description,
		IntervalDays:    reqBody.IntervalDays,
		AlertDaysBefore: reqBody.AlertDaysBefore,
		NotifyOnBreach:  reqBody.NotifyOnBreach,
		IsActive:        reqBody.IsActive,
	}

	policy, err := h.coreService.UpdateRotationPolicy(r.Context(), userCtx.UserID, req)
	if err != nil {
		log.Printf("Error updating rotation policy: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", errRotationPolicyNotFound, http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "must be less than") {
			h.sendError(w, "ValidationError", err.Error(), http.StatusUnprocessableEntity, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to update rotation policy", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, policy, "Rotation policy updated successfully")
}

// Delete handles DELETE /api/v1/rotation-policies/{id}
func (h *RotationPolicyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidRotationPolicyID, http.StatusBadRequest, nil)
		return
	}

	if err := h.coreService.DeleteRotationPolicy(r.Context(), userCtx.UserID, uint(id)); err != nil {
		log.Printf("Error deleting rotation policy: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", errRotationPolicyNotFound, http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to delete rotation policy", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// parseOptionalUintQuery parses an optional uint query parameter; returns (nil, nil)
// when absent and (nil, err) when present but not a valid uint.
func parseOptionalUintQuery(r *http.Request, key string) (*uint, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return nil, nil
	}
	id, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return nil, err
	}
	uid := uint(id)
	return &uid, nil
}

// Evaluate handles GET /api/v1/rotation-policies/evaluate
func (h *RotationPolicyHandler) Evaluate(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	var projectID *uint
	if v := r.URL.Query().Get("project_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			h.sendError(w, "InvalidParameter", errInvalidProjectIDField, http.StatusBadRequest, nil)
			return
		}
		uid := uint(id)
		projectID = &uid
	}

	// Honour environment_id so an environment-scoped reader's view is confined to their
	// environment (the route gate authorizes at {project, environment} via ScopeFromQuery,
	// but the core previously ignored the env and returned the whole project's posture).
	environmentID, perr := parseOptionalUintQuery(r, "environment_id")
	if perr != nil {
		h.sendError(w, "InvalidParameter", errInvalidEnvIDField, http.StatusBadRequest, nil)
		return
	}

	evaluations, err := h.coreService.EvaluateRotationPolicies(r.Context(), projectID, environmentID)
	if err != nil {
		log.Printf("Error evaluating rotation policies: %v", err)
		h.sendError(w, "InternalError", "Failed to evaluate rotation policies", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, evaluations, "")
}

// Status handles GET /api/v1/rotation-policies/status — the rotation posture of
// every policy-covered secret (overdue / due_soon / ok), powering the dashboard
// rotation inspector and health score. Unlike Evaluate it does not filter to
// only overdue/approaching secrets.
func (h *RotationPolicyHandler) Status(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	var projectID *uint
	if v := r.URL.Query().Get("project_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			h.sendError(w, "InvalidParameter", errInvalidProjectIDField, http.StatusBadRequest, nil)
			return
		}
		uid := uint(id)
		projectID = &uid
	}

	// Honour environment_id so an environment-scoped reader's view is confined to their
	// environment (see Evaluate).
	environmentID, perr := parseOptionalUintQuery(r, "environment_id")
	if perr != nil {
		h.sendError(w, "InvalidParameter", errInvalidEnvIDField, http.StatusBadRequest, nil)
		return
	}

	entries, err := h.coreService.GetRotationStatus(r.Context(), projectID, environmentID)
	if err != nil {
		log.Printf("Error getting rotation status: %v", err)
		h.sendError(w, "InternalError", "Failed to get rotation status", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, entries, "")
}

// GetRotationState handles GET /api/v1/secrets/{id}/rotation-state.
// Returns the per-policy execution state (idle/pending/rotating/succeeded/failed)
// for the secret's covering rotation policy. Secrets with no active policy return
// state="idle" with a 200 (not a 404) — absence of a policy is a normal case.
func (h *RotationPolicyHandler) GetRotationState(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	secretID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	info, err := h.coreService.GetRotationState(r.Context(), uint(secretID))
	if err != nil {
		log.Printf("Error getting rotation state for secret %d: %v", secretID, err)
		h.sendError(w, "InternalError", "Failed to get rotation state", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, info, "")
}
