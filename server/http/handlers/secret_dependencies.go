// secret_dependencies.go — per-secret dependency-graph handlers (ADR-052).
//
// Routes (under /api/v1/secrets, project-scoped from the {id} secret):
//
//	GET    /{id}/dependencies            — the secret's direct dependencies + dependents
//	POST   /{id}/dependencies            — declare that {id} depends on another secret
//	DELETE /{id}/dependencies/{depId}    — remove one dependency edge
//	GET    /{id}/impact                  — blast radius (transitive dependents)
//	GET    /{id}/impact-preview          — flat count/summary of cascade-delete impact
//
// Plus, under /api/v1/projects (project-scoped):
//
//	GET    /{id}/rotation-order          — a safe rotation sequence for the project graph
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// dependencyErrorStatus maps a core dependency error to an HTTP status by its message,
// matching the convention used across the secret handlers.
func dependencyErrorStatus(msg string) int {
	switch {
	case strings.Contains(msg, "not found"):
		return http.StatusNotFound
	case strings.Contains(msg, "cannot depend on itself"),
		strings.Contains(msg, "same project"),
		strings.Contains(msg, "already exists"),
		strings.Contains(msg, "cycle"),
		strings.Contains(msg, "is not a secret"):
		return http.StatusBadRequest
	case strings.Contains(msg, "permission"), strings.Contains(msg, "not authorized"):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// ListSecretDependencies handles GET /api/v1/secrets/{id}/dependencies
func (h *SecretHandler) ListSecretDependencies(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	deps, err := h.coreService.ListSecretDependencies(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), uint(id))
	if err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, deps, "")
}

// AddSecretDependency handles POST /api/v1/secrets/{id}/dependencies
func (h *SecretHandler) AddSecretDependency(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		DependsOnID uint   `json:"depends_on_id"`
		Note        string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if reqBody.DependsOnID == 0 {
		h.sendError(w, "InvalidParameter", "depends_on_id is required", http.StatusBadRequest, nil)
		return
	}
	dep, err := h.coreService.AddSecretDependency(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), uint(id), reqBody.DependsOnID, reqBody.Note, machineID(r))
	if err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, dep, "Dependency added")
}

// RemoveSecretDependency handles DELETE /api/v1/secrets/{id}/dependencies/{depId}
func (h *SecretHandler) RemoveSecretDependency(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	depID, err := strconv.ParseUint(chi.URLParam(r, "depId"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid dependency ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RemoveSecretDependency(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), uint(id), uint(depID)); err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, map[string]bool{"removed": true}, "Dependency removed")
}

// GetSecretImpact handles GET /api/v1/secrets/{id}/impact
func (h *SecretHandler) GetSecretImpact(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	impact, err := h.coreService.GetSecretImpact(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), uint(id))
	if err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, impact, "")
}

// GetSecretImpactPreview handles GET /api/v1/secrets/{id}/impact-preview.
// It returns a flat count/summary of how many secrets would be cascade-affected
// if the given secret were soft-deleted: direct dependent count, total transitive
// count, all affected IDs, and the maximum dependency chain depth reached.
func (h *SecretHandler) GetSecretImpactPreview(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	preview, err := h.coreService.GetSecretImpactPreview(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), uint(id))
	if err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, preview, "")
}

// GetProjectRotationOrder handles GET /api/v1/projects/{id}/rotation-order
func (h *SecretHandler) GetProjectRotationOrder(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	// A scoped role binding survives project soft-delete (RequireScopedPermission
	// authorizes on the binding, not on the project's current lifecycle state), so
	// re-check the project is actually live before returning its rotation data —
	// mirrors the identical fix in the gRPC twin (ProjectGRPCService.
	// GetProjectRotationOrder).
	if _, err := h.coreService.GetProject(r.Context(), uint(id)); err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	order, err := h.coreService.GetProjectRotationOrder(r.Context(), uint(id))
	if err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, order, "")
}

// GetProjectRotationPlan handles GET /api/v1/projects/{id}/rotation-plan (ADR-053):
// an ordered, dependency-respecting plan of the project's secrets that are overdue or
// due soon, batched into parallel-safe waves and prioritised by urgency.
func (h *SecretHandler) GetProjectRotationPlan(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	// See GetProjectRotationOrder above: a scoped role binding survives project
	// soft-delete, so re-check liveness before returning rotation data — mirrors
	// the gRPC twin's identical fix.
	if _, err := h.coreService.GetProject(r.Context(), uint(id)); err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	plan, err := h.coreService.GenerateRotationPlan(r.Context(), uint(id))
	if err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, plan, "")
}

// GetDeploymentRotationPlan handles GET /api/v1/rotation-plan (ADR-053): the install-wide
// rotation plan — every project's overdue/due-soon secrets aggregated into a roll-up, most
// pressing project first. Gated by GLOBAL secrets.read at the route (the same access level
// as listing all projects), so it never reveals a project the caller cannot already see.
func (h *SecretHandler) GetDeploymentRotationPlan(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	plan, err := h.coreService.GenerateDeploymentRotationPlan(r.Context())
	if err != nil {
		h.sendError(w, "Error", errorMessageFor(dependencyErrorStatus(err.Error()), err), dependencyErrorStatus(err.Error()), nil)
		return
	}
	// #G17: the response aggregates every project's own rotation plan; a
	// project that individually requires MFA must not be readable via this
	// global-scope roll-up by a session that lacks it — mirrors the gRPC-side
	// enforceProjectMFAForProjects fix in the same finding.
	projectIDs := make([]uint, 0, len(plan.Projects))
	for _, p := range plan.Projects {
		projectIDs = append(projectIDs, p.ProjectID)
	}
	if middleware.ProjectsMFABlocked(r, h.coreService, projectIDs) {
		middleware.WriteProjectMFARequired(w)
		return
	}
	h.sendSuccess(w, plan, "")
}
