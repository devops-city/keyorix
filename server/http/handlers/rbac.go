// rbac.go — RBAC HTTP handlers.
//
// Real implementations live on RBACHandler (used by the router).
// Package-level functions (ListRoles, CreateRole, …) are kept for
// backward-compatibility with existing tests; they delegate to
// defaultRBACHandler when it has been initialised via NewRBACHandler,
// otherwise they fall back to the minimal stub behaviour expected by
// those tests (auth check only).
package handlers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// RBACHandler handles RBAC-related HTTP requests using real storage.
type RBACHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewRBACHandler creates a new RBACHandler.
func NewRBACHandler(coreService *core.KeyorixCore) *RBACHandler {
	return &RBACHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Request/response types kept here so existing tests can reference them.
// ────────────────────────────────────────────────────────────────────────────

// Role is the legacy response shape used by existing tests.
type Role struct {
	ID          uint     `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// UserRole is the legacy response shape used by existing tests.
type UserRole struct {
	UserID    uint   `json:"user_id"`
	RoleID    uint   `json:"role_id"`
	Username  string `json:"username"`
	RoleName  string `json:"role_name"`
	CreatedAt string `json:"created_at"`
}

// CreateRoleRequest is the request body for role creation.
//
// #189: Name is restricted to the `identifier` charset (letters/digits/space/`-`/`_`)
// so a zero-width, RTL-override, or homograph-lookalike character can't be used to
// visually disguise a custom role in an access-review UI or audit log. This only
// constrains roles created through this API — the bootstrap-seeded system/builtin
// roles (admin, viewer, ...; see internal/core/auth_bootstrap.go) are written
// directly via storage.CreateRole and never pass through this validated request type,
// so they're unaffected.
type CreateRoleRequest struct {
	Name        string   `json:"name"        validate:"required,min=3,max=50,identifier"`
	Description string   `json:"description" validate:"required,min=1,max=200"`
	Permissions []string `json:"permissions" validate:"required,min=1"`
}

// UpdateRoleRequest is the request body for role update.
type UpdateRoleRequest struct {
	Description *string   `json:"description,omitempty" validate:"omitempty,min=1,max=200"`
	Permissions *[]string `json:"permissions,omitempty" validate:"omitempty,min=1"`
}

// AssignRoleRequest is the request body for assigning a role.
type AssignRoleRequest struct {
	UserID uint `json:"user_id" validate:"required"`
	RoleID uint `json:"role_id" validate:"required"`
	// ProjectID/EnvironmentID scope the assignment (0 = global). See core.Scope.
	ProjectID     uint `json:"project_id"`
	EnvironmentID uint `json:"environment_id"`
	// ExpiresAt, when set, makes the grant time-bound (just-in-time access): the
	// grant stops authorizing the instant it passes and the JIT scheduler sweeps it.
	// Omit for a permanent grant. Must be in the future. Mirrors share expiry.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// RemoveRoleRequest is the request body for removing a role.
type RemoveRoleRequest struct {
	UserID        uint `json:"user_id" validate:"required"`
	RoleID        uint `json:"role_id" validate:"required"`
	ProjectID     uint `json:"project_id"`
	EnvironmentID uint `json:"environment_id"`
}

var validator = validation.NewValidator()

// ────────────────────────────────────────────────────────────────────────────
// RBACHandler methods — real implementations used by the router.
// ────────────────────────────────────────────────────────────────────────────

// ListRoles handles GET /api/v1/roles
func (h *RBACHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	roles, err := h.coreService.ListRolesWithPermissions(r.Context())
	if err != nil {
		log.Printf("Error listing roles: %v", err)
		sendError(w, "InternalError", "Failed to list roles", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, map[string]any{"roles": newRoleWithPermissionsWireList(roles), "total": len(roles)}, "")
}

// CreateRole handles POST /api/v1/roles
func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	var req CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}

	// #169: resolve + authorize every requested permission BEFORE creating anything.
	toAssign, handled := h.resolveAndAuthorizePermissions(w, r, userCtx.UserID, req.Permissions)
	if handled {
		return
	}
	permissionIDs := make([]uint, len(toAssign))
	for i, p := range toAssign {
		permissionIDs[i] = p.ID
	}

	// core.CreateRole is the single place that folds the name (identity.
	// NewFoldedName — #1642), rejects reserved built-in names (#294:
	// roleSetContainsAdmin in authz.go grants a full admin bypass by NAME match
	// alone, so a caller-created row named e.g. "super_admin" would function as
	// a complete admin-bypass switch the moment it's assigned, even with zero
	// permissions of its own), runs the role-row create AND the permission
	// bundling in one transaction, and audits only after that transaction
	// commits — see its own doc comment for why this must not be split back
	// into two separately-sequenced calls (an AssignPermissionToRole failure
	// here used to be logged and swallowed, the role still reported created
	// with whatever subset happened to succeed).
	// #2545, extended to roles: a client-asserted origin (e.g. keyorix-migrate's source
	// policy/path) is recorded as a labelled note on the audit event, never as attribution.
	auditCtx := core.WithClientOrigin(r.Context(), r.Header.Get(core.ClientOriginHeader))
	role, assignedPerms, err := h.coreService.CreateRole(auditCtx, userCtx.UserID, req.Name, req.Description, permissionIDs)
	if err != nil {
		log.Printf("Error creating role: %v", err)
		msg := err.Error()
		switch {
		case strings.Contains(msg, "reserved"):
			sendError(w, "ConflictError", "this role name is reserved and cannot be created", http.StatusConflict, nil)
		case strings.Contains(msg, "already exists"), strings.Contains(msg, "UNIQUE"):
			sendError(w, "ConflictError", "Role with this name already exists", http.StatusConflict, nil)
		case strings.Contains(msg, i18n.T("ErrorValidation", nil)):
			sendError(w, "ValidationError", msg, http.StatusBadRequest, nil)
		default:
			sendError(w, "InternalError", "Failed to create role", http.StatusInternalServerError, nil)
		}
		return
	}

	sendCreated(w, map[string]any{"role": newRoleWire(role), "permissions": newPermissionWireList(assignedPerms)}, "Role created successfully")
}

// resolveAndAuthorizePermissions resolves each named permission and checks the actor
// holds it. Unknown names are skipped. Returns the resolved set and handled=true if
// an error response was already written (caller should return immediately).
func (h *RBACHandler) resolveAndAuthorizePermissions(w http.ResponseWriter, r *http.Request, actorID uint, names []string) ([]*models.Permission, bool) {
	out := make([]*models.Permission, 0, len(names))
	for _, permName := range names {
		perm, err := h.findPermissionByName(r.Context(), permName)
		if err != nil {
			if errors.Is(err, errPermissionNameNotFound) {
				continue // skip unknown permission names
			}
			// A real lookup failure (e.g. ListPermissions storage error) must abort,
			// not be silently treated as "unknown name" — that would apply a
			// truncated permission set while still reporting success.
			sendError(w, "InternalError", "Failed to resolve permission", http.StatusInternalServerError, nil)
			return nil, true
		}
		ok, aerr := h.coreService.Authorize(r.Context(), actorID, perm.Name, core.Scope{})
		if aerr != nil {
			sendError(w, "InternalError", "Failed to resolve actor authority", http.StatusInternalServerError, nil)
			return nil, true
		}
		if !ok {
			sendError(w, "Forbidden", fmt.Sprintf("cannot bundle permission %q into a role: you do not hold it yourself", permName), http.StatusForbidden, nil)
			return nil, true
		}
		out = append(out, perm)
	}
	return out, false
}

// GetRole handles GET /api/v1/roles/{id}
func (h *RBACHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	role, perms, err := h.coreService.GetRoleWithPermissions(r.Context(), id)
	if err != nil {
		log.Printf("Error getting role: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errRoleNotFound, http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", errFailedGetRole, http.StatusInternalServerError, nil)
		}
		return
	}

	sendSuccess(w, map[string]any{"role": newRoleWire(role), "permissions": newPermissionWireList(perms)}, "")
}

// GetRoleByName handles GET /api/v1/roles/by-name?name=X — looks up a role by
// name for callers (#512) that only have the role's name
// rather than its numeric ID (InviteToProject resolves every invited role —
// system and project roles alike — by name this way). The route's permission
// gate (roles.read, inherited from the /roles group — the same gate GetRole-
// by-id uses) is the sole authz check, matching GetRole's model exactly; there
// is no additional per-record check to bypass. Deliberately mirrors GetRole's
// generic NotFound response (same status code, same static message) rather
// than a distinct shape, so a caller cannot use response differences to probe
// for valid role names — a caller without roles.read never reaches this
// handler at all (401/403 from the route middleware, identical for every
// name), and a caller WITH roles.read can already enumerate every role
// (including name) via GET /roles, so this route grants no new capability at
// that permission level. Unlike GetRole, this returns the bare role (no
// permissions payload — models.Role).
func (h *RBACHandler) GetRoleByName(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		sendError(w, "InvalidParameter", "name is required", http.StatusBadRequest, nil)
		return
	}

	role, err := h.coreService.Storage().GetRoleByName(r.Context(), name)
	if err != nil {
		log.Printf("Error getting role by name: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errRoleNotFound, http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", errFailedGetRole, http.StatusInternalServerError, nil)
		}
		return
	}

	sendSuccess(w, newRoleWire(role), "")
}

// UpdateRole handles PUT /api/v1/roles/{id}
func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 18, suppress go:S3776
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}

	role, err := h.coreService.Storage().GetRole(r.Context(), id)
	if err != nil {
		log.Printf("Error getting role: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errRoleNotFound, http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", errFailedGetRole, http.StatusInternalServerError, nil)
		}
		return
	}
	// #169: resolve + authorize every requested permission BEFORE touching the
	// role's existing permission set — otherwise a request naming even one
	// permission the actor doesn't hold would abort partway through a
	// mutation already applied to the role. An authorization failure on a
	// KNOWN permission must abort before any mutation. Unknown names are still
	// skipped later, matching CreateRole's convention.
	var newPermissionIDs *[]uint
	if req.Permissions != nil {
		toAssign, aerr := h.authorizeAndCollectPermissions(r.Context(), userCtx, *req.Permissions)
		if aerr != nil {
			if strings.Contains(aerr.Error(), "cannot bundle") {
				sendError(w, "Forbidden", aerr.Error(), http.StatusForbidden, nil)
			} else {
				log.Printf("failed to resolve permissions for role update: %v", aerr)
				sendError(w, "InternalError", clientSafe(aerr), http.StatusInternalServerError, nil)
			}
			return
		}
		ids := make([]uint, len(toAssign))
		for i, p := range toAssign {
			ids[i] = p.ID
		}
		newPermissionIDs = &ids
	}

	if req.Description != nil {
		role.Description = *req.Description
	}
	// core.UpdateRole is the single place that rejects mutating a built-in
	// role, runs the role-row update AND the permission replacement in one
	// storage transaction, and audits only after that transaction commits —
	// see its own doc comment (docs/findings/2026-09-21-FINDING-role-update-permission-replace-swallows-storage-errors.md,
	// F3a/F3b) for why this must not be split back into two separately-
	// sequenced calls the way it used to be.
	updated, perms, err := h.coreService.UpdateRole(r.Context(), userCtx.UserID, role, newPermissionIDs)
	if err != nil {
		log.Printf("Error updating role: %v", err)
		if sendPartialMutation(w, err) {
			return
		}
		if strings.Contains(err.Error(), "built-in") {
			sendError(w, "Forbidden", "Cannot update built-in role: "+role.Name, http.StatusForbidden, nil)
		} else {
			sendError(w, "InternalError", "Failed to update role", http.StatusInternalServerError, nil)
		}
		return
	}
	role = updated

	sendSuccess(w, map[string]any{"role": newRoleWire(role), "permissions": newPermissionWireList(perms)}, "Role updated successfully")
}

func (h *RBACHandler) authorizeAndCollectPermissions(ctx context.Context, userCtx *middleware.UserContext, permNames []string) ([]*models.Permission, error) {
	toAssign := make([]*models.Permission, 0, len(permNames))
	for _, permName := range permNames {
		perm, err := h.findPermissionByName(ctx, permName)
		if err != nil {
			if errors.Is(err, errPermissionNameNotFound) {
				continue
			}
			// A real lookup failure (e.g. ListPermissions storage error) must abort,
			// not be silently treated as "unknown name" — that would apply a
			// truncated permission set while still reporting success.
			return nil, fmt.Errorf("failed to resolve permission %q: %w", permName, err)
		}
		ok, aerr := h.coreService.Authorize(ctx, userCtx.UserID, perm.Name, core.Scope{})
		if aerr != nil {
			return nil, fmt.Errorf("failed to resolve actor authority for %q: %w", permName, aerr)
		}
		if !ok {
			return nil, fmt.Errorf("cannot bundle permission %q into a role: you do not hold it yourself", permName)
		}
		toAssign = append(toAssign, perm)
	}
	return toAssign, nil
}

// DeleteRole handles DELETE /api/v1/roles/{id}
func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	if err := h.coreService.DeleteRole(r.Context(), userCtx.UserID, id); err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			sendError(w, "NotFound", errRoleNotFound, http.StatusNotFound, nil)
		case strings.Contains(msg, "built-in role"):
			sendError(w, "Forbidden", msg, http.StatusForbidden, nil)
		default:
			log.Printf("Error deleting role: %v", err)
			sendError(w, "InternalError", "Failed to delete role", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// roleExpiryValid reports whether a time-bound grant's expiry is acceptable. A nil
// expiry (permanent grant) is always valid; a set expiry must be in the future — an
// already-past expiry would create a grant that never authorizes. On rejection it
// writes a 400 and returns false (mirrors the share-expiry guard).
func roleExpiryValid(w http.ResponseWriter, expiresAt *time.Time) bool {
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		sendError(w, "ValidationError", "Role expiry must be in the future", http.StatusBadRequest, nil)
		return false
	}
	return true
}

// AssignRole handles POST /api/v1/user-roles
func (h *RBACHandler) AssignRole(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	var req AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}

	if !roleExpiryValid(w, req.ExpiresAt) {
		return
	}

	scope := core.Scope{ProjectID: req.ProjectID, EnvironmentID: req.EnvironmentID}
	// Through the audited core choke point (records role.assigned with the actor),
	// not storage directly — keeps this endpoint in the RBAC audit trail. A set
	// expiry routes through the time-bound (JIT) path.
	ctx := r.Context()
	if userCtx.ActorKind() == core.ActorTypeMachine {
		// A genuine, directly-authenticated machine actor requesting this
		// grant as itself (not a /system proxy relay) -- tag ctx so
		// requireGranterHoldsRolePermissions checks ITS real permissions
		// instead of unconditionally refusing. See that function's doc.
		ctx = core.WithSelfMachineGranter(ctx, userCtx.PrincipalID())
	}
	var err error
	if req.ExpiresAt != nil {
		// #1542: a machine identity (UserID==0 by construction, see
		// server/middleware/auth.go's UserContext doc) reaching this endpoint via
		// RequireScopedPermission must not be treated as the trusted
		// actorID==0 local-CLI exemption inside requireGranterHoldsRolePermissions.
		err = h.coreService.AssignUserRoleWithExpiry(ctx, userCtx.UserID, req.UserID, req.RoleID, scope, *req.ExpiresAt, userCtx.ActorKind() == core.ActorTypeMachine)
	} else {
		err = h.coreService.AssignUserRole(ctx, userCtx.UserID, req.UserID, req.RoleID, scope, userCtx.ActorKind() == core.ActorTypeMachine)
	}
	if err != nil {
		log.Printf("Error assigning role: %v", err)
		if strings.Contains(err.Error(), "already assigned") {
			sendError(w, "ConflictError", "Role already assigned to user", http.StatusConflict, nil)
		} else {
			sendError(w, "InternalError", "Failed to assign role", http.StatusInternalServerError, nil)
		}
		return
	}

	sendCreated(w, map[string]any{"user_id": req.UserID, "role_id": req.RoleID, "expires_at": req.ExpiresAt}, "Role assigned successfully")
}

// RemoveRole handles DELETE /api/v1/user-roles
func (h *RBACHandler) RemoveRole(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	var req RemoveRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}

	scope := core.Scope{ProjectID: req.ProjectID, EnvironmentID: req.EnvironmentID}
	// Through the audited core choke point (records role.removed with the actor).
	if err := h.coreService.RemoveUserRole(r.Context(), userCtx.UserID, req.UserID, req.RoleID, scope); err != nil {
		log.Printf("Error removing role: %v", err)
		if strings.Contains(err.Error(), "not assigned") {
			sendError(w, "NotFound", "Role not assigned to user", http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to remove role", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetUserRoles handles GET /api/v1/user-roles/user/{userId}
func (h *RBACHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	id, ok := parseUintParam(w, r, "userId")
	if !ok {
		return
	}

	assignment, err := h.coreService.GetUserRoleAssignment(r.Context(), id)
	if err != nil {
		log.Printf("Error getting user role assignment: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to get user roles", http.StatusInternalServerError, nil)
		}
		return
	}

	sendSuccess(w, newUserRoleAssignmentWire(assignment), "")
}

// ListPermissions handles GET /api/v1/permissions
func (h *RBACHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	perms, err := h.coreService.ListPermissions(r.Context())
	if err != nil {
		log.Printf("Error listing permissions: %v", err)
		sendError(w, "InternalError", "Failed to list permissions", http.StatusInternalServerError, nil)
		return
	}

	// Optional ?resource= filter.
	if res := r.URL.Query().Get("resource"); res != "" {
		filtered := perms[:0]
		for _, p := range perms {
			if p.Resource == res {
				filtered = append(filtered, p)
			}
		}
		perms = filtered
	}

	sendSuccess(w, map[string]any{"permissions": newPermissionWireList(perms), "total": len(perms)}, "")
}

// GetPermission handles GET /api/v1/permissions/{id} — added for #526: the
// now-deleted RemoteStorage's GetPermission proxied onto this same route.
// ListPermissions and GetRolePermissions already had human-facing routes to
// reuse, but no route
// previously covered a per-ID permission lookup, which AssignPermissionToRole
// needs to resolve permissionID -> name. Gated by the SAME roles.read as the
// rest of the /permissions group — a caller who can already enumerate every
// permission (including this one) via GET /permissions gains no new
// capability from looking one up individually. Returns the bare permission
// object (not wrapped), matching GetRoleByName's response shape.
func (h *RBACHandler) GetPermission(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	perm, err := h.coreService.Storage().GetPermission(r.Context(), id)
	if err != nil {
		log.Printf("Error getting permission: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", "Permission not found", http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to get permission", http.StatusInternalServerError, nil)
		}
		return
	}

	sendSuccess(w, newPermissionWire(perm), "")
}

// GetRolePermissions handles GET /api/v1/roles/{id}/permissions
func (h *RBACHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	role, perms, err := h.coreService.GetRoleWithPermissions(r.Context(), id)
	if err != nil {
		log.Printf("Error getting role permissions: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errRoleNotFound, http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to get role permissions", http.StatusInternalServerError, nil)
		}
		return
	}

	sendSuccess(w, map[string]any{"role_id": role.ID, "role_name": role.Name, "permissions": newPermissionWireList(perms)}, "")
}

// AssignPermissionToRole handles POST /api/v1/roles/{id}/permissions
func (h *RBACHandler) AssignPermissionToRole(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	roleID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	var body struct {
		PermissionID uint `json:"permission_id" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}

	ctx := r.Context()
	if userCtx.ActorKind() == core.ActorTypeMachine {
		// #1545 sibling gap: without this tag, AssignPermissionToRole's
		// machine-actor branch fails closed for EVERY machine caller, even
		// one that genuinely holds the permission via its own machine role
		// -- see that function's doc comment. Mirrors this file's other
		// WithSelfMachineGranter call sites.
		ctx = core.WithSelfMachineGranter(ctx, userCtx.PrincipalID())
	}
	if err := h.coreService.AssignPermissionToRole(ctx, userCtx.UserID, roleID, body.PermissionID, isMachineActor(r)); err != nil {
		log.Printf("Error assigning permission to role: %v", err)
		switch {
		case strings.Contains(err.Error(), errNotFound):
			sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "do not hold it yourself"):
			// #169: the actor doesn't hold the permission being bundled — 403, not 500.
			sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
		case strings.Contains(err.Error(), "already has permission"):
			// storage.ErrDuplicateRolePermission (role_permissions' composite primary
			// key already held) — 409, not 500. Found by SESSION-I's fresh-install API
			// smoke driver: a re-assign of an already-held permission (a plausible
			// idempotent-retry shape, not an attack) 500ed before this case existed.
			sendError(w, "Conflict", err.Error(), http.StatusConflict, nil)
		default:
			sendError(w, "InternalError", "Failed to assign permission", http.StatusInternalServerError, nil)
		}
		return
	}

	sendCreated(w, map[string]any{"role_id": roleID, "permission_id": body.PermissionID}, "Permission assigned successfully")
}

// RemovePermissionFromRole handles DELETE /api/v1/roles/{id}/permissions/{permissionId}
func (h *RBACHandler) RemovePermissionFromRole(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	roleID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	permID, ok := parseUintParam(w, r, "permissionId")
	if !ok {
		return
	}

	if err := h.coreService.RemovePermissionFromRole(r.Context(), userCtx.UserID, roleID, permID); err != nil {
		log.Printf("Error removing permission from role: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to remove permission", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetGroupRoles handles GET /api/v1/groups/{id}/roles
func (h *RBACHandler) GetGroupRoles(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	groupID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	// Grants carry each role's time-bound expiry (nil = permanent) so the UI can
	// show remaining time on a JIT grant.
	roles, err := h.coreService.GetGroupRoleGrants(r.Context(), groupID)
	if err != nil {
		log.Printf("Error getting group roles: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", "Group not found", http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to get group roles", http.StatusInternalServerError, nil)
		}
		return
	}

	sendSuccess(w, map[string]any{"group_id": groupID, "roles": roles}, "")
}

// AssignRoleToGroup handles POST /api/v1/groups/{id}/roles
func (h *RBACHandler) AssignRoleToGroup(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	groupID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	var body struct {
		RoleID        uint       `json:"role_id" validate:"required"`
		ProjectID     uint       `json:"project_id"`
		EnvironmentID uint       `json:"environment_id"`
		ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}
	if !roleExpiryValid(w, body.ExpiresAt) {
		return
	}

	scope := core.Scope{ProjectID: body.ProjectID, EnvironmentID: body.EnvironmentID}
	// A set expiry routes through the time-bound (JIT) path.
	ctx := r.Context()
	if userCtx.ActorKind() == core.ActorTypeMachine {
		// A genuine, directly-authenticated machine actor requesting this
		// grant as itself (not a /system proxy relay) -- tag ctx so
		// requireGranterHoldsRolePermissions checks ITS real permissions
		// instead of unconditionally refusing. See that function's doc.
		ctx = core.WithSelfMachineGranter(ctx, userCtx.PrincipalID())
	}
	var err error
	if body.ExpiresAt != nil {
		err = h.coreService.AssignGroupRoleWithExpiry(ctx, userCtx.UserID, groupID, body.RoleID, scope, *body.ExpiresAt, userCtx.ActorKind() == core.ActorTypeMachine)
	} else {
		err = h.coreService.AssignRoleToGroup(ctx, userCtx.UserID, groupID, body.RoleID, scope, userCtx.ActorKind() == core.ActorTypeMachine)
	}
	if err != nil {
		log.Printf("Error assigning role to group: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "already assigned") {
			sendError(w, "ConflictError", "Role already assigned to group", http.StatusConflict, nil)
		} else {
			sendError(w, "InternalError", "Failed to assign role to group", http.StatusInternalServerError, nil)
		}
		return
	}

	sendCreated(w, map[string]any{"group_id": groupID, "role_id": body.RoleID, "expires_at": body.ExpiresAt}, "Role assigned to group successfully")
}

// RemoveRoleFromGroup handles DELETE /api/v1/groups/{id}/roles/{roleId}
func (h *RBACHandler) RemoveRoleFromGroup(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	groupID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	roleID, ok := parseUintParam(w, r, "roleId")
	if !ok {
		return
	}
	scope := core.Scope{
		ProjectID:     queryUint(r, "project_id"),
		EnvironmentID: queryUint(r, "environment_id"),
	}

	if err := h.coreService.RemoveRoleFromGroup(r.Context(), userCtx.UserID, groupID, roleID, scope); err != nil {
		log.Printf("Error removing role from group: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to remove role from group", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ────────────────────────────────────────────────────────────────────────────
// Package-level compatibility stubs — existing tests call these directly.
// The router uses RBACHandler methods directly; these are kept only for
// backward-compat with the rbac_test.go suite and return minimal responses.
// ────────────────────────────────────────────────────────────────────────────

func ListRoles(w http.ResponseWriter, r *http.Request) {
	if _, ok := mustGetUser(w, r); !ok {
		return
	}
	sendSuccess(w, map[string]any{"roles": []any{}, "total": 0}, "")
}

func CreateRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := mustGetUser(w, r); !ok {
		return
	}
	var req CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}
	sendCreated(w, map[string]any{"name": req.Name}, "Role created successfully")
}

// GetRole returns a mock 200 for IDs in the predefined stub set, 404 otherwise.
// IDs 1-10 are treated as existing mock roles to satisfy legacy test contracts.
func GetRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := mustGetUser(w, r); !ok {
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidRoleID, http.StatusBadRequest, nil)
		return
	}
	if id >= 1 && id <= 10 {
		sendSuccess(w, map[string]any{"id": id, "name": "mock-role", "permissions": []any{}}, "")
		return
	}
	sendError(w, "NotFound", errRoleNotFound, http.StatusNotFound, nil)
}

func UpdateRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := mustGetUser(w, r); !ok {
		return
	}
	if _, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32); err != nil {
		sendError(w, "InvalidParameter", errInvalidRoleID, http.StatusBadRequest, nil)
		return
	}
	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}
	sendSuccess(w, map[string]any{}, "Role updated successfully")
}

func DeleteRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := mustGetUser(w, r); !ok {
		return
	}
	if _, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32); err != nil {
		sendError(w, "InvalidParameter", errInvalidRoleID, http.StatusBadRequest, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func AssignRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := mustGetUser(w, r); !ok {
		return
	}
	var req AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}
	sendCreated(w, map[string]any{"user_id": req.UserID, "role_id": req.RoleID}, "Role assigned successfully")
}

func RemoveRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := mustGetUser(w, r); !ok {
		return
	}
	var req RemoveRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", errInvalidRequestData, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func GetUserRoles(w http.ResponseWriter, r *http.Request) {
	if _, ok := mustGetUser(w, r); !ok {
		return
	}
	if _, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32); err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	sendSuccess(w, map[string]any{"roles": []any{}, "total": 0}, "")
}

// ────────────────────────────────────────────────────────────────────────────
// Shared helper
// ────────────────────────────────────────────────────────────────────────────

// errPermissionNameNotFound distinguishes "this name genuinely isn't a real
// permission" (safe to silently skip, matching CreateRole/UpdateRole's
// unknown-name convention) from any other error findPermissionByName can
// return (a ListPermissions storage failure) — the latter must never be
// treated the same way. Found live by FuzzStorageFaultOperations: a transient
// ListPermissions fault on one name in a multi-permission request used to be
// swallowed identically to "unknown name," silently dropping that permission
// from the role's final set while the request still reported success —
// oracle (a) violation (reported SUCCESS, but the committed RolePermission/
// AuditEvent state didn't match a fault-free run).
var errPermissionNameNotFound = errors.New("permission name not found")

// findPermissionByName looks up a permission by name via ListPermissions.
func (h *RBACHandler) findPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	perms, err := h.coreService.ListPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	for _, p := range perms {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("permission %q not found: %w", name, errPermissionNameNotFound)
}

func parseUintParam(w http.ResponseWriter, r *http.Request, param string) (uint, bool) {
	s := chi.URLParam(r, param)
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid "+param, http.StatusBadRequest, nil)
		return 0, false
	}
	return uint(v), true
}

// queryUint reads an optional uint query parameter, defaulting to 0 (the global
// scope sentinel) when absent or unparseable.
func queryUint(r *http.Request, key string) uint {
	if v, err := strconv.ParseUint(r.URL.Query().Get(key), 10, 32); err == nil {
		return uint(v)
	}
	return 0
}

// GetPermissionMatrix handles GET /api/v1/rbac/permission-matrix[?project_id=N&format=csv].
// It returns a deployment-wide audit matrix of every (user, role, permission, scope)
// tuple. Gated on roles.read permission.
//
// ?project_id=N  — optional project filter (0 = all projects, including global grants)
// ?format=csv    — return CSV instead of JSON
func (h *RBACHandler) GetPermissionMatrix(w http.ResponseWriter, r *http.Request) {
	projectID := queryUint(r, "project_id")
	format := r.URL.Query().Get("format")

	rows, err := h.coreService.GetPermissionMatrix(r.Context(), projectID)
	if err != nil {
		sendError(w, "InternalError", "Failed to build permission matrix", http.StatusInternalServerError, nil)
		return
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="permission-matrix.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{
			"username", "email", "role", "permission", "resource", "action",
			"scope", "project", "environment", "expires_at",
		})
		for _, row := range rows {
			expiresAt := "never"
			if row.ExpiresAt != nil {
				expiresAt = row.ExpiresAt.UTC().Format(time.RFC3339)
			}
			_ = cw.Write([]string{
				csvSafe(row.Username),
				csvSafe(row.Email),
				csvSafe(row.RoleName),
				csvSafe(row.PermissionName),
				csvSafe(row.Resource),
				csvSafe(row.Action),
				csvSafe(row.Scope),
				csvSafe(row.ProjectName),
				csvSafe(row.EnvironmentName),
				expiresAt,
			})
		}
		cw.Flush()
		return
	}

	sendSuccess(w, map[string]any{"rows": rows, "total": len(rows)}, "")
}
