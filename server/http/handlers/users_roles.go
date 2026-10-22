package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

type updateUserRolesRequest struct {
	RoleIDs []uint `json:"role_ids" validate:"omitempty"`
	// ProjectID/EnvironmentID scope the replacement (0 = global). Only the
	// user's roles at this exact scope are replaced; others are left intact.
	ProjectID     uint `json:"project_id"`
	EnvironmentID uint `json:"environment_id"`
}

type apiRole struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// UsersRolesHandler handles user role management HTTP requests.
type UsersRolesHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewUsersRolesHandler creates a new UsersRolesHandler.
func NewUsersRolesHandler(coreService *core.KeyorixCore) *UsersRolesHandler {
	return &UsersRolesHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}
}

// GetUserRolesForUser handles GET /api/v1/users/{id}/roles
func (h *UsersRolesHandler) GetUserRolesForUser(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	roles, err := h.coreService.GetUserRolesByID(r.Context(), userID)
	if err != nil {
		log.Printf("Error getting roles for user %d: %v", userID, err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to get user roles", http.StatusInternalServerError, nil)
		}
		return
	}

	apiRoles := make([]apiRole, 0, len(roles))
	for _, role := range roles {
		apiRoles = append(apiRoles, apiRole{ID: role.ID, Name: role.Name})
	}
	sendSuccess(w, map[string]any{"roles": apiRoles}, "")
}

// canReadRBACStateFor reports whether actor may view TARGET user's RBAC state
// (effective permissions or project memberships): either the actor IS the target
// (own-profile read), or the actor holds roles.read (global scope) — the same
// admin-tier gate GetUserRolesForUser already requires for a user's role list
// (#141), and the tier this codebase treats as "may manage/inspect access" rather
// than the much broader, nearly-universally-held users.read. G84.
func (h *UsersRolesHandler) canReadRBACStateFor(r *http.Request, actor *middleware.UserContext, targetUserID uint) bool {
	if actor.UserID == targetUserID {
		return true
	}
	allowed, err := h.coreService.AuthorizePrincipal(r.Context(), actor.ActorKind(), actor.PrincipalID(), "roles.read", core.Scope{})
	if err != nil {
		log.Printf("Error checking roles.read for RBAC-state read (actor=%d target=%d): %v", actor.UserID, targetUserID, err)
		return false
	}
	return allowed
}

// apiPermission is one entry in a user's effective-permission view.
type apiPermission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// GetUserPermissionsForUser handles GET /api/v1/users/{id}/permissions — the user's
// effective permission set (the de-duplicated union across all assigned roles). The
// "what can this user do" view for the dashboard and access reviews.
//
// This discloses a TARGET user's full effective RBAC state, which is a much bigger
// disclosure than the route's group-level users.read gate implies (users.read is held
// by nearly every seeded role, so it lets any project member reconnoiter an arbitrary
// other user's complete permission set — privilege-escalation targeting material).
// Require self OR roles.read: the same roles.read tier GetUserRolesForUser already
// requires for the sibling roles-list view (#141), which restricts this data to the
// personas that actually manage access (system_admin/system_auditor/project_admin).
func (h *UsersRolesHandler) GetUserPermissionsForUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	if !h.canReadRBACStateFor(r, actor, userID) {
		sendError(w, "Forbidden", "You may not view another user's permissions", http.StatusForbidden, nil)
		return
	}

	perms, err := h.coreService.GetUserPermissionsByID(r.Context(), userID)
	if err != nil {
		log.Printf("Error getting permissions for user %d: %v", userID, err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to get user permissions", http.StatusInternalServerError, nil)
		}
		return
	}

	apiPerms := make([]apiPermission, 0, len(perms))
	for _, p := range perms {
		apiPerms = append(apiPerms, apiPermission{Name: p.Name, Description: p.Description, Resource: p.Resource, Action: p.Action})
	}
	sendSuccess(w, map[string]any{"permissions": apiPerms}, "")
}

// apiUserMembership is one row of a user's project-assignments view.
//
// `roles` and `via_group` were added with #2781's fix: a user can hold more than
// one role at a project's scope (a direct grant plus a group-inherited one), and an
// admin reviewing access needs to know when a membership comes from a group — the
// project's Members tab cannot remove that one.
type apiUserMembership struct {
	ProjectID   uint     `json:"project_id"`
	ProjectName string   `json:"project_name"`
	Role        string   `json:"role"`
	Roles       []string `json:"roles"`
	State       string   `json:"state"`
	ViaGroup    bool     `json:"via_group"`
	// ProjectDeleted marks a membership of a SOFT-DELETED project. The grant
	// survives a soft-delete by design (RestoreProject reinstates it), so the row
	// is reported rather than hidden — but it must be distinguishable, and it used
	// to come back with an empty project_name instead.
	ProjectDeleted bool `json:"project_deleted"`
}

// GetUserMembershipsForUser handles GET /api/v1/users/{id}/memberships — the
// user's project memberships with project name, role(s), and lifecycle state,
// powering the per-user assignments table on the detail page.
//
// #2781: this used to answer from the ADR-022 onboarding journal
// (`storage.ListUserProjectMemberships`), which nothing the web UI writes — so it
// reported "Not a member of any project" for EVERY user on an install whose project
// members were all added through `POST /projects/{id}/members`, while that same
// project's Members tab listed them. It now answers from
// `core.ListProjectMembershipsForUser`, the repo's single definition of project
// membership (internal/core/project_membership_definition.go), which is built from
// the same query `GET /projects/{id}/members` uses — so the two screens agree by
// construction. The journal still supplies the lifecycle STATE where a row exists,
// and keeps its own endpoint (`GET /projects/{id}/memberships`).
//
// # The gate, stated in full
//
// It is TWO layers, and both are load-bearing:
//
//	router.go's /users group:  r.Use(RequirePermission(permUsersRead))
//	this handler:              canReadRBACStateFor -> self OR roles.read
//
// i.e. **global users.read AND (self OR global roles.read)**. Note that
// `RequirePermission(p)` is `RequireScopedPermission(p, ScopeGlobal)`
// (server/middleware/auth.go), so both permissions mean the GLOBAL grant — a
// project-scoped users.read or roles.read satisfies neither.
//
// Two consequences worth having written down, because neither is obvious from
// either layer alone:
//
//   - A caller holding global roles.read but NOT global users.read is refused by the
//     ROUTE and never reaches this function. #2781's fix noted this as an open
//     residual (a custom role could in principle be built that way); it is not open,
//     and server/http/user_memberships_gate_2781_test.go pins it — through the
//     router, because a handler-level test cannot see route middleware at all.
//   - The `self` arm therefore cannot serve a PROJECT-scoped user. project_viewer
//     bundles users.read, but only at its project's scope, so the ordinary
//     least-privilege persona (system_viewer globally + project_viewer on one
//     project) gets 403 on their OWN memberships. That is fail-closed and currently
//     unreachable from the UI — this endpoint is only called from the admin-only
//     /admin/users/:id page — but it means a "my project assignments" view on
//     /profile would need a deliberate decision, not just a new component.
//     TestUserMemberships2781_ProjectScopedUserCannotReadEvenTheirOwn is the thing
//     that will fail and point at it.
//
// Disclosure: no new data reaches any caller this route did not already serve it to.
// The same gate already serves the sibling `GET /users/{id}/roles` the identical role
// grants; what is new here is the project each grant is scoped to, which is this
// route's own documented contract and which every caller able to pass the gate can
// already read via `GET /projects/{id}/members`.
//
// Same disclosure class as GetUserPermissionsForUser above (G84), and the same fix
// (self OR roles.read). One correction to that sibling's phrasing while we are here:
// it reasons that the group's users.read gate "lets any project member" reconnoiter
// another user — but because the gate is GLOBAL (see above), a project member holding
// only project-scoped users.read does not pass it. G84's fix is right either way; the
// premise was stated more broadly than the scope allows.
func (h *UsersRolesHandler) GetUserMembershipsForUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	if !h.canReadRBACStateFor(r, actor, userID) {
		sendError(w, "Forbidden", "You may not view another user's memberships", http.StatusForbidden, nil)
		return
	}

	memberships, err := h.coreService.ListProjectMembershipsForUser(r.Context(), userID)
	if err != nil {
		log.Printf("Error getting memberships for user %d: %v", userID, err)
		sendError(w, "InternalError", "Failed to get user memberships", http.StatusInternalServerError, nil)
		return
	}

	out := make([]apiUserMembership, 0, len(memberships))
	for _, m := range memberships {
		roles := m.Roles
		if roles == nil {
			roles = []string{}
		}
		out = append(out, apiUserMembership{
			ProjectID:      m.ProjectID,
			ProjectName:    m.ProjectName,
			Role:           m.Role,
			Roles:          roles,
			State:          m.State,
			ViaGroup:       m.ViaGroup,
			ProjectDeleted: m.ProjectDeleted,
		})
	}
	sendSuccess(w, map[string]any{"memberships": out}, "")
}

// UpdateUserRoles handles PUT /api/v1/users/{id}/roles — full role replacement.
func (h *UsersRolesHandler) UpdateUserRoles(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	var req updateUserRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	if len(req.RoleIDs) > 0 {
		allRoles, err := h.coreService.Storage().ListRoles(r.Context())
		if err != nil {
			log.Printf("Error listing roles for validation: %v", err)
			sendError(w, "InternalError", "Failed to validate role IDs", http.StatusInternalServerError, nil)
			return
		}
		existingIDs := make(map[uint]bool, len(allRoles))
		for _, role := range allRoles {
			existingIDs[role.ID] = true
		}
		for _, id := range req.RoleIDs {
			if !existingIDs[id] {
				sendError(w, "NotFound", fmt.Sprintf("Role ID %d does not exist", id), http.StatusBadRequest, nil)
				return
			}
		}
	}

	scope := core.Scope{ProjectID: req.ProjectID, EnvironmentID: req.EnvironmentID}
	if err := h.coreService.SetUserRoles(r.Context(), actor.UserID, userID, req.RoleIDs, scope, actor.ActorKind() == core.ActorTypeMachine); err != nil {
		log.Printf("Error setting roles for user %d: %v", userID, err)
		if sendRoleScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to update user roles", http.StatusInternalServerError, nil)
		}
		return
	}

	roles, err := h.coreService.GetUserRolesByID(r.Context(), userID)
	if err != nil {
		log.Printf("Error fetching updated roles for user %d: %v", userID, err)
		sendError(w, "InternalError", "Roles updated but failed to retrieve updated list", http.StatusInternalServerError, nil)
		return
	}

	apiRoles := make([]apiRole, 0, len(roles))
	for _, role := range roles {
		apiRoles = append(apiRoles, apiRole{ID: role.ID, Name: role.Name})
	}
	sendSuccess(w, map[string]any{"roles": apiRoles}, "Roles updated successfully")
}
