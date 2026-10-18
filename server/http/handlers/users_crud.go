// users_crud.go — CreateUser, GetUser, UpdateUser, DeleteUser, RestoreUser handlers.
//
// Handles core user lifecycle operations.
// For list/search see users_list.go.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// CreateUser handles POST /api/v1/users
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	var body struct {
		Username    string `json:"username" validate:"required,min=3,max=50"`
		Email       string `json:"email" validate:"required,email"`
		DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
		// Password is optional when DeliverSetupLink is set — the user sets their own
		// password via the setup link (ADR-028) instead of the admin choosing one.
		Password string `json:"password" validate:"omitempty,min=8"`
		IsActive *bool  `json:"is_active,omitempty"`
		// DeliverSetupLink provisions an account_setup link instead of an admin-set
		// password: the account is created in pending_first_login state and a setup
		// link is delivered (or returned for out-of-band relay).
		DeliverSetupLink bool `json:"deliver_setup_link,omitempty"`
		// GenerateOneTimePassword provisions a server-generated initial password instead
		// of an admin-set one or a setup link: the account is created in
		// password_reset_required state and the password is returned once for the admin
		// to relay out-of-band (ADR-028 Part E). The user must change it on first login.
		GenerateOneTimePassword bool `json:"generate_one_time_password,omitempty"`
		// Atomic provisioning (ADR-028): an optional system role override and a set
		// of project-scoped role assignments, applied with the create in one
		// transaction. Supported on the admin-set-password path only.
		Role               string                  `json:"role,omitempty"`
		ProjectAssignments []projectAssignmentBody `json:"project_assignments,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.CreateUserRequest{
		Username:    body.Username,
		Email:       body.Email,
		DisplayName: body.DisplayName,
		Password:    body.Password,
		IsActive:    body.IsActive,
	}

	// The three credential modes are mutually exclusive: admin-set password, setup
	// link, or generated one-time password.
	if body.DeliverSetupLink && body.GenerateOneTimePassword {
		sendError(w, "ValidationError", "Choose either deliver_setup_link or generate_one_time_password, not both", http.StatusBadRequest, nil)
		return
	}

	// Atomic role/project assignments are supported only on the admin-set-password
	// path for now (the setup-link / one-time-password paths create the account in
	// a restricted state before the user finishes setup).
	hasAssignments := body.Role != "" || len(body.ProjectAssignments) > 0
	if hasAssignments && (body.DeliverSetupLink || body.GenerateOneTimePassword) {
		sendError(w, "ValidationError", "role/project_assignments are only supported with an admin-set password", http.StatusBadRequest, nil)
		return
	}

	// One-time-password path (ADR-028 Part E): server generates the initial password,
	// returns it once for out-of-band relay, and forces a change on first login.
	if body.GenerateOneTimePassword {
		h.createUserWithOTP(w, r, req, userCtx.UserID)
		return
	}
	if body.DeliverSetupLink {
		h.createUserWithSetupLink(w, r, req, userCtx.UserID)
		return
	}
	h.createUserClassic(w, r, req, userCtx, body.Password, body.Role, body.ProjectAssignments)
}

type projectAssignmentBody struct {
	ProjectID uint   `json:"project_id"`
	Role      string `json:"role"`
}

func (h *UserHandler) createUserWithOTP(w http.ResponseWriter, r *http.Request, req *core.CreateUserRequest, actorID uint) {
	created, otp, err := h.coreService.CreateUserWithOneTimePassword(r.Context(), req, actorID)
	if err != nil {
		log.Printf("Error creating user with one-time password: %v", err)
		if errors.Is(err, core.ErrUserAlreadyExists) {
			sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
			return
		}
		if strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) {
			sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
			return
		}
		sendError(w, "InternalError", "Failed to create user", http.StatusInternalServerError, nil)
		return
	}
	sendCreated(w, map[string]any{
		"user":              userToAPIResponse(created),
		"one_time_password": otp,
	}, i18n.T("SuccessUserCreated", nil))
}

func (h *UserHandler) createUserWithSetupLink(w http.ResponseWriter, r *http.Request, req *core.CreateUserRequest, actorID uint) {
	created, prov, err := h.coreService.CreateUserWithSetupLink(r.Context(), req, actorID)
	if err != nil {
		log.Printf("Error creating user with setup link: %v", err)
		if errors.Is(err, core.ErrUserAlreadyExists) {
			sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
			return
		}
		if errors.Is(err, core.ErrSetupBaseURLRequired) {
			sendError(w, "ConfigError", err.Error(), http.StatusBadRequest, nil)
			return
		}
		if strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) {
			sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
			return
		}
		sendError(w, "InternalError", "Failed to create user", http.StatusInternalServerError, nil)
		return
	}
	sendCreated(w, map[string]any{
		"user":       userToAPIResponse(created),
		"setup_link": prov,
	}, i18n.T("SuccessUserCreated", nil))
}

func (h *UserHandler) createUserClassic(w http.ResponseWriter, r *http.Request, req *core.CreateUserRequest, userCtx *middleware.UserContext, password, role string, projAssignments []projectAssignmentBody) {
	if password == "" {
		sendError(w, "ValidationError", "Password is required unless deliver_setup_link or generate_one_time_password is set", http.StatusBadRequest, nil)
		return
	}
	if role != "" || len(projAssignments) > 0 {
		if err := h.authorizeUserCreationAssignments(r.Context(), userCtx, role, projAssignments); err != nil {
			sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
			return
		}
	}
	var created *models.User
	var err error
	if role != "" || len(projAssignments) > 0 {
		assignments := make([]core.ProjectAssignment, 0, len(projAssignments))
		for _, a := range projAssignments {
			assignments = append(assignments, core.ProjectAssignment{ProjectID: a.ProjectID, Role: a.Role})
		}
		ctx := r.Context()
		if userCtx.ActorKind() == core.ActorTypeMachine {
			// A genuine, directly-authenticated machine actor requesting this
			// grant as itself (not a /system proxy relay) -- tag ctx so
			// requireGranterHoldsRolePermissions checks ITS real permissions
			// instead of unconditionally refusing. See that function's doc.
			ctx = core.WithSelfMachineGranter(ctx, userCtx.PrincipalID())
		}
		created, err = h.coreService.CreateUserWithAssignments(ctx, req, role, assignments, userCtx.UserID, userCtx.ActorKind() == core.ActorTypeMachine)
	} else {
		// AUDIT-TX-2: core writes user.created in the create's transaction.
		created, err = h.coreService.CreateUserAudited(r.Context(), req, userCtx.UserID)
	}
	if err != nil {
		log.Printf("Error creating user: %v", err)
		switch {
		case errors.Is(err, core.ErrUserAlreadyExists):
			sendError(w, "ConflictError", errUserAlreadyExists, http.StatusConflict, nil)
		case strings.Contains(err.Error(), "cannot grant this role"):
			sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
		case strings.Contains(err.Error(), "unknown role"), strings.Contains(err.Error(), "unknown project"),
			strings.Contains(err.Error(), "each project assignment"),
			strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)):
			sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			sendError(w, "InternalError", errFailedCreateUser, http.StatusInternalServerError, nil)
		}
		return
	}
	sendCreated(w, userToAPIResponse(created), i18n.T("SuccessUserCreated", nil))
}

func (h *UserHandler) authorizeUserCreationAssignments(ctx context.Context, userCtx *middleware.UserContext, role string, projAssignments []projectAssignmentBody) error {
	if role != "" {
		if ok, aerr := h.coreService.AuthorizePrincipal(ctx, userCtx.ActorKind(), userCtx.PrincipalID(), "roles.assign", core.Scope{}); aerr != nil || !ok {
			return fmt.Errorf("you may not assign a system role")
		}
	}
	for _, a := range projAssignments {
		if ok, aerr := h.coreService.AuthorizePrincipal(ctx, userCtx.ActorKind(), userCtx.PrincipalID(), "roles.assign", core.Scope{ProjectID: a.ProjectID}); aerr != nil || !ok {
			return fmt.Errorf("you may not assign roles in the target project")
		}
	}
	return nil
}

// GetUser handles GET /api/v1/users/{id}
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	u, err := h.coreService.GetUser(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error getting user: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", errFailedGetUser, http.StatusInternalServerError, nil)
		return
	}
	resp := userToAPIResponse(u)
	h.attachProjectCounts(r.Context(), []map[string]any{resp}, []uint{u.ID})
	sendSuccess(w, resp, "")
}

// GetUserByEmail handles GET /api/v1/users/by-email?email=X — looks up a user by
// email address for callers (#503) that only have the email
// rather than the numeric ID. The route's permission gate (users.read, inherited
// from the /users group — the same gate GetUser-by-id uses) is the sole authz
// check, matching GetUser's model exactly; there is no additional per-record
// check to bypass. Deliberately mirrors GetUser's generic NotFound response
// (same status code, same static message) rather than a distinct shape, so a
// caller cannot use response differences to enumerate valid email addresses —
// a caller without users.read never reaches this handler at all (401/403 from
// the route middleware, identical for every email), and a caller WITH users.read
// can already enumerate every user (including email) via GET /users, so this
// route grants no new capability at that permission level.
func (h *UserHandler) GetUserByEmail(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		sendError(w, "InvalidParameter", "email is required", http.StatusBadRequest, nil)
		return
	}
	u, err := h.coreService.GetUserByEmail(r.Context(), email)
	if err != nil {
		log.Printf("Error getting user by email: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", errFailedGetUser, http.StatusInternalServerError, nil)
		return
	}
	resp := userToAPIResponse(u)
	h.attachProjectCounts(r.Context(), []map[string]any{resp}, []uint{u.ID})
	sendSuccess(w, resp, "")
}

// GetUserByUsername handles GET /api/v1/users/by-username?username=X (#505).
// Same gate and NotFound shape as GetUserByEmail: users.read (the group-wide gate above),
// generic NotFound on a miss so the route adds no username-enumeration surface
// beyond what GET /users already exposes to a users.read caller.
func (h *UserHandler) GetUserByUsername(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		sendError(w, "InvalidParameter", "username is required", http.StatusBadRequest, nil)
		return
	}
	u, err := h.coreService.GetUserByUsername(r.Context(), username)
	if err != nil {
		log.Printf("Error getting user by username: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", errFailedGetUser, http.StatusInternalServerError, nil)
		return
	}
	resp := userToAPIResponse(u)
	h.attachProjectCounts(r.Context(), []map[string]any{resp}, []uint{u.ID})
	sendSuccess(w, resp, "")
}

// GetUserByExternalID handles GET /api/v1/users/by-external-id?external_id=X
// (#505) — for SSO/SCIM identity resolution. Same gate and NotFound shape as
// GetUserByEmail/GetUserByUsername: users.read, generic NotFound on a miss.
func (h *UserHandler) GetUserByExternalID(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	externalID := strings.TrimSpace(r.URL.Query().Get("external_id"))
	if externalID == "" {
		sendError(w, "InvalidParameter", "external_id is required", http.StatusBadRequest, nil)
		return
	}
	u, err := h.coreService.GetUserByExternalID(r.Context(), externalID)
	if err != nil {
		log.Printf("Error getting user by external id: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", errFailedGetUser, http.StatusInternalServerError, nil)
		return
	}
	resp := userToAPIResponse(u)
	h.attachProjectCounts(r.Context(), []map[string]any{resp}, []uint{u.ID})
	sendSuccess(w, resp, "")
}

// UpdateUser handles PUT /api/v1/users/{id}
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}

	var body struct {
		Username    *string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
		Email       *string `json:"email,omitempty" validate:"omitempty,email"`
		DisplayName *string `json:"display_name,omitempty" validate:"omitempty,min=1,max=100"`
		Active      *bool   `json:"active,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.UpdateUserRequest{ID: uint(id), ActorID: userCtx.UserID}
	if body.Username != nil {
		req.Username = *body.Username
	}
	if body.Email != nil {
		req.Email = *body.Email
	}
	if body.DisplayName != nil {
		req.DisplayName = *body.DisplayName
	}
	if body.Active != nil {
		req.IsActive = body.Active
	}

	updated, err := h.coreService.UpdateUser(r.Context(), req)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		switch {
		case errors.Is(err, core.ErrInsufficientAdminAuthority):
			sendError(w, "PermissionDenied", clientSafe(err), http.StatusForbidden, nil)
		case errors.Is(err, core.ErrCannotActOnSelf):
			sendError(w, "BadRequest", "Cannot deactivate your own account", http.StatusBadRequest, nil)
		case strings.Contains(err.Error(), errNotFound):
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
		case errors.Is(err, core.ErrUserAlreadyExists):
			sendError(w, "ConflictError", errUserAlreadyExists, http.StatusConflict, nil)
		case strings.Contains(err.Error(), "last install administrator"):
			// Sibling of DeleteUser's identical case below: core.UpdateUser's
			// deactivating branch (IsActive=false) shares the SAME
			// guardLastAdminDeactivation core.DeleteUser calls, but until now
			// only DeleteUser's handler actually surfaced it -- this route fell
			// through to the generic 500 below, discarding the real reason.
			// Found during the ADR-108 PR 6 port (docs/cli-split-inventory.md
			// §7): the thin CLI's `user update --active=false` on the last
			// admin got a useless "Failed to update user" (HTTP 500) instead of
			// the readable refusal `user delete` on the same target already got.
			sendError(w, "Conflict", err.Error(), http.StatusConflict, nil)
		default:
			sendError(w, "InternalError", "Failed to update user", http.StatusInternalServerError, nil)
		}
		return
	}
	sendSuccess(w, userToAPIResponse(updated), i18n.T("SuccessUserUpdated", nil))
}

// DeleteUser handles DELETE /api/v1/users/{id}
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	// A global admin must not delete their own account and lock themselves out
	// of admin access. Mirrors accountStateAction's / RevokeSessions' self-action
	// guard; core's "last install administrator" check does not fire here since
	// other admins may still exist.
	if uint(id) == userCtx.UserID {
		sendError(w, "BadRequest", "Cannot delete your own account", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteUser(r.Context(), userCtx.UserID, uint(id)); err != nil {
		log.Printf("Error deleting user: %v", err)
		switch {
		case errors.Is(err, core.ErrInsufficientAdminAuthority):
			sendError(w, "PermissionDenied", clientSafe(err), http.StatusForbidden, nil)
		case strings.Contains(err.Error(), errNotFound):
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "last install administrator"):
			sendError(w, "Conflict", err.Error(), http.StatusConflict, nil)
		default:
			sendError(w, "InternalError", "Failed to delete user", http.StatusInternalServerError, nil)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RestoreUser handles POST /api/v1/users/{id}/restore
func (h *UserHandler) RestoreUser(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RestoreUser(r.Context(), userCtx.UserID, uint(id)); err != nil {
		log.Printf("Error restoring user: %v", err)
		switch {
		case errors.Is(err, core.ErrInsufficientAdminAuthority):
			sendError(w, "PermissionDenied", clientSafe(err), http.StatusForbidden, nil)
		case strings.Contains(err.Error(), errNotFound):
			sendError(w, "NotFound", "User not found or not soft-deleted", http.StatusNotFound, nil)
		default:
			sendError(w, "InternalError", "Failed to restore user", http.StatusInternalServerError, nil)
		}
		return
	}
	sendSuccess(w, nil, "User restored successfully")
}

// UnlockUser handles POST /api/v1/users/{id}/unlock — clears a user's login-lockout
// state (failed-attempt counter + active lock) after repeated failed logins.
func (h *UserHandler) UnlockUser(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.UnlockUser(r.Context(), userCtx.UserID, uint(id)); err != nil {
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to unlock user", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, nil, "User login lockout cleared")
}

// accountStateAction is the shared handler body for the admin account-state
// transitions (ADR-025). transition performs the state change.
func (h *UserHandler) accountStateAction(w http.ResponseWriter, r *http.Request, okMessage string, transition func(ctx context.Context, adminID, userID uint) error) {
	admin, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	// A global admin must not suspend / lock themselves out of admin access.
	if uint(id) == admin.UserID {
		sendError(w, "BadRequest", "Cannot change your own account state", http.StatusBadRequest, nil)
		return
	}
	if err := transition(r.Context(), admin.UserID, uint(id)); err != nil {
		status := http.StatusInternalServerError
		msg := clientSafe(err)
		switch {
		case errors.Is(err, core.ErrInsufficientAdminAuthority):
			status = http.StatusForbidden
		case strings.Contains(err.Error(), "last install administrator"):
			// SuspendUser calls guardLastAdminDeactivation (#G02) exactly as
			// UpdateUser and DeleteUser do, and both of those map this refusal to a
			// readable 409 (see their own switches above). This one did not, so the
			// same refusal arrived as a bare 500 "Failed to ..." — the identical
			// readability defect ADR-108 PR 6 fixed for UpdateUser, still open on
			// this route.
			//
			// It matters more here than on either sibling: UpdateUser and DeleteUser
			// both run requireAdminRankCeilingForTarget first, which (since #2496
			// unified admin resolution on the structural bypass flag) means any actor
			// who reaches their guard at all is itself a surviving global-admin
			// holder — so their 409 case cannot fire. accountStateAction applies NO
			// ceiling, only a self-action check, so THIS is the route on which the
			// last-admin refusal is actually reachable, and the one whose message a
			// real operator will see.
			//
			// The real reason is forwarded verbatim rather than through
			// clientSafe, matching UpdateUser's and DeleteUser's identical cases:
			// it is a deliberate, operator-facing policy refusal, not an internal
			// failure whose detail might leak anything — and clientSafe replaces it
			// with "an internal error occurred", which is precisely the useless
			// message ADR-108 PR 6 set out to remove.
			status = http.StatusConflict
			msg = err.Error()
		case strings.Contains(err.Error(), errNotFound):
			status = http.StatusNotFound
		default:
			log.Printf("account state transition error for user %d: %v", uint(id), err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, okMessage)
}

// SuspendUser handles POST /api/v1/users/{id}/suspend.
func (h *UserHandler) SuspendUser(w http.ResponseWriter, r *http.Request) {
	h.accountStateAction(w, r, "User suspended", h.coreService.SuspendUser)
}

// ReactivateUser handles POST /api/v1/users/{id}/reactivate.
func (h *UserHandler) ReactivateUser(w http.ResponseWriter, r *http.Request) {
	h.accountStateAction(w, r, "User reactivated", h.coreService.ReactivateUser)
}

// RequirePasswordReset handles POST /api/v1/users/{id}/require-password-reset.
func (h *UserHandler) RequirePasswordReset(w http.ResponseWriter, r *http.Request) {
	h.accountStateAction(w, r, "Password reset required", h.coreService.RequirePasswordReset)
}

// RevokeSessions handles POST /api/v1/users/{id}/revoke-sessions — admin force-logout:
// terminate all of the user's active sessions without changing their account state
// (e.g. suspected token/session theft). Scoped users.write is enforced by the router.
func (h *UserHandler) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	admin, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	// Mirrors accountStateAction's self-action guard: an admin must not be
	// able to revoke their own active sessions out from under themselves mid-request.
	if uint(id) == admin.UserID {
		sendError(w, "BadRequest", "Cannot revoke your own sessions", http.StatusBadRequest, nil)
		return
	}
	n, err := h.coreService.RevokeUserSessions(r.Context(), admin.UserID, uint(id))
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, core.ErrInsufficientAdminAuthority):
			status = http.StatusForbidden
		case strings.Contains(err.Error(), errNotFound):
			status = http.StatusNotFound
		default:
			log.Printf("revoke sessions error for user %d: %v", uint(id), err)
		}
		sendError(w, "Error", clientSafe(err), status, nil)
		return
	}
	sendSuccess(w, map[string]any{"revoked": n}, "Sessions revoked")
}

// ReissueOneTimePassword handles POST /api/v1/users/{id}/reissue-one-time-password
// (REISSUE-1): issue a new server-generated one-time password for an existing user.
// The password is returned once, in this response only, for the admin to relay out of
// band. Same gate as creating a user with a one-time password (users.write, enforced
// by the router); core adds the admin-rank ceiling and refuses the caller's own
// account (recover-admin is the way back for that) and SSO-only / suspended users.
func (h *UserHandler) ReissueOneTimePassword(w http.ResponseWriter, r *http.Request) {
	admin, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	res, err := h.coreService.ReissueOneTimePassword(r.Context(), admin.UserID, uint(id))
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInsufficientAdminAuthority):
			// clientSafe: the underlying error names the permission the target holds.
			sendError(w, "PermissionDenied", clientSafe(err), http.StatusForbidden, nil)
		case errors.Is(err, core.ErrCannotActOnSelf):
			sendError(w, "BadRequest", "Cannot reissue your own one-time password; use `keyorix-server admin recover-admin` to recover your own account", http.StatusBadRequest, nil)
		case errors.Is(err, core.ErrReissueExternalIdentity):
			sendError(w, "Conflict", core.ReissueExternalIdentityMessage, http.StatusConflict, nil)
		case errors.Is(err, core.ErrReissueAccountBlocked):
			sendError(w, "Conflict", core.ReissueAccountBlockedMessage, http.StatusConflict, nil)
		case errors.Is(err, storage.ErrUserNotFound):
			// The typed sentinel, not the "not found" substring: a storage fault is a
			// 500, never a 404 the admin would read as "no such user".
			sendError(w, "Error", errNotFound, http.StatusNotFound, nil)
		case strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)):
			sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			log.Printf("reissue one-time password error for user %d: %v", uint(id), err)
			sendError(w, "InternalError", "Failed to reissue the one-time password", http.StatusInternalServerError, nil)
		}
		return
	}
	// The body carries a credential: never cache it.
	w.Header().Set("Cache-Control", "no-store")
	sendSuccess(w, map[string]any{
		"user_id":           uint(id),
		"one_time_password": res,
	}, "One-time password reissued")
}

// ResendSetupLink handles POST /api/v1/users/{id}/resend-setup-link (ADR-028). It
// reissues the user's account_setup link (superseding any prior one) and re-delivers
// it, returning the delivery outcome — including the link itself in out-of-band mode.
func (h *UserHandler) ResendSetupLink(w http.ResponseWriter, r *http.Request) {
	admin, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	res, err := h.coreService.ResendAccountSetupLink(r.Context(), uint(id), admin.UserID)
	if err != nil {
		// S1 (CLI-split inventory #2012): the ceiling refusal must go through
		// clientSafe, not the raw msg this handler otherwise returns verbatim —
		// requireEqualOrGreaterAdminAuthority's underlying error names the
		// specific permission the target holds, which must not reach the client.
		if errors.Is(err, core.ErrInsufficientAdminAuthority) {
			sendError(w, "PermissionDenied", clientSafe(err), http.StatusForbidden, nil)
			return
		}
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "limit") || strings.Contains(msg, "wait"):
			status = http.StatusTooManyRequests
		case strings.Contains(msg, "base_url") || strings.Contains(msg, "suspended"):
			status = http.StatusBadRequest
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, res, "Setup link resent")
}
