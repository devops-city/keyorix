// users_handler.go — UserHandler struct, constructor, legacy dispatch layer.
//
// UserHandler methods are split across:
//   - users_list.go  — ListUsers, SearchUsers
//   - users_crud.go  — CreateUser, GetUser, UpdateUser, DeleteUser, RestoreUser
//
// Package-level functions (ListUsers, CreateUser, etc.) in this file dispatch to
// defaultUserHandler when wired, or to legacy stubs for test compatibility.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// UserHandler handles user HTTP requests (wired to core when InitCoreHandlers runs).
type UserHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

var defaultUserHandler *UserHandler

// NewUserHandler constructs a UserHandler.
func NewUserHandler(coreService *core.KeyorixCore) (*UserHandler, error) {
	return &UserHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}, nil
}

// --- Legacy shapes (used when defaultUserHandler is nil, e.g. rbac_test direct calls) ---

type legacyAPIUser struct {
	ID          uint   `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Active      bool   `json:"active"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type legacyCreateUserBody struct {
	Username    string `json:"username" validate:"required,min=3,max=50"`
	Email       string `json:"email" validate:"required,email"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
}

type legacyUpdateUserBody struct {
	Email       *string `json:"email,omitempty" validate:"omitempty,email"`
	DisplayName *string `json:"display_name,omitempty" validate:"omitempty,min=1,max=100"`
	Active      *bool   `json:"active,omitempty"`
}

func userToAPIResponse(u *models.User) map[string]interface{} {
	dn := u.DisplayName
	if dn == "" {
		dn = u.Username
	}
	out := map[string]interface{}{
		"id":            u.ID,
		"username":      u.Username,
		"email":         u.Email,
		"display_name":  dn,
		"active":        u.IsActive,
		"account_state": core.NormalizeAccountState(u.AccountState),
		// external_id (#505): the IdP-assigned SCIM/SSO identifier (empty for a
		// native account). The now-deleted RemoteStorage's GetUserByExternalID/
		// GetUserByEmail/GetUser decoded this exact field — without it on the wire,
		// every decoded user's ExternalID would have silently read back as "" under
		// storage.type: remote, which
		// defeated resolveSSOUser's (internal/core/sso.go) cross-provider-takeover
		// guard on the already-shipped email-fallback path, not just the new
		// by-external-id lookup.
		"external_id":   u.ExternalID,
		"created_at":    u.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":    u.UpdatedAt.UTC().Format(time.RFC3339),
		"last_login_at": nil,
		"deleted_at":    nil,
	}
	if u.LastLoginAt != nil {
		out["last_login_at"] = u.LastLoginAt.UTC().Format(time.RFC3339)
	}
	if u.DeletedAt.Valid {
		out["deleted_at"] = u.DeletedAt.Time.UTC().Format(time.RFC3339)
	}
	// Surface an ACTIVE per-account login lockout (ADR-040 hardening) so an admin can
	// see a locked-out account and clear it via POST /users/{id}/unlock. Only emitted
	// while the lock is in the future; an expired lock reads as unlocked.
	if u.LoginLockedUntil != nil && time.Now().Before(*u.LoginLockedUntil) {
		out["login_locked_until"] = u.LoginLockedUntil.UTC().Format(time.RFC3339)
	}
	// #500: also surface the raw lockout-accounting counters, not just the derived
	// "is currently locked" fact above. This endpoint is only reachable with the
	// users.read/users.write permission (server/http/router.go) — the same
	// admin-level trust boundary that already sees account_state, active, and (just
	// above) an active login_locked_until, and that already has UnlockUser authority
	// over this exact state; the self-service /auth/profile endpoint is a completely
	// separate handler (auth.go's userProfileMap) that never reaches this function, so
	// no lower-trust caller gains visibility here. Exposing these matters beyond mere
	// admin-UI completeness: under storage.type: remote, checkLockAndClearLoginFailures
	// (internal/core/login_lockout.go) reads this exact response (via LockUserForUpdate,
	// which is just GetUser over HTTP) to decide its "nothing to clear" fast path;
	// without these fields on the wire that path always read a false all-zero snapshot
	// and silently skipped even the operator-visible "lockout accounting is INERT"
	// warning whenever an account had accumulated (but not yet tripped) failures — the
	// "fail open" half of that design worked, but the "loudly" half silently didn't,
	// from this call path.
	out["failed_login_attempts"] = u.FailedLoginAttempts
	out["login_lockout_count"] = u.LoginLockoutCount
	out["last_failed_login_at"] = nil
	if u.LastFailedLoginAt != nil {
		out["last_failed_login_at"] = u.LastFailedLoginAt.UTC().Format(time.RFC3339)
	}
	// mfa_enabled (#524): this endpoint already surfaces the identical
	// admin-level lockout-accounting fields just above (users.read/users.write
	// trust boundary — not a lower-trust caller, and MFAEnabled is not
	// sensitive the way PasswordHash is). Historically (#524, since resolved by
	// RemoteStorage's full removal in #2162) this field also fixed a
	// storage.type: remote deployment: RemoteStorage's own GetUser had decoded
	// every user's MFAEnabled as the Go zero value (false) regardless of the
	// upstream's real state, silently breaking every internal/core/mfa.go
	// caller that branches on user.MFAEnabled.
	out["mfa_enabled"] = u.MFAEnabled
	return out
}

func listUsersLegacy(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	page := 1
	pageSize := 20
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}
	users := []legacyAPIUser{
		{ID: 1, Username: "admin", Email: testAdminEmail, DisplayName: testSysAdminRole, Active: true, CreatedAt: testTimestamp1, UpdatedAt: testTimestamp1},
		{ID: 2, Username: "user1", Email: "user1@keyorix.com", DisplayName: "Regular User", Active: true, CreatedAt: "2024-01-02T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z"},
	}
	sendSuccess(w, map[string]interface{}{
		"users": users, "page": page, "page_size": pageSize, "total": len(users), "total_pages": 1,
	}, "")
}

func createUserLegacy(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var req legacyCreateUserBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}
	u := legacyAPIUser{ID: 3, Username: req.Username, Email: req.Email, DisplayName: req.DisplayName, Active: true, CreatedAt: testTimestamp2, UpdatedAt: testTimestamp2}
	sendCreated(w, u, "User created successfully")
}

func getUserLegacy(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	if id == 1 {
		sendSuccess(w, legacyAPIUser{ID: 1, Username: "admin", Email: testAdminEmail, DisplayName: testSysAdminRole, Active: true, CreatedAt: testTimestamp1, UpdatedAt: testTimestamp1}, "")
		return
	}
	sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
}

func updateUserLegacy(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	var req legacyUpdateUserBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}
	u := legacyAPIUser{ID: uint(id), Username: "admin", Email: testAdminEmail, DisplayName: testSysAdminRole, Active: true, CreatedAt: testTimestamp1, UpdatedAt: testTimestamp2}
	if req.Email != nil {
		u.Email = *req.Email
	}
	if req.DisplayName != nil {
		u.DisplayName = *req.DisplayName
	}
	if req.Active != nil {
		u.Active = *req.Active
	}
	sendSuccess(w, u, "User updated successfully")
}

func deleteUserLegacy(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	if _, err := strconv.ParseUint(idStr, 10, 32); err != nil {
		sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Package-level dispatch functions ---

// SearchUsers handles GET /api/v1/users/search?q=<query>
func SearchUsers(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.SearchUsers(w, r)
}

// ListUsers handles GET /api/v1/users
func ListUsers(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		listUsersLegacy(w, r)
		return
	}
	defaultUserHandler.ListUsers(w, r)
}

// StaleAccounts handles GET /api/v1/users/stale (ADR-025).
func StaleAccounts(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.StaleAccounts(w, r)
}

// CreateUser handles POST /api/v1/users
func CreateUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		createUserLegacy(w, r)
		return
	}
	defaultUserHandler.CreateUser(w, r)
}

// GetUser handles GET /api/v1/users/{id}
func GetUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		getUserLegacy(w, r)
		return
	}
	defaultUserHandler.GetUser(w, r)
}

// GetUserByEmail handles GET /api/v1/users/by-email?email=X (#503).
func GetUserByEmail(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.GetUserByEmail(w, r)
}

// GetUserByUsername handles GET /api/v1/users/by-username?username=X (#505).
func GetUserByUsername(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.GetUserByUsername(w, r)
}

// GetUserByExternalID handles GET /api/v1/users/by-external-id?external_id=X (#505).
func GetUserByExternalID(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.GetUserByExternalID(w, r)
}

// UpdateUser handles PUT /api/v1/users/{id}
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		updateUserLegacy(w, r)
		return
	}
	defaultUserHandler.UpdateUser(w, r)
}

// DeleteUser handles DELETE /api/v1/users/{id}
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		deleteUserLegacy(w, r)
		return
	}
	defaultUserHandler.DeleteUser(w, r)
}

// RestoreUser handles POST /api/v1/users/{id}/restore
func RestoreUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.RestoreUser(w, r)
}

// UnlockUser handles POST /api/v1/users/{id}/unlock — clears login lockout.
func UnlockUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.UnlockUser(w, r)
}

// SuspendUser handles POST /api/v1/users/{id}/suspend (ADR-025).
func SuspendUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.SuspendUser(w, r)
}

// RevokeSessions handles POST /api/v1/users/{id}/revoke-sessions — admin force-logout.
func RevokeSessions(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.RevokeSessions(w, r)
}

// ReactivateUser handles POST /api/v1/users/{id}/reactivate (ADR-025).
func ReactivateUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.ReactivateUser(w, r)
}

// RequirePasswordReset handles POST /api/v1/users/{id}/require-password-reset (ADR-025).
func RequirePasswordReset(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.RequirePasswordReset(w, r)
}

// ResendSetupLink handles POST /api/v1/users/{id}/resend-setup-link (ADR-028).
func ResendSetupLink(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.ResendSetupLink(w, r)
}

// ReissueOneTimePassword handles POST /api/v1/users/{id}/reissue-one-time-password (REISSUE-1).
func ReissueOneTimePassword(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.ReissueOneTimePassword(w, r)
}
