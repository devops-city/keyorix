// groups_members.go — Group membership handlers and InitCoreHandlers.
//
// GetGroupMembers, AddGroupMember, RemoveGroupMember, InitCoreHandlers.
// For group CRUD see groups_handler.go.
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

// GetGroupMembers handles GET /api/v1/groups/{id}/members
func (h *GroupHandler) GetGroupMembers(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidGroupID, http.StatusBadRequest, nil)
		return
	}
	members, err := h.coreService.GetGroupMembers(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing group members: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "Group not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to list group members", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]any, 0, len(members))
	for _, u := range members {
		out = append(out, userToAPIResponse(u))
	}
	sendSuccess(w, map[string]any{"members": out, "total": len(out)}, "")
}

// AddGroupMember handles POST /api/v1/groups/{id}/members.
// Body: {"user_id": <uint>, "project_id": <uint>}
// project_id is optional; omitting it (or passing 0) creates a global membership.
func (h *GroupHandler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	groupID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidGroupID, http.StatusBadRequest, nil)
		return
	}
	var body struct {
		UserID    uint `json:"user_id"`
		ProjectID uint `json:"project_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if body.UserID == 0 {
		sendError(w, "ValidationError", "user_id is required", http.StatusBadRequest, nil)
		return
	}
	// #PM-006 sibling: actorIsMachine must be derived from the real actor kind, not
	// hardcoded false -- a machine-authenticated caller has UserID==0 (ADR-030), and
	// AddUserToGroup's outer skip-gate (`actorID != 0 || actorIsMachine`) treats a
	// hardcoded false the same as "no actor at all", silently skipping the entire
	// per-role authority-ceiling check (validateGroupJoinRoles) for every machine
	// caller reaching this route. isMachineActor(r) is the same helper every other
	// ceiling-sensitive handler in this package already uses for this purpose.
	ctx := r.Context()
	if userCtx.ActorKind() == core.ActorTypeMachine {
		// A genuine, directly-authenticated machine actor requesting this
		// membership as itself (not a /system proxy relay) -- tag ctx so
		// requireGranterHoldsRolePermissions checks ITS real permissions
		// instead of unconditionally refusing. See that function's doc.
		ctx = core.WithSelfMachineGranter(ctx, userCtx.PrincipalID())
	}
	if err := h.coreService.AddUserToGroup(ctx, userCtx.UserID, isMachineActor(r), body.UserID, uint(groupID), body.ProjectID); err != nil {
		log.Printf("Error adding group member: %v", err)
		switch {
		case strings.Contains(err.Error(), "not found"):
			sendError(w, "NotFound", "User or group not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "cannot grant this role"):
			sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
		default:
			sendError(w, "InternalError", "Failed to add group member", http.StatusInternalServerError, nil)
		}
		return
	}
	sendSuccess(w, map[string]any{"group_id": uint(groupID), "user_id": body.UserID, "project_id": body.ProjectID}, "Member added to group")
}

// RemoveGroupMember handles DELETE /api/v1/groups/{id}/members/{userId}.
// Optional query param: project_id (default 0 = global membership).
func (h *GroupHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	groupID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidGroupID, http.StatusBadRequest, nil)
		return
	}
	userID, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	var projectID uint
	if pidStr := r.URL.Query().Get("project_id"); pidStr != "" {
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			sendError(w, "InvalidParameter", "Invalid project_id", http.StatusBadRequest, nil)
			return
		}
		projectID = uint(pid)
	}
	if err := h.coreService.RemoveUserFromGroup(r.Context(), userCtx.UserID, uint(userID), uint(groupID), projectID); err != nil {
		log.Printf("Error removing group member: %v", err)
		if strings.Contains(err.Error(), "refusing to remove the last member") {
			sendError(w, "Conflict", err.Error(), http.StatusConflict, nil)
			return
		}
		sendError(w, "InternalError", "Failed to remove group member", http.StatusInternalServerError, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// InitCoreHandlers wires user and group HTTP handlers to the application core.
// Returns the same instances used by package-level user handlers (ListUsers, etc.).
func InitCoreHandlers(cs *core.KeyorixCore) (*UserHandler, *GroupHandler, error) {
	uh, err := NewUserHandler(cs)
	if err != nil {
		return nil, nil, err
	}
	gh, err := NewGroupHandler(cs)
	if err != nil {
		return nil, nil, err
	}
	defaultUserHandler = uh
	return uh, gh, nil
}
