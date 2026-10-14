// project_memberships.go — project membership lifecycle endpoints (ADR-022).
//
// These drive the onboarding state machine (invited → identity_verified →
// provisioned → active, revoked terminal), separate from the role-grant
// endpoints in project_members.go. All are project-scoped and gated by
// roles.assign at the project scope (so a project_admin can run onboarding).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// staleInviteThreshold is when an unaccepted invite is surfaced as stale (ADR-022).
const staleInviteThreshold = 7 * 24 * time.Hour

// ListProjectMemberships handles GET /api/v1/projects/{id}/memberships.
// With ?stale=true it returns only invited memberships older than 7 days.
func (h *CatalogHandler) ListProjectMemberships(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	if r.URL.Query().Get("stale") == "true" {
		all, err := h.coreService.StaleInvites(r.Context(), staleInviteThreshold)
		if err != nil {
			log.Printf("Error listing stale invites: %v", err)
			sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
			return
		}
		// StaleInvites is install-wide; narrow to this project for the endpoint.
		stale := make([]any, 0, len(all))
		for _, m := range all {
			if m.ProjectID == uint(id) {
				stale = append(stale, m)
			}
		}
		sendSuccess(w, map[string]any{"memberships": stale}, "")
		return
	}
	memberships, err := h.coreService.ListProjectMemberships(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing memberships for project %d: %v", id, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"memberships": memberships}, "")
}

// InviteMember handles POST /api/v1/projects/{id}/memberships.
func (h *CatalogHandler) InviteMember(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	// PM-008: this general-purpose, roles.assign-gated endpoint deliberately does
	// NOT accept idp_resolved from the request body. In ValidationModeIDP,
	// InviteMember starts a membership straight at `provisioned` (skipping
	// invited/identity_verified) when idpResolved is true — that's supposed to
	// be a guarantee that the identity was actually vouched for by the
	// configured IdP. Any project_admin holding roles.assign can call this
	// endpoint, so a client-supplied bool here would let them assert IdP
	// resolution for anyone, defeating the mode's purpose while leaving an
	// audit trail indistinguishable from a genuinely IdP-resolved invite. The
	// only trustworthy signal is the actual SSO/JIT-provisioning code path
	// (internal/core/sso.go) that validates the IdP's signed assertion itself —
	// that path, if and when it starts project onboarding, should call
	// core.InviteMember directly with a real server-derived idpResolved,
	// bypassing this HTTP endpoint entirely. A legacy client that still sends
	// "idp_resolved" in the JSON body is unaffected: the field decodes into
	// nothing and is silently ignored, same as any other unknown field.
	var body struct {
		UserID uint   `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.UserID == 0 || body.Role == "" {
		sendError(w, "ValidationError", "user_id and role are required", http.StatusBadRequest, nil)
		return
	}
	const idpResolvedNotAcceptedFromClient = false
	m, err := h.coreService.InviteMember(r.Context(), uint(id), body.UserID, body.Role, actor.UserID, machineID(r), idpResolvedNotAcceptedFromClient)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errDomainNotAllowed):
			status = http.StatusForbidden
		case strings.Contains(msg, "already has"):
			status = http.StatusConflict
		case strings.Contains(msg, "unknown role"), strings.Contains(msg, "required"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error inviting member to project %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendCreated(w, map[string]any{"membership": m}, "Member invited")
}

// TransitionMembership handles PUT /api/v1/projects/{id}/memberships/{membershipId}.
// Body: {"action": "verify" | "provision" | "activate" | "revoke"}.
func (h *CatalogHandler) TransitionMembership(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	membershipID, err := strconv.ParseUint(chi.URLParam(r, "membershipId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid membership ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	to, ok := membershipActionState(body.Action)
	if !ok {
		sendError(w, "ValidationError", "action must be verify, provision, activate, or revoke", http.StatusBadRequest, nil)
		return
	}
	ctx := r.Context()
	if actor.ActorKind() == core.ActorTypeMachine {
		// A genuine, directly-authenticated machine actor requesting this
		// transition as itself (not a /system proxy relay) -- tag ctx so
		// requireGranterHoldsRolePermissions checks ITS real permissions
		// instead of unconditionally refusing. See that function's doc.
		ctx = core.WithSelfMachineGranter(ctx, actor.PrincipalID())
	}
	m, err := h.coreService.TransitionMembership(ctx, uint(projectID), uint(membershipID), to, actor.UserID, actor.ActorKind() == core.ActorTypeMachine)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "cannot transition"):
			status = http.StatusConflict
		default:
			log.Printf("Error transitioning membership %d for project %d: %v", membershipID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, map[string]any{"membership": m}, "Membership updated")
}

// membershipActionState maps a request action verb to its target state.
func membershipActionState(action string) (string, bool) {
	switch action {
	case "verify":
		return core.MembershipIdentityVerified, true
	case "provision":
		return core.MembershipProvisioned, true
	case "activate":
		return core.MembershipActive, true
	case "revoke":
		return core.MembershipRevoked, true
	default:
		return "", false
	}
}
