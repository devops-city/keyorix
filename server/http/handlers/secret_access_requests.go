// secret_access_requests.go — HTTP surface for RequestSecretAccess /
// ApproveSecretAccessRequest / RejectSecretAccessRequest / WithdrawAccessRequest
// / GetSecretAccessRequest (internal/core/classification_gate.go): approval to
// read ONE restricted secret's value, distinct from the project-scoped
// /projects/{id}/access-requests family (invitations.go) this mirrors the shape
// of. None of the underlying core functions take a project ID (the project is
// always inferred from the secret or the request row itself), so unlike its
// project-scoped sibling this family is NOT nested under /projects/{id} —
// see docs/cli-split-inventory.md §6 GAP-1.
package handlers

import (
	"log"
	"net/http"
	"strings"
)

// CreateSecretAccessRequest handles POST /api/v1/secret-access-requests
// (self-service): body {"secret_id":..., "reason":...}, reason required.
//
// Anti-enumeration: GetSecretWithPermissionCheck is consulted first and ANY
// failure — the secret genuinely does not exist, or it exists but the caller
// cannot see it — maps to the SAME "Secret not found" 404, never branching
// into a distinct "forbidden" response the way GetSecret's own handler does.
// A restricted secret's very existence must not be inferable from this
// endpoint's response shape.
func (h *CatalogHandler) CreateSecretAccessRequest(w http.ResponseWriter, r *http.Request) {
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	var body struct {
		SecretID uint   `json:"secret_id"`
		Reason   string `json:"reason"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	if body.SecretID == 0 {
		sendError(w, "ValidationError", "secret_id is required", http.StatusBadRequest, nil)
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		sendError(w, "ValidationError", "reason is required", http.StatusBadRequest, nil)
		return
	}
	if _, err := h.coreService.GetSecretWithPermissionCheck(r.Context(), body.SecretID, actor.UserID); err != nil {
		sendError(w, "NotFound", errSecretNotFound, http.StatusNotFound, nil)
		return
	}
	req, err := h.coreService.RequestSecretAccess(r.Context(), body.SecretID, actor.UserID, body.Reason)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, "already have a pending"):
			status = http.StatusConflict
		case strings.Contains(msg, errNotFound), strings.Contains(msg, "required"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error creating secret access request for secret %d: %v", body.SecretID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendCreated(w, map[string]any{"access_request": req}, "Secret access requested")
}

// ListSecretAccessRequests handles GET /api/v1/secret-access-requests
// (self-service): returns the caller's own secret-scoped requests ("mine")
// plus, when the caller holds admin authority at the relevant project, the
// pending ones they may approve ("pending_approval") — ListSecretAccessRequestsForUser
// computes both, scoped per caller, so no separate permission gate is needed
// at the route level.
func (h *CatalogHandler) ListSecretAccessRequests(w http.ResponseWriter, r *http.Request) {
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	mine, pending, err := h.coreService.ListSecretAccessRequestsForUser(r.Context(), actor.UserID)
	if err != nil {
		log.Printf("Error listing secret access requests for user %d: %v", actor.UserID, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"mine": mine, "pending_approval": pending}, "")
}

// GetSecretAccessRequest handles GET /api/v1/secret-access-requests/{requestId}.
// core.GetSecretAccessRequest itself enforces visibility (requester or an
// admin at the request's project) and returns an identical "not found" for a
// nonexistent request, a project/role request ID, and a real secret-scoped
// request the caller may not see.
func (h *CatalogHandler) GetSecretAccessRequest(w http.ResponseWriter, r *http.Request) {
	reqID, ok := mustParseUintParam(w, r, "requestId", "InvalidParameter", errInvalidAccessRequestID)
	if !ok {
		return
	}
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	req, err := h.coreService.GetSecretAccessRequest(r.Context(), reqID, actor.UserID)
	if err != nil {
		sendError(w, "NotFound", "Access request not found", http.StatusNotFound, nil)
		return
	}
	sendSuccess(w, map[string]any{"access_request": req}, "")
}

// ResolveSecretAccessRequest handles PUT /api/v1/secret-access-requests/{requestId}:
// body {"action":"approve"|"reject", "reason":...}. Unlike the project/role
// family's ResolveAccessRequest, no granted_role/grant_ttl — a secret-scoped
// approval grants no role at all. Authority (admin at the request's own
// project, req.ProjectID — never a URL parameter, since this route family
// carries none) is enforced entirely inside
// ApproveSecretAccessRequest/RejectSecretAccessRequest; there is no coarser
// HTTP-layer permission gate to duplicate it, because roles.assign is not the
// bar the classification gate sets (classification_gate.go's own doc
// comment).
func (h *CatalogHandler) ResolveSecretAccessRequest(w http.ResponseWriter, r *http.Request) {
	reqID, ok := mustParseUintParam(w, r, "requestId", "InvalidParameter", errInvalidAccessRequestID)
	if !ok {
		return
	}
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	var body struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	// #1573: distinguishes one machine approver from another for reject's audit
	// attribution — ApproverID/ResolvedBy is 0 for every machine caller (ADR-030).
	var approverMachineID uint
	if actor.MachineIdentityID != nil {
		approverMachineID = *actor.MachineIdentityID
	}
	var resolveErr error
	switch body.Action {
	case "approve":
		_, resolveErr = h.coreService.ApproveSecretAccessRequest(r.Context(), reqID, actor.UserID)
	case "reject":
		_, resolveErr = h.coreService.RejectSecretAccessRequest(r.Context(), reqID, actor.UserID, approverMachineID, body.Reason)
	default:
		sendError(w, "ValidationError", "action must be approve or reject", http.StatusBadRequest, nil)
		return
	}
	if resolveErr != nil {
		status := http.StatusInternalServerError
		msg := resolveErr.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, errOnlyPending), strings.Contains(msg, "no longer pending"),
			strings.Contains(msg, "has expired"), strings.Contains(msg, "no longer exists"):
			status = http.StatusConflict
		// A requester approving their own request, or a caller lacking admin
		// authority at the request's project, is a business rule about who may
		// act, not a state conflict.
		case strings.Contains(msg, "cannot approve their own"), strings.Contains(msg, "admin authority is required"),
			strings.Contains(msg, "administrator"):
			status = http.StatusForbidden
		case strings.Contains(msg, "not a secret-scoped"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error resolving secret access request %d: %v", reqID, resolveErr)
			msg = clientSafe(resolveErr)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Access request "+body.Action+"d")
}

// WithdrawSecretAccessRequest handles POST
// /api/v1/secret-access-requests/{requestId}/withdraw (self-service): lets the
// requester cancel their own pending request. Reuses WithdrawAccessRequest
// unchanged — it is already generic over SecretID-scoped rows (#G14's
// identical "not found" for a nonexistent request and one belonging to
// someone else applies here too).
func (h *CatalogHandler) WithdrawSecretAccessRequest(w http.ResponseWriter, r *http.Request) {
	reqID, ok := mustParseUintParam(w, r, "requestId", "InvalidParameter", errInvalidAccessRequestID)
	if !ok {
		return
	}
	actor, ok := mustGetUser(w, r)
	if !ok {
		return
	}
	if err := h.coreService.WithdrawAccessRequest(r.Context(), reqID, actor.UserID); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, errOnlyPending):
			status = http.StatusConflict
		default:
			log.Printf("Error withdrawing secret access request %d: %v", reqID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Access request withdrawn")
}
