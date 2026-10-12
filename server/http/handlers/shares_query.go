// shares_query.go — List and status query handlers.
//
// ListSecretShares, ListShares, ListSharedSecrets,
// GetSharingStatusWithIndicators, RemoveSelfFromShare.
// For share create/update/revoke see shares_crud.go.
package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListSecretShares handles GET /api/v1/secrets/{id}/shares
func (h *ShareHandler) ListSecretShares(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	// The router's scoped secrets.read gate is coarse RBAC, independent of
	// ownership. The share list (who has access, at what tier) is owner-only by
	// design — go through the permission-checked variant, matching gRPC's
	// ListSecretShares (share_service.go), so a caller with only project-scoped
	// secrets.read can't enumerate another owner's share graph.
	shares, err := h.coreService.ListSecretSharesWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		log.Printf("Error listing secret shares: %v", err)
		switch {
		case strings.Contains(err.Error(), errNotFound):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized"):
			h.sendError(w, "Forbidden", "Not authorized to view this secret's shares", http.StatusForbidden, nil)
		default:
			h.sendError(w, "InternalError", "Failed to list secret shares", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, map[string]interface{}{"shares": newShareRecordWireList(shares)}, "")
}

// ListShares handles GET /api/v1/shares — returns the caller's shares (received +
// owned) as a paginated list of enriched views (recipient/creator names resolved,
// expiry included). Supports ?secretId= and ?recipientType=user|group filters and
// ?page / ?pageSize paging. The response shape matches the web client's
// PaginatedResponse (camelCase), which consumes it without field mapping.
func (h *ShareHandler) ListShares(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	views, err := h.coreService.ListUserShareViews(r.Context(), userCtx.UserID)
	if err != nil {
		log.Printf("Error listing shares: %v", err)
		if errors.Is(err, core.ErrShareListOverCap) {
			h.sendError(w, "ShareListOverCap", err.Error(), http.StatusUnprocessableEntity, nil)
			return
		}
		h.sendError(w, "InternalError", "Failed to list shares", http.StatusInternalServerError, nil)
		return
	}
	// #G17: ShareView only carries SecretID, so resolve each share's owning
	// project in one batched lookup before applying the aggregate MFA check —
	// mirrors the gRPC-side ListUserShares fix in the same finding.
	if !h.shareViewsMFAAllowed(w, r, views) {
		return
	}

	h.sendShareViewPage(w, r, views)
}

// ListOwnedShares handles GET /api/v1/shares/owned — the owner-scoped list behind the
// Sharing Management page for a caller without global secrets.read (SHARE-3): only the
// shares the caller created, on secrets in projects they are a member of now
// (core.ListOwnedShareViews). Same filters, paging and response shape as ListShares.
// The route gate (RequirePermissionInAnyScope) refuses a caller with no secrets.read
// anywhere; core refuses machine identities. Both refusals carry
// core.OwnedShareListDeniedMessage. Like ListShares, a read: no audit event.
func (h *ShareHandler) ListOwnedShares(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	views, err := h.coreService.ListOwnedShareViews(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID())
	if err != nil {
		if reason, ok := core.ShareRefusalMessage(err); ok {
			h.sendError(w, "Forbidden", reason, http.StatusForbidden, nil)
			return
		}
		log.Printf("Error listing owned shares: %v", err)
		if errors.Is(err, core.ErrShareListOverCap) {
			h.sendError(w, "ShareListOverCap", err.Error(), http.StatusUnprocessableEntity, nil)
			return
		}
		h.sendError(w, "InternalError", "Failed to list shares", http.StatusInternalServerError, nil)
		return
	}
	if !h.shareViewsMFAAllowed(w, r, views) {
		return
	}
	h.sendShareViewPage(w, r, views)
}

// shareViewsMFAAllowed applies the aggregate per-project MFA check (#G17) to the
// projects views disclose. It writes the refusal and returns false when a project
// requires MFA the session lacks, or when those projects can't be resolved: an
// unverifiable policy denies (500), it never lets the list through.
func (h *ShareHandler) shareViewsMFAAllowed(w http.ResponseWriter, r *http.Request, views []core.ShareView) bool {
	projectIDs, err := h.shareViewProjectIDs(r.Context(), views)
	if err != nil {
		log.Printf("share list: failed to resolve project ids for the MFA check: %v", err)
		h.sendError(w, "InternalError", "Failed to list shares", http.StatusInternalServerError, nil)
		return false
	}
	if middleware.ProjectsMFABlocked(r, h.coreService, projectIDs) {
		middleware.WriteProjectMFARequired(w)
		return false
	}
	return true
}

// sendShareViewPage applies the optional ?secretId= and ?recipientType= filters and
// ?page / ?pageSize paging to views and writes the PaginatedResponse shape the web
// client consumes. Shared by ListShares and ListOwnedShares so the two lists cannot
// drift apart in shape.
func (h *ShareHandler) sendShareViewPage(w http.ResponseWriter, r *http.Request, views []core.ShareView) {
	// Optional server-side filters.
	if v := r.URL.Query().Get("secretId"); v != "" {
		if sid, perr := strconv.ParseUint(v, 10, 32); perr == nil {
			views = filterShareViews(views, func(s core.ShareView) bool { return s.SecretID == uint(sid) })
		}
	}
	if rt := r.URL.Query().Get("recipientType"); rt == "user" || rt == "group" {
		views = filterShareViews(views, func(s core.ShareView) bool { return s.RecipientType == rt })
	}

	page := atoiDefault(r.URL.Query().Get("page"), 1)
	pageSize := atoiDefault(r.URL.Query().Get("pageSize"), 20)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}

	total := len(views)
	totalPages := (total + pageSize - 1) / pageSize
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	pageItems := views[start:end]
	if pageItems == nil {
		pageItems = []core.ShareView{}
	}

	h.sendSuccess(w, map[string]interface{}{
		"data":       pageItems,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": totalPages,
	}, "")
}

// shareViewProjectIDs resolves the distinct projects the given share views'
// secrets belong to, via one batched GetSecretsByIDs lookup. A resolution failure
// is returned: treating it as an empty set made the MFA check fail open (review of
// #3018), matching the gRPC-side shareProjectIDs (share_service.go).
func (h *ShareHandler) shareViewProjectIDs(ctx context.Context, views []core.ShareView) ([]uint, error) {
	if len(views) == 0 {
		return nil, nil
	}
	secretIDSet := make(map[uint]bool, len(views))
	secretIDs := make([]uint, 0, len(views))
	for _, v := range views {
		if !secretIDSet[v.SecretID] {
			secretIDSet[v.SecretID] = true
			secretIDs = append(secretIDs, v.SecretID)
		}
	}
	secrets, err := h.coreService.Storage().GetSecretsByIDs(ctx, secretIDs)
	if err != nil {
		return nil, err
	}
	projectIDs := make([]uint, 0, len(secrets))
	for _, sec := range secrets {
		projectIDs = append(projectIDs, sec.ProjectID)
	}
	return projectIDs, nil
}

// filterShareViews returns the views satisfying keep.
func filterShareViews(views []core.ShareView, keep func(core.ShareView) bool) []core.ShareView {
	out := views[:0:0]
	for _, v := range views {
		if keep(v) {
			out = append(out, v)
		}
	}
	return out
}

// atoiDefault parses s as an int, returning def on empty/invalid input.
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// ListSharedSecrets handles GET /api/v1/shared-secrets
func (h *ShareHandler) ListSharedSecrets(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	secrets, err := h.coreService.ListSharedSecrets(r.Context(), userCtx.UserID)
	if err != nil {
		log.Printf("Error listing shared secrets: %v", err)
		h.sendError(w, "InternalError", "Failed to list shared secrets", http.StatusInternalServerError, nil)
		return
	}
	// #G17: each SecretNode already carries its own ProjectID — no extra lookup
	// needed. Mirrors the gRPC-side ListSharedSecrets fix in the same finding.
	projectIDs := make([]uint, 0, len(secrets))
	for _, sec := range secrets {
		projectIDs = append(projectIDs, sec.ProjectID)
	}
	if middleware.ProjectsMFABlocked(r, h.coreService, projectIDs) {
		middleware.WriteProjectMFARequired(w)
		return
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}

	h.sendSuccess(w, map[string]interface{}{"secrets": newSecretNodeWireList(secrets)}, "")
}

// ListSharedSecretsForUser handles GET /api/v1/users/{id}/shared-secrets — the
// secrets shared WITH the target user, for an arbitrary target rather than
// just the caller. Mirrors ListSharedSecrets (the caller's own shares) in
// response shape and MFA gating; the authorization is core.KeyorixCore's
// ListSharedSecretsForUser, which additionally enforces the S1 admin-rank
// ceiling for any target other than the caller and collapses "target doesn't
// exist" into the same refusal as a real ceiling refusal (no existence
// oracle). #2012 CLI-split inventory §6 secondary gap: `keyorix share
// shared-secrets --user-id N` had no REST route to reach for a target other
// than the caller before this.
func (h *ShareHandler) ListSharedSecretsForUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	targetID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidUserID, http.StatusBadRequest, nil)
		return
	}

	secrets, err := h.coreService.ListSharedSecretsForUser(r.Context(), userCtx.UserID, uint(targetID))
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInsufficientAdminAuthority):
			h.sendError(w, "PermissionDenied", clientSafe(err), http.StatusForbidden, nil)
		default:
			log.Printf("Error listing shared secrets for user: %v", err)
			h.sendError(w, "InternalError", "Failed to list shared secrets", http.StatusInternalServerError, nil)
		}
		return
	}
	// #G17-style: each SecretNode already carries its own ProjectID — no extra
	// lookup needed. Mirrors ListSharedSecrets' own MFA gate.
	projectIDs := make([]uint, 0, len(secrets))
	for _, sec := range secrets {
		projectIDs = append(projectIDs, sec.ProjectID)
	}
	if middleware.ProjectsMFABlocked(r, h.coreService, projectIDs) {
		middleware.WriteProjectMFARequired(w)
		return
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}

	h.sendSuccess(w, map[string]interface{}{"secrets": newSecretNodeWireList(secrets)}, "")
}

// ListGroupSharedSecrets handles GET /api/v1/groups/{id}/shared-secrets — the live
// secrets currently shared with a group (the "what can this group reach" view).
func (h *ShareHandler) ListGroupSharedSecrets(w http.ResponseWriter, r *http.Request) {
	// #G10: this used to check only that the caller was authenticated and never passed
	// the caller's identity into the core call — the identical gap the core layer itself
	// had (ListGroupSharedSecrets), independently rediscovered here.
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	groupID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}

	secrets, err := h.coreService.ListGroupSharedSecrets(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), uint(groupID))
	if err != nil {
		if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized") {
			h.sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
			return
		}
		log.Printf("Error listing group shared secrets: %v", err)
		h.sendError(w, "InternalError", "Failed to list group shared secrets", http.StatusInternalServerError, nil)
		return
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}

	h.sendSuccess(w, map[string]interface{}{"secrets": newSecretNodeWireList(secrets)}, "")
}

// ListGroupShares handles GET /api/v1/groups/{id}/shares — the share grants
// made TO a group (as opposed to ListGroupSharedSecrets' resolved-secrets
// view). #G66: previously only the embedded/local CLI path
// (`keyorix share group-shares`) could reach this data at all, silently
// ignoring a connected server; there was no HTTP endpoint to route it
// through. Mirrors ListGroupSharedSecrets' actor-threading exactly — #G10
// already made the core function self-authorize, so this can safely expose
// it without shipping a new unauthenticated-scope disclosure surface.
func (h *ShareHandler) ListGroupShares(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	groupID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}

	shares, err := h.coreService.ListGroupShares(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), uint(groupID))
	if err != nil {
		if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized") {
			h.sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
			return
		}
		log.Printf("Error listing group shares: %v", err)
		h.sendError(w, "InternalError", "Failed to list group shares", http.StatusInternalServerError, nil)
		return
	}
	if shares == nil {
		shares = []*models.ShareRecord{}
	}

	h.sendSuccess(w, map[string]interface{}{"shares": newShareRecordWireList(shares)}, "")
}

// GetSharingStatusWithIndicators handles GET /api/v1/secrets/{id}/sharing-status
func (h *ShareHandler) GetSharingStatusWithIndicators(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	status, err := h.coreService.GetSecretSharingStatusWithIndicators(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		log.Printf("Error getting sharing status: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get sharing status", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, status, "")
}

// RemoveSelfFromShare handles DELETE /api/v1/secrets/{id}/self-share
func (h *ShareHandler) RemoveSelfFromShare(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	if err := h.coreService.RemoveSelfFromShare(r.Context(), uint(id), userCtx.UserID); err != nil {
		log.Printf("Error removing self from share: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", "Share not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to remove self from share", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
