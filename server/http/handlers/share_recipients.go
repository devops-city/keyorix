package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SearchShareRecipients handles GET /api/v1/projects/{id}/share-recipients
// (?q=&page=&page_size=): the active members of the project the caller could share a
// secret with. The route gate requires secrets.write at the project's scope;
// core.SearchShareRecipients adds the membership rule and decides whether emails are
// shown.
func (h *ShareHandler) SearchShareRecipients(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil || projectID == 0 {
		h.sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))

	result, err := h.coreService.SearchShareRecipients(r.Context(), core.ShareRecipientSearchRequest{
		ActorType: userCtx.ActorKind(),
		ActorID:   userCtx.PrincipalID(),
		ProjectID: uint(projectID),
		Query:     strings.TrimSpace(q.Get("q")),
		Page:      page,
		PageSize:  pageSize,
	})
	if err != nil {
		if reason, ok := core.ShareRefusalMessage(err); ok {
			h.sendError(w, "Forbidden", reason, http.StatusForbidden, nil)
			return
		}
		log.Printf("Error searching share recipients in project %d: %v", projectID, err)
		h.sendError(w, "InternalError", "Failed to search share recipients", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, result, "")
}
