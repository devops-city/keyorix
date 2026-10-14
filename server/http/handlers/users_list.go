// users_list.go — ListUsers and SearchUsers handlers.
//
// Handles GET /api/v1/users (paginated + filtered) and GET /api/v1/users/search.
// For CRUD operations see users_crud.go.
package handlers

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// inactiveUserWindow defines how long without a login marks a user "inactive".
// Matches the dashboard's 30-day inactive-users signal.
const inactiveUserWindow = 30 * 24 * time.Hour

// maxListPage caps the page number on offset-paginated list endpoints, so a very large
// page can't force an enormous OFFSET table scan on each request (deep-pagination DoS).
const maxListPage = 10000

// ListUsers serves user list from core.
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 23, suppress go:S3776
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	page := 1
	pageSize := 20
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			// Clamp the page so a very large value can't force a huge OFFSET scan (DoS).
			if p > maxListPage {
				p = maxListPage
			}
			page = p
		}
	}
	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	filter := &storage.UserFilter{Page: page, PageSize: pageSize}
	if s := strings.TrimSpace(r.URL.Query().Get("search")); s != "" {
		filter.Search = &s
	}
	if u := strings.TrimSpace(r.URL.Query().Get("username")); u != "" {
		filter.Username = &u
	}
	if e := strings.TrimSpace(r.URL.Query().Get("email")); e != "" {
		filter.Email = &e
	}
	if a := r.URL.Query().Get("is_active"); a != "" {
		v := a == "true" || a == "1"
		filter.IsActive = &v
	}
	if d := r.URL.Query().Get("include_deleted"); d == "true" || d == "1" {
		filter.IncludeDeleted = true
	}
	// ?filter=inactive — users with no login in the last 30 days (incl. never).
	if r.URL.Query().Get("filter") == "inactive" {
		cutoff := time.Now().UTC().Add(-inactiveUserWindow)
		filter.InactiveSince = &cutoff
	}

	users, total, err := h.coreService.ListUsers(r.Context(), filter)
	if err != nil {
		log.Printf("Error listing users: %v", err)
		sendError(w, "InternalError", "Failed to list users", http.StatusInternalServerError, nil)
		return
	}

	out := make([]map[string]any, 0, len(users))
	ids := make([]uint, 0, len(users))
	for _, u := range users {
		out = append(out, userToAPIResponse(u))
		ids = append(ids, u.ID)
	}
	h.attachProjectCounts(r.Context(), out, ids)
	totalPages := int64(0)
	if pageSize > 0 {
		totalPages = (total + int64(pageSize) - 1) / int64(pageSize)
	}
	sendSuccess(w, map[string]any{
		"users":       out,
		"page":        page,
		"page_size":   pageSize,
		"total":       total,
		"total_pages": totalPages,
	}, "")
}

// SearchUsers handles GET /api/v1/users/search?q=<query>
func (h *UserHandler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		sendError(w, "BadRequest", "query parameter 'q' is required", http.StatusBadRequest, nil)
		return
	}

	filter := &storage.UserFilter{Search: &q, Page: 1, PageSize: 10}
	users, _, err := h.coreService.ListUsers(r.Context(), filter)
	if err != nil {
		log.Printf("Error searching users: %v", err)
		sendError(w, "InternalError", "Failed to search users", http.StatusInternalServerError, nil)
		return
	}

	type userResult struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	results := make([]userResult, 0, len(users))
	for _, u := range users {
		results = append(results, userResult{ID: u.ID, Username: u.Username, Email: u.Email})
	}
	sendSuccess(w, map[string]any{"users": results}, "")
}

// attachProjectCounts merges each user's project-membership tallies
// (project_count = non-revoked total, active_project_count = active) into the
// already-built response maps via one grouped query. Best-effort: on error the
// counts default to zero so the fields are always present (ADR-025).
func (h *UserHandler) attachProjectCounts(ctx context.Context, resp []map[string]any, ids []uint) {
	var counts map[uint]storage.MembershipCounts
	if len(ids) > 0 {
		counts = h.projectCountsRecovered(ctx, ids)
	}
	for _, m := range resp {
		id, _ := m["id"].(uint)
		c := counts[id]
		m["project_count"] = c.Total
		m["active_project_count"] = c.Active
	}
}

// projectCountsRecovered is attachProjectCounts' ProjectMembershipCounts call,
// isolated so a panic there (not just a returned error, already handled below)
// can't take down a ListUsers/SearchUsers response whose primary query already
// succeeded. Same best-effort-enrichment-must-not-mask-success shape as the
// gRPC UserService sibling this mirrors (docs/findings/2026-10-02-FINDING-grpc-
// createuser-usertoproto-projectcounts-panic-masks-commit.md's "check fix
// siblings" note) — lower severity here (a read-only list, nothing committed
// to misreport as failed), but the same gap, so fixed alongside it.
func (h *UserHandler) projectCountsRecovered(ctx context.Context, ids []uint) map[uint]storage.MembershipCounts {
	var counts map[uint]storage.MembershipCounts
	besteffort.Run(ctx, "http.UserHandler.projectCountsRecovered", func() error {
		c, err := h.coreService.ProjectMembershipCounts(ctx, ids)
		if err != nil {
			return err
		}
		counts = c
		return nil
	})
	return counts
}

// staleAccountStates are the account states it makes sense to surface as "stuck":
// an admin provisioned the account but the user never finished (ADR-025).
var staleAccountStates = map[string]bool{
	core.AccountPendingFirstLogin:     true,
	core.AccountPasswordResetRequired: true,
}

// StaleAccounts serves GET /api/v1/users/stale?state=pending_first_login&days=7 —
// users that have sat in a restricted state longer than the window (ADR-025).
func (h *UserHandler) StaleAccounts(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		state = core.AccountPendingFirstLogin
	}
	if !staleAccountStates[state] {
		sendError(w, "InvalidParameter", "Unsupported state (want pending_first_login or password_reset_required)", http.StatusBadRequest, nil)
		return
	}

	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n >= 0 {
			days = n
		}
	}

	users, err := h.coreService.StaleAccounts(r.Context(), state, time.Duration(days)*24*time.Hour)
	if err != nil {
		log.Printf("Error listing stale accounts: %v", err)
		sendError(w, "InternalError", "Failed to list stale accounts", http.StatusInternalServerError, nil)
		return
	}

	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, userToAPIResponse(u))
	}
	sendSuccess(w, map[string]any{"users": out, "state": state, "days": days}, "")
}
