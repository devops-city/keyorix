// audit_search.go — SearchAuditLogs HTTP handler.
//
// GET /api/v1/audit/search exposes the richer AuditSearchRequest filters
// (actor username partial match, IP address, resource type, success flag,
// RFC3339 time range, limit/offset) on top of the existing GET /audit/logs
// endpoint. It shares the same audit.read permission gate.
package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func parseQueryUint(q url.Values, key string) (uint, bool) {
	v := q.Get(key)
	if v == "" {
		return 0, false
	}
	u, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint(u), true
}

func parseQueryInt(q url.Values, key string) (int, bool) {
	v := q.Get(key)
	if v == "" {
		return 0, false
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return i, true
}

func parseQueryTime(q url.Values, key string) (time.Time, bool) {
	v := q.Get(key)
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func parseQueryBoolPtr(q url.Values, key string) *bool {
	switch q.Get(key) {
	case "true":
		t := true
		return &t
	case "false":
		f := false
		return &f
	default:
		return nil
	}
}

// errAuditSearchOffset refuses an offset that is not an integer or is negative.
var errAuditSearchOffset = errors.New("offset must be a non-negative integer")

// parseAuditSearchOffset reads offset: absent is 0; anything but an integer in
// [0, core.AuditOffsetCap) is refused here, so no out-of-range value reaches
// the core's offset+limit check (core.ListAuditPage re-checks it, overflow-safe).
func parseAuditSearchOffset(q url.Values) (int, error) {
	v := q.Get("offset")
	if v == "" {
		return 0, nil
	}
	o, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		var numErr *strconv.NumError
		if errors.As(err, &numErr) && errors.Is(numErr.Err, strconv.ErrRange) && !strings.HasPrefix(v, "-") {
			return 0, core.ErrAuditOffsetBeyondCap
		}
		return 0, errAuditSearchOffset
	}
	if o < 0 {
		return 0, errAuditSearchOffset
	}
	if o >= core.AuditOffsetCap {
		return 0, core.ErrAuditOffsetBeyondCap
	}
	return int(o), nil
}

// parseAuditSearchRequest extracts and coerces all query-string parameters for the
// audit search endpoint into a core.AuditSearchRequest. Its errors are the
// caller's (400).
func parseAuditSearchRequest(r *http.Request) (core.AuditSearchRequest, error) {
	q := r.URL.Query()
	req := core.AuditSearchRequest{
		ActorUsername: q.Get("actor"),
		Action:        q.Get("action"),
		ResourceType:  q.Get("resource_type"),
		IPAddress:     q.Get("ip"),
		Success:       parseQueryBoolPtr(q, "success"),
	}
	if uid, ok := parseQueryUint(q, "user_id"); ok {
		req.UserID = uid
	}
	if pid, ok := parseQueryUint(q, "project_id"); ok {
		req.ProjectID = pid
	}
	if rid, ok := parseQueryUint(q, "resource_id"); ok {
		req.ResourceID = rid
	}
	if t, ok := parseQueryTime(q, "since"); ok {
		req.Since = t
	}
	if t, ok := parseQueryTime(q, "until"); ok {
		req.Until = t
	}
	if l, ok := parseQueryInt(q, "limit"); ok {
		req.Limit = l
	}
	offset, err := parseAuditSearchOffset(q)
	if err != nil {
		return req, err
	}
	req.Offset = offset
	req.Cursor = q.Get("cursor")
	req.IncludeTotal = q.Get("include_total") == "true"
	return req, nil
}

// SearchAuditLogs handles GET /api/v1/audit/search.
//
// Supported query parameters:
//
//	actor        — partial username match
//	user_id      — exact numeric user ID
//	project_id   — exact numeric project ID
//	action       — exact event_type (e.g. secret.read)
//	resource_type — resource kind prefix (e.g. "secret")
//	resource_id  — exact secret_node_id
//	ip           — exact originating IP address
//	success      — "true" or "false"
//	since        — RFC3339 start of time range (inclusive)
//	until        — RFC3339 end of time range (inclusive)
//	limit        — max results (1–1000, default 100)
//	offset       — pagination offset (default 0; offset+limit ≤ core.AuditOffsetCap; 400 when not an integer in range)
//	cursor       — continue after a previous page's next_cursor (offset ignored)
//	include_total — "true" for the exact total (a full count)
func (h *AuditHandler) SearchAuditLogs(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	req, err := parseAuditSearchRequest(r)
	if err != nil {
		if !sendAuditPageError(w, err) {
			sendError(w, "InvalidParameter", err.Error(), http.StatusBadRequest, nil)
		}
		return
	}

	result, err := h.coreService.SearchAuditLogs(r.Context(), req)
	if err != nil {
		if sendAuditPageError(w, err) {
			return
		}
		sendError(w, "InternalServerError", "Failed to search audit logs", http.StatusInternalServerError, nil)
		return
	}

	// Same redaction as GetAuditLogs (both share the audit.read gate, router.go):
	// no IPAddress, no PrevHash/EntryHash, actor IDs resolved to usernames. This
	// used to send result.Events raw -- see
	// docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
	entries := h.toAuditLogEntries(r.Context(), result.Events)

	resp := map[string]any{
		"events":      entries,
		"next_cursor": nullableCursor(result.NextCursor),
	}
	if result.HasTotal {
		resp["total"] = result.Total
		resp["total_exact"] = result.TotalExact
	}
	sendSuccess(w, resp, "")
}
