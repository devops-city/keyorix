// audit_search.go — SearchAuditLogs: a richer audit-log query surface that
// exposes every AuditFilter field (IP address, actor username, resource type,
// success flag, time range, pagination) behind a single typed request/response
// pair. It validates inputs (caps limit, rejects inverted time ranges) and
// delegates to the existing GetAuditLogs storage method so all storage
// backends benefit without duplication.
package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	// AuditSearchDefaultLimit is the default number of results returned when
	// the caller does not specify a Limit.
	AuditSearchDefaultLimit = 100
	// AuditSearchMaxLimit is the hard cap on results per call.
	AuditSearchMaxLimit = 1000
)

// AuditSearchRequest carries all supported filter dimensions for SearchAuditLogs.
// Zero / nil values mean "no filter" on that dimension.
type AuditSearchRequest struct {
	// ActorUsername filters events by a partial match on the actor's username.
	ActorUsername string
	// UserID filters events by the exact numeric user ID.
	UserID uint
	// ProjectID filters events to a specific project.
	ProjectID uint
	// ResourceType filters events by the resource kind embedded in event_type
	// (e.g. "secret" matches "secret.read", "secret.created", etc.).
	ResourceType string
	// ResourceID filters events about a specific resource (secret_node_id).
	ResourceID uint
	// Action filters events to an exact event_type value (e.g. "secret.read").
	Action string
	// IPAddress filters events by the exact originating IP.
	IPAddress string
	// Success filters events by outcome: nil = all, true = only successes,
	// false = only failures.
	Success *bool
	// Since is the inclusive start of the time range.
	Since time.Time
	// Until is the inclusive end of the time range.
	Until time.Time
	// Limit caps results (default 100, max 1000).
	Limit int
	// Offset controls pagination (0-based); Offset+Limit must stay within
	// AuditOffsetCap. Ignored when Cursor is set.
	Offset int
	// Cursor continues after a previous page's NextCursor.
	Cursor string
	// IncludeTotal asks for the exact total (a full COUNT over the filter).
	IncludeTotal bool
}

// AuditSearchResult is the typed response for SearchAuditLogs.
type AuditSearchResult struct {
	Events []*models.AuditEvent `json:"events"`
	// Total, TotalExact and HasTotal: see AuditPage.
	Total      int64  `json:"total"`
	TotalExact bool   `json:"total_exact"`
	HasTotal   bool   `json:"-"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// SearchAuditLogs executes a structured audit-log query against the storage
// layer. It validates Limit (capping at AuditSearchMaxLimit), rejects an
// Until that precedes Since, maps the typed request onto an AuditFilter, and
// reads one page through ListAuditPage (ErrInvalidAuditCursor and
// ErrAuditOffsetBeyondCap are returned unwrapped-comparable for a 400).
func (k *KeyorixCore) SearchAuditLogs(ctx context.Context, req AuditSearchRequest) (*AuditSearchResult, error) {
	// Validate and normalise limit.
	limit := req.Limit
	if limit <= 0 {
		limit = AuditSearchDefaultLimit
	}
	if limit > AuditSearchMaxLimit {
		limit = AuditSearchMaxLimit
	}

	// Reject an inverted time range — it would return zero results and is
	// almost certainly a caller mistake.
	if !req.Until.IsZero() && !req.Since.IsZero() && req.Until.Before(req.Since) {
		return nil, fmt.Errorf("until must not be before since")
	}

	page, err := k.ListAuditPage(ctx, AuditPageRequest{
		Filter:       *buildAuditFilter(req),
		Offset:       req.Offset,
		Limit:        limit,
		Cursor:       req.Cursor,
		IncludeTotal: req.IncludeTotal,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidAuditCursor) || errors.Is(err, ErrAuditOffsetBeyondCap) {
			return nil, err
		}
		return nil, fmt.Errorf("SearchAuditLogs: %w", err)
	}
	events := page.Events
	if events == nil {
		events = []*models.AuditEvent{}
	}
	return &AuditSearchResult{
		Events:     events,
		Total:      page.Total,
		TotalExact: page.TotalExact,
		HasTotal:   page.HasTotal,
		NextCursor: page.NextCursor,
	}, nil
}

// buildAuditFilter maps an AuditSearchRequest's predicates onto an
// AuditFilter (paging is ListAuditPage's).
func buildAuditFilter(req AuditSearchRequest) *storage.AuditFilter {
	filter := &storage.AuditFilter{}
	if req.ActorUsername != "" {
		filter.ActorUsername = &req.ActorUsername
	}
	if req.UserID != 0 {
		filter.UserID = &req.UserID
	}
	if req.ProjectID != 0 {
		filter.ProjectID = &req.ProjectID
	}
	if req.ResourceType != "" {
		filter.ResourceType = &req.ResourceType
	}
	if req.ResourceID != 0 {
		filter.SecretID = &req.ResourceID
	}
	if req.Action != "" {
		filter.Action = &req.Action
	}
	if req.IPAddress != "" {
		filter.IPAddress = &req.IPAddress
	}
	if req.Success != nil {
		filter.Success = req.Success
	}
	if !req.Since.IsZero() {
		filter.StartTime = &req.Since
	}
	if !req.Until.IsZero() {
		filter.EndTime = &req.Until
	}
	return filter
}
