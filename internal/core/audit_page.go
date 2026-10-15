// audit_page.go — ListAuditPage: one page of the newest-first audit list, shared
// by GET /audit/logs, GET /audit/search and gRPC AuditService.GetAuditLogs
// (docs/specs/audit-list-keyset.md §3).
//
// A page is either the offset/limit page old clients ask for, bounded to the
// newest AuditOffsetCap rows, or a keyset page after an opaque cursor. Every
// page that has a successor carries next_cursor. The total is the capped count
// unless the caller asks for the exact one.
package core

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AuditOffsetCap is the deepest row an offset/page request can reach. Deeper
// pages go through the cursor, whose cost does not grow with depth.
const AuditOffsetCap = storage.AuditCountCap

// AuditOffsetCapMessage is the client-facing text of ErrAuditOffsetBeyondCap:
// fixed, and naming the way to page deeper.
const AuditOffsetCapMessage = "page × page_size reaches beyond the newest 10000 audit events; use cursor=<next_cursor> to page further"

// ErrAuditOffsetBeyondCap refuses an offset/page request past AuditOffsetCap.
var ErrAuditOffsetBeyondCap = errors.New(AuditOffsetCapMessage)

// ErrInvalidAuditCursor refuses a cursor that is not one this server issued.
var ErrInvalidAuditCursor = errors.New("invalid cursor")

const auditCursorVersion = "v1"

// EncodeAuditCursor is the opaque cursor positioned after e. It carries the
// row's event_time to the nanosecond, exactly as the database returned it, so
// the keyset comparison matches the stored value on both dialects.
func EncodeAuditCursor(e *models.AuditEvent) string {
	raw := auditCursorVersion + "." + strconv.FormatInt(e.EventTime.UnixNano(), 10) + "." + strconv.FormatUint(uint64(e.ID), 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeAuditCursor parses a cursor from EncodeAuditCursor. It has no
// authority: it only bounds where a page starts inside a result set the caller
// may already read, so it is not signed, only strictly parsed.
func DecodeAuditCursor(s string) (*storage.AuditCursor, error) {
	if len(s) > 64 {
		return nil, ErrInvalidAuditCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidAuditCursor
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 || parts[0] != auditCursorVersion {
		return nil, ErrInvalidAuditCursor
	}
	ns, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, ErrInvalidAuditCursor
	}
	id, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil || id == 0 {
		return nil, ErrInvalidAuditCursor
	}
	return &storage.AuditCursor{EventTime: time.Unix(0, ns).UTC(), ID: uint(id)}, nil
}

// AuditPageRequest selects one page. Filter carries the predicates only; its
// paging, cursor and count fields are set here.
type AuditPageRequest struct {
	Filter       storage.AuditFilter
	Offset       int
	Limit        int
	Cursor       string
	IncludeTotal bool
}

// AuditPage is one page of events in (event_time DESC, id DESC) order.
type AuditPage struct {
	Events []*models.AuditEvent
	// HasTotal is false on a cursor page without IncludeTotal: no count ran.
	HasTotal bool
	// Total is exact when TotalExact; otherwise it is AuditOffsetCap and more
	// rows match.
	Total      int64
	TotalExact bool
	// NextCursor positions the next page; "" when this page is the last.
	NextCursor string
}

// ListAuditPage reads one page of the audit list. Errors ErrInvalidAuditCursor
// and ErrAuditOffsetBeyondCap are the caller's (400); anything else is a
// storage error.
func (k *KeyorixCore) ListAuditPage(ctx context.Context, req AuditPageRequest) (*AuditPage, error) {
	if req.Limit <= 0 {
		return nil, fmt.Errorf("ListAuditPage: limit must be positive")
	}
	// No page is wider than the cap, so neither Limit+1 below nor the offset
	// check can overflow.
	if req.Limit > AuditOffsetCap {
		return nil, ErrAuditOffsetBeyondCap
	}
	f := req.Filter
	f.Ascending = false
	f.Page = 0

	if req.Cursor != "" {
		cur, err := DecodeAuditCursor(req.Cursor)
		if err != nil {
			return nil, err
		}
		f.Before = cur
		// One extra row tells whether a further page exists.
		f.PageSize = req.Limit + 1
		f.Count = storage.AuditCountNone
		if req.IncludeTotal {
			f.Count = storage.AuditCountExact
		}
		events, total, err := k.storage.GetAuditLogs(ctx, &f)
		if err != nil {
			return nil, err
		}
		page := &AuditPage{Events: events}
		if len(events) > req.Limit {
			page.Events = events[:req.Limit]
			page.NextCursor = EncodeAuditCursor(page.Events[req.Limit-1])
		}
		if req.IncludeTotal {
			page.HasTotal, page.Total, page.TotalExact = true, total, true
		}
		return page, nil
	}

	// Offset > Cap-Limit, not Offset+Limit > Cap: the sum wraps negative for
	// an offset near math.MaxInt and would pass.
	if req.Offset < 0 || req.Offset > AuditOffsetCap-req.Limit {
		return nil, ErrAuditOffsetBeyondCap
	}
	f.Before = nil
	f.PageSize = req.Limit
	f.Page = req.Offset/req.Limit + 1
	f.Count = storage.AuditCountCapped
	if req.IncludeTotal {
		f.Count = storage.AuditCountExact
	}
	events, total, err := k.storage.GetAuditLogs(ctx, &f)
	if err != nil {
		return nil, err
	}
	page := &AuditPage{Events: events, HasTotal: true, Total: total, TotalExact: true}
	if !req.IncludeTotal && total > AuditOffsetCap {
		page.Total, page.TotalExact = AuditOffsetCap, false
	}
	start := int64((f.Page - 1) * req.Limit)
	more := !page.TotalExact || start+int64(len(events)) < total
	if more && len(events) > 0 {
		page.NextCursor = EncodeAuditCursor(events[len(events)-1])
	}
	return page, nil
}
