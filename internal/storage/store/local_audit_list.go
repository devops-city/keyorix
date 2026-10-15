// local_audit_list.go — GetAuditLogs: the one read path behind the audit list,
// search and export views (docs/specs/audit-list-keyset.md).
//
// Newest-first reads order by (event_time DESC, id DESC) and are served by the
// time indexes in AuditListIndexes; deep pages use a keyset cursor
// (AuditFilter.Before) instead of OFFSET. The total is exact, capped or skipped
// as the caller asks (AuditFilter.Count). Ascending reads (the SIEM export and
// internal chronological walks) go by primary key from a resolved start id.
package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GetAuditLogs retrieves audit events with optional filtering and pagination.
func (ls *LocalStorage) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	f := storage.AuditFilter{}
	if filter != nil {
		f = *filter
	}
	page, pageSize := 1, 20
	if f.Page > 1 {
		page = f.Page
	}
	if f.PageSize > 0 {
		pageSize = f.PageSize
	}
	pageSize = clampPageSize(pageSize)
	page = clampPage(page)

	base := func() *gorm.DB {
		return applyAuditFilter(ls.db.WithContext(ctx).Model(&models.AuditEvent{}), &f)
	}

	if f.Ascending {
		return ls.getAuditLogsAscending(ctx, base, &f, pageSize)
	}

	total, err := countAuditLogs(ls.db.WithContext(ctx), base, f.Count)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	q := base()
	if f.Before != nil {
		// (event_time, id) < (t, i) in the (event_time DESC, id DESC) order. The
		// redundant event_time <= t is what lets every time index range-scan
		// from the cursor (a row-value comparison is an index bound only on
		// (event_time, id) itself, not on the (x, event_time) composites).
		t := f.Before.EventTime.UTC()
		q = q.Where("event_time <= ? AND (event_time < ? OR id < ?)", t, t, f.Before.ID)
	} else {
		q = q.Offset((page - 1) * pageSize)
	}
	var events []*models.AuditEvent
	if err := q.Order("event_time DESC, id DESC").Limit(pageSize).Find(&events).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
	}
	return events, total, nil
}

// getAuditLogsAscending is the forward id cursor (SIEM export, chronological
// walks): id ASC from AfterID, no page offset. On the first page (no AfterID) a
// StartTime is resolved to the exact lowest id among rows at or after it, via
// the time index, so the read is a primary-key range instead of an id-order
// walk that filters every older row out. Later pages start from AfterID, which
// is already past those older rows; the event_time filter keeps both exact.
func (ls *LocalStorage) getAuditLogsAscending(ctx context.Context, base func() *gorm.DB, f *storage.AuditFilter, pageSize int) ([]*models.AuditEvent, int64, error) {
	total, err := countAuditLogs(ls.db.WithContext(ctx), base, f.Count)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}
	q := base()
	if f.StartTime != nil && f.AfterID == nil {
		startID, ok, err := ls.resolveAuditSinceID(ctx, f.StartTime.UTC())
		if err != nil {
			return nil, 0, fmt.Errorf("failed to resolve audit start time: %w", err)
		}
		if !ok {
			return []*models.AuditEvent{}, total, nil
		}
		q = q.Where("id >= ?", startID)
	}
	var events []*models.AuditEvent
	if err := q.Order("id ASC").Limit(pageSize).Find(&events).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
	}
	return events, total, nil
}

// resolveAuditSinceID returns the lowest id among ALL rows with event_time >=
// since (ok false when there are none): exact, whatever the skew between id
// order and event_time order (clock skew between replicas, a writer that waited
// long between stamping event_time and taking an id). It reads the
// (event_time, id) index from since to its end, so its cost grows with the rows
// at or after since, the same rows the export then returns.
func (ls *LocalStorage) resolveAuditSinceID(ctx context.Context, since time.Time) (uint, bool, error) {
	var minID []struct{ ID *uint }
	// MIN(id + 0), not MIN(id): Postgres rewrites a bare MIN(id) into "first
	// row of the primary key that passes the time filter", a walk from id 1
	// through every older row. The expression keeps it an aggregate over the
	// time-index range (pinned by TestAuditListQueries_UseTheirIndexes_Postgres).
	if err := ls.db.WithContext(ctx).Model(&models.AuditEvent{}).
		Select("MIN(id + 0) AS id").
		Where("event_time >= ?", since).
		Find(&minID).Error; err != nil {
		return 0, false, err
	}
	if len(minID) == 0 || minID[0].ID == nil {
		return 0, false, nil
	}
	return *minID[0].ID, true, nil
}

// countAuditLogs computes the total for mode. The capped count reads at most
// AuditCountCap+1 matching rows, so its cost is bounded by the cap, not by the
// table. It has no ORDER BY: any AuditCountCap+1 matches answer "more than the
// cap", and the planner is free to pick the filter's own index or a scan.
func countAuditLogs(db *gorm.DB, base func() *gorm.DB, mode storage.AuditCountMode) (int64, error) {
	var total int64
	switch mode {
	case storage.AuditCountNone:
		return 0, nil
	case storage.AuditCountCapped:
		sub := base().Select("1").Limit(storage.AuditCountCap + 1)
		err := db.Table("(?) AS capped", sub).Count(&total).Error
		return total, err
	default:
		err := base().Count(&total).Error
		return total, err
	}
}

// applyAuditFilter adds every AuditFilter predicate to q. Paging, ordering and
// the cursor are applied by the caller.
func applyAuditFilter(q *gorm.DB, f *storage.AuditFilter) *gorm.DB {
	if f.ProjectID != nil {
		q = q.Where("project_id = ?", *f.ProjectID)
	}
	if f.UserID != nil {
		q = q.Where("user_id = ?", *f.UserID)
	}
	if f.SecretID != nil {
		q = q.Where("secret_node_id = ?", *f.SecretID)
	}
	if f.Action != nil {
		q = q.Where("event_type = ?", *f.Action)
	}
	if len(f.Actions) > 0 {
		q = q.Where("event_type IN ?", f.Actions)
	}
	if f.StartTime != nil {
		// G81 (third recurrence, read side): normalize here rather than trusting
		// every caller to pass UTC, mirroring ListExpiredActiveLeases. event_time
		// is now always stored in UTC (models.AuditEvent.BeforeSave); a bound in
		// any other Location denotes the same instant but, on SQLite, compares as
		// a different string, silently mismatching rows that are actually in range.
		q = q.Where("event_time >= ?", f.StartTime.UTC())
	}
	if f.EndTime != nil {
		q = q.Where("event_time <= ?", f.EndTime.UTC())
	}
	if f.Success != nil {
		q = q.Where("success = ?", *f.Success)
	}
	if f.ActorType != nil {
		// The displayed kind, not the raw column (#2951): one rule shared with
		// the HTTP/gRPC views, storage.AuditActorKind.
		cond, args := storage.AuditActorKindWhere(*f.ActorType)
		q = q.Where(cond, args...)
	}
	if f.AfterID != nil {
		q = q.Where("id > ?", *f.AfterID)
	}
	if f.IPAddress != nil {
		q = q.Where("ip_address = ?", *f.IPAddress)
	}
	if f.ActorUsername != nil {
		// Resolve username → user_id via a subquery so we stay on the
		// audit_events table (no JOIN needed for the count query too).
		// escapeLIKE sanitises % and _ in the caller-supplied username so
		// a value like "admin%" doesn't turn into a wildcard prefix scan
		// covering all usernames (#r124 LIKE injection).
		// LOWER on both sides: LIKE is case-insensitive (ASCII) on SQLite but
		// case-sensitive on Postgres, so without it the same search returned
		// different rows per backend.
		cond := `user_id IN (SELECT id FROM users WHERE LOWER(username) LIKE LOWER(?) ESCAPE '\' AND deleted_at IS NULL)`
		if q.Dialector.Name() == "postgres" {
			// Same set, but ARRAY(subquery) is evaluated once (an InitPlan): Postgres
			// turns a plain IN (subquery) into a semi-join and then sorts the join
			// output, losing the newest-first index walk (pinned by
			// TestAuditListQueries_UseTheirIndexes_Postgres).
			cond = `user_id = ANY(ARRAY(SELECT id FROM users WHERE LOWER(username) LIKE LOWER(?) ESCAPE '\' AND deleted_at IS NULL))`
		}
		args := []any{"%" + escapeLIKE(*f.ActorUsername) + "%"}
		// Rows of kind "system" are displayed with actor "system" (#2951), so a
		// term that is part of "system" (ASCII case-insensitive, e.g. "sys") also
		// finds exactly those rows: the same rule as actor_type=system
		// (storage.AuditSystemActorWhere). A failed login has no user but is
		// kind "user", so it is not pulled in here.
		if term := strings.ToLower(*f.ActorUsername); term != "" && strings.Contains("system", term) {
			sysCond, sysArgs := storage.AuditSystemActorWhere()
			cond = "(" + cond + " OR " + sysCond + ")"
			args = append(args, sysArgs...)
		}
		q = q.Where(cond, args...)
	}
	if f.ResourceType != nil {
		// event_type is "resource_type.action" — match rows whose event_type
		// starts with "<resource_type>." so "secret" catches "secret.read",
		// "secret.created", etc. escapeLIKE prevents a caller-supplied
		// resource_type containing % or _ from matching unintended event types.
		q = q.Where(`event_type LIKE ? ESCAPE '\'`, escapeLIKE(*f.ResourceType)+".%")
	}
	return q
}
