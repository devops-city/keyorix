// local_access_activity.go — last-secret-access timestamps per user, for
// dormant-access detection in the access review. For the remote equivalent see
// remote_access_activity.go (server-side only).
package store

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// accessActivityEventTypes are the audit event types that count as "using" access
// to a project's secrets (so a grant whose principal never triggers one is dormant).
//
// Every secret read — whether the reader is the owner or a share recipient — is
// audited generically as "secret.read" (see LogSecretReadWithProject); there is
// currently no separate event type for a share-sourced read, so only "secret.read"
// is listed here for reads. A prior "shared_secret_accessed" entry was removed
// (#418): the writer that would have produced it was dead code with no caller
// other than its own unit test, so the event never actually occurred and this list
// never matched it in practice.
//
// "secret.created" / "secret.updated" / "secret.rotated" (LogSecretCreatedWithProject
// / LogSecretUpdatedWithProject / LogSecretRotatedWithProject, internal/core/audit.go)
// are also included (#424): a plain secrets.write-tier grant (create/update/rotate,
// no read) exists to enable exactly these actions — e.g. a CI/CD pipeline operator
// or a secret-provisioning admin who writes secrets but never reads their values
// back. Before this, such a holder's genuinely-active grant was misclassified as
// dormant purely because "read" wasn't part of their workflow.
//
// Deliberately NOT included: "secret.deleted". Holding secrets.delete/admin makes a
// role admin-tier (see roleIsAdminTier, internal/core/access_review.go) and its
// grant is instead assessed against secretsDeletionActivityEventTypes below —
// folding "secret.deleted" into this plain-tier list would let an admin-tier
// grant's destructive action satisfy the WRONG activity check for
// countDormantRoleGrants' per-grant-tier split (#258).
//
// "secret.versions_listed" (listing a secret's version history, AUDIT-UX-2) is
// included on the read tier: it needs secrets.read but is deliberately not a
// "secret.read" (no value is disclosed), so without it (and "secret.metadata_read",
// the by-name metadata lookup, AUDIT-UX-3, for the same reason) a grant used only to browse
// version history would be reported dormant.
var accessActivityEventTypes = []string{
	"secret.read", "secret.versions_listed", "secret.metadata_read", "secret.created", "secret.updated", "secret.rotated",
}

// secretReadActivityEventTypes / secretWriteActivityEventTypes split
// accessActivityEventTypes along the two permissions that actually gate these
// actions (secrets.read vs secrets.write — create/update/rotate are ALL gated by
// the single secrets.write permission, see auth_bootstrap.go's permission
// catalog), so a plain-tier grant's dormancy can be credited against the
// SPECIFIC permission its own bundle confers (#487 round 112), the same
// per-permission narrowing roleManagementActivityEventTypes/
// secretsDeletionActivityEventTypes already apply one tier up. Before this
// split, a read-only grant and a separate write-only grant held by the same
// user in the same project masked each other via the single combined
// accessActivityEventTypes/LastUserSecretActivity bucket: exercising either
// permission satisfied BOTH grants' dormancy check, identical in shape to the
// admin-tier masking #487/#801 already closed.
var secretReadActivityEventTypes = []string{"secret.read", "secret.versions_listed", "secret.metadata_read"}
var secretWriteActivityEventTypes = []string{"secret.created", "secret.updated", "secret.rotated"}

// roleManagementActivityEventTypes are the audit event types that count as
// exercising a role-management (roles.assign) capability, one of the two
// admin-tier activity buckets behind dormant-role-grant detection (#258, narrowed
// per-permission by #487). Deliberately a short, high-confidence list restricted to
// event types that reliably carry project_id in practice: granting or revoking a
// role is the signature action a role-management permission (e.g. project_admin's
// roles.assign) exists to enable.
//
// Deliberately NOT included: role.created/updated/deleted and permission.assigned/
// removed are role-DEFINITION changes, not scoped to a project (global, scope-less
// in the audit trail — see writeRBACAudit), so they can't be attributed to any one
// project's dormancy check; group.member_added/removed are likewise not
// project-scoped (group membership isn't itself project-specific). This is a
// deliberate approximation, not an exhaustive "every admin action" list — see
// countDormantRoleGrants for how it's used and its documented limits.
var roleManagementActivityEventTypes = []string{
	"role.assigned", "role.removed", "role.group_assigned", "role.group_removed",
}

// secretsDeletionActivityEventTypes are the audit event types that count as
// exercising the secrets.delete/secrets.admin capability, the other admin-tier
// activity bucket (#258/#487): "secret.deleted", written with project context via
// LogSecretDeletedWithProject, is the destructive action a secrets.delete-tier role
// confers beyond plain read/write.
var secretsDeletionActivityEventTypes = []string{"secret.deleted"}

// lastActivityQuery is the one statement behind every LastUser*Activity lookup (a
// builder so the plan tests can EXPLAIN exactly what runs).
func lastActivityQuery(db *gorm.DB, projectID uint, eventTypes []string, since time.Time) *gorm.DB {
	return db.
		Table("audit_events").
		Select("user_id, event_time").
		Where("project_id = ?", projectID).
		// The window: event_time >= since, with since clamped to the hard maximum
		// lookback. Next to project_id = ? this is a range on the existing
		// idx_audit_events_project_event_time, so the rows read are the window's, not
		// the table's. event_time is always stored in UTC (AuditEvent.BeforeSave).
		Where("event_time >= ?", storage.ClampActivitySince(time.Now(), since)).
		Where("event_type IN ?", eventTypes).
		// A refused attempt (success=false, e.g. a refused secret.read, #3273) is
		// not use of the grant; NULL is a legacy row that predates the column.
		Where("success IS NULL OR success = ?", true).
		Where("user_id IS NOT NULL").
		Order("event_time DESC")
}

// lastUserActivityByEventTypes is the shared query behind the LastUser*Activity
// lookups: the most recent matching-event time per user in the project, read from
// audit_events, over the window starting at `since` (the recertification period,
// clamped to storage.ActivityLookbackMaxDays; see lastActivityQuery).
//
// It selects the typed event_time column ordered newest-first and keeps the first
// row seen per user (rather than SQL MAX(), whose result is an untyped string that
// SQLite can't scan into time.Time). There is deliberately no LIMIT: rows are
// deduplicated per user in Go, so a LIMIT would return the N newest events across
// ALL users and could drop every quiet user from the result. The bound is the time
// window instead (the G44 decision, RECERT-BOUND-1): "last activity" means within
// the review period, so a user with no event in the window is absent from the map,
// i.e. "no activity within the last N days", never "no activity ever".
func (ls *LocalStorage) lastUserActivityByEventTypes(ctx context.Context, projectID uint, eventTypes []string, since time.Time) (map[uint]time.Time, error) {
	type row struct {
		UserID    uint
		EventTime time.Time
	}
	var rows []row
	err := lastActivityQuery(ls.db.WithContext(ctx), projectID, eventTypes, since).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	out := make(map[uint]time.Time)
	for _, r := range rows {
		if r.UserID == 0 {
			continue
		}
		if _, seen := out[r.UserID]; !seen { // first seen = latest (DESC order)
			out[r.UserID] = r.EventTime
		}
	}
	return out, nil
}

// LastUserSecretActivity returns the most recent secret-access time per user in the
// project, read from audit_events (where the read events carry user_id + project_id).
func (ls *LocalStorage) LastUserSecretActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	return ls.lastUserActivityByEventTypes(ctx, projectID, accessActivityEventTypes, since)
}

// LastUserRoleManagementActivity returns the most recent time, per user, that they
// performed a role-management action (granting/revoking a role or group-role) in
// the project. See roleManagementActivityEventTypes for exactly which events count.
func (ls *LocalStorage) LastUserRoleManagementActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	return ls.lastUserActivityByEventTypes(ctx, projectID, roleManagementActivityEventTypes, since)
}

// LastUserSecretDeletionActivity returns the most recent time, per user, that they
// deleted a secret in the project. See secretsDeletionActivityEventTypes for
// exactly which events count.
func (ls *LocalStorage) LastUserSecretDeletionActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	return ls.lastUserActivityByEventTypes(ctx, projectID, secretsDeletionActivityEventTypes, since)
}

// LastUserSecretReadActivity returns the most recent secret.read time per user in
// the project — the secrets.read half of plain-tier dormant-role-grant detection
// (#487 round 112). See secretReadActivityEventTypes.
func (ls *LocalStorage) LastUserSecretReadActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	return ls.lastUserActivityByEventTypes(ctx, projectID, secretReadActivityEventTypes, since)
}

// LastUserSecretWriteActivity returns the most recent
// secret.created/updated/rotated time per user in the project — the
// secrets.write half of plain-tier dormant-role-grant detection (#487 round
// 112). See secretWriteActivityEventTypes.
func (ls *LocalStorage) LastUserSecretWriteActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	return ls.lastUserActivityByEventTypes(ctx, projectID, secretWriteActivityEventTypes, since)
}
