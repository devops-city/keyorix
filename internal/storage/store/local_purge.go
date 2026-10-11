// local_purge.go — retention purge of soft-deleted rows (ADR-032).
//
// Each method hard-deletes (Unscoped) rows whose deleted_at predates the cutoff,
// returning the count removed. The purge scheduler (main.go) drives these on an
// interval when enabled. Irreversible by design — the retention window is the
// only safety net.
package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) purgeDeletedBefore(ctx context.Context, model interface{}, before time.Time) (int64, error) {
	result := ls.db.WithContext(ctx).Unscoped().
		Where(sqlWhereDeletedBefore, before).
		Delete(model)
	if result.Error != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return result.RowsAffected, nil
}

// PurgeDeletedUsersBefore hard-deletes soft-deleted users past the retention window,
// together with every row that references them as a principal — role/group
// membership, shares they RECEIVED, personal access tokens, and sessions — in one
// transaction. None of those tables carry their own deleted_at, so a plain purge of
// only the users row (as every other purgeDeletedBefore call does) left them
// orphaned indefinitely: a stale UserRole/GroupRole grant referencing a purged ID
// that could collide with a future reused ID, a PAT/session row that (before the
// core.DeleteUser fix) may still be live, and a share the user received sitting
// unreachable but undestroyed. Returns the number of users purged.
//
// #276-sibling: like PurgeDeletedSecretsBefore, the eligible-ID list is gathered by a
// SELECT (Pluck) and the deletes run moments later — a window in which a concurrent
// RestoreUser can flip deleted_at back to NULL on one of those IDs. Deleting purely
// off the stale ID list would hard-delete that already-restored user (and cascade
// through its role grants, memberships, sessions and PATs) anyway, silently undoing a
// restore that already reported success. Every delete below therefore re-applies the
// same "deleted_at IS NOT NULL AND deleted_at < before" predicate the SELECT used,
// keyed on id — not just the ID list — so a user a restore raced out from under the
// purge is left alone.
func (ls *LocalStorage) PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error) { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	var purged int64
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if e := tx.Unscoped().Model(&models.User{}).
			Where(sqlWhereDeletedBefore, before).
			Pluck("id", &ids).Error; e != nil {
			return e
		}
		if len(ids) == 0 {
			return nil
		}
		// Re-scoped to still-deleted-and-eligible users only, via a subquery against
		// users' live deleted_at rather than the stale `ids` list, so a user restored
		// after the SELECT above is excluded from every delete below it. A fresh
		// subquery builder is used per reference since a *gorm.DB is stateful and must
		// not be shared across clauses.
		stillEligible := func() *gorm.DB {
			return tx.Unscoped().Model(&models.User{}).
				Select("id").
				Where(sqlWhereIDsDeletedBefore, ids, before)
		}
		if e := tx.Where(sqlWhereUserIDIn, stillEligible()).Delete(&models.UserRole{}).Error; e != nil {
			return e
		}
		if e := tx.Where(sqlWhereUserIDIn, stillEligible()).Delete(&models.UserGroup{}).Error; e != nil {
			return e
		}
		// ShareRecord carries its own DeletedAt (soft-delete) — Unscoped so this is a
		// true hard delete, not another soft-deleted orphan nothing else purges.
		// #store-purge-2: matches BOTH sides — recipient_id (shares the purged user
		// RECEIVED) and owner_id (shares the purged user GRANTED to someone else).
		// Only checking recipient_id left a share a purged user created for a
		// still-active recipient fully live and functional indefinitely: the
		// recipient's access grant survives (RecipientID still resolves to a real
		// user) with no owner left to attribute, audit, or ever explicitly revoke
		// it, and no account-lifecycle or access-review tooling keyed off active
		// users would ever surface it for re-certification.
		if e := tx.Unscoped().Where("(recipient_id IN (?) OR owner_id IN (?)) AND is_group = ?", stillEligible(), stillEligible(), false).Delete(&models.ShareRecord{}).Error; e != nil {
			return e
		}
		if e := tx.Where(sqlWhereUserIDIn, stillEligible()).Delete(&models.PersonalAccessToken{}).Error; e != nil {
			return e
		}
		// #G13: SecretACL (the grantee side, user_id) has no deleted_at of its own
		// and no FK/cascade — a plain purge of just the users row left these grants
		// permanently orphaned, referencing a user ID nothing else destroys.
		if e := tx.Where(sqlWhereUserIDIn, stillEligible()).Delete(&models.SecretACL{}).Error; e != nil {
			return e
		}
		if e := tx.Where("user_id IN (?) OR impersonated_by IN (?)", stillEligible(), stillEligible()).Delete(&models.Session{}).Error; e != nil {
			return e
		}
		ru := tx.Unscoped().
			Where(sqlWhereIDsDeletedBefore, ids, before).
			Delete(&models.User{})
		if ru.Error != nil {
			return ru.Error
		}
		purged = ru.RowsAffected
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return purged, nil
}

// PurgeDeletedProjectsBefore hard-deletes soft-deleted projects past the retention
// window, together with the project-scoped role grants (UserRole/GroupRole) that
// reference them, in one transaction. UserRole/GroupRole are plain join rows keyed
// by ProjectID with no FK/cascade of their own — a plain purge of just the projects
// row left these grants behind, permanently orphaned (referencing a project ID that
// no longer exists anywhere, since IDs are never reused): dead weight in every "who
// has access" report and role/access-review listing forever after. Global-scope
// grants (ProjectID 0) are untouched — they aren't project-scoped.
//
// #276-sibling: like PurgeDeletedSecretsBefore, the eligible-ID list is gathered by a
// SELECT (Pluck) and the deletes run moments later — a window in which a concurrent
// RestoreProject can flip deleted_at back to NULL on one of those IDs (and cascade the
// restore onto its environments/secrets, see LocalStorage.RestoreProject). Deleting
// purely off the stale ID list would hard-delete that already-restored project anyway,
// silently undoing a restore that already reported success — and orphaning the very
// environments/secrets RestoreProject just brought back, which would reference a
// project ID that no longer exists. Every delete below therefore re-applies the same
// "deleted_at IS NOT NULL AND deleted_at < before" predicate the SELECT used, keyed on
// id — not just the ID list — so a project a restore raced out from under the purge is
// left alone.
func (ls *LocalStorage) PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error) {
	var purged int64
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if e := tx.Unscoped().Model(&models.Project{}).
			Where(sqlWhereDeletedBefore, before).
			Pluck("id", &ids).Error; e != nil {
			return e
		}
		if len(ids) == 0 {
			return nil
		}
		// Re-scoped to still-deleted-and-eligible projects only, via a subquery against
		// projects' live deleted_at rather than the stale `ids` list, so a project
		// restored after the SELECT above is excluded from every delete below it. A
		// fresh subquery builder is used per reference since a *gorm.DB is stateful and
		// must not be shared across clauses.
		stillEligible := func() *gorm.DB {
			return tx.Unscoped().Model(&models.Project{}).
				Select("id").
				Where(sqlWhereIDsDeletedBefore, ids, before)
		}
		if e := tx.Where("project_id IN (?)", stillEligible()).Delete(&models.UserRole{}).Error; e != nil {
			return e
		}
		if e := tx.Where("project_id IN (?)", stillEligible()).Delete(&models.GroupRole{}).Error; e != nil {
			return e
		}
		rp := tx.Unscoped().
			Where(sqlWhereIDsDeletedBefore, ids, before).
			Delete(&models.Project{})
		if rp.Error != nil {
			return rp.Error
		}
		purged = rp.RowsAffected
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return purged, nil
}

// PurgeDeletedEnvironmentsBefore is NOT #276-sibling-affected despite RestoreEnvironment
// existing: unlike the Pluck-then-delete-by-ID-list shape used above, purgeDeletedBefore
// issues a single DELETE ... WHERE deleted_at IS NOT NULL AND deleted_at < before
// statement — there is no separate SELECT and no stale ID list for a concurrent restore
// to race against, so the predicate is necessarily evaluated against live row state at
// delete time already.
func (ls *LocalStorage) PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error) {
	return ls.purgeDeletedBefore(ctx, &models.Environment{}, before)
}

// secretPurgeCandidate is the projection of a soft-deleted secret the purge decides on.
type secretPurgeCandidate struct {
	ID                    uint
	DeletedAt             gorm.DeletedAt
	RetentionOverrideDays int
	PurgeAt               *time.Time
}

// eligible reports whether the purge may hard-delete this secret at now. This is THE
// purge rule, and the one invariant it exists for: a secret is never removed before
// the purge date that was shown for it (RETENTION-1; see the table test around the
// boundary in local_purge_purgeat_test.go).
//
//   - Frozen purge_at (every secret soft-deleted since the column exists, whenever the
//     store knew the window): purge strictly after it, and nothing else is consulted.
//     `before` is derived from the CURRENT soft_delete.retention_days, so honouring it
//     here would let an operator who shortens the window pull a purge earlier than the
//     date already displayed. A window changed after deletion therefore affects only
//     later deletions, in both directions (it never defers a displayed date either).
//   - No purge_at (soft-deleted before the column existed, or by a store never told the
//     window): the legacy rule, which is also the date core.SecretPurgeAt shows for such
//     a row, evaluated against the current configuration - its per-secret override, else
//     the caller's cutoff (`before` = now - retention_days, computed in UTC by the
//     scheduler so it equals models.PurgeAtFor exactly).
func (c secretPurgeCandidate) eligible(now, before time.Time) bool {
	if !c.DeletedAt.Valid {
		return false
	}
	if c.PurgeAt != nil {
		return now.After(c.PurgeAt.UTC())
	}
	cutoff := before
	if c.RetentionOverrideDays > 0 {
		cutoff = now.AddDate(0, 0, -c.RetentionOverrideDays)
	}
	return c.DeletedAt.Time.Before(cutoff)
}

// PurgeDeletedSecretsBefore hard-deletes soft-deleted secrets past the retention window,
// together with their version rows AND the dependency-graph edges incident to them, in one
// transaction. The secret VALUE lives in secret_versions.encrypted_value, which has no
// deleted_at and no FK cascade to secret_nodes — so deleting only the node row (as a plain
// purge would) left the ciphertext in the database indefinitely, still decryptable (key
// rotation even re-encrypts orphaned version rows), defeating the "irreversible by design"
// retention / GDPR-erasure guarantee. A SecretDependency edge likewise has no soft-delete of
// its own (ADR-052) — it lives and dies with its endpoints — so purging a secret without
// removing its edges would leave rows referencing a hard-deleted secret. Returns the number
// of secret_nodes purged (version and edge rows are not counted).
//
// #276: the eligible-ID list is gathered by a SELECT (Pluck) and the deletes run moments
// later — a window in which a concurrent RestoreSecret can flip deleted_at back to NULL on
// one of those IDs. Deleting purely off the stale ID list would hard-delete that
// already-restored secret anyway, silently undoing a restore that already reported success
// to its caller. Every delete below therefore re-applies the same
// "deleted_at IS NOT NULL AND deleted_at < before" predicate the SELECT used, keyed on id —
// not just the ID list — so a row a restore raced out from under the purge is left alone.
func (ls *LocalStorage) PurgeDeletedSecretsBefore(ctx context.Context, before time.Time) (int64, error) {
	var purged int64
	// #G43: SetSecretRetentionOverride's per-secret window was never consulted here —
	// every secret purged strictly on the deployment-wide cutoff regardless of a set
	// override. The candidate set below is intentionally wider than sqlWhereDeletedBefore
	// (every still-soft-deleted secret, not just ones past the global cutoff) so a
	// SHORTER override (secret should be gone sooner than the global window) is caught
	// too, not just a longer one; GetEffectiveRetentionDays (the same helper
	// SetSecretRetentionOverride's own doc points callers to) then decides per row
	// whether `before` (no override) or `now - override days` (override set) applies.
	// now is a single wall-clock read for the whole sweep, not per-row, so every
	// candidate in this run is judged against the same instant.
	now := time.Now().UTC()
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var candidates []secretPurgeCandidate
		if e := tx.Unscoped().Model(&models.SecretNode{}).
			Select("id, deleted_at, retention_override_days, purge_at").
			Where("deleted_at IS NOT NULL").
			Find(&candidates).Error; e != nil {
			return e
		}
		var ids []uint
		for _, cand := range candidates {
			if cand.eligible(now, before) {
				ids = append(ids, cand.ID)
			}
		}
		if len(ids) == 0 {
			return nil
		}
		// Destroy the ciphertext-bearing versions and the incident dependency edges
		// first, then the node rows — each re-scoped to still-deleted-and-eligible
		// secrets only, via a subquery against secret_nodes' live deleted_at rather
		// than the stale `ids` list, so a secret restored after the SELECT above is
		// excluded from every delete below it. A fresh subquery builder is used per
		// reference since a *gorm.DB is stateful and must not be shared across clauses.
		// #G43: this re-check only re-asserts "still soft-deleted" (id IN ids AND
		// deleted_at IS NOT NULL), not the age predicate sqlWhereIDsDeletedBefore
		// re-asserts elsewhere — ids above was already computed per-secret against
		// GetEffectiveRetentionDays, which a blanket "< before" re-check would
		// silently undo for any secret whose override differs from the global window.
		stillEligible := func() *gorm.DB {
			return tx.Unscoped().Model(&models.SecretNode{}).
				Select("id").
				Where("id IN ? AND deleted_at IS NOT NULL", ids)
		}
		// #3085: every mutable row that references the secret or one of its
		// versions goes first (children before parents), so the purge leaves no
		// orphan for restore's dangling-reference check to refuse. audit_events
		// and the access_review_items snapshot are deliberately NOT here: they
		// are historical references (see local_purge_secret_refs.go).
		if e := purgeSecretReferences(tx, stillEligible); e != nil {
			return e
		}
		if e := tx.Where("secret_node_id IN (?)", stillEligible()).Delete(&models.SecretVersion{}).Error; e != nil {
			return e
		}
		if e := tx.Where("dependent_secret_id IN (?) OR depends_on_secret_id IN (?)", stillEligible(), stillEligible()).
			Delete(&models.SecretDependency{}).Error; e != nil {
			return e
		}
		// #G13: SecretACL grants ON the purged secret have no deleted_at/FK of
		// their own either — the same orphaning gap PurgeDeletedUsersBefore's
		// SecretACL cleanup closes for the grantee side, mirrored here for the
		// secret side.
		if e := tx.Where("secret_id IN (?)", stillEligible()).Delete(&models.SecretACL{}).Error; e != nil {
			return e
		}
		rn := tx.Unscoped().
			Where("id IN ? AND deleted_at IS NOT NULL", ids).
			Delete(&models.SecretNode{})
		if rn.Error != nil {
			return rn.Error
		}
		purged = rn.RowsAffected
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return purged, nil
}

// --- Data-retention purges (ISO A.5.33 / GDPR storage-limitation) ---
//
// These age out compliance records the application accumulates indefinitely.
// None of the target models carry a deleted_at, so a plain Delete is a true hard
// delete (no Unscoped needed). Active/open/pending rows are excluded by predicate
// so an in-flight record is never destroyed by a too-short window.

// DeleteAnomalyAlertsBefore hard-deletes anomaly alerts matching either of two
// independent conditions:
//
//   - acknowledged = true AND detected_at < ackBefore — the normal, short
//     retention window. Matching every sibling purge in this section, which
//     excludes in-flight rows (open campaigns, active break-glass, pending access
//     requests) from age-based deletion, an old alert nobody has ever acknowledged
//     is exactly the in-flight case here: it is still a live, unreviewed security
//     signal, not a resolved record, so it is NOT matched by this clause alone.
//     Without this gate, a retention window shorter than the real review cadence
//     would silently hard-delete a genuine, never-reviewed high-severity alert —
//     and the compliance dashboard would then report FEWER unacknowledged
//     anomalies, masking the fact that a real signal was destroyed rather than
//     resolved.
//   - acknowledged = false AND detected_at < unackCeiling — a separate, much more
//     generous absolute-age safety net (#489). The creation-time dedup window
//     (CreateAnomalyAlert) only collapses alerts sharing the same secret/type/
//     actor/IP within an hour; varying any one of those fields defeats it, so
//     without this ceiling an alert stream that is never acknowledged (or an
//     actor deliberately triggering distinct anomalies) accumulates rows forever
//     with no cap — a disk-exhaustion surface, and ListAnomalyAlerts scans grow
//     correspondingly slower over time. unackCeiling is expected to be configured
//     far longer than ackBefore precisely so it only catches truly-ancient,
//     almost-certainly-abandoned alerts, never a reasonable operational backlog.
//
// A zero time.Time for either parameter disables that clause (it matches nothing,
// rather than being misread as "purge everything before year 1").
func (ls *LocalStorage) DeleteAnomalyAlertsBefore(ctx context.Context, ackBefore, unackCeiling time.Time) (int64, error) {
	// G81 (AnomalyAlert.DetectedAt): normalize internally — see GetAuditLogs.
	// IsZero() is checked before normalizing, since a UTC-converted zero time.Time
	// is still IsZero() true (Location doesn't affect the zero check) — order
	// doesn't matter here, but IsZero is checked first for clarity.
	var conds []string
	var args []interface{}
	if !ackBefore.IsZero() {
		conds = append(conds, "(acknowledged = ? AND detected_at < ?)")
		args = append(args, true, ackBefore.UTC())
	}
	if !unackCeiling.IsZero() {
		conds = append(conds, "(acknowledged = ? AND detected_at < ?)")
		args = append(args, false, unackCeiling.UTC())
	}
	if len(conds) == 0 {
		return 0, nil
	}
	result := ls.db.WithContext(ctx).
		Where(strings.Join(conds, " OR "), args...).
		Delete(&models.AnomalyAlert{})
	if result.Error != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return result.RowsAffected, nil
}

// DeleteClosedAccessReviewsBefore hard-deletes closed recertification campaigns
// closed before the cutoff together with their snapshot items, in one transaction.
// Open campaigns (closed_at IS NULL) are never touched.
func (ls *LocalStorage) DeleteClosedAccessReviewsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	// G81 (AccessReviewCampaign.ClosedAt): normalize internally — see GetAuditLogs.
	before = before.UTC()
	var campaigns, items int64
	eligible := "state = ? AND closed_at IS NOT NULL AND closed_at < ?"
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// #G21: both deletes re-evaluate the eligibility predicate LIVE, at the
		// moment each DELETE statement executes, instead of deleting by a
		// Pluck'd ID list captured earlier in the transaction. A campaign
		// reopened between an initial Pluck and a later delete-by-ID would
		// still be destroyed under the old pattern — under Postgres READ
		// COMMITTED (unlike SQLite's single-writer exclusivity) a concurrent
		// transaction's UPDATE can commit in that window without this one
		// seeing it via a lock. Filtering the item-delete via a live subquery
		// against the campaign table's CURRENT state, and the campaign-delete
		// via the same live predicate directly, closes that gap for both
		// backends.
		ri := tx.Where("campaign_id IN (?)", tx.Model(&models.AccessReviewCampaign{}).
			Select("id").Where(eligible, "closed", before)).
			Delete(&models.AccessReviewItem{})
		if ri.Error != nil {
			return ri.Error
		}
		items = ri.RowsAffected
		rc := tx.Where(eligible, "closed", before).Delete(&models.AccessReviewCampaign{})
		if rc.Error != nil {
			return rc.Error
		}
		campaigns = rc.RowsAffected
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return campaigns, items, nil
}

// DeleteExpiredBreakGlassBefore hard-deletes old break-glass activations before
// the cutoff: explicitly non-active (revoked, or reconciled-expired) AND
// reviewed rows. Before doing so it reconciles ('active' -> 'expired') rows
// still labeled 'active' whose ExpiresAt has genuinely passed -- ReconcileExpiredBreakGlassActivation
// only ever reconciles the SAME user's row at their own next activation in the
// SAME project, so a user who activates once and never revisits that project
// leaves their row 'active' in the DB indefinitely otherwise; this retention
// sweep is the backstop that still reclaims it. A row genuinely still active
// (ExpiresAt in the future, or nil) is never touched either way.
//
// #2461 round 2: an unreviewed row (reviewed_at IS NULL) is NEVER matched by
// this delete, no matter how old. ADR-112's posture deviation ("an open
// activation without a recorded review") is exactly what retention would
// otherwise silently erase: a row old enough to outlive break_glass_days
// would be purged before anyone reviewed it, and the compliance posture
// report (accumulateBreakGlassPosture) would then report FEWER unreviewed
// activations than ever actually went unreviewed -- the same masking effect
// DeleteAnomalyAlertsBefore's ackBefore/unackCeiling split exists to prevent
// for unacknowledged anomaly alerts, immediately below. Unlike that sweep,
// this one has no separate, more-generous ceiling for the unreviewed case:
// break-glass activation is rare, tightly audited, and already surfaced by
// RunBreakGlassReviewReminder's recurring overdue warning (and, since round
// 2, the "emergency-access" compliance control going to Gap), so an
// unreviewed row has an active, nagging escalation path rather than the
// anomaly-alert stream's passive accumulation risk a disk-exhaustion ceiling
// guards against -- there is no legitimate "ancient and still unreviewed and
// nobody will ever look at it" case here to additionally cap.
//
// FIX-7 (adversarial review run 2): #1653 reopened's widen hard-deleted a
// still-'active' row in the SAME statement as the reconciliation, the instant
// its ExpiresAt passed the retention cutoff -- racing any concurrent operation
// that expected to still find the row (in ANY state) to act on it, e.g. an
// admin's RevokeBreakGlass, which removes the real RBAC grant
// (c.RemoveUserRole) FIRST and only afterward conditionally updates this row
// (RevokeBreakGlassActivation, whose WHERE already accepts BOTH 'active' and
// 'expired' for exactly this reason). If the purge deletes the row between
// those two steps, the already-successful revoke's own state-transition and
// audit-event write (LogBreakGlassRevoked, only called on success) are lost --
// the caller sees a misleading "activation is not active" error despite
// having just genuinely revoked the grant.
//
// Fixed by reconciling and deleting as two separate steps: a row transitioned
// 'active' -> 'expired' by THIS call is deliberately excluded from THIS
// call's own delete and left for the NEXT sweep to hard-delete -- its
// CreatedAt does not change at reconciliation, so it would otherwise ALSO
// match the terminal-row delete criteria in this same pass (CreatedAt <=
// ExpiresAt < before already holds); explicitly tracking and excluding the
// IDs this call itself just reconciled is what actually defers them. On the
// next sweep they're no longer excluded and qualify like any other
// already-terminal row, giving one full sweep interval of grace for a
// concurrent revoke (or any other in-flight reader) to still observe and act
// on the row before it's purged. The original #edee956e/#1653 guarantee this
// widen exists for is unaffected: an abandoned 'active' row is still
// reconciled (freeing the partial-unique-index slot) on every sweep, just
// hard-deleted one cycle later than before.
// pluckExpiredActiveBreakGlassIDs reads the ids of still-'active' rows whose
// ExpiresAt has passed before -- the reconcile step's read half. Split out
// from reconcileBreakGlassIDsToExpired (rather than one combined
// Pluck-then-Update) so a test can deterministically interleave a concurrent
// write between the two steps without a real, inherently-flaky goroutine race
// -- see local_retention_test.go's
// TestDeleteExpiredBreakGlassBefore_ConcurrentRevokeBetweenPluckAndUpdate.
func (ls *LocalStorage) pluckExpiredActiveBreakGlassIDs(ctx context.Context, before time.Time) ([]uint, error) {
	var ids []uint
	if err := ls.db.WithContext(ctx).Model(&models.BreakGlassActivation{}).
		Where("state = ? AND expires_at IS NOT NULL AND expires_at < ?", breakGlassActiveState, before).
		Pluck("id", &ids).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return ids, nil
}

// reconcileBreakGlassIDsToExpired transitions ids from 'active' to 'expired'
// -- the reconcile step's write half.
//
// Part 2 regression audit (adversarial review run 2): this UPDATE must
// re-check state = 'active' at write time, not just act on an ID list a
// caller Plucked a moment earlier -- otherwise a concurrent
// RevokeBreakGlassActivation landing between the read and this write (legal:
// the row was still 'active' right after the read) gets silently overwritten
// back to 'expired' here, while revoked_by/revoked_at stay populated --
// corrupting the audit-relevant distinction between "an admin actively
// revoked this" and "it merely timed out" on a security-sensitive control.
// Same live-predicate-at-write-time discipline this file's sibling functions
// (DeleteClosedAccessReviewsBefore, DeleteResolvedAccessRequestsBefore, #G21)
// already use for exactly this class of race.
func (ls *LocalStorage) reconcileBreakGlassIDsToExpired(ctx context.Context, ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	if err := ls.db.WithContext(ctx).Model(&models.BreakGlassActivation{}).
		Where("id IN ? AND state = ?", ids, breakGlassActiveState).
		Update("state", breakGlassExpiredState).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) DeleteExpiredBreakGlassBefore(ctx context.Context, before time.Time) (int64, error) {
	// G81 (BreakGlassActivation.CreatedAt/ExpiresAt): normalize internally — see GetAuditLogs.
	before = before.UTC()
	justReconciledIDs, err := ls.pluckExpiredActiveBreakGlassIDs(ctx, before)
	if err != nil {
		return 0, err
	}
	if err := ls.reconcileBreakGlassIDsToExpired(ctx, justReconciledIDs); err != nil {
		return 0, err
	}
	q := ls.db.WithContext(ctx).Where("state <> ? AND created_at < ? AND reviewed_at IS NOT NULL", breakGlassActiveState, before)
	if len(justReconciledIDs) > 0 {
		q = q.Where("id NOT IN ?", justReconciledIDs)
	}
	result := q.Delete(&models.BreakGlassActivation{})
	if result.Error != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return result.RowsAffected, nil
}

// DeleteResolvedAccessRequestsBefore hard-deletes terminal-state access requests
// (resolved_at set, before the cutoff) together with their approval records, in one
// transaction. Pending requests (resolved_at IS NULL) are never touched.
func (ls *LocalStorage) DeleteResolvedAccessRequestsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	// G81 (AccessRequest.ResolvedAt): normalize internally — see GetAuditLogs.
	before = before.UTC()
	var requests, approvals int64
	eligible := "resolved_at IS NOT NULL AND resolved_at < ?"
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// #G21: same live-predicate-at-delete-time fix as
		// DeleteClosedAccessReviewsBefore above — see its comment for why a
		// Pluck'd ID list captured earlier in the transaction can go stale
		// under Postgres READ COMMITTED if a request is un-resolved
		// concurrently.
		ra := tx.Where("request_id IN (?)", tx.Model(&models.AccessRequest{}).
			Select("id").Where(eligible, before)).
			Delete(&models.AccessRequestApproval{})
		if ra.Error != nil {
			return ra.Error
		}
		approvals = ra.RowsAffected
		rr := tx.Where(eligible, before).Delete(&models.AccessRequest{})
		if rr.Error != nil {
			return rr.Error
		}
		requests = rr.RowsAffected
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return requests, approvals, nil
}
