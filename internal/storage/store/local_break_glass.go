// local_break_glass.go — break-glass emergency-access activation persistence
// (NIS2/DORA incident response). For the remote equivalent see remote_break_glass.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// breakGlassActiveState / breakGlassRevokedState / breakGlassExpiredState mirror
// core.BreakGlassActive / core.BreakGlassRevoked / core.BreakGlassExpired.
// Duplicated here (rather than imported) because this package is imported BY
// internal/core — importing core back would cycle.
const (
	breakGlassActiveState  = "active"
	breakGlassRevokedState = "revoked"
	breakGlassExpiredState = "expired"
)

// projectEffectiveBreakGlassState returns a's State, EXCEPT an 'active' row past
// its ExpiresAt (relative to effectiveNow) is reported as 'expired' — a pure
// in-memory projection for callers, never persisted here (see
// ReconcileExpiredBreakGlassActivation for the one place a TTL-lapse transition
// is ever actually written, and why it isn't written here or in ListBreakGlassActivations).
func projectEffectiveBreakGlassState(a *models.BreakGlassActivation, effectiveNow time.Time) string {
	if a.State == breakGlassActiveState && a.ExpiresAt != nil && a.ExpiresAt.Before(effectiveNow) {
		return breakGlassExpiredState
	}
	return a.State
}

// CreateBreakGlassActivation persists a new activation. DoNothing on conflict so a
// racing duplicate active activation for the same (project_id, user_id) — the
// partial unique index enforced by ensureBreakGlassActiveIndex — is a clean,
// driver-agnostic (SQLite + Postgres) rejection rather than a raw unique-violation
// error: RowsAffected==0 means the insert was rejected, reported as
// storage.ErrBreakGlassAlreadyActive so the core layer can surface the same friendly
// message a losing racer gets from its own pre-check.
func (ls *LocalStorage) CreateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) (*models.BreakGlassActivation, error) {
	res := ls.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(a)
	if res.Error != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, storage.ErrBreakGlassAlreadyActive
	}
	return a, nil
}

// GetBreakGlassActivation returns a's row with State projected to 'expired' if
// its TTL has lapsed relative to the watermark-clamped clock (#1651's
// rbacEffectiveNow, reused here) -- a read, never a write; see
// projectEffectiveBreakGlassState's doc for why the projection is never
// persisted from here.
func (ls *LocalStorage) GetBreakGlassActivation(ctx context.Context, id uint) (*models.BreakGlassActivation, error) {
	var a models.BreakGlassActivation
	if err := ls.db.WithContext(ctx).First(&a, id).Error; err != nil {
		// Was an unconditional "not found" wrap regardless of the underlying error,
		// so a genuine storage failure (e.g. a closed/unreachable DB) read
		// identically to a real not-found to any caller doing the same string-match
		// server/http/handlers.isNotFoundErr does -- RevokeBreakGlassActivationProxy
		// (server/http/handlers/break_glass_proxy.go), which started calling this
		// method as part of the G80 documented-exception fix, surfaced this as a
		// wrong 404 instead of 500 for a real storage error. Distinguish genuine
		// not-found (gorm.ErrRecordNotFound) from everything else, matching
		// GetMachineIdentityCredentialByID's (local_machine_credentials.go) already-
		// established pattern for the same bug class.
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Also wraps the storage.ErrBreakGlassNotFound sentinel (#2461 round 2)
			// so a caller can classify this without matching the LOCALE-DEPENDENT
			// i18n.T("ErrorNotFound") text; gorm.ErrRecordNotFound stays wrapped too
			// for the existing errors.Is callers.
			return nil, fmt.Errorf("%s: %w: %w", i18n.T("ErrorNotFound", nil), storage.ErrBreakGlassNotFound, err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	a.State = projectEffectiveBreakGlassState(&a, ls.rbacEffectiveNow(time.Now().UTC()))
	return &a, nil
}

// ListBreakGlassActivations returns the project's rows, newest first, with each
// row's State projected the same way GetBreakGlassActivation's is -- a read,
// never a write. Prior to #1653's reopening this function persisted the
// TTL-lapse transition it computed (a read path writing access-control-adjacent
// state was the actual defect #1653's original deferral rested on without ever
// asserting it); it now only ever reads.
func (ls *LocalStorage) ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error) {
	var rows []*models.BreakGlassActivation
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	effectiveNow := ls.rbacEffectiveNow(time.Now().UTC())
	for _, a := range rows {
		a.State = projectEffectiveBreakGlassState(a, effectiveNow)
	}
	return rows, nil
}

// ReconcileExpiredBreakGlassActivation transitions userID's own TTL-lapsed
// 'active' row in projectID to 'expired', if one exists -- an atomic conditional
// UPDATE, watermark-clamped (#1651's rbacEffectiveNow) so a transiently
// backward-stepped clock can never treat a genuinely-live grant as expired. The
// ONLY place a TTL-lapse transition is ever persisted (see
// projectEffectiveBreakGlassState's doc): called from ActivateBreakGlass, a
// mutating operation, immediately before it attempts to create a new
// activation, so a real-but-un-reconciled prior grant's row doesn't hold the
// partial unique index's one-active-slot-per-(project,user) indefinitely once
// its TTL has genuinely passed (#1653 reopened: this was the "backward drift
// blocks a NEW activation" mirror of the "forward drift blocks revoke" bug the
// original guard-reading-State finding also produced). Deliberately scoped to
// the single row that matters for the caller's own upcoming INSERT, not a
// broad sweep -- see DeleteExpiredBreakGlassBefore (local_purge.go) for the
// longer-horizon retention cleanup of rows nobody ever reconciles this way.
func (ls *LocalStorage) ReconcileExpiredBreakGlassActivation(ctx context.Context, projectID, userID uint) error {
	effectiveNow := ls.rbacEffectiveNow(time.Now().UTC())
	if err := ls.db.WithContext(ctx).Model(&models.BreakGlassActivation{}).
		Where("project_id = ? AND user_id = ? AND state = ? AND expires_at IS NOT NULL AND expires_at <= ?",
			projectID, userID, breakGlassActiveState, effectiveNow).
		Update("state", breakGlassExpiredState).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) UpdateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) error {
	if err := ls.db.WithContext(ctx).Save(a).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RevokeBreakGlassActivation conditionally transitions activation id from
// active-OR-expired to revoked in a single UPDATE — not a read-then-write — so
// a concurrent revoke of the same activation cannot silently overwrite this
// one's RevokedBy/RevokedAt. Accepts a row already reconciled to 'expired'
// (ReconcileExpiredBreakGlassActivation) as well as 'active': revoking a
// TTL-lapsed-but-not-yet-revoked activation is always allowed and always
// harmless (the role grant it represents is independently, correctly governed
// by #1651's watermark regardless of what this row's State says) -- #1653
// reopened: a caller must never be refused a revoke because of what a
// clock-derived State happens to read. Only 'revoked' (already revoked)
// excludes a row. Returns storage.ErrBreakGlassNotActive (wrapped) if the row
// was already revoked, or absent.
func (ls *LocalStorage) RevokeBreakGlassActivation(ctx context.Context, id, revokedBy, revokedByMachineID uint, revokedAt time.Time) error {
	result := ls.db.WithContext(ctx).Model(&models.BreakGlassActivation{}).
		Where("id = ? AND state IN ?", id, []string{breakGlassActiveState, breakGlassExpiredState}).
		Updates(map[string]any{
			"state":                          breakGlassRevokedState,
			"revoked_by":                     revokedBy,
			"revoked_by_machine_identity_id": revokedByMachineID,
			"revoked_at":                     revokedAt,
		})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), storage.ErrBreakGlassNotActive)
	}
	return nil
}

// ReviewBreakGlassActivation conditionally records a review — reviewer, when,
// and an optional note — guarded on reviewed_at IS NULL in the same single-
// UPDATE shape RevokeBreakGlassActivation uses, so two concurrent review
// submissions for the same activation cannot both "win": only the first sets
// reviewed_at, the second gets ErrBreakGlassAlreadyReviewed (RowsAffected==0
// distinguishes "already reviewed" from "activation does not exist" the same
// way the caller must anyway — see ReviewBreakGlass in internal/core, which
// looks the activation up first). Allowed regardless of the activation's
// active/expired/revoked state.
func (ls *LocalStorage) ReviewBreakGlassActivation(ctx context.Context, id, reviewerID uint, note string, reviewedAt time.Time) error {
	result := ls.db.WithContext(ctx).Model(&models.BreakGlassActivation{}).
		Where("id = ? AND reviewed_at IS NULL", id).
		Updates(map[string]any{
			"reviewed_by": reviewerID,
			"reviewed_at": reviewedAt,
			"review_note": note,
		})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), storage.ErrBreakGlassAlreadyReviewed)
	}
	return nil
}

// ListUnreviewedBreakGlassActivationsBefore returns every activation (across
// all projects — this is a global posture query, not a per-project one) with
// reviewed_at still NULL and created_at at or before cutoff, oldest first (the
// posture report's natural display order: longest-outstanding review first).
func (ls *LocalStorage) ListUnreviewedBreakGlassActivationsBefore(ctx context.Context, cutoff time.Time) ([]*models.BreakGlassActivation, error) {
	var rows []*models.BreakGlassActivation
	err := ls.db.WithContext(ctx).
		Where("reviewed_at IS NULL AND created_at <= ?", cutoff).
		Order("created_at ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}
