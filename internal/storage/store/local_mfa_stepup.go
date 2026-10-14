// local_mfa_stepup.go — MFA step-up token persistence for LocalStorage.
// One row per user (uniqueIndex on user_id); UpsertMFAStepupToken replaces it
// on each re-verification using ON CONFLICT, mirroring local_mfa.go's
// UpsertMFASecret pattern exactly.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const sqlWhereUserIDAndNotExpired = "user_id = ? AND expires_at > ?"

// UpsertMFAStepupToken inserts or replaces the step-up record for userID,
// setting its expiry to expiresAt. A second MFA verification within the window
// extends the window cleanly (ON CONFLICT updates expires_at in place).
//
// expiresAt is normalised to UTC explicitly here (G81), not left to the
// model's BeforeSave hook alone: the ON CONFLICT DoUpdates clause below
// writes expires_at from its own raw map on the UPDATE branch of the upsert,
// which bypasses GORM model hooks entirely — only the INSERT branch (via
// Create) would ever see BeforeSave run. Normalising once here up front
// keeps both branches consistent regardless of which one actually fires.
func (ls *LocalStorage) UpsertMFAStepupToken(ctx context.Context, userID uint, expiresAt time.Time) error {
	expiresAt = expiresAt.UTC()
	tok := &models.MFAStepupToken{UserID: userID, ExpiresAt: expiresAt}
	return ls.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.Assignments(map[string]any{"expires_at": expiresAt}),
	}).Create(tok).Error
}

// HasActiveMFAStepup reports whether userID has a non-expired step-up record —
// i.e., that they completed MFA verification within the configured window.
// Returns (false, nil) when no record exists or the record has expired.
func (ls *LocalStorage) HasActiveMFAStepup(ctx context.Context, userID uint) (bool, error) {
	var tok models.MFAStepupToken
	// now is normalised to UTC (G81) to match expires_at's own UTC-normalised
	// storage (UpsertMFAStepupToken above) — mirrors the identical
	// now.UTC() call MFAStepUpGrant's HasActiveMFAStepupGrant already makes
	// for the exact same reason: SQLite compares time.Time values as strings,
	// so both sides of the comparison must use the same timezone convention.
	err := ls.db.WithContext(ctx).
		Where(sqlWhereUserIDAndNotExpired, userID, time.Now().UTC()).
		First(&tok).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return err == nil, err
}
