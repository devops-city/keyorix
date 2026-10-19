// local_mfa.go — TOTP MFA persistence: the encrypted secret, single-use recovery
// codes, and short-lived login challenges.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UpsertMFASecret creates the user's TOTP secret row (one per user) or replaces
// a PENDING one; an activated row is never replaced (#2692). The replace is the
// ON CONFLICT ... DO UPDATE ... WHERE of one statement, so it is decided on the
// row as it is when the write lands, not on the caller's earlier read of
// MFAEnabled: a concurrent ActivateMFA that committed in between makes the
// conflict branch match nothing (0 rows) and this returns
// storage.ErrMFASecretActivated. Same conditional-write shape as
// ActivateMFASecret below. The replaced columns are the ones the former
// OnConflict{UpdateAll} wrote (everything but the key and created_at), so a
// re-enrolment still resets last_used_step.
//
// Bug origin (#2692):
//
//	Introduced-by: the OnConflict{UpdateAll} upsert (unconditional replace)
//	Detected-by:   review (C-GUARD3-EXEMPT-REVIEW), reproduced by ISSUE-TRIAGE-1
//	Class:         race (stale read, unconditional write)
//	Severity:      high (the late enroller holds a seed that passes MFA on an
//	               MFA-enabled account; login verification does not read Activated)
//	Guard:         TestCTAReview_BeginMFAEnrollment_vs_ActivateMFA_CrossReplicaPostgres,
//	               TestBeginMFAEnrollment_DoesNotReplaceActivatedSecret,
//	               TestUpsertMFASecret_NeverReplacesActivatedSecret
func (ls *LocalStorage) UpsertMFASecret(ctx context.Context, s *models.MFASecret) error {
	res := ls.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"secret_enc", "secret_meta", "activated", "last_used_step"}),
		// COALESCE: a NULL activated (legacy row) is not activated.
		Where: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "COALESCE(mfa_secrets.activated, ?) = ?", Vars: []any{false, false}},
		}},
	}).Create(s)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return storage.ErrMFASecretActivated
	}
	return nil
}

func (ls *LocalStorage) GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error) {
	var s models.MFASecret
	if err := ls.db.WithContext(ctx).Where(sqlWhereUserID, userID).First(&s).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

// ActivateMFASecret is a conditional write (#2655): the WHERE re-asserts that
// the stored secret is still the one the caller validated a code against, so a
// re-enrolment (UpsertMFASecret) landing in between matches zero rows instead
// of being activated.
func (ls *LocalStorage) ActivateMFASecret(ctx context.Context, userID uint, secretEnc []byte) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.MFASecret{}).
		Where("user_id = ? AND secret_enc = ?", userID, secretEnc).Update("activated", true)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// MarkTOTPStepUsed atomically advances the user's last-used TOTP step. The single
// conditional UPDATE (guard in the WHERE clause + RowsAffected check) makes accept and
// advance race-free: a code at or below the stored step matches zero rows and is
// rejected as a replay.
func (ls *LocalStorage) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.MFASecret{}).
		Where("user_id = ? AND (last_used_step IS NULL OR last_used_step < ?)", userID, step).
		Update("last_used_step", step)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// ReleaseTOTPStepIfUnchanged reverts last_used_step from step back to step-1,
// but only when it still equals step exactly (the CAS guard: nothing else has
// advanced it since the MarkTOTPStepUsed call this is undoing). See the
// interface doc (internal/core/storage/interface.go) for why step-1 — not the
// row's actual pre-mark value — is the correct revert target: it re-permits
// exactly this one step without needing to have captured the prior value.
func (ls *LocalStorage) ReleaseTOTPStepIfUnchanged(ctx context.Context, userID uint, step int64) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.MFASecret{}).
		Where("user_id = ? AND last_used_step = ?", userID, step).
		Update("last_used_step", step-1)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// DeleteMFAForUser removes the secret and all recovery codes for a user.
func (ls *LocalStorage) DeleteMFAForUser(ctx context.Context, userID uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(sqlWhereUserID, userID).Delete(&models.MFASecret{}).Error; err != nil {
			return err
		}
		return tx.Where(sqlWhereUserID, userID).Delete(&models.MFARecoveryCode{}).Error
	})
}

func (ls *LocalStorage) SetUserMFAEnabled(ctx context.Context, userID uint, enabled bool) error {
	return ls.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).Update("mfa_enabled", enabled).Error
}

func (ls *LocalStorage) CreateMFARecoveryCodes(ctx context.Context, userID uint, codeHashes []string) error {
	if len(codeHashes) == 0 {
		return nil
	}
	rows := make([]models.MFARecoveryCode, 0, len(codeHashes))
	for _, h := range codeHashes {
		rows = append(rows, models.MFARecoveryCode{UserID: userID, CodeHash: h})
	}
	return ls.db.WithContext(ctx).Create(&rows).Error
}

// CountUnusedMFARecoveryCodes returns how many of the user's recovery codes remain
// unused (so the UI can warn when the user is running low).
func (ls *LocalStorage) CountUnusedMFARecoveryCodes(ctx context.Context, userID uint) (int, error) {
	var n int64
	err := ls.db.WithContext(ctx).Model(&models.MFARecoveryCode{}).
		Where("user_id = ? AND used_at IS NULL", userID).Count(&n).Error
	return int(n), err
}

// DeleteMFARecoveryCodes removes ALL of the user's recovery codes (used + unused)
// without touching the TOTP secret — the regenerate flow replaces them wholesale.
func (ls *LocalStorage) DeleteMFARecoveryCodes(ctx context.Context, userID uint) error {
	return ls.db.WithContext(ctx).Where(sqlWhereUserID, userID).Delete(&models.MFARecoveryCode{}).Error
}

// ConsumeMFARecoveryCode marks a matching unused code used; returns true if one
// was consumed. The conditional UPDATE is atomic (no read-then-write race).
func (ls *LocalStorage) ConsumeMFARecoveryCode(ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.MFARecoveryCode{}).
		Where("user_id = ? AND code_hash = ? AND used_at IS NULL", userID, codeHash).
		Update("used_at", now)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (ls *LocalStorage) CreateMFAChallenge(ctx context.Context, c *models.MFAChallenge) error {
	return ls.db.WithContext(ctx).Create(c).Error
}

// GetActiveMFAChallenge returns a valid (unused, unexpired) challenge by hash
// WITHOUT consuming it. Returns an error if none matched.
func (ls *LocalStorage) GetActiveMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error) {
	// G81 (MFAChallenge.ExpiresAt): normalize internally — see GetAuditLogs.
	now = now.UTC()
	var ch models.MFAChallenge
	if err := ls.db.WithContext(ctx).
		Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, now).
		First(&ch).Error; err != nil {
		return nil, err
	}
	return &ch, nil
}

// ConsumeMFAChallenge atomically marks a valid (unused, unexpired) challenge used
// and returns it. Returns an error if none matched.
func (ls *LocalStorage) ConsumeMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error) {
	// G81 (MFAChallenge.ExpiresAt): normalize internally — see GetAuditLogs.
	now = now.UTC()
	// #1632: refuse a now that looks earlier than one this process has
	// already legitimately observed -- see consumeClockLooksRegressed's doc
	// comment for what this defends against (a backward-stepped host clock
	// letting an expired-but-never-consumed challenge be consumed for the
	// first time past its real window).
	if ls.consumeClockLooksRegressed(now) {
		return nil, storage.ErrMFAChallengeInvalid
	}
	var ch *models.MFAChallenge
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.MFAChallenge{}).
			Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, now).
			Update("used_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return storage.ErrMFAChallengeInvalid
		}
		var loaded models.MFAChallenge
		if err := tx.Where("token_hash = ?", tokenHash).First(&loaded).Error; err != nil {
			return err
		}
		ch = &loaded
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ch, nil
}
