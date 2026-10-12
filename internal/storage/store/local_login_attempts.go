// local_login_attempts.go — cluster-wide login rate limiting (ADR-040). Failed
// attempts are recorded per IP; a windowed count gates further attempts across all
// replicas, and a maintenance sweep prunes rows past the window.
package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error {
	return ls.db.WithContext(ctx).Create(&models.LoginAttempt{IP: ip, AttemptedAt: at}).Error
}

func (ls *LocalStorage) CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error) {
	// G81 (LoginAttempt.AttemptedAt): normalize internally — see GetAuditLogs. A
	// cross-process write (login_attempts_proxy.go, storage.type: remote) carries
	// a follower's own local clock across the wire, so this bound can genuinely
	// diverge from a write's Location, not just drift within one process.
	since = since.UTC()
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.LoginAttempt{}).
		Where("ip = ? AND attempted_at > ?", ip, since).Count(&n).Error; err != nil {
		return 0, err
	}
	return n, nil
}

// PruneLoginAttempts deletes attempts older than `before` (past the window) and
// returns how many were removed.
func (ls *LocalStorage) PruneLoginAttempts(ctx context.Context, before time.Time) (int64, error) {
	// G81 (LoginAttempt.AttemptedAt): normalize internally — see GetAuditLogs.
	before = before.UTC()
	res := ls.db.WithContext(ctx).Where("attempted_at < ?", before).Delete(&models.LoginAttempt{})
	return res.RowsAffected, res.Error
}

// ReserveLoginAttempt is RecordLoginAttempt plus returning the new row's id —
// see the Storage interface doc for why only one caller needs this.
//
// Idempotent per key: the insert does nothing if a row with this
// reservation_key already exists, and the id is always read back by key. So a
// retry after a write that landed but reported an error returns the SAME row
// and never counts the attempt twice.
func (ls *LocalStorage) ReserveLoginAttempt(ctx context.Context, ip string, at time.Time, key string) (uint, error) {
	if key == "" {
		return 0, errors.New("ReserveLoginAttempt: empty reservation key")
	}
	k := key
	row := &models.LoginAttempt{IP: ip, AttemptedAt: at, ReservationKey: &k}
	if err := ls.db.WithContext(ctx).
		Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "reservation_key"}}, DoNothing: true}).
		Create(row).Error; err != nil {
		return 0, err
	}
	var got models.LoginAttempt
	if err := ls.db.WithContext(ctx).Select("id").Where("reservation_key = ?", key).First(&got).Error; err != nil {
		return 0, err
	}
	return got.ID, nil
}

// ReleaseLoginAttempt undoes a ReserveLoginAttempt write. Deleting zero rows
// (already gone) is not an error — GORM's Delete only errors on a genuine
// storage failure, not on a missing row.
func (ls *LocalStorage) ReleaseLoginAttempt(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Delete(&models.LoginAttempt{}, id).Error
}
