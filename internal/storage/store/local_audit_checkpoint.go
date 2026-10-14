// local_audit_checkpoint.go — signed checkpoints over the audit hash chain
// (ADR-029). A checkpoint records (chained_events, head_id, head_hash) at a
// point in time with an HMAC the application holds the key for; re-verifying the
// live chain against the latest checkpoint detects on-box tail-truncation or a
// genesis re-seed that an unanchored re-walk cannot. The signing/verification of
// the HMAC lives in the core layer (which holds the DEK-derived key); this file
// only persists and reads checkpoint rows.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// CreateAuditCheckpoint appends a signed checkpoint row (append-only).
func (ls *LocalStorage) CreateAuditCheckpoint(ctx context.Context, cp *models.AuditCheckpoint) error {
	return ls.db.WithContext(ctx).Create(cp).Error
}

// UpdateAuditCheckpointAnchor stores the external-notary anchor (RFC 3161 token +
// asserted time + provider) on an already-written checkpoint row. Updates only the
// three anchor columns, leaving the signed (chained_events, head, signature)
// fields immutable.
func (ls *LocalStorage) UpdateAuditCheckpointAnchor(ctx context.Context, id uint, token []byte, anchoredAt time.Time, provider string) error {
	return ls.db.WithContext(ctx).
		Model(&models.AuditCheckpoint{}).
		Where(sqlWhereID, id).
		Updates(map[string]any{
			"anchor_token":    token,
			"anchored_at":     anchoredAt,
			"anchor_provider": provider,
		}).Error
}

// LatestAuditCheckpoint returns the most recent checkpoint by id, or (nil, nil)
// when none has been written yet.
func (ls *LocalStorage) LatestAuditCheckpoint(ctx context.Context) (*models.AuditCheckpoint, error) {
	var cp models.AuditCheckpoint
	err := ls.db.WithContext(ctx).Order("id DESC").Limit(1).Take(&cp).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cp, nil
}

// AuditEntryHashByID returns the entry_hash of one audit row. found is false when
// the row no longer exists — the signal that a checkpointed head was truncated.
func (ls *LocalStorage) AuditEntryHashByID(ctx context.Context, id uint) (string, bool, error) {
	var row struct{ EntryHash string }
	err := ls.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Select("entry_hash").
		Where(sqlWhereID, id).
		Limit(1).
		Scan(&row).Error
	if err != nil {
		return "", false, err
	}
	// Scan leaves row zero-valued when no record matched; distinguish a missing
	// row from a genuinely-empty hash via a separate existence count.
	var n int64
	if err := ls.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Where(sqlWhereID, id).
		Count(&n).Error; err != nil {
		return "", false, err
	}
	if n == 0 {
		return "", false, nil
	}
	return row.EntryHash, true, nil
}
