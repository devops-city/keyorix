// local_pending_audit.go — pending_audit_events: audit rows owed by an operation that
// took effect without waiting for the audit log (models.PendingAuditEvent). Not the
// audit write path: the owed row is appended through LogAuditEvent like any other.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// CreatePendingAuditEvent records an owed audit event. Inside WithTransaction it
// commits or rolls back with the operation that owes it.
func (ls *LocalStorage) CreatePendingAuditEvent(ctx context.Context, p *models.PendingAuditEvent) error {
	return ls.db.WithContext(ctx).Create(p).Error
}

// ListPendingAuditEvents returns up to limit owed audit events with an id above
// afterID, oldest first.
func (ls *LocalStorage) ListPendingAuditEvents(ctx context.Context, afterID uint, limit int) ([]*models.PendingAuditEvent, error) {
	var out []*models.PendingAuditEvent
	err := ls.db.WithContext(ctx).Where("id > ?", afterID).Order("id ASC").Limit(limit).Find(&out).Error
	return out, err
}

// ClaimPendingAuditEvent deletes the owed event id and reports whether THIS call
// deleted it. Run in the same transaction as the owed audit row: of two concurrent
// writers only one sees claimed=true (on Postgres the second DELETE waits for the
// first transaction and then matches nothing), so the row is written once.
func (ls *LocalStorage) ClaimPendingAuditEvent(ctx context.Context, id uint) (bool, error) {
	res := ls.db.WithContext(ctx).Delete(&models.PendingAuditEvent{}, id)
	return res.RowsAffected == 1, res.Error
}

// RecordPendingAuditEventFailure counts a failed attempt to write the owed event id
// and keeps the latest reason. A missing row is not an error.
func (ls *LocalStorage) RecordPendingAuditEventFailure(ctx context.Context, id uint, reason string) error {
	return ls.db.WithContext(ctx).Model(&models.PendingAuditEvent{}).Where("id = ?", id).
		Updates(map[string]any{"attempts": gorm.Expr("attempts + 1"), "last_error": reason}).Error
}

// CountPendingAuditEvents returns how many owed audit events have not been written.
func (ls *LocalStorage) CountPendingAuditEvents(ctx context.Context) (int64, error) {
	var n int64
	err := ls.db.WithContext(ctx).Model(&models.PendingAuditEvent{}).Count(&n).Error
	return n, err
}
