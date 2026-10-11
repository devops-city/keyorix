// local_notifications.go — in-app notification persistence (ADR-024).
//
// Notifications are addressed to a single user and surfaced via the header bell.
// For the remote (HTTP) equivalent see remote_notifications.go.
package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const defaultNotificationLimit = 50

// CreateNotification inserts a notification row. A partial unique index on
// notifications (user_id, type, project_id) scoped to unread rotation/expiry
// reminders (see storage.ensureReminderNotificationDedupIndex) allows at most one
// standing unread reminder per (user, type, project) — closing the #488 TOCTOU:
// SendRotationReminders/SendExpiryReminders's own "does a reminder already exist"
// check-then-act read cannot fully exclude a concurrent duplicate (most reliably a
// second on-demand admin-jobs HTTP trigger racing itself or the scheduler tick), so
// the losing insert fails here with storage.ErrDuplicateReminderNotification
// instead of creating a second unread reminder row. Callers treat that as a benign
// duplicate-skip, not a failure.
func (ls *LocalStorage) CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error) {
	if err := ls.db.WithContext(ctx).Create(n).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateReminderNotification, err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return n, nil
}

func (ls *LocalStorage) ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error) {
	if limit <= 0 || limit > 200 {
		limit = defaultNotificationLimit
	}
	q := ls.db.WithContext(ctx).Where("user_id = ?", userID)
	if unreadOnly {
		q = q.Where("is_read = ?", false)
	}
	var rows []*models.Notification
	if err := q.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// HasUnreadNotification reports whether userID has an unread notification of
// nType scoped to projectID. Unlike ListNotifications (newest-N, any type), this
// filters user_id/is_read/type/project_id at the DB level and stops at the first
// match, so it can't be defeated by a pile-up of newer, unrelated unread
// notifications pushing the target one outside a "top N" window (#399).
func (ls *LocalStorage) HasUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (bool, error) {
	n, err := ls.GetUnreadNotification(ctx, userID, nType, projectID)
	if err != nil {
		return false, err
	}
	return n != nil, nil
}

// GetUnreadNotification returns userID's unread notification of nType scoped to
// projectID, or nil if none exists. Same DB-level filter as HasUnreadNotification
// (#399), but returns the full row so a dedup check can also compare (and, on
// escalation, update) its recorded Severity instead of only checking existence
// (#250).
func (ls *LocalStorage) GetUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (*models.Notification, error) {
	var row models.Notification
	err := ls.db.WithContext(ctx).
		Where("user_id = ? AND is_read = ? AND type = ? AND project_id = ?", userID, false, nType, projectID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &row, nil
}

// UpdateNotification updates title/message/severity on an existing notification
// in place, scoped to its owner (#250). Used to escalate a standing reminder
// instead of creating a second unread notification and piling up.
func (ls *LocalStorage) UpdateNotification(ctx context.Context, n *models.Notification) error {
	res := ls.db.WithContext(ctx).Model(&models.Notification{}).
		Where("id = ? AND user_id = ?", n.ID, n.UserID).
		Updates(map[string]interface{}{
			"title":    n.Title,
			"message":  n.Message,
			"severity": n.Severity,
		})
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		// No row for this (id, user) — not found or not the caller's.
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) CountUnreadNotifications(ctx context.Context, userID uint) (int64, error) {
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.Notification{}).
		Where("user_id = ? AND is_read = ?", userID, false).
		Count(&n).Error; err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return n, nil
}

func (ls *LocalStorage) MarkNotificationRead(ctx context.Context, id, userID uint) error {
	res := ls.db.WithContext(ctx).Model(&models.Notification{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("is_read", true)
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		// No row for this (id, user) — not found or not the caller's.
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) MarkAllNotificationsRead(ctx context.Context, userID uint) error {
	if err := ls.db.WithContext(ctx).Model(&models.Notification{}).
		Where("user_id = ? AND is_read = ?", userID, false).
		Update("is_read", true).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// scopedNotifications is the user's notifications inside scope (a restricted PAT's
// feed, PAT-GUARD-1). Rows with no project are never in scope.
func (ls *LocalStorage) scopedNotifications(ctx context.Context, userID uint, scope storage.NotificationScope) *gorm.DB {
	q := ls.db.WithContext(ctx).Model(&models.Notification{}).Where("user_id = ? AND project_id IS NOT NULL", userID)
	if scope.ProjectID != 0 {
		q = q.Where("project_id = ?", scope.ProjectID)
	}
	return q
}

func (ls *LocalStorage) ListScopedNotifications(ctx context.Context, userID uint, scope storage.NotificationScope, unreadOnly bool, limit int) ([]*models.Notification, error) {
	if limit <= 0 || limit > 200 {
		limit = defaultNotificationLimit
	}
	q := ls.scopedNotifications(ctx, userID, scope)
	if unreadOnly {
		q = q.Where("is_read = ?", false)
	}
	var rows []*models.Notification
	if err := q.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) CountUnreadScopedNotifications(ctx context.Context, userID uint, scope storage.NotificationScope) (int64, error) {
	var n int64
	if err := ls.scopedNotifications(ctx, userID, scope).Where("is_read = ?", false).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return n, nil
}

func (ls *LocalStorage) MarkScopedNotificationRead(ctx context.Context, id, userID uint, scope storage.NotificationScope) error {
	res := ls.scopedNotifications(ctx, userID, scope).Where("id = ?", id).Update("is_read", true)
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		// No row for this (id, user) inside scope — the same answer as not found.
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) MarkAllScopedNotificationsRead(ctx context.Context, userID uint, scope storage.NotificationScope) error {
	if err := ls.scopedNotifications(ctx, userID, scope).Where("is_read = ?", false).Update("is_read", true).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}
