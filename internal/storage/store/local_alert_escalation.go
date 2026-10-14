// local_alert_escalation.go — CRUD for AlertEscalationPolicy records and the
// ListUnacknowledgedAnomalyAlertsBefore helper used by the escalation runner.
// All methods are LocalStorage-only; the REST API is the remote surface.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error {
	if err := ls.db.WithContext(ctx).Create(p).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) GetAlertEscalationPolicy(ctx context.Context, id uint) (*models.AlertEscalationPolicy, error) {
	var row models.AlertEscalationPolicy
	err := ls.db.WithContext(ctx).First(&row, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &row, nil
}

func (ls *LocalStorage) ListAlertEscalationPolicies(ctx context.Context) ([]models.AlertEscalationPolicy, error) {
	var rows []models.AlertEscalationPolicy
	if err := ls.db.WithContext(ctx).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) UpdateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error {
	res := ls.db.WithContext(ctx).Model(p).Updates(map[string]any{
		"name":                   p.Name,
		"min_severity":           p.MinSeverity,
		"escalate_after_minutes": p.EscalateAfterMinutes,
		"channel_ids":            p.ChannelIDs,
		"enabled":                p.Enabled,
		"updated_at":             p.UpdatedAt,
	})
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) DeleteAlertEscalationPolicy(ctx context.Context, id uint) error {
	res := ls.db.WithContext(ctx).Delete(&models.AlertEscalationPolicy{}, id)
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// ListUnacknowledgedAnomalyAlertsBefore returns unacknowledged AnomalyAlerts whose
// detected_at is before the given threshold (i.e. older than the threshold time).
func (ls *LocalStorage) ListUnacknowledgedAnomalyAlertsBefore(ctx context.Context, threshold time.Time) ([]models.AnomalyAlert, error) {
	// G81 (AnomalyAlert.DetectedAt): normalize internally — see GetAuditLogs.
	var rows []models.AnomalyAlert
	err := ls.db.WithContext(ctx).
		Where("acknowledged = ? AND detected_at < ?", false, threshold.UTC()).
		Order("detected_at ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list unacknowledged anomaly alerts: %w", err)
	}
	return rows, nil
}
