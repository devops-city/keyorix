// local_rotation_policies.go — RotationPolicy operations for LocalStorage.
//
// Covers: CreateRotationPolicy, GetRotationPolicy, GetRotationPolicyBySecret,
// ListRotationPolicies, UpdateRotationPolicy, DeleteRotationPolicy,
// UpdateRotationState.
//
// All operations use direct GORM queries; no network calls.
// For the remote (HTTP) equivalent see remote_rotation_policies.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

func (ls *LocalStorage) CreateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error {
	return ls.db.WithContext(ctx).Create(p).Error
}

func (ls *LocalStorage) GetRotationPolicy(ctx context.Context, id uint) (*models.RotationPolicy, error) {
	var policy models.RotationPolicy
	if err := ls.db.WithContext(ctx).First(&policy, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("rotation policy not found")
		}
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}
	return &policy, nil
}

func (ls *LocalStorage) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	query := ls.db.WithContext(ctx).Model(&models.RotationPolicy{})
	if projectID != nil {
		query = query.Where("project_id = ?", *projectID)
	}
	if environmentID != nil {
		query = query.Where("environment_id = ?", *environmentID)
	}
	var policies []*models.RotationPolicy
	if err := query.Limit(maxUnboundedListRows).Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}
	return policies, nil
}

// UpdateRotationPolicyFields persists ONLY the six operator-editable columns
// (plus updated_at), onto a LIVE policy row — see the storage.Storage interface
// doc for why the full-row UpdateRotationPolicy this replaced (a bare Save) both
// resurrected a concurrently deleted policy and reverted the executor's recorded
// rotation_state (#2700).
//
// GORM adds `deleted_at IS NULL` for this soft-delete model, which is the clause
// that stops the resurrection. The rotation_state/last_rotation_error/
// last_state_at columns are deliberately absent: UpdateRotationState owns them.
func (ls *LocalStorage) UpdateRotationPolicyFields(ctx context.Context, id uint, f storage.RotationPolicyFieldUpdate, updatedAt time.Time) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.RotationPolicy{}).Where(sqlWhereID, id).
		Updates(map[string]any{
			"name":              f.Name,
			"description":       f.Description,
			"interval_days":     f.IntervalDays,
			"alert_days_before": f.AlertDaysBefore,
			"notify_on_breach":  f.NotifyOnBreach,
			"is_active":         f.IsActive,
			"updated_at":        updatedAt,
		})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func (ls *LocalStorage) DeleteRotationPolicy(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Delete(&models.RotationPolicy{}, id).Error
}

// GetRotationPolicyBySecret returns the first active rotation policy that covers
// a secret (matched by the secret's project_id or environment_id). Returns
// a "rotation policy not found" error (checked via strings.Contains by callers)
// when no policy exists for the secret.
func (ls *LocalStorage) GetRotationPolicyBySecret(ctx context.Context, secretID uint) (*models.RotationPolicy, error) {
	// Resolve the secret's project + environment so we can match policies.
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).First(&secret, secretID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("secret not found")
		}
		return nil, fmt.Errorf("GetRotationPolicyBySecret: secret lookup: %w", err)
	}
	// Prefer the narrowest scope first (environment-scoped), then fall back to
	// a project-scoped policy that covers the secret's environment.
	var policy models.RotationPolicy
	err := ls.db.WithContext(ctx).
		Where("(scope = 'environment' AND environment_id = ?) OR (scope = 'project' AND project_id = ?)",
			secret.EnvironmentID, secret.ProjectID).
		Where("is_active = ? AND deleted_at IS NULL", true).
		Order("CASE scope WHEN 'environment' THEN 0 ELSE 1 END").
		First(&policy).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("rotation policy not found")
	}
	if err != nil {
		return nil, fmt.Errorf("GetRotationPolicyBySecret: policy lookup: %w", err)
	}
	return &policy, nil
}

// UpdateRotationState stamps the execution state on a RotationPolicy row.
func (ls *LocalStorage) UpdateRotationState(ctx context.Context, policyID uint, state, errMsg string) error {
	now := time.Now().UTC()
	result := ls.db.WithContext(ctx).Model(&models.RotationPolicy{}).
		Where("id = ?", policyID).
		Updates(map[string]any{
			"rotation_state":      state,
			"last_rotation_error": errMsg,
			"last_state_at":       now,
		})
	if result.Error != nil {
		return fmt.Errorf("UpdateRotationState: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("rotation policy not found")
	}
	return nil
}
