// local_secret_templates.go — SecretTemplate operations for LocalStorage.
//
// Covers: CreateSecretTemplate, GetSecretTemplate, GetSecretTemplateByName,
// ListSecretTemplates, UpdateSecretTemplate, DeleteSecretTemplate.
//
// All operations use direct GORM queries; no network calls.
// For the remote (HTTP) equivalent see remote_secret_templates.go.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"time"
)

func (ls *LocalStorage) CreateSecretTemplate(ctx context.Context, t *models.SecretTemplate) error {
	return ls.db.WithContext(ctx).Create(t).Error
}

func (ls *LocalStorage) GetSecretTemplate(ctx context.Context, id uint) (*models.SecretTemplate, error) {
	var tmpl models.SecretTemplate
	if err := ls.db.WithContext(ctx).First(&tmpl, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("secret template not found")
		}
		return nil, fmt.Errorf("failed to get secret template: %w", err)
	}
	return &tmpl, nil
}

func (ls *LocalStorage) GetSecretTemplateByName(ctx context.Context, name string) (*models.SecretTemplate, error) {
	var tmpl models.SecretTemplate
	if err := ls.db.WithContext(ctx).Where("name = ?", name).First(&tmpl).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("secret template not found")
		}
		return nil, fmt.Errorf("failed to get secret template by name: %w", err)
	}
	return &tmpl, nil
}

func (ls *LocalStorage) ListSecretTemplates(ctx context.Context) ([]*models.SecretTemplate, error) {
	var templates []*models.SecretTemplate
	if err := ls.db.WithContext(ctx).Order("name").Limit(maxUnboundedListRows).Find(&templates).Error; err != nil {
		return nil, fmt.Errorf("failed to list secret templates: %w", err)
	}
	return templates, nil
}

// UpdateSecretTemplateFields persists ONLY the six editable columns (plus
// updated_at) of an EXISTING template row — see the storage.Storage interface
// doc for why the full-row UpdateSecretTemplate this replaced (a bare Save)
// re-INSERTED a concurrently hard-deleted template with its old id (#2700).
// SecretTemplate has no DeletedAt, so RowsAffected is the whole guarantee here:
// an Updates against a missing row matches nothing, where Save would upsert.
func (ls *LocalStorage) UpdateSecretTemplateFields(ctx context.Context, id uint, f storage.SecretTemplateFieldUpdate, updatedAt time.Time) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.SecretTemplate{}).Where(sqlWhereID, id).
		Updates(map[string]any{
			"name":                   f.Name,
			"description":            f.Description,
			"default_classification": f.DefaultClassification,
			"default_tags":           f.DefaultTags,
			"description_pattern":    f.DescriptionPattern,
			"rotation_hint_days":     f.RotationHintDays,
			"updated_at":             updatedAt,
		})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func (ls *LocalStorage) DeleteSecretTemplate(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Delete(&models.SecretTemplate{}, id).Error
}
