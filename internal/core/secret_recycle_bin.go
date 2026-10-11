// secret_recycle_bin.go — the recycle bin: list a project's soft-deleted (restorable)
// secrets so an operator can discover what to restore. Secrets soft-delete on DELETE
// (ADR-033) and are reaped by the purge job after the retention window; until then a
// restore is possible, but the restore route needs the secret's ID — which, without
// this view, an operator has no way to find. Read-only and metadata-only: it never
// returns or touches a secret value. Project-scoped (route-gated secrets.read).
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// defaultSoftDeleteRetentionDays is config.SoftDeleteConfig.GetRetentionDays's default,
// used when the service was never told the configured window (tests, library use). The
// server wires soft_delete.retention_days at construction (server/main.go), so this value
// never applies in a running server; it equals the config default so the unwired case
// shows the same date an unconfigured server would, and
// TestDefaultSoftDeleteRetentionDays_MatchesConfigDefault fails if the two drift apart.
const defaultSoftDeleteRetentionDays = 30

// SecretPurgeAt is the UTC instant the purge job will first hard-delete a soft-deleted
// secret - the date shown in the trash listing and returned by delete - and false for a
// live secret. It is models.SecretNode.EffectivePurgeAt with this service's configured
// window as the fallback for rows that carry no frozen purge date. Because the purge job
// decides with the very same value, "never purged earlier than shown" holds by
// construction (see storage/store.secretPurgeCandidate.eligible for the rule and why).
func (c *KeyorixCore) SecretPurgeAt(s *models.SecretNode) (time.Time, bool) {
	days := c.softDeleteRetentionDays
	if days <= 0 {
		days = defaultSoftDeleteRetentionDays
	}
	return s.EffectivePurgeAt(days)
}

// DeletedSecretPurgeAt returns the purge date of a secret that has just been
// soft-deleted, read back from the row so the caller reports exactly what was stored.
func (c *KeyorixCore) DeletedSecretPurgeAt(ctx context.Context, id uint) (time.Time, error) {
	s, err := c.storage.GetSecretIncludingDeleted(ctx, id)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	at, ok := c.SecretPurgeAt(s)
	if !ok {
		return time.Time{}, fmt.Errorf("%s: secret %d is not deleted", i18n.T("ErrorValidation", nil), id)
	}
	return at, nil
}

// defaultRecycleBinLimit bounds the trash listing when no limit is given.
const defaultRecycleBinLimit = 100

// maxRecycleBinLimit caps a single trash page.
const maxRecycleBinLimit = 500

// ListDeletedSecrets returns the project's soft-deleted secrets, most-recently-deleted
// first, for the restore UI. `limit` is clamped to [1, maxRecycleBinLimit]; a
// non-positive limit falls back to defaultRecycleBinLimit. Returns metadata only.
func (c *KeyorixCore) ListDeletedSecrets(ctx context.Context, projectID uint, limit int) ([]*models.SecretNode, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	if limit <= 0 {
		limit = defaultRecycleBinLimit
	}
	if limit > maxRecycleBinLimit {
		limit = maxRecycleBinLimit
	}
	secrets, _, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID:   &projectID,
		DeletedOnly: true,
		Page:        1,
		PageSize:    limit,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// Already newest-deleted first (ordered in the storage query, before LIMIT).
	return secrets, nil
}
