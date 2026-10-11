// secret_retention_override.go — per-secret retention policy override.
//
// Allows operators to set a per-secret retention window that takes precedence
// over the global data-retention policy (ADR-032). High-value secrets can
// therefore be retained longer than the global default without changing the
// deployment-wide window for every secret.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrInvalidRetentionDays is returned when a caller supplies a non-zero
// retention override value that is below the minimum allowed floor (7 days).
var ErrInvalidRetentionDays = errors.New("retention_override_days must be 0 (clear) or >= 7")

const minRetentionOverrideDays = 7

// SetSecretRetentionOverride sets or clears the per-secret retention override.
//
//   - days = 0 clears the override (reverts to the global policy).
//   - days >= 7 sets the override.
//   - Any other non-zero value returns ErrInvalidRetentionDays.
//
// The caller (transport layer) is responsible for ensuring the actor holds
// secrets.manage at the secret's scope before invoking this method.
func (c *KeyorixCore) SetSecretRetentionOverride(ctx context.Context, actorID, secretID uint, days int) error {
	if days != 0 && days < minRetentionOverrideDays {
		return fmt.Errorf("%w (got %d)", ErrInvalidRetentionDays, days)
	}
	if err := c.storage.SetRetentionOverride(ctx, secretID, days); err != nil {
		return err
	}
	uid := actorID
	sid := secretID
	var desc string
	if days == 0 {
		desc = fmt.Sprintf("cleared per-secret retention override on %s (reverts to global policy)", c.auditRef(ctx, c.storage, auditKindSecret, secretID))
	} else {
		desc = fmt.Sprintf("set per-secret retention override on %s to %d days", c.auditRef(ctx, c.storage, auditKindSecret, secretID), days)
	}
	c.writeAuditEvent(ctx, "secret.retention_override_set", &uid, &sid, desc)
	return nil
}

// GetEffectiveRetentionDays returns the effective retention window for a
// secret. If the secret has a non-zero RetentionOverrideDays the override wins;
// otherwise globalDays (the deployment-wide policy value) is returned. This is
// a pure, dependency-free helper for purge-sweep callers so they do not need to
// re-read the config for every secret they evaluate.
func GetEffectiveRetentionDays(secret *models.SecretNode, globalDays int) int {
	if secret.RetentionOverrideDays > 0 {
		return secret.RetentionOverrideDays
	}
	return globalDays
}
