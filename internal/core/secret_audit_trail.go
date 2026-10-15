// secret_audit_trail.go — per-secret audit trail: the lifecycle events of a single
// secret (created, rotated, rolled-back, suspended/resumed, shared, owner-transferred,
// reclassified, …) in newest-first order. Complements the access inspector (who CAN
// read) and access history (who HAS read) with WHAT HAPPENED to the secret — an
// investigation aid. Read-only; the caller must be able to read the secret. Returns
// audit-event metadata only (event type, actor, time, description, non-sensitive
// diff), never any secret value.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// defaultSecretAuditLimit bounds the trail when the caller does not specify a limit.
const defaultSecretAuditLimit = 50

// maxSecretAuditLimit caps the trail so a single request cannot pull an unbounded
// page of audit rows.
const maxSecretAuditLimit = 500

// ListSecretAuditEvents returns the secret's audit-trail entries, newest first. The
// actor must be able to read the secret. `limit` is clamped to [1, maxSecretAuditLimit];
// a non-positive limit falls back to defaultSecretAuditLimit.
func (c *KeyorixCore) ListSecretAuditEvents(ctx context.Context, secretID, actorID uint, limit int) ([]*models.AuditEvent, error) {
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = defaultSecretAuditLimit
	}
	if limit > maxSecretAuditLimit {
		limit = maxSecretAuditLimit
	}
	events, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		SecretID: &secretID,
		PageSize: limit,
		Count:    storage.AuditCountNone,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return events, nil
}
