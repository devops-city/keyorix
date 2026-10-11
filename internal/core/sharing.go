// sharing.go — ShareSecret, UpdateSharePermission, RevokeShare, RemoveSelfFromShare.
//
// Request types also live here (ShareSecretRequest, UpdateShareRequest).
// For list/query operations see sharing_query.go.
// For validation helpers see sharing_validation.go.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ShareSecretRequest represents a request to share a secret with another user or group.
type ShareSecretRequest struct {
	SecretID    uint   `json:"secret_id" validate:"required"`
	RecipientID uint   `json:"recipient_id" validate:"required"`
	IsGroup     bool   `json:"is_group"`
	Permission  string `json:"permission" validate:"required,oneof=read write"`
	SharedBy    uint   `json:"shared_by" validate:"required"`
	// ExpiresAt, when set, makes the share time-bound (just-in-time access): it stops
	// authorizing the instant it passes and is later swept. nil = a permanent share.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// UpdateShareRequest represents a request to update a share's permissions and,
// optionally, its time-bound expiry. Expiry semantics: ClearExpiry makes the share
// permanent; otherwise a non-nil ExpiresAt sets/extends/shortens it (must be in the
// future); leaving both unset preserves the share's current expiry.
type UpdateShareRequest struct {
	ShareID     uint       `json:"share_id" validate:"required"`
	Permission  string     `json:"permission" validate:"required,oneof=read write"`
	UpdatedBy   uint       `json:"updated_by" validate:"required"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	ClearExpiry bool       `json:"clear_expiry,omitempty"`
}

// ShareSecret shares a secret with another user or group.
func (c *KeyorixCore) ShareSecret(ctx context.Context, req *ShareSecretRequest) (*models.ShareRecord, error) {
	if err := c.validateShareSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	secret, err := c.GetSecret(ctx, req.SecretID)
	if err != nil {
		return nil, err
	}

	// Only the secret owner may share it (an ownerless / machine-created secret —
	// OwnerID 0 — is owned by nobody and cannot be shared via the owner gate), and
	// only while still a live member of the secret's project — mirrors
	// CheckSecretPermission's owner branch (RBAC-001): an owner removed from the
	// project keeps their OwnerID tag until ClearProjectSecretOwnership runs.
	// requireShareAuthority says which half failed (#2976: a global-only admin owns
	// what they create but is a member of no project, and used to get a bare 403).
	if err := c.requireShareAuthority(ctx, secret, req.SharedBy); err != nil {
		return nil, err
	}

	// For user shares, reject cross-project grants: the recipient must be a member of
	// the secret's project. Group shares are not gated here — every group-share
	// caller (HTTP, gRPC) routes to ShareSecretWithGroup (group_sharing.go) instead
	// of here, and that function performs its own analogous cross-project check
	// (IsGroupProjectScoped) against the group recipient. This is NOT compensated
	// for at access time: CheckGroupPermissions (permissions.go) checks only group
	// membership, never the accessing user's project affiliation.
	if !req.IsGroup {
		if isMember, merr := c.IsProjectMember(ctx, req.RecipientID, secret.ProjectID); merr != nil {
			return nil, fmt.Errorf("failed to verify project membership: %w", merr)
		} else if !isMember {
			return nil, shareRefusal(ErrShareRecipientNotMember)
		}
	}

	// A time-bound share must expire in the future; a past/now expiry would create a
	// share that never authorizes.
	if req.ExpiresAt != nil && !req.ExpiresAt.After(c.now()) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "share expiry must be in the future")
	}

	shareRecord := &models.ShareRecord{
		SecretID:    req.SecretID,
		OwnerID:     secret.OwnerID,
		RecipientID: req.RecipientID,
		IsGroup:     req.IsGroup,
		Permission:  req.Permission,
		ExpiresAt:   req.ExpiresAt,
	}
	createdShare, err := c.storage.CreateShareRecord(ctx, shareRecord)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	auditCtx := &ShareAuditContext{
		ActorID:     req.SharedBy,
		SecretID:    secret.ID,
		RecipientID: req.RecipientID,
		IsGroup:     req.IsGroup,
		Permission:  req.Permission,
		ShareID:     createdShare.ID,
	}
	if req.IsGroup {
		c.LogGroupShareCreated(ctx, auditCtx)
		// Fan the "shared with you" notice out to each group member. Best-effort.
		c.notifyGroupSecretShared(ctx, secret, req.RecipientID, req.SharedBy, req.Permission)
	} else {
		c.LogShareCreated(ctx, auditCtx)
		// Tell the recipient they've been granted access. Best-effort.
		c.notifySecretShared(ctx, secret, req.RecipientID, req.SharedBy, req.Permission)
	}

	return createdShare, nil
}

// UpdateSharePermission updates the permission level of an existing share.
func (c *KeyorixCore) UpdateSharePermission(ctx context.Context, req *UpdateShareRequest) (*models.ShareRecord, error) {
	if err := c.validateUpdateShareRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	shareRecord, err := c.storage.GetShareRecord(ctx, req.ShareID)
	if err != nil {
		return nil, err
	}

	secret, err := c.storage.GetSecret(ctx, shareRecord.SecretID)
	if err != nil {
		return nil, err
	}
	// Owner authority also requires live project membership — see ShareSecret.
	if err := c.requireShareAuthority(ctx, secret, req.UpdatedBy); err != nil {
		return nil, err
	}

	if shareRecord.ExpiresAt != nil && shareRecord.ExpiresAt.Before(c.now()) {
		return nil, fmt.Errorf("cannot update an expired share record; revoke and re-share instead")
	}

	// Resolve the share's expiry: clear it (permanent), set/extend/shorten it, or
	// preserve the current value when the request specifies neither. A new expiry must
	// be in the future, just like at creation.
	switch {
	case req.ClearExpiry:
		shareRecord.ExpiresAt = nil
	case req.ExpiresAt != nil:
		if !req.ExpiresAt.After(c.now()) {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "share expiry must be in the future")
		}
		shareRecord.ExpiresAt = req.ExpiresAt
	}

	oldPermission := shareRecord.Permission
	shareRecord.Permission = req.Permission
	updatedShare, err := c.storage.UpdateShareRecord(ctx, shareRecord)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	auditCtx := &ShareAuditContext{
		ActorID:       req.UpdatedBy,
		SecretID:      updatedShare.SecretID,
		RecipientID:   updatedShare.RecipientID,
		IsGroup:       updatedShare.IsGroup,
		Permission:    updatedShare.Permission,
		OldPermission: oldPermission,
		ShareID:       updatedShare.ID,
	}
	if updatedShare.IsGroup {
		c.LogGroupShareUpdated(ctx, auditCtx)
	} else {
		c.LogShareUpdated(ctx, auditCtx)
	}

	return updatedShare, nil
}

// RevokeShare revokes a share. Only the secret owner can revoke.
func (c *KeyorixCore) RevokeShare(ctx context.Context, shareID uint, revokedBy uint) error {
	shareRecord, err := c.storage.GetShareRecord(ctx, shareID)
	if err != nil {
		return err
	}

	secret, err := c.storage.GetSecret(ctx, shareRecord.SecretID)
	if err != nil {
		return err
	}
	// Owner authority also requires live project membership — see ShareSecret.
	if err := c.requireShareAuthority(ctx, secret, revokedBy); err != nil {
		return err
	}

	// Wrapped in a transaction (not a bare c.storage.DeleteShareRecord call) so a
	// fault that reports an error AFTER the real delete already committed (effect-
	// then-error — e.g. a lost ack, not just a genuine failure) rolls the delete
	// back too, instead of leaving a mixed state: ShareRecord deleted (new state)
	// but the audit/notification below never attempted (old state) — a share
	// silently revoked with zero audit trail and no notification to the affected
	// user. Found live: FuzzStorageFaultOperations op="REST DELETE /api/v1/shares/{id}"
	// fault=DeleteShareRecord#1/effect-then-error, ORACLE (d) VIOLATION (differing
	// tables vs before: [ShareRecord]; vs reference: [SecretAccessLog AuditEvent
	// Notification]). Same root cause and fix shape as PR #1996 (CreateSecret).
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return tx.DeleteShareRecord(ctx, shareID)
	}); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Only log the revocation once the storage mutation has actually succeeded —
	// logging first would leave a phantom "revoked" audit record if the delete
	// failed and the share stayed live (#283).
	auditCtx := &ShareAuditContext{
		ActorID:     revokedBy,
		SecretID:    shareRecord.SecretID,
		RecipientID: shareRecord.RecipientID,
		IsGroup:     shareRecord.IsGroup,
		Permission:  shareRecord.Permission,
		ShareID:     shareRecord.ID,
	}
	if shareRecord.IsGroup {
		c.LogGroupShareRevoked(ctx, auditCtx)
	} else {
		c.LogShareRevoked(ctx, auditCtx)
	}
	// Tell the affected user(s) their access was revoked. Best-effort.
	if shareRecord.IsGroup {
		c.notifyGroupSecretShareRevoked(ctx, secret, shareRecord.RecipientID, revokedBy)
	} else {
		c.notifySecretShareRevoked(ctx, secret, shareRecord.RecipientID, revokedBy)
	}
	return nil
}

// RemoveSelfFromShare allows a user to remove themselves from a shared secret.
func (c *KeyorixCore) RemoveSelfFromShare(ctx context.Context, secretID, userID uint) error {
	if secretID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	shares, err := c.storage.ListSharesBySecret(ctx, secretID, c.shareEffectiveNow())
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var shareToRemove *models.ShareRecord
	for _, share := range shares {
		if !share.IsGroup && share.RecipientID == userID {
			shareToRemove = share
			break
		}
	}
	if shareToRemove == nil {
		return fmt.Errorf("%s", i18n.T("ErrorShareNotFound", nil))
	}

	if _, err = c.storage.GetSecret(ctx, secretID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	if err := c.storage.DeleteShareRecord(ctx, shareToRemove.ID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Only log the removal once the storage mutation has actually succeeded — see
	// RevokeShare for why (#283).
	c.LogSelfRemovalFromShare(ctx, &ShareAuditContext{
		ActorID:     userID,
		SecretID:    secretID,
		RecipientID: userID,
		IsGroup:     false,
		Permission:  shareToRemove.Permission,
		ShareID:     shareToRemove.ID,
	})
	return nil
}
