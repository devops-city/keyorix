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

	// Reject cross-project grants: the recipient must be a member of the secret's
	// project. Group shares never reach here (validateShareSecretRequest refuses
	// IsGroup, #3422): they go through ShareSecretWithGroup (group_sharing.go), which
	// performs the analogous cross-project check (IsGroupProjectScoped). That check
	// is NOT compensated for at access time: CheckGroupPermissions (permissions.go)
	// checks only group membership, never the accessing user's project affiliation.
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
	// AUDIT-TX-2: the share record and its share_created / group_share_created
	// row commit in ONE transaction; notifications run after the commit.
	// SHARE-CAS-1: no row lock needed for the upsert of an existing share: it is
	// never classified, so it always fails closed whatever the row held.
	var createdShare *models.ShareRecord
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var err error
		if createdShare, err = tx.CreateShareRecord(ctx, shareRecord); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		eventType := ShareAuditEventCreated
		if req.IsGroup {
			eventType = ShareAuditEventGroupCreated
		}
		c.logShareCreatedOn(ctx, tgt, eventType, &ShareAuditContext{
			ActorID:     req.SharedBy,
			SecretID:    secret.ID,
			RecipientID: req.RecipientID,
			IsGroup:     req.IsGroup,
			Permission:  req.Permission,
			ShareID:     createdShare.ID,
		})
		return nil
	}); err != nil {
		return nil, err
	}

	if req.IsGroup {
		// Fan the "shared with you" notice out to each group member. Best-effort.
		c.notifyGroupSecretShared(ctx, secret, req.RecipientID, req.SharedBy, req.Permission)
	} else {
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
	// preserve the current value when the request specifies neither (resolved from
	// the locked row inside the transaction below). A new expiry must be in the
	// future, just like at creation.
	preserveExpiry := !req.ClearExpiry && req.ExpiresAt == nil
	switch {
	case req.ClearExpiry:
		shareRecord.ExpiresAt = nil
	case req.ExpiresAt != nil:
		if !req.ExpiresAt.After(c.now()) {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "share expiry must be in the future")
		}
		shareRecord.ExpiresAt = req.ExpiresAt
	}

	shareRecord.Permission = req.Permission
	// AUDIT-TX-2 + REVIEW-2 on #3367: an update can widen a share (permission
	// or expiry) or narrow it, so it is classified per call against the share
	// as read INSIDE the transaction. One that only narrows it (or changes
	// nothing) is a revocation or neutral: never blocked by the audit log, its
	// share_updated / group_share_updated row owed (withOwedAuditMutation). One
	// that only widens commits with its row or not at all. One that does both
	// (a lower permission and a later expiry, or the reverse) is split
	// (audit_split.go, MERGE-FIX-3482K, ask 3482-mixed-update-role-share (a)):
	// commit 1 applies the narrower value of each part, owed; commit 2 then
	// applies the requested share, fail closed.
	//
	// SHARE-CAS-1: each commit reads with LockShareRecordForUpdate, so on
	// PostgreSQL READ COMMITTED no other writer can change the row between that
	// commit's classification and its UPDATE: a concurrent narrowing waits for
	// the commit and then applies on top of it. With a plain read it could commit
	// in between, and a write classified neutral (write→write) would land write
	// over read with only an owed row. The expiry check and a preserved expiry
	// use the same row. Group shares take this same path (there is no separate
	// group-share update).
	var updatedShare *models.ShareRecord
	// lockShare is the locked read both commits start from; it resolves the requested
	// share (want) against it.
	lockShare := func(tx storage.Storage) (cur, want *models.ShareRecord, err error) {
		if cur, err = tx.LockShareRecordForUpdate(ctx, shareRecord.ID); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		if cur.ExpiresAt != nil && cur.ExpiresAt.Before(c.now()) {
			return nil, nil, fmt.Errorf("cannot update an expired share record; revoke and re-share instead")
		}
		want = shareRecord
		if preserveExpiry {
			want.ExpiresAt = cur.ExpiresAt
		}
		return cur, want, nil
	}
	// write sets the share to (perm, exp) and writes its row through tgt, last.
	write := func(tx storage.Storage, tgt auditTarget, cur *models.ShareRecord, perm string, exp *time.Time) error {
		next := *cur
		next.Permission, next.ExpiresAt = perm, exp
		var err error
		if updatedShare, err = tx.UpdateShareRecord(ctx, &next); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		eventType := ShareAuditEventUpdated
		if updatedShare.IsGroup {
			eventType = ShareAuditEventGroupUpdated
		}
		c.logShareUpdatedOn(ctx, tgt, eventType, &ShareAuditContext{
			ActorID:       req.UpdatedBy,
			SecretID:      updatedShare.SecretID,
			RecipientID:   updatedShare.RecipientID,
			IsGroup:       updatedShare.IsGroup,
			Permission:    updatedShare.Permission,
			OldPermission: cur.Permission,
			ShareID:       updatedShare.ID,
		})
		return nil
	}
	// Commit 1, owed: the narrowing part alone, or all of an update that widens
	// nothing; nothing at all for one that only widens.
	var narrowed, rest bool
	if err := c.withOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		// fn may run again (the owed fallback): start from a clean slate.
		updatedShare, narrowed, rest = nil, false, false
		cur, want, err := lockShare(tx)
		if err != nil {
			return err
		}
		if !shareUpdateWidens(cur.Permission, cur.ExpiresAt, want.Permission, want.ExpiresAt) {
			return write(tx, tgt, cur, want.Permission, want.ExpiresAt)
		}
		rest = true
		perm, exp, ok := shareUpdateNarrowing(cur.Permission, cur.ExpiresAt, want.Permission, want.ExpiresAt)
		if !ok {
			return nil // only widens: commit 2 alone, fail closed
		}
		narrowed = true
		return write(tx, tgt, cur, perm, exp)
	}); err != nil {
		return nil, err
	}
	if !rest {
		return updatedShare, nil
	}
	// Commit 2, fail closed: the requested share, on the row as locked now.
	widen := func(tx storage.Storage, tgt auditTarget) error {
		cur, want, err := lockShare(tx)
		if err != nil {
			return err
		}
		return write(tx, tgt, cur, want.Permission, want.ExpiresAt)
	}
	if narrowed {
		// A retry of the same request finds the narrowing applied, so only this part runs.
		if err := c.commitSplitRemainder(ctx, "share narrowing", "share widening", true, widen); err != nil {
			return nil, err
		}
	} else if err := c.withAuditedMutation(ctx, widen); err != nil {
		return nil, err
	}

	return updatedShare, nil
}

// shareUpdateNarrowing is the narrowing part of changing a share from (oldPerm,
// oldExp) to (newPerm, newExp): each part at the narrower of its old and new value (the
// lower permission, the earlier expiry; a nil expiry is permanent). ok is false when
// that is the old share itself (nothing narrows) or a permission level is unknown (the
// update is then fail closed as a whole, like shareUpdateWidens).
func shareUpdateNarrowing(oldPerm string, oldExp *time.Time, newPerm string, newExp *time.Time) (perm string, exp *time.Time, ok bool) {
	oldRank, newRank := sharePermissionRank(oldPerm), sharePermissionRank(newPerm)
	if oldRank == 0 || newRank == 0 {
		return "", nil, false
	}
	perm, exp = oldPerm, oldExp
	if newRank < oldRank {
		perm, ok = newPerm, true
	}
	if newExp != nil && (oldExp == nil || newExp.Before(*oldExp)) {
		exp, ok = newExp, true
	}
	return perm, exp, ok
}

// sharePermissionRank orders the share permission levels; 0 is unknown.
func sharePermissionRank(p string) int {
	switch PermissionLevel(p) {
	case PermissionRead:
		return 1
	case PermissionWrite:
		return 2
	}
	return 0
}

// shareUpdateWidens reports whether changing a share from (oldPerm, oldExp) to
// (newPerm, newExp) gives the recipient anything it did not have: a higher
// permission, a later expiry, or no expiry where there was one. A mixed change
// (one narrower, one wider) widens. An unknown permission level counts as
// widening, so it fails closed. A nil expiry means permanent.
func shareUpdateWidens(oldPerm string, oldExp *time.Time, newPerm string, newExp *time.Time) bool {
	oldRank, newRank := sharePermissionRank(oldPerm), sharePermissionRank(newPerm)
	if oldRank == 0 || newRank == 0 || newRank > oldRank {
		return true
	}
	switch {
	case oldExp == nil:
		return false // permanent before: any expiry narrows, none keeps it
	case newExp == nil:
		return true // time-bound before, permanent now
	default:
		return newExp.After(*oldExp)
	}
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
	//
	// AUDIT-TX-3: the share-revoked row is owed from this same transaction (a
	// revocation is never blocked by the audit log; its row is never lost either).
	// The row describes a revocation that really committed with it (#283).
	auditCtx := &ShareAuditContext{
		ActorID:     revokedBy,
		SecretID:    shareRecord.SecretID,
		RecipientID: shareRecord.RecipientID,
		IsGroup:     shareRecord.IsGroup,
		Permission:  shareRecord.Permission,
		ShareID:     shareRecord.ID,
	}
	if err := c.withOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.DeleteShareRecord(ctx, shareID); err != nil {
			return err
		}
		if shareRecord.IsGroup {
			c.logGroupShareRevokedOn(ctx, tgt, auditCtx)
		} else {
			c.logShareRevokedOn(ctx, tgt, auditCtx)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
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

	// AUDIT-TX-3: see RevokeShare: the row is owed from the removal's transaction.
	if err := c.withOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.DeleteShareRecord(ctx, shareToRemove.ID); err != nil {
			return err
		}
		c.logSelfRemovalFromShareOn(ctx, tgt, &ShareAuditContext{
			ActorID:     userID,
			SecretID:    secretID,
			RecipientID: userID,
			IsGroup:     false,
			Permission:  shareToRemove.Permission,
			ShareID:     shareToRemove.ID,
		})
		return nil
	}); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}
