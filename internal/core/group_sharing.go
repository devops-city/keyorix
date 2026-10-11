package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GroupShareSecretRequest represents a request to share a secret with a group
type GroupShareSecretRequest struct {
	SecretID   uint   `json:"secret_id" validate:"required"`
	GroupID    uint   `json:"group_id" validate:"required"`
	Permission string `json:"permission" validate:"required,oneof=read write"`
	SharedBy   uint   `json:"shared_by" validate:"required"`
	// ExpiresAt, when set, makes the group share time-bound; see ShareSecretRequest.ExpiresAt.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ShareSecretWithGroup shares a secret with a group
func (c *KeyorixCore) ShareSecretWithGroup(ctx context.Context, req *GroupShareSecretRequest) (*models.ShareRecord, error) {
	// Validate request
	if err := c.validateGroupShareSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Get the secret to check ownership.
	secret, err := c.GetSecret(ctx, req.SecretID)
	if err != nil {
		return nil, err
	}
	// Only the owner may share a secret — mirror the direct (non-group) path.
	// Without this, any caller with secrets.write could group-share a secret they
	// do not own, granting their group read/write access to it. Owner authority also
	// requires live project membership — see ShareSecret / CheckSecretPermission
	// (RBAC-001): an owner removed from the project keeps their OwnerID tag until
	// ClearProjectSecretOwnership runs.
	if err := c.requireShareAuthority(ctx, secret, req.SharedBy); err != nil {
		return nil, err
	}

	// Reject cross-project grants: the target group must itself be scoped to the
	// secret's project (i.e. hold a live role grant at that project), mirroring
	// the cross-project rejection ShareSecret's direct-user path performs for
	// individual recipients. Without this, sharing with a group pulls in every
	// current and future member of that group — including members with no tie
	// to this project at all — into standing access to the secret; see
	// CheckGroupPermissions, which enforces group membership but never the
	// accessing user's project affiliation, so nothing downstream catches this.
	if isScoped, serr := c.storage.IsGroupProjectScoped(ctx, req.GroupID, secret.ProjectID); serr != nil {
		return nil, fmt.Errorf("failed to verify group project scope: %w", serr)
	} else if !isScoped {
		return nil, shareRefusal(ErrShareGroupNotInProject)
	}

	// A time-bound share must expire in the future (see ShareSecret).
	if req.ExpiresAt != nil && !req.ExpiresAt.After(c.now()) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "share expiry must be in the future")
	}

	// Create share record
	shareRecord := &models.ShareRecord{
		SecretID:    req.SecretID,
		OwnerID:     secret.OwnerID,
		RecipientID: req.GroupID,
		IsGroup:     true,
		Permission:  req.Permission,
		ExpiresAt:   req.ExpiresAt,
	}

	// Validate the group share record
	if err := models.ValidateGroupShare(shareRecord); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Store the share record
	createdShare, err := c.storage.CreateShareRecord(ctx, shareRecord)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Log the group share creation with enhanced audit logging
	auditCtx := &ShareAuditContext{
		ActorID:     req.SharedBy,
		SecretID:    secret.ID,
		RecipientID: req.GroupID,
		IsGroup:     true,
		Permission:  req.Permission,
		ShareID:     createdShare.ID,
	}
	c.LogGroupShareCreated(ctx, auditCtx)

	return createdShare, nil
}

// ListGroupShares lists all shares for a group.
//
// #G10: this used to have no caller-scoping of its own — any principal reaching it
// (directly, or via a future transport this codebase hasn't wired yet) could list any
// group's shares, trusting the HTTP router's own permSecretsRead gate to have already
// run. It now checks that gate itself, mirroring the router's actual requirement
// (server/http/router.go), so it's safe to call from any transport.
func (c *KeyorixCore) ListGroupShares(ctx context.Context, actorKind string, actorID, groupID uint) ([]*models.ShareRecord, error) {
	if groupID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	if allowed, err := c.AuthorizePrincipal(ctx, actorKind, actorID, permSecretsRead, Scope{}); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	} else if !allowed {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "not authorized to list this group's shares")
	}

	// Get shares from storage
	shares, err := c.storage.ListSharesByGroup(ctx, groupID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return shares, nil
}

// ListGroupSharedSecrets lists the live secrets currently shared with a group — the
// "what can this group reach via shares" view. Composes the group's share records
// (ListSharesByGroup) with the secrets themselves, skipping expired time-bound shares
// (which no longer authorize) and any share whose secret is gone, and de-duplicating
// by secret. Never reads a value.
//
// #G10: this had no caller-scoping parameter at all — same gap as ListGroupShares
// above, closed the same way.
func (c *KeyorixCore) ListGroupSharedSecrets(ctx context.Context, actorKind string, actorID, groupID uint) ([]*models.SecretNode, error) {
	if groupID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	if allowed, err := c.AuthorizePrincipal(ctx, actorKind, actorID, permSecretsRead, Scope{}); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	} else if !allowed {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "not authorized to list this group's shared secrets")
	}

	shares, err := c.storage.ListSharesByGroup(ctx, groupID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	// #1653: shares the same clamp-based clock as shareActive/activeShares
	// (permissions.go) rather than a bare c.now() — this is the same
	// "share still authorizes" predicate, duplicated inline instead of
	// calling shareActive, so it gets the same defense against a
	// backward-stepped clock resurrecting an expired time-bound share.
	now := c.shareEffectiveNow()
	secrets := make([]*models.SecretNode, 0, len(shares))
	seen := make(map[uint]bool, len(shares))
	for _, s := range shares {
		// An expired time-bound share no longer authorizes, so it must not surface here.
		if s.ExpiresAt != nil && !s.ExpiresAt.After(now) {
			continue
		}
		if seen[s.SecretID] {
			continue
		}
		secret, err := c.storage.GetSecret(ctx, s.SecretID)
		if err != nil || secret == nil {
			continue // secret deleted/missing — skip it
		}
		seen[s.SecretID] = true
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

// CheckUserGroupPermission checks if a user has permission to access a secret via group membership
func (c *KeyorixCore) CheckUserGroupPermission(ctx context.Context, secretID, userID uint) (bool, string, error) {
	if secretID == 0 {
		return false, "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return false, "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	// This would require a new method in the storage interface
	// For now, we'll just return false
	return false, "", nil
}

// Validation methods

func (c *KeyorixCore) validateGroupShareSecretRequest(req *GroupShareSecretRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.SecretID == 0 {
		return fmt.Errorf("secret ID is required")
	}
	if req.GroupID == 0 {
		return fmt.Errorf("group ID is required")
	}
	if req.Permission != "read" && req.Permission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", req.Permission)
	}
	if req.SharedBy == 0 {
		return fmt.Errorf("sharedBy is required")
	}
	return nil
}
