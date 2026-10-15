// secret_listing_sharing.go — Sharing status queries and UI indicator builders.
//
// Provides GetSecretSharingStatus, GetSecretSharingStatusWithIndicators,
// GetUserSecretPermission, and the buildSharingIndicators / buildShareDetails helpers
// used by both this file and secret_listing_query.go.
//
// For the main list/filter/sort/paginate flow see secret_listing_query.go.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GetSecretSharingStatus returns the sharing status of a secret.
//
// #G10: this had no authorization check at all (and no actor param to check with) — any
// caller could learn a secret's share count and every recipient's name/ID. It now
// requires secrets.read on the secret, matching its sibling
// GetSecretSharingStatusWithIndicators's implicit owner-or-active-share gate.
func (c *KeyorixCore) GetSecretSharingStatus(ctx context.Context, actorKind string, actorID, secretID uint) (*models.SharingStatus, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if allowed, err := c.AuthorizeSecretPrincipal(ctx, actorKind, actorID, secretID, permSecretsRead); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	} else if !allowed {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "insufficient permissions")
	}

	shares, err := c.storage.ListSharesBySecret(ctx, secretID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	status := &models.SharingStatus{
		IsShared:   len(shares) > 0,
		ShareCount: len(shares),
	}

	for _, share := range shares {
		recipientName := ""
		if share.IsGroup {
			recipientName = fmt.Sprintf("Group %d", share.RecipientID)
		} else {
			if user, err := c.storage.GetUser(ctx, share.RecipientID); err == nil && user != nil {
				recipientName = user.Username
			}
		}
		status.Shares = append(status.Shares, &models.ShareSummary{
			ID:            share.ID,
			RecipientID:   share.RecipientID,
			RecipientName: recipientName,
			IsGroup:       share.IsGroup,
			Permission:    share.Permission,
			SharedAt:      share.CreatedAt,
		})
	}
	return status, nil
}

// GetSecretSharingStatusWithIndicators returns the sharing status of a secret with UI indicators.
func (c *KeyorixCore) GetSecretSharingStatusWithIndicators(ctx context.Context, secretID, userID uint) (*models.SharingStatusWithIndicators, error) { // NOSONAR -- cognitive complexity 21, suppress go:S3776
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	shares, err := c.storage.ListSharesBySecret(ctx, secretID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// Expired (time-bound) shares no longer authorize, so the reported sharing
	// status must not count or display them — keep it consistent with enforcement.
	shares = activeShares(shares, c.shareEffectiveNow())

	// Owner authority requires live project membership (requireLiveOwnerAuthority),
	// matching this file's GetUserSecretPermission and sharing_query.go's
	// ListSecretSharesWithPermissionCheck (RBAC-001): a departed owner keeps their
	// OwnerID tag until ClearProjectSecretOwnership runs, so a bare secretOwnedBy
	// check alone would report them as still holding owner-only sharing indicators
	// (and the full recipient list below) forever.
	// Owner authority requires live project membership (requireLiveOwnerAuthority),
	// matching this file's GetUserSecretPermission and sharing_query.go's
	// ListSecretSharesWithPermissionCheck (RBAC-001): a departed owner keeps their
	// OwnerID tag until ClearProjectSecretOwnership runs, so a bare secretOwnedBy
	// check alone would report them as still holding owner-only sharing indicators
	// (and the full recipient list below) forever.
	isOwner, err := c.requireLiveOwnerAuthority(ctx, secret, userID)
	if err != nil {
		return nil, err
	}
	userPermission := ""
	if !isOwner {
		for _, share := range shares {
			if !share.IsGroup && share.RecipientID == userID {
				userPermission = share.Permission
				break
			}
		}
		if userPermission == "" {
			return nil, fmt.Errorf("user does not have permission to access this secret")
		}
	}

	status := &models.SharingStatusWithIndicators{
		IsShared:       len(shares) > 0,
		ShareCount:     len(shares),
		IsOwner:        isOwner,
		UserPermission: userPermission,
	}

	for _, share := range shares {
		recipientName := ""
		if share.IsGroup {
			recipientName = fmt.Sprintf("Group %d", share.RecipientID)
		} else {
			if user, err := c.storage.GetUser(ctx, share.RecipientID); err == nil && user != nil {
				recipientName = user.Username
			} else {
				recipientName = fmt.Sprintf("User %d", share.RecipientID)
			}
		}
		status.Shares = append(status.Shares, &models.ShareSummary{
			ID:            share.ID,
			RecipientID:   share.RecipientID,
			RecipientName: recipientName,
			IsGroup:       share.IsGroup,
			Permission:    share.Permission,
			SharedAt:      share.CreatedAt,
		})
	}

	status.SharingIndicators = c.buildSharingIndicators(secret, shares, isOwner, userPermission)
	return status, nil
}

// GetUserSecretPermission returns a user's effective permission for a specific secret.
func (c *KeyorixCore) GetUserSecretPermission(ctx context.Context, secretID, userID uint) (*models.UserSecretPermission, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	// Owner authority requires live project membership (requireLiveOwnerAuthority),
	// matching this file's GetSecretSharingStatusWithIndicators and
	// sharing_query.go's ListSecretSharesWithPermissionCheck (RBAC-001): a departed
	// owner keeps their OwnerID tag until ClearProjectSecretOwnership runs, so a bare
	// secretOwnedBy check alone would report them as still holding "owner" permission.
	// Owner authority requires live project membership (requireLiveOwnerAuthority),
	// matching this file's GetSecretSharingStatusWithIndicators and
	// sharing_query.go's ListSecretSharesWithPermissionCheck (RBAC-001): a departed
	// owner keeps their OwnerID tag until ClearProjectSecretOwnership runs, so a bare
	// secretOwnedBy check alone would report them as still holding "owner" permission.
	isLiveOwner, err := c.requireLiveOwnerAuthority(ctx, secret, userID)
	if err != nil {
		return nil, err
	}
	if isLiveOwner {
		return &models.UserSecretPermission{
			SecretID:   secretID,
			UserID:     userID,
			Permission: "owner",
			Source:     "owner",
		}, nil
	}

	shares, err := c.storage.ListSharesBySecret(ctx, secretID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// An expired share grants no permission — match the authorization gate.
	shares = activeShares(shares, c.shareEffectiveNow())

	for _, share := range shares {
		if !share.IsGroup && share.RecipientID == userID {
			return &models.UserSecretPermission{
				SecretID:   secretID,
				UserID:     userID,
				Permission: share.Permission,
				Source:     "direct_share",
				ShareID:    &share.ID,
			}, nil
		}
	}

	return nil, fmt.Errorf("user does not have permission to access this secret")
}

// buildSharingIndicators creates UI indicators for a secret based on sharing information.
func (c *KeyorixCore) buildSharingIndicators(secret *models.SecretNode, shares []*models.ShareRecord, isOwner bool, userPermission string) *models.SharingIndicators {
	return c.buildSharingIndicatorsNamed(secret, shares, isOwner, userPermission, nil)
}

// buildSharingIndicatorsNamed is buildSharingIndicators with the share recipients'
// usernames already resolved (a listing resolves them once for the whole page,
// LIST-ENDPOINTS-1). nil names means "look each recipient up", the single-secret path.
func (c *KeyorixCore) buildSharingIndicatorsNamed(_ *models.SecretNode, shares []*models.ShareRecord, isOwner bool, userPermission string, names map[uint]string) *models.SharingIndicators {
	indicators := &models.SharingIndicators{
		CanRead:   true,
		CanWrite:  isOwner || userPermission == string(PermissionWrite),
		CanShare:  isOwner,
		CanDelete: isOwner,
	}

	if isOwner {
		if len(shares) > 0 {
			indicators.Icon = "shared-owner"
			indicators.Badge = "OWNER"
			indicators.BadgeColor = "green"
			indicators.StatusText = fmt.Sprintf("You own this secret (shared with %d)", len(shares))
		} else {
			indicators.Icon = "owned"
			indicators.Badge = "OWNER"
			indicators.BadgeColor = "blue"
			indicators.StatusText = "You own this secret"
		}
	} else {
		switch userPermission {
		case string(PermissionRead):
			indicators.Icon = "shared-read"
			indicators.Badge = "READ-ONLY"
			indicators.BadgeColor = "orange"
			indicators.StatusText = "Shared with you (read-only)"
		case string(PermissionWrite):
			indicators.Icon = "shared-write"
			indicators.Badge = "SHARED"
			indicators.BadgeColor = "blue"
			indicators.StatusText = "Shared with you (can edit)"
		default:
			indicators.Icon = "shared"
			indicators.Badge = "SHARED"
			indicators.BadgeColor = "gray"
			indicators.StatusText = "Shared with you"
		}
	}

	if len(shares) > 0 {
		indicators.ShareDetails = c.buildShareDetailsNamed(shares, names)
	}
	return indicators
}

// buildShareDetails creates detailed sharing information for UI display.
func (c *KeyorixCore) buildShareDetails(shares []*models.ShareRecord) *models.ShareDetails {
	return c.buildShareDetailsNamed(shares, nil)
}

// buildShareDetailsNamed is buildShareDetails with pre-resolved recipient usernames;
// nil names falls back to one GetUser per direct recipient. A recipient missing from
// a non-nil names map keeps the "User N" placeholder, as an unreadable user does.
func (c *KeyorixCore) buildShareDetailsNamed(shares []*models.ShareRecord, names map[uint]string) *models.ShareDetails { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	details := &models.ShareDetails{TotalShares: len(shares)}

	var directShares, groupShares, readCount, writeCount int
	var recentShares []*models.RecentShareInfo

	for _, share := range shares {
		if share.IsGroup {
			groupShares++
		} else {
			directShares++
		}
		switch share.Permission {
		case string(PermissionRead):
			readCount++
		case string(PermissionWrite):
			writeCount++
		}

		isRecent := time.Since(share.CreatedAt).Hours() < 168 // 7 days

		recipientName := fmt.Sprintf("User %d", share.RecipientID)
		recipientType := "user" //nolint:goconst
		if share.IsGroup {
			recipientType = "group" //nolint:goconst
			recipientName = fmt.Sprintf("Group %d", share.RecipientID)
		} else if names != nil {
			if n := names[share.RecipientID]; n != "" {
				recipientName = n
			}
		} else if user, err := c.storage.GetUser(context.Background(), share.RecipientID); err == nil && user != nil {
			recipientName = user.Username
		}

		if isRecent || len(recentShares) < 5 {
			recentShares = append(recentShares, &models.RecentShareInfo{
				RecipientName: recipientName,
				RecipientType: recipientType,
				Permission:    share.Permission,
				SharedAt:      share.CreatedAt,
				IsRecent:      isRecent,
			})
		}
	}

	details.DirectShares = directShares
	details.GroupShares = groupShares
	details.RecentShares = recentShares

	switch {
	case directShares > 0 && groupShares > 0:
		details.ShareSummary = fmt.Sprintf("Shared with %d users and %d groups", directShares, groupShares)
	case directShares > 0:
		details.ShareSummary = fmt.Sprintf("Shared with %d users", directShares)
	case groupShares > 0:
		details.ShareSummary = fmt.Sprintf("Shared with %d groups", groupShares)
	default:
		details.ShareSummary = "Not shared"
	}

	switch {
	case readCount > 0 && writeCount > 0:
		details.PermissionText = fmt.Sprintf("%d with read access, %d with write access", readCount, writeCount)
	case readCount > 0:
		details.PermissionText = fmt.Sprintf("%d with read access", readCount)
	case writeCount > 0:
		details.PermissionText = fmt.Sprintf("%d with write access", writeCount)
	}

	return details
}
