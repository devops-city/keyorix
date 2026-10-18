// pat_expiry_enforce.go — PAT expiry enforcement helpers (ADR-027).
//
// IsPATExpired is a pure, clock-injectable predicate used both on the auth hot
// path (ValidatePATToken) and in tests.  emitPATExpiredNotification fires a
// best-effort in-app notification so the owner knows to clean up.
// ListExpiredOwnPATs / BulkRevokeExpiredOwnPATs give the user a self-service
// way to enumerate and retire their dead tokens.
package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrPATExpired is returned by ValidatePATToken when the presented token has
// passed its ExpiresAt.  The caller (auth middleware) surfaces it as a 401.
var ErrPATExpired = errors.New("token expired")

// ErrPATRevoked is returned by ValidatePATToken/CurrentPATRestriction when the
// presented token has been revoked.  The caller (auth middleware) surfaces it
// as a 401.
var ErrPATRevoked = errors.New("token revoked")

// IsPATExpired reports whether pat has a non-nil ExpiresAt that is in the past
// relative to now.  It is a pure function — injectable for testing.
func IsPATExpired(pat *models.PersonalAccessToken, now time.Time) bool {
	return pat.ExpiresAt != nil && now.After(*pat.ExpiresAt)
}

// emitPATExpiredNotification creates a best-effort in-app notification for the
// PAT owner when an expired token is presented at the auth boundary.  Errors
// are swallowed so a failed insert never blocks the auth rejection.
//
// Deduplicated the same way as every other standing reminder in this package
// (see unreadPATExpiryReminder / unreadMachineCredExpiryReminder in
// token_expiry_remind.go, unreadRoleExpiryReminder, unreadRotationReminder,
// unreadExpiryReminder): skip creating a new notification while the owner
// already has an unread one of this type for this exact token. Without this,
// anyone who ever captured the raw token string — even long after it stopped
// being valid for anything else — could keep presenting it at the auth
// boundary and get a fresh notification (and any wired email/webhook
// delivery) fired every single time, spamming the owner indefinitely. The
// standing notification only clears, letting a fresh one fire, once the
// owner reads/dismisses it — this codebase has no time-window/cooldown-based
// dedup anywhere; every periodic-notification mechanism here dedups on
// unread-notification presence instead, so this follows suit rather than
// inventing a new mechanism.
func (c *KeyorixCore) emitPATExpiredNotification(ctx context.Context, pat *models.PersonalAccessToken) {
	if pat.UserID == 0 {
		return
	}
	link := patExpiredUsedLink(pat.ID)
	if c.unreadPATExpiredUsedReminder(ctx, pat.UserID, link) != nil {
		return
	}
	c.notifyWithSeverity(
		ctx,
		pat.UserID,
		NotificationPATExpiredUsed,
		"Expired PAT presented",
		fmt.Sprintf("Personal access token '%s' has expired and was rejected. Revoke or replace it.", pat.Name),
		nil,
		link,
		models.NotificationSeverityWarning,
	)
}

// patExpiredUsedLink builds the stable per-token dedup key (and in-app
// navigation target) for an "expired PAT presented" notification. Keyed on
// the token's ID, not its display Name — two PATs owned by the same user are
// not required to have distinct names, and matching on name would let one
// token's standing reminder silently suppress a distinct token's reminder
// (mirrors the #G22 rationale for patExpiryLink/machineCredExpiryLink in
// token_expiry_remind.go).
func patExpiredUsedLink(patID uint) string {
	return fmt.Sprintf("/account/tokens?token=%d", patID)
}

// unreadPATExpiredUsedReminder returns an existing unread "expired PAT
// presented" notification for the given user matching link (see
// patExpiredUsedLink), or nil if none exists (including on a storage error —
// best-effort, same fail-open behavior as unreadPATExpiryReminder).
func (c *KeyorixCore) unreadPATExpiredUsedReminder(ctx context.Context, userID uint, link string) *models.Notification {
	notes, err := c.storage.ListNotifications(ctx, userID, true, 200)
	if err != nil {
		return nil
	}
	for _, n := range notes {
		if n.Type == NotificationPATExpiredUsed && n.Link == link {
			return n
		}
	}
	return nil
}

// ListExpiredOwnPATs returns the caller's own non-revoked PATs whose ExpiresAt
// is in the past.
func (c *KeyorixCore) ListExpiredOwnPATs(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.ListExpiredPATsByUser(ctx, userID, c.now())
}

// BulkRevokeExpiredOwnPATs revokes all the caller's non-revoked, expired PATs
// and returns the revoked token hashes for auth-cache eviction.
func (c *KeyorixCore) BulkRevokeExpiredOwnPATs(ctx context.Context, userID uint) ([]string, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	// AUDIT-TX-3: a revocation: the row is owed from the revoke's own transaction and
	// appended after the eviction (the caller evicts too; this is idempotent).
	var revoked []string
	settle, err := c.runOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var rerr error
		if revoked, rerr = tx.BulkRevokeExpiredPATsByUser(ctx, userID, c.now()); rerr != nil {
			return rerr
		}
		c.writeAuditEventFullOn(ctx, tgt, EventPATRevoked, actorPtr(userID), nil, nil, "",
			fmt.Sprintf("user %d bulk-revoked %d expired PAT(s)", userID, len(revoked)))
		return nil
	})
	if err != nil {
		return nil, err
	}
	c.invalidateTokenCache(revoked...)
	settle()
	return revoked, nil
}
