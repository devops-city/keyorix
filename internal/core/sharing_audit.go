package core

import (
	"context"
	"fmt"
)

// ShareAuditEvent represents different types of sharing audit events
type ShareAuditEvent string

const (
	// ShareAuditEventCreated represents a share creation event
	ShareAuditEventCreated ShareAuditEvent = "share_created"

	// ShareAuditEventUpdated represents a share permission update event
	ShareAuditEventUpdated ShareAuditEvent = "share_updated"

	// ShareAuditEventRevoked represents a share revocation event
	ShareAuditEventRevoked ShareAuditEvent = "share_revoked"

	// ShareAuditEventGroupCreated represents a group share creation event
	ShareAuditEventGroupCreated ShareAuditEvent = "group_share_created"

	// ShareAuditEventGroupUpdated represents a group share permission update event
	ShareAuditEventGroupUpdated ShareAuditEvent = "group_share_updated"

	// ShareAuditEventGroupRevoked represents a group share revocation event
	ShareAuditEventGroupRevoked ShareAuditEvent = "group_share_revoked"

	// ShareAuditEventSelfRemoved represents a user removing themselves from a share
	ShareAuditEventSelfRemoved ShareAuditEvent = "share_self_removed"

	// ShareAuditEventSharedSecretsAdminViewed represents an admin (a caller
	// other than the target) viewing the secrets shared with another user —
	// see ListSharedSecretsForUser (sharing_query.go). A self-view is not
	// audited here, matching GET /api/v1/shared-secrets (the caller's own
	// list), which never has been.
	ShareAuditEventSharedSecretsAdminViewed ShareAuditEvent = "shared_secrets_admin_viewed"
)

// ShareAuditContext contains context information for audit logging
type ShareAuditContext struct {
	ActorID       uint
	SecretID      uint
	RecipientID   uint
	IsGroup       bool
	Permission    string
	OldPermission string // For update events
	// ShareID is the share record the event is about (#2941: every share
	// create/update/revoke names its share, so an elevated action's
	// share_access_elevated row can be tied back to the grant). 0 = unknown.
	ShareID uint
}

// shareRef renders " (share N)" for a known share id, "" otherwise.
func shareRef(auditCtx *ShareAuditContext) string {
	if auditCtx.ShareID == 0 {
		return ""
	}
	return fmt.Sprintf(" (share %d)", auditCtx.ShareID)
}

// LogShareCreated logs a share creation event
func (c *KeyorixCore) LogShareCreated(ctx context.Context, auditCtx *ShareAuditContext) {
	c.logShareCreatedOn(ctx, c.auditNow(), ShareAuditEventCreated, auditCtx)
}

// logShareCreatedOn is LogShareCreated / LogGroupShareCreated (by eventType)
// against an explicit audit target (AUDIT-TX-2: written inside the share's own
// transaction).
func (c *KeyorixCore) logShareCreatedOn(ctx context.Context, tgt auditTarget, eventType ShareAuditEvent, auditCtx *ShareAuditContext) {
	desc := fmt.Sprintf("Shared %s with %s (permission: %s)%s", c.auditRef(ctx, tgt.st, auditKindSecret, auditCtx.SecretID), c.auditRef(ctx, tgt.st, shareRecipientKind(eventType, auditCtx), auditCtx.RecipientID), auditCtx.Permission, shareRef(auditCtx))
	// Route through the shared choke point so impersonation context
	// (ActorType/ImpersonatedBy/ActingAs/Impersonation) gets stamped consistently (#284).
	c.writeShareAuditOn(ctx, tgt, eventType, auditCtx, desc)
}

// LogShareUpdated logs a share permission update event
func (c *KeyorixCore) LogShareUpdated(ctx context.Context, auditCtx *ShareAuditContext) {
	c.logShareUpdatedOn(ctx, c.auditNow(), ShareAuditEventUpdated, auditCtx)
}

// logShareUpdatedOn is LogShareUpdated / LogGroupShareUpdated (by eventType)
// against an explicit audit target.
func (c *KeyorixCore) logShareUpdatedOn(ctx context.Context, tgt auditTarget, eventType ShareAuditEvent, auditCtx *ShareAuditContext) {
	what := "share"
	if eventType == ShareAuditEventGroupUpdated {
		what = "group share"
	}
	desc := fmt.Sprintf("Updated %s permission of %s for %s (from %s to %s)%s", what,
		c.auditRef(ctx, tgt.st, auditKindSecret, auditCtx.SecretID), c.auditRef(ctx, tgt.st, shareRecipientKind(eventType, auditCtx), auditCtx.RecipientID), auditCtx.OldPermission, auditCtx.Permission, shareRef(auditCtx))
	c.writeShareAuditOn(ctx, tgt, eventType, auditCtx, desc)
}

// shareRecipientKind is the audit-ref kind of a share's recipient: always a
// group for the group_share_* events, else by IsGroup.
func shareRecipientKind(eventType ShareAuditEvent, auditCtx *ShareAuditContext) string {
	if auditCtx.IsGroup || eventType == ShareAuditEventGroupCreated || eventType == ShareAuditEventGroupUpdated {
		return auditKindGroup
	}
	return "user"
}

func (c *KeyorixCore) writeShareAuditOn(ctx context.Context, tgt auditTarget, eventType ShareAuditEvent, auditCtx *ShareAuditContext, desc string) {
	actor, secret := auditCtx.ActorID, auditCtx.SecretID
	c.writeAuditEventFullOn(ctx, tgt, string(eventType), &actor, &secret, nil, "", desc)
}

// LogShareRevoked logs a share revocation event
func (c *KeyorixCore) LogShareRevoked(ctx context.Context, auditCtx *ShareAuditContext) {
	recipientType := "user"
	if auditCtx.IsGroup {
		recipientType = "group"
	}

	desc := fmt.Sprintf("Revoked share of %s for %s%s", c.auditRef(ctx, c.storage, auditKindSecret, auditCtx.SecretID), c.auditRef(ctx, c.storage, recipientType, auditCtx.RecipientID), shareRef(auditCtx))
	c.writeAuditEvent(ctx, string(ShareAuditEventRevoked), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}

// LogGroupShareCreated logs a group share creation event
func (c *KeyorixCore) LogGroupShareCreated(ctx context.Context, auditCtx *ShareAuditContext) {
	c.logShareCreatedOn(ctx, c.auditNow(), ShareAuditEventGroupCreated, auditCtx)
}

// LogGroupShareUpdated logs a group share permission update event
func (c *KeyorixCore) LogGroupShareUpdated(ctx context.Context, auditCtx *ShareAuditContext) {
	c.logShareUpdatedOn(ctx, c.auditNow(), ShareAuditEventGroupUpdated, auditCtx)
}

// LogGroupShareRevoked logs a group share revocation event
func (c *KeyorixCore) LogGroupShareRevoked(ctx context.Context, auditCtx *ShareAuditContext) {
	desc := fmt.Sprintf("Revoked group share of %s for %s%s", c.auditRef(ctx, c.storage, auditKindSecret, auditCtx.SecretID), c.auditRef(ctx, c.storage, auditKindGroup, auditCtx.RecipientID), shareRef(auditCtx))
	c.writeAuditEvent(ctx, string(ShareAuditEventGroupRevoked), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}

// LogSelfRemovalFromShare logs when a user removes themselves from a shared secret
func (c *KeyorixCore) LogSelfRemovalFromShare(ctx context.Context, auditCtx *ShareAuditContext) {
	desc := fmt.Sprintf("User removed themselves from shared secret (permission: %s)%s", auditCtx.Permission, shareRef(auditCtx))
	c.writeAuditEvent(ctx, string(ShareAuditEventSelfRemoved), &auditCtx.ActorID, &auditCtx.SecretID, desc)
}
