package core

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// shareEffectiveNow returns a wall-clock reading that never regresses
// relative to what this KeyorixCore has already observed for share-active
// resolution (#1653, follow-up to #1632): max(now, shareClockWatermark).
// shareActive/activeShares are reached on every secret listing and
// access-list resolution that involves shares — see rbacEffectiveNow's doc
// comment (internal/storage/store/local_rbac.go) for why this clamps rather
// than refuses.
// .UTC() strips any monotonic clock reading c.now() carries — see
// authEffectiveNow's doc comment (auth.go) for why an unstripped comparison
// here would never actually detect a backward wall-clock step.
func (c *KeyorixCore) shareEffectiveNow() time.Time {
	c.shareClockWatermarkMu.Lock()
	defer c.shareClockWatermarkMu.Unlock()
	now := c.now().UTC()
	if now.Before(c.shareClockWatermark) {
		return c.shareClockWatermark
	}
	c.shareClockWatermark = now
	return now
}

// shareActive reports whether a share still authorizes at time now: a nil ExpiresAt
// is permanent, otherwise the share stops authorizing the instant it passes (a
// time-bound / JIT secret share, mirroring UserRole.ExpiresAt). The JIT sweeper later
// reclaims the row, but enforcement denies an expired share immediately regardless.
func shareActive(share *models.ShareRecord, now time.Time) bool {
	return share.ExpiresAt == nil || now.Before(*share.ExpiresAt)
}

// activeShares returns only the shares still authorizing at now (drops expired ones).
func activeShares(shares []*models.ShareRecord, now time.Time) []*models.ShareRecord {
	active := make([]*models.ShareRecord, 0, len(shares))
	for _, s := range shares {
		if shareActive(s, now) {
			active = append(active, s)
		}
	}
	return active
}

// secretOwnedBy reports whether actorID is the owner of a secret with the given
// OwnerID. A zero OwnerID means the secret has NO human owner — e.g. one created by
// a machine identity (ADR-023/030 store OwnerID 0 for machines) or a legacy/ownerless
// row. Such a secret must be owned by nobody: without the zero guard, a machine
// actor (whose ID is also 0) would match every ownerless secret via 0 == 0 and gain
// owner-level rights over all of them. Ownership therefore requires a non-zero,
// matching id on both sides.
func secretOwnedBy(ownerID, actorID uint) bool {
	return ownerID != 0 && ownerID == actorID
}

// requireLiveOwnerAuthority reports whether actorID holds owner-level authority over
// secret: they must be the secret's OwnerID AND still be a LIVE member of the
// secret's project. An owner who is removed from the project keeps their OwnerID tag
// on the secret row until ClearProjectSecretOwnership runs, so a bare secretOwnedBy
// check alone would let a departed owner retain full authority over the secret
// forever (RBAC-001). Every owner-gated operation — CheckSecretPermission's owner
// branch, and the sharing.go/group_sharing.go mutation paths — must call this instead
// of secretOwnedBy directly.
func (c *KeyorixCore) requireLiveOwnerAuthority(ctx context.Context, secret *models.SecretNode, actorID uint) (bool, error) {
	if !secretOwnedBy(secret.OwnerID, actorID) {
		return false, nil
	}
	member, err := c.IsProjectMember(ctx, actorID, secret.ProjectID)
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return member, nil
}

// PermissionLevel represents the level of access a user has to a secret.
type PermissionLevel string

const (
	PermissionNone  PermissionLevel = "none"
	PermissionRead  PermissionLevel = "read"
	PermissionWrite PermissionLevel = "write"
	PermissionOwner PermissionLevel = "owner"
)

// PermissionContext contains information about a user's permission for a secret.
type PermissionContext struct {
	SecretID   uint
	UserID     uint
	Permission PermissionLevel
	Source     string // "owner", "direct_share", "group_share"
	ShareID    *uint  // ID of the share record if applicable
}

// CheckSecretPermission checks if a user has the required permission for a secret.
// It names no SecretAction, so a write share does not satisfy PermissionWrite here
// (#3001 follow-up: unnamed means not allowlisted); a core write path that a share may
// elevate calls EnforceSecretActionPermission with its action.
func (c *KeyorixCore) CheckSecretPermission(ctx context.Context, secretID, userID uint, requiredPermission PermissionLevel) (*PermissionContext, error) {
	pc, _, err := c.checkSecretPermission(ctx, secretID, userID, requiredPermission, "")
	return pc, err
}

// EnforceSecretActionPermission enforces write permission for action on the secret:
// owner, an allowlisted share (secretActionShareElevates), an ACL or a role. A refusal
// for an actor whose share covers secrets.write but not this action wraps
// ErrShareActionNotElevated, so transports can say why (ShareRefusalMessage).
func (c *KeyorixCore) EnforceSecretActionPermission(ctx context.Context, secretID, userID uint, action SecretAction) (*PermissionContext, error) {
	pc, _, err := c.checkSecretPermission(ctx, secretID, userID, PermissionWrite, action)
	return pc, err
}

// checkSecretPermission is the decision behind CheckSecretPermission and
// EnforceSecretActionPermission. On a grant it also returns the secret it fetched to
// decide (the row storage.GetSecret returned), so a caller that serves that secret
// does not fetch it again (GetSecretWithPermissionCheck, PERF-FIX-5); on a refusal the
// secret is nil.
func (c *KeyorixCore) checkSecretPermission(ctx context.Context, secretID, userID uint, requiredPermission PermissionLevel, action SecretAction) (*PermissionContext, *models.SecretNode, error) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	if secretID == 0 {
		return nil, nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return nil, nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	// PAT-GUARD-1: ownership, shares and ACL rows below grant access without ever
	// calling Authorize, so a PAT restriction has to be checked here, against the
	// secret's own scope, before any of them is honoured — the same check
	// AuthorizeSecret makes before its ACL grant (PAT-SCOPE-002). Same denial as a
	// caller with no grant at all, so it is not an existence oracle either.
	if !patRestrictionFromContext(ctx).Allows(permissionLevelToRBACPerm(requiredPermission),
		Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}) {
		return nil, nil, fmt.Errorf("%s: insufficient permissions", i18n.T("ErrorPermissionDenied", nil))
	}

	// Owners have all permissions, but only while still a member of the secret's
	// project. A user removed from the project retains their OwnerID tag until
	// ClearProjectSecretOwnership runs (RBAC-002), so we gate owner access on live
	// project membership to prevent post-offboarding access (RBAC-001).
	if isLiveOwner, err := c.requireLiveOwnerAuthority(ctx, secret, userID); err != nil {
		return nil, nil, err
	} else if isLiveOwner {
		return &PermissionContext{
			SecretID:   secretID,
			UserID:     userID,
			Permission: PermissionOwner,
			Source:     "owner",
		}, secret, nil
	}

	// Direct and group shares: the one share term every per-secret decision uses
	// (share_authz.go) — active, project-member-only, read|write only.
	grant, err := c.sharePermissionFor(ctx, userID, secretID, secret.ProjectID, requiredPermission, action)
	if err != nil {
		return nil, nil, err
	}
	if grant.Level != PermissionNone {
		return &PermissionContext{
			SecretID:   secretID,
			UserID:     userID,
			Permission: grant.Level,
			Source:     grant.Source,
			ShareID:    grant.ShareID,
		}, secret, nil
	}

	// Per-secret ACL fallback (RBAC Phase 3, additive — see secret_acl.go's design
	// doc): a SecretACL grant on this exact secret (or an inherited ancestor
	// folder, via HasSecretACL) satisfies read/write independently of any
	// project role. Without this, a caller who only holds an ACL grant passed
	// the HTTP router's RequireScopedSecretPermission gate but was silently
	// denied here, because CheckSecretPermission previously recognized only
	// ownership, share records, and project RBAC (r140) — the same
	// two-authorization-models gap the RBAC fallback below closed for roles
	// (#r124). ACL never grants secrets.delete/owner, so PermissionOwner
	// requests skip this and fall straight to the RBAC fallback. SecretACL rows
	// are user-scoped (see AuthorizeSecretPrincipal), so a machine-identity actor
	// skips this and relies on the RBAC fallback exclusively, unchanged from
	// before.
	if aclPerm := permissionLevelToRBACPerm(requiredPermission); aclPerm != "" && aclPerm != "secrets.delete" &&
		actorTypeFromContext(ctx) != ActorTypeMachine {
		hasACL, aerr := c.HasSecretACL(ctx, userID, secretID, aclPerm)
		if aerr != nil {
			// A REAL read failure (not "no grant" -- e.g. a faulted
			// GetSecretAncestors). Must propagate,
			// not silently fall through to the RBAC fallback below as if this ACL
			// check had simply found nothing -- mirrors AuthorizeSecret's identical
			// HasSecretACL call (the middleware's own path, authz.go), which already
			// fails closed on this exact error. Found 2026-09-23: the mismatch between
			// this function and AuthorizeSecret let FuzzStorageFaultOperations flag a
			// GetSecretAncestors#2 fault on UpdateSecret as an apparent fail-open --
			// traced to here, not a real bypass (ACL is additive-only, so silently
			// falling through to RBAC can only ever under-grant relative to RBAC alone,
			// never over-grant), but still wrong: a caller with a genuine ACL-only
			// grant (no independent RBAC access) was wrongly DENIED under this fault
			// instead of seeing the real error.
			return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), aerr)
		}
		if hasACL {
			return &PermissionContext{
				SecretID:   secretID,
				UserID:     userID,
				Permission: requiredPermission,
				Source:     "acl",
			}, secret, nil
		}
	}

	// RBAC fallback: a project editor/admin whose role grants secrets.write (or
	// secrets.delete for owner-level operations) passes the HTTP router's
	// RequireScopedPermission gate but was silently denied here because
	// CheckSecretPermission only recognized ownership and share records. This
	// unifies the two authorization models so both the middleware and the core
	// function accept the same set of legitimate callers (#r124).
	if rbacPerm := permissionLevelToRBACPerm(requiredPermission); rbacPerm != "" {
		actorType := actorTypeFromContext(ctx)
		scope := Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
		ok, aerr := c.AuthorizePrincipal(ctx, actorType, userID, rbacPerm, scope)
		if aerr != nil {
			// Falls through to the same "insufficient permissions" denial as a clean
			// !ok would (unchanged) — but a check that failed to EVALUATE is logged,
			// since it would otherwise be indistinguishable from a caller who is
			// legitimately ungranted here.
			log.Printf("CheckSecretPermission: RBAC fallback authorization check failed (actor_type=%s principal_id=%d permission=%s project_id=%d environment_id=%d): %v",
				actorType, userID, rbacPerm, scope.ProjectID, scope.EnvironmentID, aerr)
		} else if ok {
			return &PermissionContext{
				SecretID:   secretID,
				UserID:     userID,
				Permission: requiredPermission,
				Source:     "rbac",
			}, secret, nil
		}
	}

	if c.shareCoversButNotElevated(ctx, userID, secretID, secret.ProjectID, requiredPermission, action) {
		return nil, nil, shareRefusal(ErrShareActionNotElevated)
	}
	return nil, nil, fmt.Errorf("%s: insufficient permissions", i18n.T("ErrorPermissionDenied", nil))
}

// permissionLevelToRBACPerm maps a PermissionLevel to the equivalent RBAC permission
// string used by AuthorizePrincipal. PermissionOwner maps to secrets.delete (the most
// restrictive mutation the RBAC model expresses). Returns "" for PermissionNone.
func permissionLevelToRBACPerm(level PermissionLevel) string {
	switch level {
	case PermissionRead:
		return "secrets.read"
	case PermissionWrite:
		return "secrets.write"
	case PermissionOwner:
		return "secrets.delete"
	}
	return ""
}

// hasRequiredPermission checks if the user's permission level meets the required level.
func (c *KeyorixCore) hasRequiredPermission(userPermission, requiredPermission PermissionLevel) bool {
	permissionLevels := map[PermissionLevel]int{
		PermissionNone:  0,
		PermissionRead:  1,
		PermissionWrite: 2,
		PermissionOwner: 3,
	}
	userLevel, exists := permissionLevels[userPermission]
	if !exists {
		return false
	}
	requiredLevel, exists := permissionLevels[requiredPermission]
	if !exists {
		return false
	}
	return userLevel >= requiredLevel
}

// CheckGroupPermissions checks if a user has permission through group membership.
// Only counts a group share when the user's OWN membership in that group is
// global or scoped to secretProjectID (#G01) — GetUserGroupsAt, not the
// unscoped GetUserGroups, so a membership scoped to a different project can't
// grant access to a secret it was never meant to reach.
func (c *KeyorixCore) CheckGroupPermissions(ctx context.Context, secretID, userID uint, shares []*models.ShareRecord, secretProjectID uint) (PermissionLevel, *uint, error) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	userGroups, err := c.storage.GetUserGroupsAt(ctx, userID, Scope{ProjectID: secretProjectID})
	if err != nil {
		return PermissionNone, nil, err
	}

	highestPermission := PermissionNone
	var shareID *uint

	for _, share := range shares {
		if share.IsGroup {
			for _, group := range userGroups {
				if group.ID == share.RecipientID {
					permission := PermissionLevel(share.Permission)
					if c.hasRequiredPermission(permission, highestPermission) {
						highestPermission = permission
						shareID = &share.ID
					}
				}
			}
		}
	}

	return highestPermission, shareID, nil
}

// EnforceSecretReadPermission enforces read permission for secret operations.
func (c *KeyorixCore) EnforceSecretReadPermission(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.CheckSecretPermission(ctx, secretID, userID, PermissionRead)
}

// EnforceSecretWritePermission enforces write permission for secret operations.
func (c *KeyorixCore) EnforceSecretWritePermission(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.CheckSecretPermission(ctx, secretID, userID, PermissionWrite)
}

// EnforceSecretOwnerPermission enforces owner permission for secret operations.
func (c *KeyorixCore) EnforceSecretOwnerPermission(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.CheckSecretPermission(ctx, secretID, userID, PermissionOwner)
}

// ValidateSecretAccess validates that a user can access a secret (requires at least read).
func (c *KeyorixCore) ValidateSecretAccess(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.EnforceSecretReadPermission(ctx, secretID, userID)
}

// CanUserModifySecret checks if a user can modify a secret's value (write or owner
// permission; a write share counts, since updating the value is allowlisted).
func (c *KeyorixCore) CanUserModifySecret(ctx context.Context, secretID, userID uint) (bool, error) {
	permCtx, err := c.EnforceSecretActionPermission(ctx, secretID, userID, SecretActionUpdate)
	if err != nil {
		return false, nil
	}
	return permCtx != nil, nil
}

// CanUserShareSecret checks if a user can share a secret (requires owner permission).
func (c *KeyorixCore) CanUserShareSecret(ctx context.Context, secretID, userID uint) (bool, error) {
	permCtx, err := c.CheckSecretPermission(ctx, secretID, userID, PermissionOwner)
	if err != nil {
		return false, nil
	}
	return permCtx != nil, nil
}

// GetEffectivePermission returns the effective permission level for a user on a secret.
func (c *KeyorixCore) GetEffectivePermission(ctx context.Context, secretID, userID uint) (PermissionLevel, error) {
	permCtx, err := c.CheckSecretPermission(ctx, secretID, userID, PermissionRead)
	if err != nil {
		return PermissionNone, nil
	}
	return permCtx.Permission, nil
}

// listUserPermissionsOwnedPageSize bounds each page of the owned-secrets walk in
// ListUserPermissions. A single fixed-size page silently under-lists a user who owns
// more than the page size; paginating through every page instead keeps this correct
// at any scale.
const listUserPermissionsOwnedPageSize = 500

// ListUserPermissions returns all secrets a user has access to with their permission levels.
func (c *KeyorixCore) ListUserPermissions(ctx context.Context, userID uint) ([]*models.UserSecretPermission, error) { // NOSONAR -- cognitive complexity 22, suppress go:S3776
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	var permissions []*models.UserSecretPermission

	// Owned == owner_id (the canonical ownership), not created_by (a username
	// string). Page through every owned secret so a user who owns more than
	// listUserPermissionsOwnedPageSize secrets isn't silently truncated.
	for page := 1; ; page++ {
		ownedSecrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			OwnerID: &userID, Page: page, PageSize: listUserPermissionsOwnedPageSize,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		for _, secret := range ownedSecrets {
			permissions = append(permissions, &models.UserSecretPermission{
				SecretID:   secret.ID,
				UserID:     userID,
				Permission: string(PermissionOwner),
				Source:     "owner",
			})
		}
		if len(ownedSecrets) < listUserPermissionsOwnedPageSize || int64(page*listUserPermissionsOwnedPageSize) >= total {
			break
		}
	}

	// A time-bound share stops granting access the instant it expires, so it must
	// not appear in the access listing either — same filter the read-path
	// authorization (CheckSecretPermission via activeShares) applies.
	//
	// #1655 (Part 2 regression audit, 2026-09-04): this was the 8th of 8 shareActive
	// call sites -- the other 7 were hardened against a backward-stepped host clock
	// via shareEffectiveNow's monotonic watermark, but this one, despite the exact
	// comment above naming it as sharing the read-path's filter, was left on a bare
	// c.now(). Currently unreachable (ListUserPermissions has zero production
	// callers), but matching the sibling sites closes the gap before any caller
	// exists rather than after.
	now := c.shareEffectiveNow()

	directShares, err := c.storage.ListSharesByUser(ctx, userID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, share := range directShares {
		if !shareActive(share, now) {
			continue
		}
		permissions = append(permissions, &models.UserSecretPermission{
			SecretID:   share.SecretID,
			UserID:     userID,
			Permission: share.Permission,
			Source:     "direct_share",
			ShareID:    &share.ID,
		})
	}

	// Secrets shared with any group the user belongs to.
	groups, err := c.storage.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, group := range groups {
		groupShares, err := c.storage.ListSharesByGroup(ctx, group.ID, c.shareEffectiveNow())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		for _, share := range groupShares {
			if !shareActive(share, now) {
				continue
			}
			groupID := group.ID
			permissions = append(permissions, &models.UserSecretPermission{
				SecretID:   share.SecretID,
				UserID:     userID,
				Permission: share.Permission,
				Source:     "group_share",
				ShareID:    &share.ID,
				GroupID:    &groupID,
			})
		}
	}

	return permissions, nil
}
