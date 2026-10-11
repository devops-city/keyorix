// jit_access.go — just-in-time / time-bound role grants. A grant carries an
// optional expiry; the storage authorization queries deny it the instant it
// passes, and RemoveExpiredRoleGrants (run by the JIT scheduler) sweeps the rows
// and audits each auto-expiry. The grant itself is created via the access-request
// approval flow (invitations.go) or directly through these helpers.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AssignUserRoleWithExpiry assigns a time-bound role to a user at scope (the grant
// stops authorizing once expiresAt passes) and records the assignment. actorID is
// the granting principal (0 = unauthenticated/system).
//
// #G15: mirrors AssignUserRole's two gates exactly —
// requireGranterHoldsRolePermissions (#93/#107/#141, the escalation-by-proxy
// grant-ceiling: a roles.assign holder cannot bundle-grant a time-bound role
// carrying a permission they don't hold themselves) and requireNoSoDViolation
// (#419, the separation-of-duties preventive gate — this is precisely the
// JIT-timing-evasion vector the finding describes: "a toxic-permission overlap
// that both starts and fully expires between two SoD digest runs ...
// concretely constructible by arranging two overlapping short-lived grants").
// The HTTP JIT-assign-with-expiry path (POST /user-roles with expires_at) and
// the access-request TTL-grant path (invitations.go) both go through this
// function, so both gates now apply there. Break-glass is the one caller that
// legitimately cannot be blocked by either — its self-service emergency grant
// MUST elevate a user beyond their current permissions (that's break-glass's
// entire purpose), and a false-positive SoD block during a genuine incident is
// an unacceptable failure mode for the control that exists to remediate
// incidents — so break_glass.go calls assignUserRoleWithExpirySkipSoD
// directly instead, never this function.
// actorIsMachine distinguishes a machine-credential-authenticated caller from
// the true absent/local-CLI case -- both produce actorID==0, but only the
// latter is the trusted exemption requireGranterHoldsRolePermissions was
// written for. #1542.
func (c *KeyorixCore) AssignUserRoleWithExpiry(ctx context.Context, actorID, userID, roleID uint, scope Scope, expiresAt time.Time, actorIsMachine bool) error {
	if err := c.requireGranterHoldsRolePermissions(ctx, actorID, roleID, scope, actorIsMachine); err != nil {
		return err
	}
	// #1646: same cross-replica race as AssignUserRole (see WithNamedLock's doc
	// comment) — this is its time-bound sibling.
	return c.storage.WithNamedLock(ctx, sodGrantLockKey("user", userID), func(ctx context.Context) error {
		if err := c.requireNoSoDViolation(ctx, userID, roleID); err != nil {
			return err
		}
		return c.assignUserRoleWithExpirySkipSoD(ctx, actorID, userID, roleID, scope, expiresAt)
	})
}

// assignUserRoleWithExpirySkipSoD performs the identical time-bound grant as
// AssignUserRoleWithExpiry but deliberately SKIPS both the #93/#107/#141
// grant-ceiling check and the #419 separation-of-duties preventive check. Use
// it ONLY where the action is break-glass's self-service emergency access
// (break_glass.go's ActivateBreakGlass): break-glass is documented as
// "Deliberately un-gated by RBAC — the whole point is access the user does
// NOT already have", so both the ceiling check (which would refuse the very
// elevation break-glass exists to grant) and the SoD block (a false positive
// during a genuine incident is an unacceptable failure mode for the control
// that exists to remediate incidents) would defeat break-glass's purpose.
// Never call this from any other path — the HTTP JIT-assign endpoint and the
// access-request TTL-approval path must go through AssignUserRoleWithExpiry
// so both gates apply.
func (c *KeyorixCore) assignUserRoleWithExpirySkipSoD(ctx context.Context, actorID, userID, roleID uint, scope Scope, expiresAt time.Time) error {
	if err := c.storage.AssignRoleWithExpiry(ctx, userID, roleID, scope, expiresAt); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogRoleAssigned(ctx, actorID, userID, roleID, scope)
	return nil
}

// AssignGroupRoleWithExpiry assigns a time-bound role to a group at scope, gated by
// the same escalation-by-proxy ceiling as the permanent grant (AssignRoleToGroup —
// a JIT grant to a group is just as much a self-escalation vector as a permanent
// one, and is gated by the role's real bundled permissions, not only its name);
// see AssignUserRoleWithExpiry. Also gated by the #419 separation-of-duties
// preventive check (requireGroupGrantNoSoDViolation) — no caller of this function
// needs a break-glass-style carve-out, unlike the direct user grant above.
// actorIsMachine distinguishes a machine-credential caller (also actorID==0) from
// the true actorID==0 system pseudo-actor.
func (c *KeyorixCore) AssignGroupRoleWithExpiry(ctx context.Context, actorID, groupID, roleID uint, scope Scope, expiresAt time.Time, actorIsMachine bool) error {
	if _, err := c.storage.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.requireGranterHoldsRolePermissions(ctx, actorID, roleID, scope, actorIsMachine); err != nil {
		return err
	}
	// #1646: see AssignUserRole's identical WithNamedLock use.
	// #1780: the group key alone does not serialize against a concurrent DIRECT
	// grant to one of this group's members — see withGroupMemberSoDLocks
	// (rbac_management.go).
	return c.storage.WithNamedLock(ctx, sodGrantLockKey("group", groupID), func(ctx context.Context) error {
		write := func(ctx context.Context) error {
			if err := c.storage.AssignRoleToGroupWithExpiry(ctx, groupID, roleID, scope, expiresAt); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
			c.LogGroupRoleAssigned(ctx, actorID, groupID, roleID, scope)
			return nil
		}
		policies, adding, needed, err := c.groupGrantSoDContext(ctx, roleID)
		if err != nil {
			return err
		}
		if !needed {
			return write(ctx)
		}
		return c.withGroupMemberSoDLocks(ctx, groupID, func(ctx context.Context, members []*models.User) error {
			if err := c.requireGroupGrantNoSoDViolation(ctx, members, policies, adding); err != nil {
				return err
			}
			return write(ctx)
		})
	})
}

// EventShareExpired is audited when a time-bound secret share is swept after expiry.
const EventShareExpired = "share.expired"

// RemoveExpiredShares removes every time-bound secret share whose expiry is at or
// before `before` and audits each as share.expired (the system sweep, no actor).
// Returns the number removed. Idempotent. Expired shares already stop authorizing
// the instant they pass (the permission queries filter on expiry); this just reclaims
// the rows and writes the expiry audit trail. Backs the JIT access-expiry scheduler.
func (c *KeyorixCore) RemoveExpiredShares(ctx context.Context, before time.Time) (int, error) {
	removed, err := c.storage.DeleteExpiredShareRecords(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	for _, s := range removed {
		sid := s.SecretID
		recipientKind := "user"
		if s.IsGroup {
			recipientKind = "group"
		}
		c.writeAuditEvent(ctx, EventShareExpired, nil, &sid,
			fmt.Sprintf("time-bound share of %s expired for %s", c.auditRef(ctx, c.storage, auditKindSecret, s.SecretID), c.auditRef(ctx, c.storage, recipientKind, s.RecipientID)))
	}
	return len(removed), nil
}

// RemoveExpiredRoleGrants removes every user/group role grant whose expiry is at or
// before `before` and audits each as role.expired (actor 0 = the system sweep).
// Returns the number of grants removed. Idempotent — a tick that finds nothing
// removes nothing. Backs the JIT access-expiry scheduler.
func (c *KeyorixCore) RemoveExpiredRoleGrants(ctx context.Context, before time.Time) (int, error) {
	removed, err := c.storage.DeleteExpiredRoleGrants(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	for _, g := range removed {
		scope := Scope{ProjectID: g.ProjectID, EnvironmentID: g.EnvironmentID}
		detail := rbacAuditDetail{
			RoleID:        g.RoleID,
			ProjectID:     g.ProjectID,
			EnvironmentID: g.EnvironmentID,
		}
		var desc string
		if g.PrincipalType == "group" {
			detail.GroupID = g.PrincipalID
			desc = fmt.Sprintf("%s expired for %s", c.auditRef(ctx, c.storage, auditKindRole, g.RoleID), c.auditRef(ctx, c.storage, auditKindGroup, g.PrincipalID))
		} else {
			detail.TargetUserID = g.PrincipalID
			desc = fmt.Sprintf("%s expired for %s", c.auditRef(ctx, c.storage, auditKindRole, g.RoleID), c.auditRef(ctx, c.storage, auditKindUser, g.PrincipalID))
		}
		c.writeRBACAudit(ctx, EventRoleExpired, desc, 0, scope, detail)
	}
	return len(removed), nil
}
