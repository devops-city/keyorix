// groups.go — Group CRUD, membership, and validation.
//
// CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups,
// AddUserToGroup, RemoveUserFromGroup, GetGroupMembers.
// For user operations see users.go. Types are in users_types.go.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Group lifecycle audit event types (API/CLI-driven; the SCIM provisioning path
// has its own scim.group_* events). Surfaced in the audit log like other mutations.
const (
	EventGroupCreated  = "group.created"
	EventGroupUpdated  = "group.updated"
	EventGroupDeleted  = "group.deleted"
	EventGroupRestored = "group.restored"
)

// CreateGroup creates a new group. actorID is the admin performing it (0 = no
// authenticated principal, e.g. a local CLI invocation).
func (c *KeyorixCore) CreateGroup(ctx context.Context, actorID uint, req *CreateGroupRequest) (*models.Group, error) {
	if err := c.validateCreateGroupRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	// #1642: fold once here — group names are identity (a human reads them to
	// decide who's a member), so "Support Team"/"support team" and NFC/NFD
	// forms of the same name must collide, not coexist as two indistinguishable
	// groups.
	foldedName, ferr := identity.NewFoldedName(req.Name)
	if ferr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
	}
	group := &models.Group{Name: req.Name, NameFolded: foldedName.Folded(), Description: req.Description}
	created, err := c.storage.CreateGroup(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventGroupCreated, actorPtr(actorID), nil,
		fmt.Sprintf("group %q (id %d) created", created.Name, created.ID))
	return created, nil
}

// GetGroup retrieves a group by ID.
func (c *KeyorixCore) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	group, err := c.storage.GetGroup(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return group, nil
}

// UpdateGroup updates an existing group. See CreateGroup for actorID semantics.
func (c *KeyorixCore) UpdateGroup(ctx context.Context, actorID uint, req *UpdateGroupRequest) (*models.Group, error) {
	if err := c.validateUpdateGroupRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	group, err := c.storage.GetGroup(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// #2697: a column-scoped write of only the fields this request carries, onto
	// a row that is still live. The previous full-row Save persisted the whole
	// pre-read struct, and its upsert fallback resurrected a group deleted (or
	// SCIM-deprovisioned) after the GetGroup above — bringing back every
	// GroupRole and UserGroup row, which DeleteGroup deliberately retains so
	// RestoreGroup can work, with no restore audit event.
	var namePtr, foldedPtr, descPtr *string
	if req.Name != "" {
		foldedName, ferr := identity.NewFoldedName(req.Name)
		if ferr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
		}
		folded := foldedName.Folded()
		namePtr, foldedPtr = &req.Name, &folded
	}
	if req.Description != "" {
		descPtr = &req.Description
	}
	matched, err := c.storage.UpdateGroupFields(ctx, group.ID, namePtr, foldedPtr, descPtr, c.now())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !matched {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	// Return the committed row, not the struct read before the write.
	updated, err := c.storage.GetGroup(ctx, group.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventGroupUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("group %q (id %d) updated", updated.Name, updated.ID))
	return updated, nil
}

// deleteGroupGuarded runs the last-admin guard checks and the actual group
// delete under withGroupProjectAdminGuardLocks (SESSION-AT #2352), returning
// the pre-delete group row for the caller's own audit message. It does not
// write an audit event itself — DeleteGroup and DeprovisionSCIMGroup
// (scim_groups.go) each emit a different event type for the same underlying
// guarded delete, so both call this instead of duplicating the guard+lock
// logic (the original #2348 fix lived only in DeleteGroup; DeprovisionSCIMGroup
// called c.storage.DeleteGroup directly, bypassing every guard — found during
// the #2352 sweep).
//
// lastAdminGuardLockKey alone (an earlier version of this function) is NOT
// enough on its own for the project-admin check: RemoveProjectMember/
// SetProjectMemberRole/RemoveUserRole/RemoveRoleFromGroup only ever take a
// PER-PROJECT lock (projectAdminGuardLockKey), never the global one, so a
// delete serialized only against the global key could still race any of
// those four — see withGroupProjectAdminGuardLocks's own doc comment.
func (c *KeyorixCore) deleteGroupGuarded(ctx context.Context, id uint) (*models.Group, error) {
	var group *models.Group
	err := c.withGroupProjectAdminGuardLocks(ctx, id, func(ctx context.Context) error {
		var gerr error
		group, gerr = c.storage.GetGroup(ctx, id)
		if gerr != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), gerr)
		}
		if err := c.guardLastGlobalAdminGroupDelete(ctx, id); err != nil {
			return err
		}
		if err := c.guardLastProjectAdminGroupDelete(ctx, id); err != nil {
			return err
		}
		if err := c.storage.DeleteGroup(ctx, id); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		return nil
	})
	return group, err
}

// DeleteGroup deletes a group by ID. See CreateGroup for actorID semantics. It
// refuses to delete a group holding the install's last global-admin-conferring
// role grant (#107; see guardLastGlobalAdminGroupDelete) OR any project's last
// roles.assign-conferring grant (see guardLastProjectAdminGroupDelete) —
// deleting a group cascades to remove every role grant it holds, at every scope.
func (c *KeyorixCore) DeleteGroup(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	group, err := c.deleteGroupGuarded(ctx, id)
	if err != nil {
		return err
	}
	c.writeAuditEvent(ctx, EventGroupDeleted, actorPtr(actorID), nil,
		fmt.Sprintf("group %q (id %d) deleted", group.Name, id))
	return nil
}

// RestoreGroup reverses a soft-delete, bringing the group back with the role grants
// and memberships it had at deletion. See CreateGroup for actorID semantics.
//
// #147: restoring reinstates EVERY role the group held atomically — potentially
// several at once, including admin-tier ones — so before restoring, this checks the
// group's whole role SET against the actor's own authority (requireGlobalAdmin
// ToReinstateAdminRoles), the same ceiling roles.assign/requireAuthorityForRole is
// meant to enforce on a direct grant. Without it, a principal holding only
// roles.assign (the router's permission gate) who is themselves a member of an
// admin-conferring group that was soft-deleted (e.g. an incident-response
// revocation) could restore it and get their admin access back.
func (c *KeyorixCore) RestoreGroup(ctx context.Context, actorID, id uint) (*models.Group, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	// #2455: GetGroupRoles, the ceiling check, and the restore write all run
	// under sodGrantLockKey("group", id) -- the same key AssignRoleToGroup/
	// AssignGroupRoleWithExpiry (rbac_management.go, jit_access.go) take
	// before adding a role to this group. A role grant racing this restore
	// now either fully commits before this read (and is then correctly
	// subject to requireGlobalAdminToReinstateAdminRoles below) or blocks
	// until this call finishes. Previously the read+check and the write ran
	// unlocked and separately: a role landing on the soft-deleted group in
	// between could let a non-global-admin restore a group that now carries
	// an admin-conferring role the check never saw (TOCTOU) -- note the
	// storage-level AssignRoleToGroupWithExpiry write never checks the
	// target group's existence/soft-delete state at all, so this is reachable
	// via a JIT/time-bound grant even while the group is soft-deleted.
	var restored *models.Group
	if err := c.storage.WithNamedLock(ctx, sodGrantLockKey("group", id), func(ctx context.Context) error {
		roles, err := c.storage.GetGroupRoles(ctx, id)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		roleIDs := make([]uint, 0, len(roles))
		for _, r := range roles {
			roleIDs = append(roleIDs, r.ID)
		}
		if err := c.requireGlobalAdminToReinstateAdminRoles(ctx, actorID, roleIDs, "group"); err != nil {
			return err
		}
		// The restore and the read-back that builds the caller's response share one
		// transaction (#2428): a GetGroup read failing AFTER an unwrapped RestoreGroup
		// had already committed used to report the whole call as failed while the
		// group was, in fact, already active again (with its memberships and grants)
		// -- the caller had no way to tell. Wrapping both means a failure here rolls
		// the restore back too, so "reported failed" and "nothing happened" stay in
		// sync, matching #2354/#2381's CreateRole fix for the identical class of bug.
		if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			if err := tx.RestoreGroup(ctx, id); err != nil {
				return err
			}
			var gerr error
			restored, gerr = tx.GetGroup(ctx, id)
			return gerr
		}); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	c.writeAuditEvent(ctx, EventGroupRestored, actorPtr(actorID), nil, c.auditRef(ctx, c.storage, auditKindGroup, id)+" restored")
	return restored, nil
}

// ListGroups lists all groups.
func (c *KeyorixCore) ListGroups(ctx context.Context) ([]*models.Group, error) {
	groups, err := c.storage.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, nil
}

// AddUserToGroup adds a user to a group. actorID is the admin performing it (0 = no
// authenticated principal, e.g. a local CLI invocation). actorIsMachine distinguishes
// that true "no principal" case from a machine-credential-authenticated caller — both
// present as actorID==0, but only the former is exempt from the ceiling check below;
// see #1524. projectID scopes the membership: 0 = global (applies in every project),
// non-zero = this project only. Membership confers every role the group holds at the
// matching scope, so this is recorded in the RBAC audit trail (#233).
//
// Joining an admin-conferring group inherits that access just as directly as a
// role grant, so every global-scope admin role the group already holds is gated
// by the same escalation-by-proxy ceiling AssignRoleToGroup applies
// (requireAuthorityForRole): a non-admin roles.assign holder must not be able to
// self-escalate by joining a privileged group instead of being granted the role.
// The local CLI (actorID 0, actorIsMachine false) is exempt — it is already fully
// trusted (it can grant any role directly via AssignRoleToUser, which bypasses this
// ceiling entirely) and the exemption avoids forcing an existing admin group
// deployment through this new check retroactively. A MACHINE credential (actorID 0,
// actorIsMachine true — e.g. the former RemoteStorage node relay, #1524 finding (b)) is NOT
// exempt: it is not the local CLI, and requireAuthorityForRole already fails closed
// correctly for actorID 0 when the check actually runs (no real user holds the
// admin-tier role an escalation attempt would need) — an ordinary, non-admin-conferring
// group join still succeeds unaffected, since requireAuthorityForRole only evaluates
// anything for admin-tier roles in the first place.
// validateGroupJoinRoles checks that actorID has the authority to grant all roles
// the group already holds, and that userID would not gain a SoD-violating role
// combination by joining (AUTHZ-007). Skips roles whose definition cannot be loaded.
//
// #G05: the SoD check is done ONCE, over the group's FULL role set
// (requireGroupJoinNoSoDViolation), not per role inside the authority loop
// below. A per-role check (each call only weighing ONE new role's permissions
// against what the user held before the join) cannot see a violation that
// only exists because two of the group's OWN roles combine with each other —
// see requireGroupJoinNoSoDViolation's doc comment (sod.go) for the concrete
// gap and how this mirrors requireGrantSetNoSoDViolation's set-based shape.
func (c *KeyorixCore) validateGroupJoinRoles(ctx context.Context, actorID uint, actorIsMachine bool, userID, groupID uint) error {
	grants, err := c.storage.ListGroupRoleAssignments(ctx, groupID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, g := range grants {
		if _, err := c.storage.GetRole(ctx, g.RoleID); err != nil {
			continue
		}
		if err := c.requireGranterHoldsRolePermissions(ctx, actorID, g.RoleID, Scope{ProjectID: g.ProjectID, EnvironmentID: g.EnvironmentID}, actorIsMachine); err != nil {
			return err
		}
	}
	return c.requireGroupJoinNoSoDViolation(ctx, userID, grants)
}

// domainAllowedForGroupJoin applies domainAllowedForUser's onboarding-domain
// restriction to AddUserToGroup. A group membership only needs the check when
// the join would actually confer a live role grant — a purely organizational
// group with no role grants isn't an onboarding path and isn't gated, mirroring
// the direct-grant paths (which only ever fire once a role is being assigned).
//
// Scope matching mirrors GetUserGroupRoleIDsAt (local_rbac.go): a project-scoped
// membership (projectID != 0) is reached by the group's global (ProjectID==0)
// grants and by grants scoped exactly to projectID; a global membership
// (projectID == 0) is reached by EVERY grant the group holds — each at its own
// matching project — so it is, if anything, the more dangerous case, not one to
// skip.
func (c *KeyorixCore) domainAllowedForGroupJoin(ctx context.Context, userID, groupID, projectID uint) error {
	if len(c.membershipDomainAllowlist) == 0 {
		return nil
	}
	grants, err := c.storage.ListGroupRoleAssignments(ctx, groupID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, g := range grants {
		if projectID == 0 || g.ProjectID == 0 || g.ProjectID == projectID {
			return c.domainAllowedForUser(ctx, userID)
		}
	}
	return nil
}

func (c *KeyorixCore) AddUserToGroup(ctx context.Context, actorID uint, actorIsMachine bool, userID, groupID, projectID uint) error {
	if userID == 0 || groupID == 0 {
		return fmt.Errorf("%s: user ID and group ID are required", i18n.T("ErrorValidation", nil))
	}
	// #PM-006: a group membership confers every role the group holds at the
	// matching scope (see this function's doc comment above), which is exactly
	// the "grants a project-scope role directly by user ID" case
	// domainAllowedForUser's doc comment (membership_lifecycle.go) says every
	// onboarding path must cover — otherwise an install's membership domain
	// allowlist (SetMembershipDomainAllowlist) can be bypassed entirely by
	// routing a disallowed-domain user through group membership instead of
	// InviteMember/AddProjectMember. Runs unconditionally, with no actorID==0
	// exemption, matching AddProjectMember/InviteMember (this is an onboarding
	// restriction, not an escalation-by-proxy authority ceiling).
	if err := c.domainAllowedForGroupJoin(ctx, userID, groupID, projectID); err != nil {
		return err
	}
	// #1646: validateGroupJoinRoles' set-based requireGroupJoinNoSoDViolation check
	// and the membership write below must be treated as one step, serialized
	// across every replica of an HA deployment -- see WithNamedLock's doc comment
	// (AssignUserRole has the identical race).
	return c.storage.WithNamedLock(ctx, sodGrantLockKey("user", userID), func(ctx context.Context) error {
		if actorID != 0 || actorIsMachine {
			if err := c.validateGroupJoinRoles(ctx, actorID, actorIsMachine, userID, groupID); err != nil {
				return err
			}
		}
		if err := c.storage.AddUserToGroup(ctx, userID, groupID, projectID); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		c.LogGroupMemberAdded(ctx, actorID, userID, groupID)
		return nil
	})
}

// AddUserToGroupGlobal is a convenience wrapper that adds a global membership
// (projectID=0). Callers that do not need project-scoped membership (e.g. SSO
// JIT provisioning, SCIM) should call this rather than hard-coding 0.
func (c *KeyorixCore) AddUserToGroupGlobal(ctx context.Context, actorID uint, actorIsMachine bool, userID, groupID uint) error {
	return c.AddUserToGroup(ctx, actorID, actorIsMachine, userID, groupID, 0)
}

// RemoveUserFromGroup removes a user from a group at the given projectID scope.
// See AddUserToGroup for actorID semantics. It refuses to remove a user whose
// global admin-tier authority comes solely from this group's role grant when no
// other admin route remains (#107; see guardLastGlobalAdminMembership), OR whose
// removal would leave some project this group administers with no roles.assign
// holder (see guardLastProjectAdminGroupMembership).
func (c *KeyorixCore) RemoveUserFromGroup(ctx context.Context, actorID, userID, groupID, projectID uint) error {
	if userID == 0 || groupID == 0 {
		return fmt.Errorf("%s: user ID and group ID are required", i18n.T("ErrorValidation", nil))
	}
	// SESSION-AT #2352: guard+write serialized via withGroupProjectAdminGuardLocks
	// (global key + every project key this group holds roles.assign at) — an
	// earlier version ran both guards entirely unguarded by any lock, so two
	// concurrent removals of two DIFFERENT users (each independently the last
	// route to admin via this or another group) could each observe "another
	// admin survives" before either commits.
	return c.withGroupProjectAdminGuardLocks(ctx, groupID, func(ctx context.Context) error {
		if err := c.guardLastGlobalAdminMembership(ctx, userID, groupID); err != nil {
			return err
		}
		if err := c.guardLastProjectAdminGroupMembership(ctx, userID, groupID); err != nil {
			return err
		}
		if err := c.storage.RemoveUserFromGroup(ctx, userID, groupID, projectID); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		c.LogGroupMemberRemoved(ctx, actorID, userID, groupID)
		return nil
	})
}

// RemoveUserFromGroupGlobal is a convenience wrapper that removes the global
// membership (projectID=0). Callers that do not need project-scoped removal (e.g.
// SSO JIT de-provisioning, SCIM) should call this rather than hard-coding 0.
func (c *KeyorixCore) RemoveUserFromGroupGlobal(ctx context.Context, actorID, userID, groupID uint) error {
	return c.RemoveUserFromGroup(ctx, actorID, userID, groupID, 0)
}

// GetGroupMembers returns all users that belong to a group.
func (c *KeyorixCore) GetGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	if groupID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	members, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return members, nil
}

// ── Validation ────────────────────────────────────────────────────────────────

func (c *KeyorixCore) validateCreateGroupRequest(req *CreateGroupRequest) error {
	if req.Name == "" {
		return fmt.Errorf("group name is required")
	}
	if err := validateNameLength("group name", req.Name); err != nil {
		return err
	}
	return validateDescription(req.Description)
}

func (c *KeyorixCore) validateUpdateGroupRequest(req *UpdateGroupRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("group ID is required")
	}
	if err := validateNameLength("group name", req.Name); err != nil {
		return err
	}
	return validateDescription(req.Description)
}
