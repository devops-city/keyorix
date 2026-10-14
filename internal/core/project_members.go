// project_members.go — project-scoped membership (ADR-021 two-tier model).
//
// A "project member" is a user holding a role at the project's scope
// (project_id = P, environment_id = 0). These helpers sit on top of the audited
// RBAC choke point (AssignUserRole/RemoveUserRole, see rbac_management.go) to give
// the Members tab a membership-shaped API — the same underlying grant as
// /user-roles, so it must be audited identically (#234).
package core

import (
	"context"
	"fmt"
	"slices"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// ListProjectMembers returns the users with a role at the project's scope.
func (c *KeyorixCore) ListProjectMembers(ctx context.Context, projectID uint) ([]storage.ProjectMember, error) {
	return c.storage.ListProjectMembers(ctx, projectID)
}

// AddProjectMember assigns roleName to userID at the project scope. actorID is the
// acting principal (0 = no authenticated principal, e.g. a system-driven onboarding
// transition); actorIsMachine distinguishes a machine-credential-authenticated
// caller (also actorID==0) from that true unauthenticated case — see
// AssignUserRole for actorID semantics — including the
// requireGranterHoldsRolePermissions escalation-by-proxy ceiling (#93/#107/#141)
// AssignUserRole applies to every grant, so a non-admin roles.assign holder cannot
// mint a project_admin (or any role bundling permissions they don't hold) through
// this direct entry point.
func (c *KeyorixCore) AddProjectMember(ctx context.Context, actorID, projectID, userID uint, roleName string, actorIsMachine bool) error {
	if err := c.domainAllowedForUser(ctx, userID); err != nil {
		return err
	}
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("unknown role %q: %w", roleName, err)
	}
	return c.AssignUserRole(ctx, actorID, userID, role.ID, Scope{ProjectID: projectID}, actorIsMachine)
}

// SetProjectMemberRole replaces the user's role(s) at the project scope with
// roleName, adding the member if they had none. See AddProjectMember for actorID
// semantics.
func (c *KeyorixCore) SetProjectMemberRole(ctx context.Context, actorID, projectID, userID uint, roleName string, actorIsMachine bool) error {
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("unknown role %q: %w", roleName, err)
	}
	scope := Scope{ProjectID: projectID}
	existing, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
	if err != nil {
		return err
	}
	// Only re-run the domain check when this call is establishing NEW project
	// membership (the user holds no role at this scope yet) — an existing
	// member changing roles already passed the check when they joined.
	if len(existing) == 0 {
		if err := c.domainAllowedForUser(ctx, userID); err != nil {
			return err
		}
	}
	// Refuse a demotion that would leave the project with no roles.assign holder
	// (#236): after this call the user's only project-scope role is roleName, so
	// check whether THAT role still carries roles.assign before touching anything.
	// #1646: the guard's read and the role changes below must be serialized across
	// every replica of an HA deployment, not just within this process —
	// projectAdminGuardMu (an in-process sync.Mutex) alone let two independent
	// replicas each observe "another admin survives" and both proceed, jointly
	// stripping the project of every roles.assign holder. WithNamedLock's
	// Postgres advisory lock, keyed per project, closes that; see its doc
	// comment in internal/core/storage/interface.go.
	return c.storage.WithNamedLock(ctx, projectAdminGuardLockKey(projectID), func(ctx context.Context) error {
		if err := c.guardLastProjectAdmin(ctx, projectID, userID, existing, []uint{role.ID}); err != nil {
			return err
		}
		hasTarget := false
		for _, rid := range existing {
			if rid == role.ID {
				hasTarget = true
				continue
			}
			// removeUserRoleUnguarded, not RemoveUserRole: the guardLastProjectAdmin
			// call above already validated the FULL before/after transition
			// (existing -> []uint{role.ID}) atomically under this call's own
			// WithNamedLock. RemoveUserRole's own project-scope guard can only see
			// this one role's removal in isolation -- blind to the AssignUserRole
			// below that's about to restore admin coverage -- and would falsely
			// refuse swapping the project's sole administrator directly from one
			// admin-tier role to another (see removeUserRoleUnguarded's doc).
			if err := c.removeUserRoleUnguarded(ctx, actorID, userID, rid, scope); err != nil {
				return err
			}
		}
		if hasTarget {
			// The user already held exactly roleName at this scope (no other
			// project-scoped role to remove above, so removeUserRoleUnguarded's
			// own LogRoleRemoved never fired either) -- a complete no-op that
			// would otherwise leave zero trail this call was made (F5,
			// audit-completeness campaign). AssignUserRole/removeUserRoleUnguarded
			// already cover every branch that actually changes a role grant.
			c.writeAuditEvent(ctx, "project_member.role_confirmed_unchanged", actorPtr(actorID), nil,
				fmt.Sprintf("project %d member %d already held role %q; no change made", projectID, userID, roleName))
			return nil
		}
		return c.AssignUserRole(ctx, actorID, userID, role.ID, scope, actorIsMachine)
	})
}

// projectAdminGuardLockKey is the WithNamedLock key for guardLastProjectAdmin's
// check-then-act sequence (#1646), scoped per project so unrelated projects'
// membership changes never contend on the same lock.
func projectAdminGuardLockKey(projectID uint) string {
	return fmt.Sprintf("project-admin-guard:%d", projectID)
}

// RemoveProjectMember removes ALL of the user's role grants scoped to the
// project — not just the project-level (environment_id = 0) grant the Members
// UI shows, but any environment-scoped grant (e.g. "prod-only access") in the
// same project too. A prior version only deleted the exact-scope match, so an
// environment-scoped grant silently survived an offboarding admin's removal,
// invisible and uncorrectable by that admin (project-scoped roles.assign
// cannot see or edit /user-roles grants, which require global scope) (#232).
// See AddProjectMember for actorID semantics.
func (c *KeyorixCore) RemoveProjectMember(ctx context.Context, actorID, projectID, userID uint) error {
	scope := Scope{ProjectID: projectID}
	existing, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return ErrNotProjectMember
	}
	// Refuse to remove the project's last roles.assign holder (#236): the ordinary
	// member-management API has no other safeguard, so without this the sole
	// remaining project admin could remove themselves (or be removed by anyone
	// else holding roles.assign), leaving the project with zero project-scoped
	// admins. Not a permanent lockout — a GLOBAL admin can always re-add one via
	// GetUserRoleIDsAt's project_id = 0 OR project_id = ? matching — but still an
	// availability risk worth refusing outright rather than requiring recovery.
	// #1646: see SetProjectMemberRole's identical WithNamedLock use above.
	return c.storage.WithNamedLock(ctx, projectAdminGuardLockKey(projectID), func(ctx context.Context) error {
		if err := c.guardLastProjectAdmin(ctx, projectID, userID, existing, nil); err != nil {
			return err
		}
		// Capture every grant (any environment) this deletes so each can be recorded
		// in the RBAC audit trail (#234) — RemoveAllProjectRoleGrants is a single
		// bulk delete, not a per-role RemoveUserRole loop, so it doesn't audit itself.
		assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
		if err != nil {
			return fmt.Errorf("failed to list project role assignments: %w", err)
		}
		// All three removals run in one transaction: RemoveAllProjectRoleGrants alone
		// is not sufficient protection (see below), so a partial failure here must
		// roll back rather than leave the member's role grants gone but their
		// secret-level access still live.
		if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			if err := tx.RemoveAllProjectRoleGrants(ctx, userID, projectID); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
			// Clear owner_id on secrets this user owned in the project (RBAC-002):
			// without this the stale owner tag would grant them owner-level access via
			// CheckSecretPermission's owner short-circuit even after all role grants
			// are gone. NOT best-effort: fatal, same transaction as the role-grant
			// removal above.
			if err := tx.ClearProjectSecretOwnership(ctx, userID, projectID); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
			// Revoke per-secret ACL grants in this project (CWE-284): without this a
			// removed member retains access to any secret they held a SecretACL grant
			// for, because AuthorizeSecret checks ACL grants BEFORE project-scope RBAC
			// and short-circuits on the first match — this is NOT defense-in-depth
			// (a prior version's comment claimed it was; it is the only protection
			// against stale per-secret ACL access surviving a removed member), so a
			// failure here must roll back the role-grant removal above too, not be
			// silently swallowed.
			if err := tx.DeleteSecretACLsByUserAndProject(ctx, userID, projectID); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, a := range assignments {
			if a.PrincipalType != "user" || a.PrincipalID != userID {
				continue
			}
			c.LogRoleRemoved(ctx, actorID, userID, a.RoleID, Scope{ProjectID: projectID, EnvironmentID: a.EnvironmentID})
		}
		return nil
	})
}

// guardLastProjectAdmin refuses an operation that would strip targetID's
// roles.assign authority at projectID's PROJECT scope (environment_id = 0 — a
// member removal or role change) unless either (a) targetRoleIDsAfter still
// carries roles.assign, or (b) some OTHER project-level grant (user or group)
// already carries it, so governance of the project survives. Only environment_id
// = 0 grants count: RequireScopedPermission on /projects/{id}/members itself
// only matches project-level grants (GetUserRoleIDsAt's "environment_id = 0 OR
// environment_id = ?" against a target scope whose EnvironmentID is 0), so an
// environment-scoped roles.assign grant could not actually administer this
// project's membership either — it doesn't count as a survivor. Passing a
// nil/roles.assign-free targetRoleIDsBefore is a fast no-op (the target wasn't
// an admin to begin with).
//
// Uses resolveProjectAdminHolders (the project-scope counterpart of
// resolveGlobalAdminHolders, #G05) to expand a surviving group grant to its
// LIVE members before counting it as a survivor — NOT the previous per-row
// scan, which treated ANY project-level roles.assign-granting group ASSIGNMENT
// as "another admin survives" without checking whether the group actually had
// any live members. A group that's empty, whose every member was deactivated,
// or that was itself soft-deleted therefore never covers the project, even
// though its group_roles grant row (pre-fix: even its soft-deleted self) still
// existed.
func (c *KeyorixCore) guardLastProjectAdmin(ctx context.Context, projectID, targetID uint, targetRoleIDsBefore, targetRoleIDsAfter []uint) error {
	hadAssign, err := c.storage.RoleSetHasPermission(ctx, targetRoleIDsBefore, permRolesAssign)
	if err != nil {
		return err
	}
	if !hadAssign {
		return nil // target wasn't a project admin — not the last-admin case
	}
	willHaveAssign, err := c.storage.RoleSetHasPermission(ctx, targetRoleIDsAfter, permRolesAssign)
	if err != nil {
		return err
	}
	if willHaveAssign {
		return nil // still an admin afterward — no governance gap
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to check project administrators: %w", err)
	}
	holders, err := c.resolveProjectAdminHolders(ctx, targetID, assignments)
	if err != nil {
		return fmt.Errorf("failed to check project administrators: %w", err)
	}
	if len(holders) > 0 {
		return nil // another admin (user or group, live members only) survives the change
	}
	return fmt.Errorf("cannot remove or demote the project's last administrator; assign another project admin first")
}

// resolveProjectAdminHolders is guardLastProjectAdmin's project-scope
// counterpart of resolveGlobalAdminHolders (internal/core/authz.go, #G03):
// it expands the project-level (environment_id = 0) assignments in
// `assignments` that carry roles.assign into the set of user IDs who would
// actually survive as project admins after targetID's change — group grants
// are expanded to their LIVE members via resolveGroupAdminMembers (a
// soft-deleted group's assignment row is already excluded upstream by
// ListProjectRoleAssignments, but an undeleted, empty, or fully-deactivated
// group must also not count), and filterActiveHolders drops any holder
// (direct or group-derived) who is themselves deactivated or soft-deleted.
// targetID is excluded both as a direct grant holder and as a group member —
// a grant belonging to the target themselves doesn't count as "another"
// admin. `assignments` is assumed already scoped to a single project (the
// caller's ListProjectRoleAssignments(ctx, projectID) result).
func (c *KeyorixCore) resolveProjectAdminHolders(ctx context.Context, targetID uint, assignments []storage.RoleAssignment) (map[uint]bool, error) {
	holders := make(map[uint]bool)
	checked := make(map[uint]bool, len(assignments))
	for _, a := range assignments {
		if a.EnvironmentID != 0 {
			continue // not project-level; can't administer /projects/{id}/members
		}
		hasAssign, ok := checked[a.RoleID]
		if !ok {
			var err error
			hasAssign, err = c.storage.RoleSetHasPermission(ctx, []uint{a.RoleID}, permRolesAssign)
			if err != nil {
				return nil, err
			}
			checked[a.RoleID] = hasAssign
		}
		if !hasAssign {
			continue
		}
		switch a.PrincipalType {
		case "user":
			if a.PrincipalID == targetID {
				continue
			}
			holders[a.PrincipalID] = true
		case "group":
			if err := c.resolveGroupAdminMembers(ctx, a.PrincipalID, func(_, userID uint) bool { return userID == targetID }, holders); err != nil {
				return nil, err
			}
		}
	}
	return c.filterActiveHolders(ctx, holders)
}

// guardLastProjectAdminGroupDelete is guardLastProjectAdmin's group-deletion
// counterpart (findings-core/core-project-members.json#3): generalizes
// guardLastGlobalAdminGroupDelete (#107, global scope only) to every PROJECT
// scope the group holds a roles.assign-granting role at. Deleting a group
// cascades to remove EVERY role grant it holds — if one of those grants is a
// project's last roles.assign holder, deleting the group leaves that project
// ungoverned (no one able to manage its membership), a gap the global-only
// guard cannot see.
func (c *KeyorixCore) guardLastProjectAdminGroupDelete(ctx context.Context, groupID uint) error {
	projectIDs, err := c.projectAdminScopesHeldByGroup(ctx, groupID)
	if err != nil {
		return err
	}
	for projectID := range projectIDs {
		if err := c.guardProjectAdminSurvivesGroupChange(ctx, projectID, func(a storage.RoleAssignment) bool {
			return a.PrincipalType == "group" && a.PrincipalID == groupID
		}, nil); err != nil {
			return fmt.Errorf("refusing to delete group %d: %w", groupID, err)
		}
	}
	return nil
}

// guardLastProjectAdminGroupMembership is guardLastProjectAdmin's group-
// membership-removal counterpart (findings-core/core-project-members.json#3):
// refuses to remove userID from groupID when groupID's project-scoped
// roles.assign grant is userID's only remaining route to administering that
// project and no other holder survives either. Unlike a group deletion, the
// group's own grant row survives a membership removal — only that one
// member's derived authority through THIS group disappears.
func (c *KeyorixCore) guardLastProjectAdminGroupMembership(ctx context.Context, userID, groupID uint) error {
	projectIDs, err := c.projectAdminScopesHeldByGroup(ctx, groupID)
	if err != nil {
		return err
	}
	for projectID := range projectIDs {
		if err := c.guardProjectAdminSurvivesGroupChange(ctx, projectID, nil, func(gID, uID uint) bool {
			return gID == groupID && uID == userID
		}); err != nil {
			return fmt.Errorf("refusing to remove user %d from group %d: %w", userID, groupID, err)
		}
	}
	return nil
}

// guardLastProjectAdminGroupRole is guardLastGlobalAdminGroupRole's project-scope
// counterpart (FIX-2): refuses to remove a group's roles.assign-conferring role
// grant at a project's scope when doing so would leave that project with no
// surviving roles.assign holder (direct or group-derived). A group losing its
// project-admin-conferring role grant is the third way a group can stop
// conferring project-admin authority — group deletion and membership removal
// were already guarded (guardLastProjectAdminGroupDelete/
// guardLastProjectAdminGroupMembership); this one, exercised through
// RemoveRoleFromGroup, was not. Mirrors SetProjectMemberRole/
// RemoveProjectMember's "not a permanent lockout (a global admin can always
// re-add one), but still an availability risk worth refusing outright" stance
// for direct grants, rather than guardLastGlobalAdminGroupRole's narrower
// "project admins are recoverable, so don't bother" one.
func (c *KeyorixCore) guardLastProjectAdminGroupRole(ctx context.Context, groupID, roleID, projectID uint) error {
	hasAssign, err := c.storage.RoleSetHasPermission(ctx, []uint{roleID}, permRolesAssign)
	if err != nil {
		return err
	}
	if !hasAssign {
		return nil // not removing a roles.assign-bearing role
	}
	if err := c.guardProjectAdminSurvivesGroupChange(ctx, projectID, func(a storage.RoleAssignment) bool {
		return a.PrincipalType == "group" && a.PrincipalID == groupID && a.RoleID == roleID
	}, nil); err != nil {
		return fmt.Errorf("refusing to remove role %d from group %d: %w", roleID, groupID, err)
	}
	return nil
}

// projectAdminScopesHeldByGroup returns the project IDs at which groupID
// holds a project-level (environment_id = 0) role granting roles.assign —
// every project whose governance depends, at least in part, on this group.
// A group with no such grant anywhere returns an empty set, so the group-path
// project-admin guards above are a cheap no-op for the common case (most
// groups never hold project-admin authority at all).
func (c *KeyorixCore) projectAdminScopesHeldByGroup(ctx context.Context, groupID uint) (map[uint]bool, error) {
	assignments, err := c.storage.ListGroupRoleAssignments(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve group role assignments: %w", err)
	}
	checked := make(map[uint]bool, len(assignments))
	projectIDs := make(map[uint]bool)
	for _, a := range assignments {
		if a.EnvironmentID != 0 || a.ProjectID == 0 {
			continue // not a project-level grant; the global scope has its own guard
		}
		hasAssign, ok := checked[a.RoleID]
		if !ok {
			var herr error
			hasAssign, herr = c.storage.RoleSetHasPermission(ctx, []uint{a.RoleID}, permRolesAssign)
			if herr != nil {
				return nil, herr
			}
			checked[a.RoleID] = hasAssign
		}
		if hasAssign {
			projectIDs[a.ProjectID] = true
		}
	}
	return projectIDs, nil
}

// withGroupProjectAdminGuardLocks acquires lastAdminGuardLockKey (the global
// admin-guard key) and projectAdminGuardLockKey(P) for every project P that
// groupID currently holds a roles.assign-granting role at, THEN runs fn —
// the shared lock acquisition every group-WIDE admin-removing operation
// (DeleteGroup, RemoveUserFromGroup, the SCIM group-membership/deprovision
// paths) needs (SESSION-AT #2352). Unlike a single-project operation
// (RemoveUserRole, SetProjectMemberRole, RemoveProjectMember — each only
// ever needs ONE project's key, already correctly scoped), any of these can
// affect the group's role grant across MULTIPLE projects in one call, so it
// must hold every affected project's key for the duration of its guard
// check AND write — a caller that only acquired lastAdminGuardLockKey (as
// an earlier version of DeleteGroup did) is not actually serialized against
// RemoveProjectMember/SetProjectMemberRole/RemoveUserRole/RemoveRoleFromGroup,
// which only ever take a project key: two operations in DIFFERENT lock
// domains can each independently observe "another admin survives" using a
// stale view of the other's not-yet-committed write, exactly the race this
// whole guard family exists to close.
//
// Lock order is fixed: global first, then project keys ascending by ID.
// This is the ONLY thing that prevents a deadlock between two concurrent
// callers of this same helper whose affected-project sets overlap but were
// computed in a different order — every group-wide caller MUST go through
// this helper rather than acquiring these locks itself, so the order stays
// centrally enforced in one place. WithNamedLock's own reentrancy guard
// (internal/storage/store/local_named_lock.go) makes nesting these calls
// cheap: on Postgres, a nested call under a DIFFERENT key reuses the outer
// call's already-checked-out connection rather than taking a second one, so
// locking N project keys costs zero additional pooled connections beyond
// the first.
//
// KNOWN RESIDUAL GAP: the project set is computed ONCE, before any lock is
// taken. A role newly granted to groupID at a project NOT in that set,
// landing in the narrow window between this computation and lock
// acquisition, would not have its key locked here. This is a NEW-GRANT
// race during a REMOVAL — not the removal-vs-removal race this guard
// family exists to close, and not among the paths #2352 asked to cover —
// so it is documented, not fixed.
func (c *KeyorixCore) withGroupProjectAdminGuardLocks(ctx context.Context, groupID uint, fn func(ctx context.Context) error) error {
	return c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
		projectIDs, err := c.projectAdminScopesHeldByGroup(ctx, groupID)
		if err != nil {
			return err
		}
		sorted := make([]uint, 0, len(projectIDs))
		for pid := range projectIDs {
			sorted = append(sorted, pid)
		}
		slices.Sort(sorted)
		return c.lockProjectAdminGuardsInOrder(ctx, sorted, fn)
	})
}

// lockProjectAdminGuardsInOrder acquires projectAdminGuardLockKey for each ID
// in projectIDs, in slice order (the caller is responsible for sorting), then
// runs fn under all of them. See withGroupProjectAdminGuardLocks for why the
// order matters.
func (c *KeyorixCore) lockProjectAdminGuardsInOrder(ctx context.Context, projectIDs []uint, fn func(ctx context.Context) error) error {
	if len(projectIDs) == 0 {
		return fn(ctx)
	}
	return c.storage.WithNamedLock(ctx, projectAdminGuardLockKey(projectIDs[0]), func(ctx context.Context) error {
		return c.lockProjectAdminGuardsInOrder(ctx, projectIDs[1:], fn)
	})
}

// guardProjectAdminSurvivesGroupChange checks whether projectID still has a
// live roles.assign holder after the given group-scoped exclusion — a grant
// removal (group deletion) or one member's derived authority (membership
// removal). Reuses resolveGlobalAdminHolders (internal/core/authz.go)
// verbatim for the group-expansion/exclusion/active-filtering machinery;
// despite its name that function is scope-agnostic — it only cares which
// assignment rows are passed in and which role IDs count as "admin". Here the
// admin-role test is "does this role carry roles.assign" (a permission
// check, since project administration isn't tied to a specific role name),
// not the fixed install-admin role-ID set the global guards use.
func (c *KeyorixCore) guardProjectAdminSurvivesGroupChange(ctx context.Context, projectID uint, excludeAssignment func(storage.RoleAssignment) bool, excludeMember func(groupID, userID uint) bool) error {
	all, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to check project %d administrators: %w", projectID, err)
	}
	projectLevel := make([]storage.RoleAssignment, 0, len(all))
	assignAdminIDs := make(map[uint]bool)
	checked := make(map[uint]bool, len(all))
	for _, a := range all {
		if a.EnvironmentID != 0 {
			continue // not project-level; can't administer /projects/{id}/members
		}
		projectLevel = append(projectLevel, a)
		hasAssign, ok := checked[a.RoleID]
		if !ok {
			var herr error
			hasAssign, herr = c.storage.RoleSetHasPermission(ctx, []uint{a.RoleID}, permRolesAssign)
			if herr != nil {
				return herr
			}
			checked[a.RoleID] = hasAssign
		}
		assignAdminIDs[a.RoleID] = hasAssign
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, assignAdminIDs, projectLevel, excludeAssignment, excludeMember)
	if err != nil {
		return fmt.Errorf("failed to check project %d administrators: %w", projectID, err)
	}
	if len(holders) == 0 {
		return fmt.Errorf("project %d's last administrative role grant would be lost, leaving no roles.assign holder", projectID)
	}
	return nil
}
