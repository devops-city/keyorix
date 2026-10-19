// scim_groups.go — SCIM 2.0 group sync (RFC 7644), the companion to scim.go. An IdP
// creates groups and pushes their membership; Keyorix maps a SCIM Group to a native
// Group (displayName → Name) and its members to user↔group links. PUT replaces the
// full member set; PATCH adds/removes members (and may rename). All mutations are
// audited.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	EventSCIMGroupProvisioned   = "scim.group_provisioned"
	EventSCIMGroupUpdated       = "scim.group_updated"
	EventSCIMGroupDeprovisioned = "scim.group_deprovisioned"
)

// ListSCIMGroupsPage returns one page of groups for a SCIM list and the total
// count, mirroring ListSCIMUsersPage (scim.go): startIndex is 1-based (SCIM
// convention), count is clamped to [0, SCIMMaxPageSize]. Unlike ListGroups (used
// by SSO group sync and other callers that intentionally want every group),
// this is backed by a bounded, offset-limited storage query so an unfiltered SCIM
// directory sync can't load the whole groups table into memory.
func (c *KeyorixCore) ListSCIMGroupsPage(ctx context.Context, startIndex, count int) ([]*models.Group, int, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 0
	}
	if count > SCIMMaxPageSize {
		count = SCIMMaxPageSize
	}
	if count == 0 {
		// SCIM count=0 → return totalResults only. Use PageSize=1 to get an accurate
		// total without a separate count API; the single fetched row is discarded.
		// (Requesting PageSize=0 directly is not relied on here: GORM's Limit(0)
		// semantics are not "zero rows" across all backends, so ListSCIMUsersPage
		// avoids it too — mirrored here for the same reason.)
		_, total, err := c.storage.ListGroupsPage(ctx, 0, 1)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		return []*models.Group{}, int(total), nil
	}
	groups, total, err := c.storage.ListGroupsPage(ctx, startIndex-1, count)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, int(total), nil
}

// scimManagedMember reports whether uid identifies a SCIM-owned account (scimOwned: a
// stored externalId set by SCIM user-provisioning — not empty like a native/local
// account, not the SSO scheme like an account SSO claimed or JIT-provisioned, #3418).
// SCIM group membership mutations (Create/Replace/PATCH) must refuse any
// target that isn't: those endpoints take arbitrary numeric member ids straight off
// the SCIM payload with no check that the id belongs to an account SCIM actually owns,
// so a valid (e.g. group-provisioning-only) SCIM bearer token could otherwise add ANY
// native user — including one the attacker already controls — into a group. If that
// group carries an admin-conferring role (a common "IdP group X = Keyorix admins"
// integration pattern), membership alone grants the role immediately, with no SSO
// step required (#167 — the group-membership sibling of #120's user-level guard).
// Fails CLOSED (treats a lookup error as not-managed) so an inability to verify never
// opens the add.
func (c *KeyorixCore) scimManagedMember(ctx context.Context, uid uint) bool {
	user, err := c.storage.GetUser(ctx, uid)
	if err != nil {
		return false
	}
	return scimOwned(user)
}

// maxSCIMGroupMembersPerCall bounds how many member ids a single SCIM group
// provision/replace/patch request may carry. Each id costs one
// scimManagedMember (GetUser) round trip via filterSCIMManaged below; an IdP
// integration (or a compromised/misbehaving one) submitting an unbounded
// member list in one request is a per-request resource-exhaustion vector, the
// same class of bug as maxBulkAccessRequestBatchSize
// (internal/core/bulk_access_requests.go). Enforced at each of the three SCIM
// group entry points (ProvisionSCIMGroup, ReplaceSCIMGroup, PatchSCIMGroup)
// against their raw incoming id list, before any storage access.
const maxSCIMGroupMembersPerCall = 500

// filterSCIMManaged splits ids into (allowed, rejected) member ids based on
// scimManagedMember, so callers can add only the SCIM-managed subset and report the
// rest as refused rather than silently dropping them.
func (c *KeyorixCore) filterSCIMManaged(ctx context.Context, ids []uint) (allowed, rejected []uint) { // nosemgrep: keyorix-unbounded-bulk-slice-param -- all three callers (ProvisionSCIMGroup, ReplaceSCIMGroup, PatchSCIMGroup) enforce maxSCIMGroupMembersPerCall on their raw incoming id list before calling this
	for _, id := range ids {
		if id == 0 {
			continue
		}
		if c.scimManagedMember(ctx, id) {
			allowed = append(allowed, id)
		} else {
			rejected = append(rejected, id)
		}
	}
	return allowed, rejected
}

// ProvisionSCIMGroup creates a group from a SCIM Create and adds its initial members.
// Only SCIM-managed members may be added (scimManagedMember, #167); a non-SCIM-managed
// id in memberIDs is refused.
func (c *KeyorixCore) ProvisionSCIMGroup(ctx context.Context, actorID uint, displayName string, memberIDs []uint) (*models.Group, error) {
	if displayName == "" {
		return nil, fmt.Errorf("displayName is required")
	}
	if len(memberIDs) > maxSCIMGroupMembersPerCall {
		return nil, fmt.Errorf("memberIDs exceeds the maximum batch size of %d", maxSCIMGroupMembersPerCall)
	}
	allowed, rejected := c.filterSCIMManaged(ctx, memberIDs)
	if len(rejected) > 0 {
		return nil, fmt.Errorf("%s: SCIM can only add SCIM-managed users to a group (rejected member id(s): %v)", i18n.T("ErrorNotAuthorized", nil), rejected)
	}
	// #1642: SCIM-provisioned group names come from an external IdP and
	// bypass core.CreateGroup entirely (see the storage-direct note below),
	// so they need their own fold — mirrors ProvisionSCIMUser's identical
	// treatment (scim.go).
	foldedName, ferr := identity.NewFoldedName(displayName)
	if ferr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
	}
	// Storage-direct: the SCIM path emits its own scim.group_provisioned event below,
	// so it must not also fire the generic group.created from CreateGroup.
	//
	// The group row and its initial membership run in one transaction: a partial
	// membership apply used to be best-effort (`_ =`), and — since a POST is not
	// retry-safe the way PATCH is — a failed member add on a create previously left
	// a partially-populated group with no signal to the IdP that anything was wrong
	// (the create itself reported success), and a retry would create a SECOND,
	// duplicate group rather than complete the first one. AddUserToGroup is
	// idempotent (a second add to the same (user, group, 0) is a no-op), so this is
	// also safe to retry once the whole create is atomic.
	var group *models.Group
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var cerr error
		group, cerr = tx.CreateGroup(ctx, &models.Group{Name: displayName, NameFolded: foldedName.Folded()})
		if cerr != nil {
			return cerr
		}
		for _, uid := range allowed {
			if aerr := tx.AddUserToGroup(ctx, uid, group.ID, 0); aerr != nil { // SCIM memberships are always global
				return aerr
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	c.writeAuditEvent(ctx, EventSCIMGroupProvisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM provisioned group %d (%q) with %d member(s)", group.ID, displayName, len(allowed)))
	return group, nil
}

// ReplaceSCIMGroup applies a SCIM Replace (PUT): an optional rename plus the FULL
// member set (members not in memberIDs are removed; new ones are added).
func (c *KeyorixCore) ReplaceSCIMGroup(ctx context.Context, actorID, groupID uint, displayName string, memberIDs []uint) (*models.Group, error) {
	if len(memberIDs) > maxSCIMGroupMembersPerCall {
		return nil, fmt.Errorf("memberIDs exceeds the maximum batch size of %d", maxSCIMGroupMembersPerCall)
	}
	group, err := c.storage.GetGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if displayName != "" && displayName != group.Name {
		// #1642: keep NameFolded in lockstep with Name on every rename path,
		// not just core.UpdateGroup's — a stale NameFolded here would leave
		// the DB's uniqueness index checking a value that no longer matches
		// the group's actual display name.
		foldedName, ferr := identity.NewFoldedName(displayName)
		if ferr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
		}
		// #2697: column-scoped, conditional on the group row still being live —
		// a full-row Save here resurrected a group a concurrent
		// DeprovisionSCIMGroup/DeleteGroup had just removed, bringing its
		// retained role grants and memberships back with it. An IdP DELETE
		// followed closely by a PUT/PATCH is exactly this interleaving.
		folded := foldedName.Folded()
		matched, uerr := c.storage.UpdateGroupFields(ctx, groupID, &displayName, &folded, nil, c.now())
		if uerr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), uerr)
		}
		if !matched {
			return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
	}
	current, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	want, have := buildSCIMMemberMaps(memberIDs, current)
	toAdd := computeSCIMToAdd(want, have)
	// SCIM must not be able to grant administrative access by adding members to a group
	// that carries an admin role. Block the add (de-escalating removals are still fine).
	if len(toAdd) > 0 && c.scimGroupConfersAdmin(ctx, groupID) {
		return nil, fmt.Errorf("%s: SCIM cannot add members to a group that grants administrative roles", i18n.T("ErrorNotAuthorized", nil))
	}
	// Every add must target a SCIM-managed account (#167); a native/non-SCIM id in the
	// requested member set is refused outright rather than silently skipped.
	if _, rejected := c.filterSCIMManaged(ctx, toAdd); len(rejected) > 0 {
		return nil, fmt.Errorf("%s: SCIM can only add SCIM-managed users to a group (rejected member id(s): %v)", i18n.T("ErrorNotAuthorized", nil), rejected)
	}
	if err := c.applyGroupMembershipChanges(ctx, groupID, want, current, toAdd); err != nil {
		return nil, err
	}
	c.writeAuditEvent(ctx, EventSCIMGroupUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM replaced group %d (members=%d)", groupID, len(want)))
	return c.storage.GetGroup(ctx, groupID)
}

// PatchSCIMGroup applies a SCIM PATCH: an optional rename plus incremental member
// add/remove. nil newName leaves the name unchanged.
func (c *KeyorixCore) PatchSCIMGroup(ctx context.Context, actorID, groupID uint, newName *string, addIDs, removeIDs []uint) (*models.Group, error) {
	if len(addIDs) > maxSCIMGroupMembersPerCall || len(removeIDs) > maxSCIMGroupMembersPerCall {
		return nil, fmt.Errorf("addIDs/removeIDs exceeds the maximum batch size of %d", maxSCIMGroupMembersPerCall)
	}
	group, err := c.storage.GetGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if newName != nil && *newName != "" && *newName != group.Name {
		foldedName, ferr := identity.NewFoldedName(*newName)
		if ferr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
		}
		// #2697: see ReplaceSCIMGroup's identical rename above.
		folded := foldedName.Folded()
		matched, uerr := c.storage.UpdateGroupFields(ctx, groupID, newName, &folded, nil, c.now())
		if uerr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), uerr)
		}
		if !matched {
			return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
	}
	if hasSCIMAdditions(addIDs) && c.scimGroupConfersAdmin(ctx, groupID) {
		return nil, fmt.Errorf("%s: SCIM cannot add members to a group that grants administrative roles", i18n.T("ErrorNotAuthorized", nil))
	}
	// Every add must target a SCIM-managed account (#167); a native/non-SCIM id in the
	// requested add set is refused outright rather than silently skipped.
	allowedAdds, rejected := c.filterSCIMManaged(ctx, addIDs)
	if len(rejected) > 0 {
		return nil, fmt.Errorf("%s: SCIM can only add SCIM-managed users to a group (rejected member id(s): %v)", i18n.T("ErrorNotAuthorized", nil), rejected)
	}
	// SESSION-AT #2352: guard checks + the write both now run under
	// withGroupProjectAdminGuardLocks (global key + every project key this
	// group holds roles.assign at). An earlier version ran these guard checks
	// with no lock at all, before the transaction below — two concurrent
	// membership changes (another SCIM PATCH/PUT, or a native RemoveUserFromGroup)
	// could each observe "another admin survives" before either commits.
	toRemove := filterNonZero(removeIDs)
	if err := c.withGroupProjectAdminGuardLocks(ctx, groupID, func(ctx context.Context) error {
		// Check every removal against guardLastGlobalAdminMembership (#G02) BEFORE
		// applying any of them, so a PATCH that would strip the install's last route
		// to global-admin authority is refused atomically — see
		// applyGroupMembershipChanges's identical precheck-then-apply shape. Also
		// checked against guardLastProjectAdminGroupMembership (core-project-
		// members.json#3) so a removal can't strip a project's last roles.assign
		// holder either — SCIM group management previously only saw the global case.
		for _, id := range toRemove {
			if err := c.guardLastGlobalAdminMembership(ctx, id, groupID); err != nil {
				return err
			}
			if err := c.guardLastProjectAdminGroupMembership(ctx, id, groupID); err != nil {
				return err
			}
		}
		// All add/remove membership writes run in one transaction: a partial apply used
		// to be best-effort (`_ =`). Both AddUserToGroup and RemoveUserFromGroup are
		// idempotent (a duplicate add / already-gone remove is a no-op, not an error),
		// so a fatal error here from a genuine storage failure — and a retry of the
		// SAME PATCH after it — stay safe; this only changes the transient-failure case
		// from "silently half-applied" to "rolled back, retry re-applies cleanly."
		// Wrapped in ErrorStorageFailed HERE, inside the closure, so the guard
		// checks above (returned bare, their own message is already specific)
		// aren't also mislabeled as a storage failure by the caller below.
		if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			for _, id := range allowedAdds {
				if err := tx.AddUserToGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
					return err
				}
			}
			for _, id := range toRemove {
				if err := tx.RemoveUserFromGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	c.writeAuditEvent(ctx, EventSCIMGroupUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM patched group %d (+%d/-%d members)", groupID, len(addIDs), len(removeIDs)))
	return c.storage.GetGroup(ctx, groupID)
}

// scimGroupConfersAdmin reports whether membership in groupID grants an escalation-tier
// role, so the SCIM group-sync paths (and the SSO group-membership path, sso.go) can refuse
// to add members to it. "Escalation-tier" is the shared idpAutoGrantOfRoleIsEscalation
// predicate: a canonical admin role, an admin-bypass role, OR a role carrying roles.assign
// (the role-granting primitive — a self-service group member who obtains it becomes a
// privilege pump). This is the SAME backstop the SSO GroupRoleMap path now uses; the two
// were inconsistent before (SCIM: bypass flag only; SSO: admin name only) and both missed
// the roles.assign case. Fails CLOSED (treats the group as escalation-bearing) on a
// GetGroupRoles lookup error — and idpAutoGrantOfRoleIsEscalation itself fails closed on a
// per-role resolution error (#G17-style: a lookup failure must not be indistinguishable
// from a legitimate negative result) — so an inability to verify never opens the grant.
func (c *KeyorixCore) scimGroupConfersAdmin(ctx context.Context, groupID uint) bool {
	confers, err := c.idpGroupConfersAdminVerdict(ctx, groupID)
	return confers || err != nil
}

// idpGroupConfersAdminVerdict is scimGroupConfersAdmin with a lookup failure
// kept apart from the verdict (err != nil: nothing decided). See
// idpAutoGrantEscalationVerdict for why SSO reconcile needs the difference.
// A role that IS an escalation decides the answer even if a sibling role's
// lookup failed: "confers admin" is already known, so the error is moot.
func (c *KeyorixCore) idpGroupConfersAdminVerdict(ctx context.Context, groupID uint) (bool, error) {
	roles, err := c.storage.GetGroupRoles(ctx, groupID)
	if err != nil {
		return false, fmt.Errorf("resolving group %d's roles: %w", groupID, err)
	}
	var firstErr error
	for _, r := range roles {
		escalation, verr := c.idpAutoGrantEscalationVerdict(ctx, r.ID, r.Name)
		if escalation {
			return true, nil
		}
		if verr != nil && firstErr == nil {
			firstErr = verr
		}
	}
	return false, firstErr
}

func buildSCIMMemberMaps(memberIDs []uint, current []*models.User) (want, have map[uint]bool) {
	want = make(map[uint]bool, len(memberIDs))
	for _, id := range memberIDs {
		if id != 0 {
			want[id] = true
		}
	}
	have = make(map[uint]bool, len(current))
	for _, u := range current {
		have[u.ID] = true
	}
	return want, have
}

func computeSCIMToAdd(want, have map[uint]bool) []uint {
	toAdd := make([]uint, 0)
	for id := range want {
		if !have[id] {
			toAdd = append(toAdd, id)
		}
	}
	return toAdd
}

func hasSCIMAdditions(addIDs []uint) bool {
	for _, id := range addIDs {
		if id != 0 {
			return true
		}
	}
	return false
}

func filterNonZero(ids []uint) []uint {
	out := make([]uint, 0, len(ids))
	for _, id := range ids {
		if id != 0 {
			out = append(out, id)
		}
	}
	return out
}

// applyGroupMembershipChanges applies the add/remove sets computed by the
// caller. Every removal is checked against guardLastGlobalAdminMembership
// (#G02) and guardLastProjectAdminGroupMembership (core-project-members.json#3)
// BEFORE any storage write happens, so a SCIM PUT that would strip the
// install's last route to global-admin authority, or a project's last
// roles.assign holder, is refused atomically — not applied member-by-member
// with some removals already committed.
//
// SESSION-AT #2352: guard checks + the write both now run under
// withGroupProjectAdminGuardLocks — an earlier version ran the guard checks
// with no lock at all, so two concurrent membership changes (this same PUT
// racing a SCIM PATCH or a native RemoveUserFromGroup) could each observe
// "another admin survives" before either commits.
func (c *KeyorixCore) applyGroupMembershipChanges(ctx context.Context, groupID uint, want map[uint]bool, current []*models.User, toAdd []uint) error {
	return c.withGroupProjectAdminGuardLocks(ctx, groupID, func(ctx context.Context) error {
		for _, u := range current {
			if !want[u.ID] {
				if err := c.guardLastGlobalAdminMembership(ctx, u.ID, groupID); err != nil {
					return err
				}
				if err := c.guardLastProjectAdminGroupMembership(ctx, u.ID, groupID); err != nil {
					return err
				}
			}
		}
		// All add/remove membership writes run in one transaction: a partial apply used
		// to be best-effort (`_ =`). Both storage calls are idempotent, so this stays
		// safe under an IdP's own retry of the same PUT.
		return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			for _, u := range current {
				if !want[u.ID] {
					if err := tx.RemoveUserFromGroup(ctx, u.ID, groupID, 0); err != nil { // SCIM memberships are always global
						return err
					}
				}
			}
			for _, id := range toAdd {
				if err := tx.AddUserToGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
					return err
				}
			}
			return nil
		})
	})
}

// DeprovisionSCIMGroup handles a SCIM DELETE — removes the group (membership links
// go with it). Refuses to delete a group holding the install's last
// global-admin-conferring role grant (guardLastGlobalAdminGroupDelete, #G02) or
// any project's last roles.assign-conferring grant
// (guardLastProjectAdminGroupDelete, core-project-members.json#3) — the same
// guards the native DeleteGroup already applies.
//
// SESSION-AT #2352: this used to call c.storage.DeleteGroup directly after its
// own, UNLOCKED guard checks — bypassing core.DeleteGroup's lock entirely (it
// never called DeleteGroup at all, it duplicated the guard logic and then went
// storage-direct). A SCIM DELETE racing a native DeleteGroup, another SCIM
// DELETE, or any other group-wide admin-removing operation could each observe
// "another admin survives" before either commits. Now shares DeleteGroup's own
// deleteGroupGuarded helper (groups.go) — guard + lock + write identical to the
// native path — and only the audit event differs.
func (c *KeyorixCore) DeprovisionSCIMGroup(ctx context.Context, actorID, groupID uint) error {
	if _, err := c.deleteGroupGuarded(ctx, groupID); err != nil {
		return err
	}
	c.writeAuditEvent(ctx, EventSCIMGroupDeprovisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM deprovisioned group %d", groupID))
	return nil
}
