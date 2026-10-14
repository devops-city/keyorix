// project_membership_definition.go — THE definition of "is a member of project P".
//
// Keyorix has exactly one answer to that question, and this file is it:
//
//	A user is a member of project P iff they hold a LIVE role grant scoped to P
//	(project_id = P, any environment), directly or through a non-deleted group.
//	A global/install-wide grant (project_id = 0) does NOT make anyone a member of
//	any project.
//
// That is ADR-021's two-tier model, and it is the definition authorization already
// enforces: every access decision that asks "is this user affiliated with this
// project" reads it (per-secret ACL eligibility, share-recipient eligibility,
// break-glass affiliation, secret permission resolution), and every project
// notification fan-out addresses it.
//
// # Why this file exists
//
// There used to be a second, non-equivalent notion in the codebase: a row in the
// ADR-022 `project_memberships` table (#2781). Two admin screens contradicted each
// other about the same user because `GET /api/v1/projects/{id}/members` answered
// from the role grants while `GET /api/v1/users/{id}/memberships` answered from
// that table — and nothing the web UI does writes the table, so it reported
// "Not a member of any project" for every user on an install whose grants were all
// real.
//
// The two were never equivalent, and the containment runs one way only:
//
//	{active project_memberships rows} ⊆ {project-scoped role grants}
//
// by construction — `POST /projects/{id}/members` (AddProjectMember → AssignUserRole)
// writes a grant and no membership row, while `POST /projects/{id}/memberships`
// (inviteMemberWithMode) and invitation-accept write both. INV-CORE-44 pins that one
// direction and nothing establishes the other.
//
// So `project_memberships` is an ONBOARDING JOURNAL — it records how some grants came
// to exist, and drives ADR-022's 5-state invite machine — not the answer to
// "is X a member of P". It keeps its own reader
// (`GET /api/v1/projects/{id}/memberships`, `TransitionMembership`); what it no longer
// does is answer a membership question. `project_membership_definition_guard_test.go`
// fails the build if a second definition reappears.
//
// # Membership is not the same question as readability
//
// Deliberately NOT in this file: "which projects may this caller READ". That is a
// permission question — `Authorize(secrets.read, Scope{ProjectID: P})` — and its
// answer is a strict SUPERSET of membership, because a global `secrets.read` holder
// can read every project while being a member of none. `GetReadableScopes`
// (authz.go) is that question's single source of truth, and it is what the project
// LISTING uses (#2780). Conflating the two would either hide every project from a
// global admin or hand project data to a non-member; keep them apart.
package core

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// UserProjectMembership is one row of "which projects is this user a member of",
// as defined at the top of this file: one entry per project where the user holds a
// live project-scoped role grant.
//
// State is the ADR-022 onboarding-journal state for this (user, project) where a
// journal row exists. A member with NO journal row — the ordinary result of
// `POST /projects/{id}/members`, which is what the web UI calls — reports
// MembershipActive, because that is what the grant is: live, in force, nothing
// pending. State is never "" for a returned row; a row is only returned when the
// grant exists, and a grant in force is active by definition.
type UserProjectMembership struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`
	// Role is the role name granted at the project's scope. When the user holds
	// more than one (e.g. a direct grant plus a group-inherited one), Role carries
	// the highest-ranked of them and Roles carries all of them, sorted.
	Role  string   `json:"role"`
	Roles []string `json:"roles"`
	State string   `json:"state"`
	// ViaGroup is true when the user holds NO direct project-scoped grant and this
	// membership comes entirely from a group they belong to. An admin removing the
	// user from the project's members list will not revoke it; the group grant has
	// to go instead.
	ViaGroup bool `json:"via_group"`
	// ProjectDeleted is true when the project has been SOFT-deleted. The grant
	// survives a soft-delete by design (RestoreProject reinstates it), so the
	// membership is real and is reported — but an auditor must be able to tell it
	// apart from a membership of a live project, and a restore will bring it back.
	// Before this flag existed these rows came back with an EMPTY project name,
	// which is strictly worse than saying so.
	ProjectDeleted bool `json:"project_deleted"`
}

// IsProjectMember reports whether userID is a member of projectID, per the
// definition at the top of this file. This is the ONE function every caller asks;
// `storage.IsProjectMember` has exactly one call site in the repo (this one), which
// is what project_membership_definition_guard_test.go enforces.
//
// projectID 0 is never a project (it is the global-scope sentinel), so it is always
// false — the storage layer agrees, and this is load-bearing for break-glass, which
// must not treat "holds the install baseline" as "affiliated with this project".
//
// Fails closed: any storage error returns (false, err), never (true, err).
func (c *KeyorixCore) IsProjectMember(ctx context.Context, userID, projectID uint) (bool, error) {
	return c.storage.IsProjectMember(ctx, userID, projectID)
}

// ListProjectMembershipsForUser returns every project userID is a member of, per
// the definition at the top of this file, annotated with the ADR-022 journal state
// where a journal row exists.
//
// It is built from the SAME storage query that backs
// `GET /api/v1/projects/{id}/members` and `GET /api/v1/projects/{id}/access-review`
// (`ListProjectRoleAssignments`: direct user_roles plus non-deleted-group
// group_roles, expired grants excluded), so the per-user view and the per-project
// view agree by construction rather than by two queries happening to match — which
// is the whole point of #2781.
//
// This performs NO authorization of its own. Every caller is responsible for its
// own gate (the HTTP route's is self-OR-global-roles.read, users_roles.go's
// canReadRBACStateFor).
func (c *KeyorixCore) ListProjectMembershipsForUser(ctx context.Context, userID uint) ([]UserProjectMembership, error) {
	// Candidate projects: every scope the user holds a live grant at, direct or via
	// a group, minus the global sentinel. GetUserRoleScopes already filters expired
	// grants and soft-deleted groups.
	scopes, err := c.storage.GetUserRoleScopes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list project memberships: enumerate role scopes: %w", err)
	}
	projectIDs := make([]uint, 0, len(scopes))
	seenProject := make(map[uint]struct{}, len(scopes))
	for _, s := range scopes {
		if s.ProjectID == 0 {
			continue // global scope is not a project membership — see the file header.
		}
		if _, dup := seenProject[s.ProjectID]; dup {
			continue // the same project can appear once per environment scope.
		}
		seenProject[s.ProjectID] = struct{}{}
		projectIDs = append(projectIDs, s.ProjectID)
	}
	if len(projectIDs) == 0 {
		return []UserProjectMembership{}, nil
	}
	slices.Sort(projectIDs)

	// The user's groups, so a group-inherited grant can be attributed to them.
	groupIDs := make(map[uint]struct{})
	groups, err := c.storage.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list project memberships: enumerate groups: %w", err)
	}
	for _, g := range groups {
		if g != nil {
			groupIDs[g.ID] = struct{}{}
		}
	}

	roleNameByID, err := c.roleNamesByID(ctx)
	if err != nil {
		return nil, err
	}
	projectByID, err := c.projectIndex(ctx)
	if err != nil {
		return nil, err
	}
	stateByProject, err := c.journalStateByProject(ctx, userID)
	if err != nil {
		return nil, err
	}

	out := make([]UserProjectMembership, 0, len(projectIDs))
	for _, pid := range projectIDs {
		assignments, aerr := c.storage.ListProjectRoleAssignments(ctx, pid)
		if aerr != nil {
			return nil, fmt.Errorf("list project memberships: project %d assignments: %w", pid, aerr)
		}
		var roles []string
		direct := false
		for _, a := range assignments {
			switch {
			case a.PrincipalType == "user" && a.PrincipalID == userID:
				direct = true
			case a.PrincipalType == "group":
				if _, ok := groupIDs[a.PrincipalID]; !ok {
					continue
				}
			default:
				continue
			}
			if name, ok := roleNameByID[a.RoleID]; ok && name != "" {
				roles = append(roles, name)
			}
		}
		roles = dedupeSortedRoleNames(roles)
		if len(roles) == 0 && !direct {
			// GetUserRoleScopes said the user holds a grant here, but no assignment
			// row attributable to them came back. The two queries disagree only if a
			// grant was revoked between them (or a role row vanished). Fail closed:
			// report nothing rather than inventing a roleless membership.
			continue
		}
		state, ok := stateByProject[pid]
		if !ok || state == "" {
			// No journal row: the grant IS the membership, and a live grant is active.
			// See UserProjectMembership.State.
			state = MembershipActive
		}
		ref := projectByID[pid]
		out = append(out, UserProjectMembership{
			ProjectID:   pid,
			ProjectName: ref.Name,
			// primaryRole (identity.go) is the same rolePrecedence ranking every
			// other "one primary role" consumer uses; roles is sorted, so ties
			// among unranked custom roles resolve to the alphabetically first and
			// the result is deterministic.
			Role:           primaryRole(roles),
			Roles:          roles,
			State:          state,
			ViaGroup:       !direct,
			ProjectDeleted: ref.Deleted,
		})
	}
	return out, nil
}

// ProjectMembershipCounts returns per-user project tallies for the admin user list
// (HTTP `GET /api/v1/users`, gRPC `UserService.ListUsers`).
//
//	Active = projects the user is a MEMBER of, per this file's definition (a live
//	         project-scoped role grant, direct or via a group).
//	Total  = Active, plus projects where the ADR-022 journal holds a non-revoked row
//	         but no grant has landed yet — i.e. onboarding still in flight.
//
// #2781: this used to count journal rows for BOTH figures
// (`storage.CountProjectMembershipsByUsers`), so the admin Users list showed
// "0 projects" for every user on an install whose members were added through
// `POST /projects/{id}/members` — the same defect as the user-detail page, one screen
// over, and the one place where HTTP and gRPC BOTH read the journal. Active is now
// the membership answer; Total keeps the field's "including pending onboarding"
// meaning by adding the journal rows that have no grant behind them yet.
//
// Cost: two queries per user ID (GetUserRoleScopes), plus one journal query per user.
// Callers pass a bounded page of IDs and treat this as best-effort enrichment
// (`attachProjectCounts`/`projectCountsRecovered`), so the per-user shape is
// deliberate: it reuses the authoritative expiry-and-soft-deleted-group-filtered
// scope query rather than re-deriving that predicate over a deployment-wide grant
// dump.
func (c *KeyorixCore) ProjectMembershipCounts(ctx context.Context, userIDs []uint) (map[uint]storage.MembershipCounts, error) {
	if len(userIDs) == 0 {
		return map[uint]storage.MembershipCounts{}, nil
	}
	// Resolved once for the whole page, not per user: the counts must exclude
	// SOFT-DELETED projects. Role grants survive a soft-delete by design
	// (RestoreProject reinstates them) and GetUserRoleScopes does not filter them, so
	// without this a user showed "3 projects" where one of the three was deleted and
	// un-navigable — a number an admin cannot reconcile with anything on screen.
	//
	// The per-user LIST keeps those rows, flagged ProjectDeleted, because an access
	// review needs to see a grant that a restore would bring back. The two surfaces
	// differ deliberately: a headline count answers "how many projects is this person
	// in", and a deleted project is not one; a review answers "what grants exist",
	// and that grant does.
	projectByID, err := c.projectIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("project membership counts: %w", err)
	}
	live := func(pid uint) bool {
		ref, known := projectByID[pid]
		// Unknown (hard-deleted or never existed) counts as not live: a grant
		// pointing at nothing must not inflate the number either.
		return known && !ref.Deleted
	}

	out := make(map[uint]storage.MembershipCounts, len(userIDs))
	for _, uid := range dedupeUints(userIDs) {
		scopes, err := c.storage.GetUserRoleScopes(ctx, uid)
		if err != nil {
			return nil, fmt.Errorf("project membership counts: enumerate role scopes for user %d: %w", uid, err)
		}
		member := make(map[uint]struct{}, len(scopes))
		for _, s := range scopes {
			if s.ProjectID == 0 {
				continue // global scope is not a project membership.
			}
			if !live(s.ProjectID) {
				continue // soft-deleted or vanished — see the comment above.
			}
			member[s.ProjectID] = struct{}{}
		}
		pending := 0
		states, err := c.journalStateByProject(ctx, uid)
		if err != nil {
			return nil, fmt.Errorf("project membership counts: user %d: %w", uid, err)
		}
		for pid, state := range states {
			if state == MembershipRevoked {
				continue
			}
			if !live(pid) {
				continue // an invite into a soft-deleted project is not pending onboarding
			}
			if _, isMember := member[pid]; !isMember {
				pending++
			}
		}
		out[uid] = storage.MembershipCounts{Active: len(member), Total: len(member) + pending}
	}
	return out, nil
}

// roleNamesByID loads every role once, so attributing N projects' assignments to
// role names is one query rather than one per assignment.
func (c *KeyorixCore) roleNamesByID(ctx context.Context) (map[uint]string, error) {
	roles, err := c.storage.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("list project memberships: list roles: %w", err)
	}
	byID := make(map[uint]string, len(roles))
	for _, r := range roles {
		if r != nil {
			byID[r.ID] = r.Name
		}
	}
	return byID, nil
}

// projectRef is a project's display identity for a membership row.
type projectRef struct {
	Name    string
	Deleted bool
}

// projectIndex loads every project's name INCLUDING soft-deleted ones, with a flag.
//
// It used to call ListProjects, which GORM soft-delete-scopes, so a membership on a
// soft-deleted project came out with an EMPTY name — a row an auditor cannot act on
// or even identify. Role grants scoped to a project deliberately survive a
// soft-delete (so RestoreProject can reinstate them), so these rows are real and
// must not be reported anonymously.
//
// ListProjectsWithCounts(includeDeleted=true) is the one call that returns a
// soft-deleted project's name together with its deleted flag, in one query; its own
// raw SQL is explicit about the deleted_at filters.
//
// It is also more expensive than this function needs: two LEFT JOINs and
// COUNT(DISTINCT ...) aggregates, every column of which is discarded here — and
// this runs on the hot path of GET /api/v1/users. Flagged by the coordinator's
// review of #2874 (F6) and deliberately NOT changed in that pass: the cheap shape
// is a new storage primitive returning (id, name, deleted) only, which means an
// interface method, both backends and their tests, and that does not belong in a
// PR fixing two visibility blockers. Correct but wasteful, with the waste written
// down, rather than a hurried new primitive.
func (c *KeyorixCore) projectIndex(ctx context.Context) (map[uint]projectRef, error) {
	projects, err := c.storage.ListProjectsWithCounts(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("list project memberships: list projects: %w", err)
	}
	byID := make(map[uint]projectRef, len(projects))
	for _, p := range projects {
		byID[p.ID] = projectRef{Name: p.Name, Deleted: p.Deleted}
	}
	return byID, nil
}

// journalStateByProject reads the ADR-022 onboarding journal for one user and
// returns the state per project. A revoked row is ignored when a non-revoked row
// also exists for the same project (a revoke-then-reinvite sequence leaves both);
// a revoked row on its own is still reported, because a live grant plus a revoked
// journal row is exactly the INV-CORE-44 violation an admin must be able to see.
//
// This is the ONLY read of the journal in the membership path, and it is an
// annotation, never the membership answer — see the file header.
func (c *KeyorixCore) journalStateByProject(ctx context.Context, userID uint) (map[uint]string, error) {
	rows, err := c.storage.ListUserProjectMemberships(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list project memberships: read onboarding journal: %w", err)
	}
	byProject := make(map[uint]string, len(rows))
	for _, m := range rows {
		if m == nil {
			continue
		}
		if existing, ok := byProject[m.ProjectID]; ok && existing != MembershipRevoked {
			continue // keep the non-revoked row
		}
		byProject[m.ProjectID] = m.State
	}
	return byProject, nil
}

// dedupeSortedRoleNames removes duplicates and sorts, so a membership row's Roles
// list is stable regardless of query order.
func dedupeSortedRoleNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
