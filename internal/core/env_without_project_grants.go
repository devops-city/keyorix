// env_without_project_grants.go — ROLE-SHAPE-1 (#2857 follow-up): the
// read-only report of existing role grants at {project_id: 0, environment_id: X}.
//
// Such a grant is honoured wherever the request's environment is X (storage
// matches project_id 0 to every project), i.e. inside environment X of its
// project P, but P's access review lists
// ListProjectRoleAssignments(P), which never returns it: an access review that
// under-reports (ISO 27001 A.5.18). New grants of this shape are refused
// (validateRoleScope, #3546); rows written before that are not changed here
// (no destructive migration: Andrei, 2026-10-17). They are named, with the fix,
// by the startup notice (server/wire_global_project_roles.go) and by P's access
// review, which reports itself degraded while one exists
// (flagEnvironmentWithoutProjectGrants).
//
// User and group grants only: a machine-identity grant at {0, X} was never
// writable (requireEnvironmentInProject refuses an environment that is not of
// the named project, and machine identities cannot hold a global role).
package core

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// EnvironmentWithoutProjectGrant is one existing user or group role grant at
// {project_id: 0, environment_id: EnvironmentID}.
type EnvironmentWithoutProjectGrant struct {
	PrincipalType string // "user" or "group"
	PrincipalID   uint
	RoleID        uint
	RoleName      string
	EnvironmentID uint
	// ProjectID is the project environment EnvironmentID belongs to: the
	// project the grant applies in and should be re-created at. 0 when the
	// environment no longer exists.
	ProjectID uint
	ExpiresAt *time.Time // nil = permanent
}

// Describe names the grant and the fix, in ids only (safe to log and to return
// to an administrator).
func (g EnvironmentWithoutProjectGrant) Describe() string {
	what := fmt.Sprintf("%s %d holds role %s (id %d) at project_id=0, environment_id=%d",
		g.PrincipalType, g.PrincipalID, g.RoleName, g.RoleID, g.EnvironmentID)
	if g.ExpiresAt != nil {
		what += ", expires " + g.ExpiresAt.UTC().Format(time.RFC3339)
	}
	remove := fmt.Sprintf("DELETE /api/v1/user-roles {user_id: %d, role_id: %d, project_id: 0, environment_id: %d}",
		g.PrincipalID, g.RoleID, g.EnvironmentID)
	regrant := fmt.Sprintf("POST /api/v1/user-roles {user_id: %d, role_id: %d, project_id: %d, environment_id: %d}",
		g.PrincipalID, g.RoleID, g.ProjectID, g.EnvironmentID)
	if g.PrincipalType == "group" {
		remove = fmt.Sprintf("DELETE /api/v1/groups/%d/roles/%d?project_id=0&environment_id=%d", g.PrincipalID, g.RoleID, g.EnvironmentID)
		regrant = fmt.Sprintf("POST /api/v1/groups/%d/roles {role_id: %d, project_id: %d, environment_id: %d}",
			g.PrincipalID, g.RoleID, g.ProjectID, g.EnvironmentID)
	}
	if g.ProjectID == 0 {
		return fmt.Sprintf("%s; environment %d no longer exists: remove the grant (%s)", what, g.EnvironmentID, remove)
	}
	return fmt.Sprintf("%s; it applies in environment %d of project %d but that project's access review does not list it: "+
		"re-create it with project_id=%d (%s), then remove the old grant (%s)", what, g.EnvironmentID, g.ProjectID, g.ProjectID, regrant, remove)
}

// ListEnvironmentWithoutProjectGrants returns every user and group grant at
// {0, X != 0}, any role, expired time-bound rows included (the sweep may not
// have run yet), each with the project X belongs to, sorted by principal type,
// principal ID, role ID, then environment. Read-only.
func (c *KeyorixCore) ListEnvironmentWithoutProjectGrants(ctx context.Context) ([]EnvironmentWithoutProjectGrant, error) {
	var out []EnvironmentWithoutProjectGrant
	userGrants, err := c.storage.ListAllUserRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, g := range userGrants {
		if g.ProjectID == 0 && g.EnvironmentID != 0 {
			out = append(out, EnvironmentWithoutProjectGrant{PrincipalType: "user", PrincipalID: g.UserID, RoleID: g.RoleID, EnvironmentID: g.EnvironmentID, ExpiresAt: g.ExpiresAt})
		}
	}
	groupGrants, err := c.storage.ListAllGroupRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, g := range groupGrants {
		if g.ProjectID == 0 && g.EnvironmentID != 0 {
			out = append(out, EnvironmentWithoutProjectGrant{PrincipalType: "group", PrincipalID: g.GroupID, RoleID: g.RoleID, EnvironmentID: g.EnvironmentID, ExpiresAt: g.ExpiresAt})
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	roles, err := c.storage.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	roleNames := make(map[uint]string, len(roles))
	for _, r := range roles {
		roleNames[r.ID] = r.Name
	}
	envProject := map[uint]uint{}
	for i := range out {
		g := &out[i]
		g.RoleName = roleNames[g.RoleID]
		pid, seen := envProject[g.EnvironmentID]
		if !seen {
			env, eerr := c.storage.GetEnvironment(ctx, g.EnvironmentID)
			switch {
			case eerr == nil:
				pid = env.ProjectID
			case !isEnvironmentNotFoundErr(eerr):
				return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), eerr)
			}
			envProject[g.EnvironmentID] = pid
		}
		g.ProjectID = pid
	}
	slices.SortFunc(out, func(a, b EnvironmentWithoutProjectGrant) int {
		return cmp.Or(cmp.Compare(a.PrincipalType, b.PrincipalType), cmp.Compare(a.PrincipalID, b.PrincipalID),
			cmp.Compare(a.RoleID, b.RoleID), cmp.Compare(a.EnvironmentID, b.EnvironmentID))
	})
	return out, nil
}

// flagEnvironmentWithoutProjectGrants marks projectID's access review degraded
// for each grant at {0, X} whose environment X belongs to the project: the
// grant applies there but is not among the report's entries. A failed lookup
// degrades the report too (the completeness of the review is then unknown).
func (c *KeyorixCore) flagEnvironmentWithoutProjectGrants(ctx context.Context, projectID uint, report *AccessReviewReport) {
	grants, err := c.ListEnvironmentWithoutProjectGrants(ctx)
	if err != nil {
		report.degrade(accessReviewRoleScopeArea, err)
		return
	}
	for _, g := range grants {
		if g.ProjectID == projectID {
			report.Degraded = true
			report.DegradedReasons = append(report.DegradedReasons, accessReviewRoleScopeArea+": "+g.Describe())
		}
	}
}

// accessReviewRoleScopeArea prefixes the degraded reasons of
// flagEnvironmentWithoutProjectGrants.
const accessReviewRoleScopeArea = "grant not listed (project_id=0 with an environment of this project)"
