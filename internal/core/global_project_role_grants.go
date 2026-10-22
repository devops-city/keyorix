// global_project_role_grants.go — GROUP-ROLE-SCOPE-1 (#3546): the read-only
// report of grants the role-scope guard (role_scope_guard.go) now refuses but
// that already exist: a project-tier role held at the global scope, which
// applies in every project. Nothing here deletes or changes a grant; some of
// these may be relied on, so they need a human's review.
package core

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// GlobalProjectRoleGrant is one existing grant of a project-tier role at the
// global scope (project_id 0), to a user or a group.
type GlobalProjectRoleGrant struct {
	PrincipalType string // "user" or "group"
	PrincipalID   uint
	RoleName      string
	EnvironmentID uint       // non-zero: the {0, X} shape, also refused now
	ExpiresAt     *time.Time // nil = permanent
}

// ListGlobalProjectTierRoleGrants returns every user and group grant of an
// ADR-021 project-tier role (IsProjectTierRole) at project 0, expired
// time-bound rows included (the sweep may not have run yet), sorted by
// principal type, principal ID, then role. Read-only.
func (c *KeyorixCore) ListGlobalProjectTierRoleGrants(ctx context.Context) ([]GlobalProjectRoleGrant, error) {
	roles, err := c.storage.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	projectTier := map[uint]string{}
	for _, r := range roles {
		if IsProjectTierRole(r.Name) {
			projectTier[r.ID] = r.Name
		}
	}
	if len(projectTier) == 0 {
		return nil, nil
	}
	var out []GlobalProjectRoleGrant
	userGrants, err := c.storage.ListAllUserRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, g := range userGrants {
		if name, ok := projectTier[g.RoleID]; ok && g.ProjectID == 0 {
			out = append(out, GlobalProjectRoleGrant{PrincipalType: "user", PrincipalID: g.UserID, RoleName: name, EnvironmentID: g.EnvironmentID, ExpiresAt: g.ExpiresAt})
		}
	}
	groupGrants, err := c.storage.ListAllGroupRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, g := range groupGrants {
		if name, ok := projectTier[g.RoleID]; ok && g.ProjectID == 0 {
			out = append(out, GlobalProjectRoleGrant{PrincipalType: "group", PrincipalID: g.GroupID, RoleName: name, EnvironmentID: g.EnvironmentID, ExpiresAt: g.ExpiresAt})
		}
	}
	slices.SortFunc(out, func(a, b GlobalProjectRoleGrant) int {
		return cmp.Or(cmp.Compare(a.PrincipalType, b.PrincipalType),
			cmp.Compare(a.PrincipalID, b.PrincipalID), cmp.Compare(a.RoleName, b.RoleName))
	})
	return out, nil
}
