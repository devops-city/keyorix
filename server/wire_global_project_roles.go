package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// maxGlobalProjectRoleGrantLines bounds how many grants the startup notice
// names one by one; the total is always stated.
const maxGlobalProjectRoleGrantLines = 50

// wireGlobalProjectRoleGrantsNotice is a core wiring step (coreWiringSteps in
// main.go). GROUP-ROLE-SCOPE-1 (#3546): grants of a project-tier role at the
// global scope apply in EVERY project, and new ones are now refused. Existing
// ones are not touched (some may be relied on): this lists them, and SSO
// settings that would create them, as a WARNING for an administrator to review.
// ROLE-SHAPE-1 adds grants at {project_id: 0, environment_id: X} of any role,
// which X's project's access review does not list.
// Read-only and best-effort: it never blocks startup.
func wireGlobalProjectRoleGrantsNotice(cw *coreWiring) error {
	for _, line := range ssoProjectTierRoleWarnings(cw.cfg) {
		log.Printf("WARNING: %s", line)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	grants, err := cw.core.ListGlobalProjectTierRoleGrants(ctx)
	if err != nil {
		log.Printf("global project-role grant check: %v (continuing; the check did not run)", err)
		return nil
	}
	for _, line := range globalProjectRoleGrantNotice(grants) {
		log.Print(line)
	}
	envGrants, err := cw.core.ListEnvironmentWithoutProjectGrants(ctx)
	if err != nil {
		log.Printf("environment-without-project grant check: %v (continuing; the check did not run)", err)
		return nil
	}
	for _, line := range environmentWithoutProjectGrantNotice(envGrants) {
		log.Print(line)
	}
	return nil
}

// environmentWithoutProjectGrantNotice renders the startup notice for grants at
// {project_id: 0, environment_id: X} (ROLE-SHAPE-1, #2857); nil when there are
// none. Any role: unlike the project-tier notice above, the problem is the
// shape, which the access review of X's project does not list.
func environmentWithoutProjectGrantNotice(grants []core.EnvironmentWithoutProjectGrant) []string {
	if len(grants) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("WARNING: %d existing role grant(s) at project_id=0 with an environment_id: each applies "+
		"inside that environment but is missing from its project's access review. New grants like these are refused "+
		"since #3546; these were left in place. Re-create each with the environment's project_id, then remove it:", len(grants))}
	for i, g := range grants {
		if i == maxGlobalProjectRoleGrantLines {
			lines = append(lines, fmt.Sprintf("WARNING:   ... and %d more (each project's access review names its own)", len(grants)-i))
			break
		}
		lines = append(lines, "WARNING:   "+g.Describe())
	}
	return lines
}

// globalProjectRoleGrantNotice renders the startup notice for grants; nil when
// there are none.
func globalProjectRoleGrantNotice(grants []core.GlobalProjectRoleGrant) []string {
	if len(grants) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("WARNING: %d existing grant(s) of a project role at the global scope (no project): "+
		"each applies in EVERY project. New grants like these are refused since #3546; these were left in place "+
		"for review. For each, re-grant the role on the project(s) intended, then remove the global grant "+
		"(DELETE /api/v1/user-roles, or DELETE /api/v1/groups/{id}/roles/{roleId} without project_id).", len(grants))}
	for i, g := range grants {
		if i == maxGlobalProjectRoleGrantLines {
			lines = append(lines, fmt.Sprintf("WARNING:   ... and %d more", len(grants)-i))
			break
		}
		detail := ""
		if g.EnvironmentID != 0 {
			detail += fmt.Sprintf(", environment_id=%d", g.EnvironmentID)
		}
		if g.ExpiresAt != nil {
			detail += ", expires " + g.ExpiresAt.UTC().Format(time.RFC3339)
		}
		lines = append(lines, fmt.Sprintf("WARNING:   %s %d holds %s globally%s", g.PrincipalType, g.PrincipalID, g.RoleName, detail))
	}
	return lines
}

// ssoProjectTierRoleWarnings names each SSO provider setting that maps a
// project-tier role: both default_role and group_role_map grant at the global
// scope, so such a mapping is refused at login now.
func ssoProjectTierRoleWarnings(cfg *config.Config) []string {
	var out []string
	for _, p := range cfg.SSO.Providers {
		if role := strings.TrimSpace(p.DefaultRole); core.IsProjectTierRole(role) {
			out = append(out, fmt.Sprintf("sso provider %q: default_role %s is a project role, which would apply in every project; "+
				"JIT provisioning through this provider is refused until default_role names a system role (e.g. system_viewer)", p.Name, role))
		}
		groups := make([]string, 0, len(p.GroupRoleMap))
		for group, role := range p.GroupRoleMap {
			if core.IsProjectTierRole(strings.TrimSpace(role)) {
				groups = append(groups, group)
			}
		}
		sort.Strings(groups)
		for _, group := range groups {
			out = append(out, fmt.Sprintf("sso provider %q: group_role_map %q -> %s maps a project role at the global scope; "+
				"the grant is refused at login. Use a Keyorix group with a project-scoped role grant instead",
				p.Name, group, strings.TrimSpace(p.GroupRoleMap[group])))
		}
	}
	return out
}
