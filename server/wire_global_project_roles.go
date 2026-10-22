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
	return nil
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
