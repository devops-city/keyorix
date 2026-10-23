// role_grant_env_without_project_walk_test.go — ROLE-SHAPE-1 (#2857 follow-up):
// no HTTP route creates or changes a role assignment at {project_id: 0,
// environment_id: X}.
//
// # The shape
//
// A grant at {0, X} is honoured at that scope (inside X's project), but the
// project's access review lists ListProjectRoleAssignments(P), which never
// returns it: an ISO 27001 A.5.18 under-report. Andrei decided (2026-10-17) to
// REJECT the shape; core's validateRoleScope refuses it at every storage grant
// write (#3546, INV-CORE-role-grant-scope-valid-for-role). This walk proves no
// transport route gets around that check.
//
// # The walk: TestEveryRoleGrantRouteRefusesEnvironmentWithoutProject
//
// The route set is derived, not listed: chi.Walk over NewRouter, every POST/PUT/
// PATCH under /api/v1. Each route is called by the global admin three times, with
// a fresh target user, group and custom role (so every grant row the route writes
// is attributable to it by role_id), the awBody union plus the scope fields:
//
//	probe    {project_id: 0, environment_id: X}  X = an environment of project P
//	ctl-env  {project_id: P, environment_id: X}  does the route honour environment_id?
//	ctl-glob {project_id: 0, environment_id: 0}  does it let the caller choose project 0?
//
// Oracle:
//
//  1. no route, whatever its status, leaves a user/group/machine grant row at
//     {0, X != 0};
//  2. every route that honoured BOTH controls (it wrote the ctl-env grant at
//     {P, X} and the ctl-glob grant at {0, 0}) is a route that can express the
//     shape; its probe must be answered 400 with core's client message.
//
// Non-vacuity: the derived set of (2) must contain roleShapeRouteFloor, the grant
// routes known today. The floor is a lower bound the derivation must reach, not
// the enumeration: a new route that honours both controls joins the set by
// itself.
//
// Not covered, said plainly: query-parameter scopes (no grant route reads one),
// bodies outside the awBody union plus the scope fields (a handler reading the
// scope under another key would look like it ignores environment_id and fall
// out of (2), though (1) still holds it), and SCIM (/scim/v2 has no role field).
// gRPC is TestEveryRoleGrantRPCRefusesEnvironmentWithoutProject (server/grpc).
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// roleShapeClientMessage is core's refusal of the shape (role_scope_guard.go).
const roleShapeClientMessage = "environment_id requires project_id"

// roleShapeRouteFloor are the routes known to accept a caller-chosen
// {project_id, environment_id} grant scope: the derived set must contain them.
var roleShapeRouteFloor = []string{
	"POST /api/v1/user-roles/",
	"PUT /api/v1/users/{id}/roles",
	"POST /api/v1/groups/{id}/roles",
}

// roleShapeSkip are routes that would end the admin session the rest of the
// walk needs (the same set awControl skips). None of them writes a grant.
func roleShapeSkip(path string) bool {
	return path == "/api/v1/auth/change-password" || strings.HasPrefix(path, "/api/v1/auth/mfa") ||
		path == "/api/v1/admin/impersonate"
}

// roleShapeScope is a grant row's scope, with the table it is in.
type roleShapeScope struct {
	table       string
	project     uint
	environment uint
}

func (s roleShapeScope) String() string {
	return fmt.Sprintf("%s{%d,%d}", s.table, s.project, s.environment)
}

// roleShapeGrants returns every grant row of roleID, in every grant table.
func roleShapeGrants(t *testing.T, r *svReplica, roleID uint) []roleShapeScope {
	t.Helper()
	var out []roleShapeScope
	var users []models.UserRole
	require.NoError(t, r.db.Where("role_id = ?", roleID).Find(&users).Error)
	for _, g := range users {
		out = append(out, roleShapeScope{"user_roles", g.ProjectID, g.EnvironmentID})
	}
	var groups []models.GroupRole
	require.NoError(t, r.db.Where("role_id = ?", roleID).Find(&groups).Error)
	for _, g := range groups {
		out = append(out, roleShapeScope{"group_roles", g.ProjectID, g.EnvironmentID})
	}
	var machines []models.MachineIdentityRole
	require.NoError(t, r.db.Where("role_id = ?", roleID).Find(&machines).Error)
	for _, g := range machines {
		out = append(out, roleShapeScope{"machine_identity_roles", g.ProjectID, g.EnvironmentID})
	}
	return out
}

// roleShapeBody is the awBody union with the grant target, role and scope set.
func roleShapeBody(t *testing.T, w *awWorld, n int, role *models.Role, project, env uint) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(w.awBodyN(n), &m))
	m["project_id"], m["environment_id"] = project, env
	m["role_id"], m["role_ids"] = role.ID, []uint{role.ID}
	m["role"], m["role_name"] = role.Name, role.Name
	m["user_id"], m["user_ids"], m["group_id"] = w.ids["user"], []uint{w.ids["user"]}, w.ids["group"]
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return out
}

func TestEveryRoleGrantRouteRefusesEnvironmentWithoutProject(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { roleShapeWalk(t, backend) })
	}
}

func roleShapeWalk(t *testing.T, backend string) {
	w := newAWWorld(t, backend, 1)
	r, ctx := w.a, context.Background()
	p, x := w.ids["project"], w.ids["env"]
	var mutating []awRoute
	for _, rt := range awMutatingRoutes(t, r) {
		if rt.Method != http.MethodDelete && !roleShapeSkip(rt.Path) {
			mutating = append(mutating, rt)
		}
	}

	var expressible, violations []string
	for i, rt := range mutating {
		// A fresh target user, group and role per route: every row of the role is
		// this route's, and no earlier route can have deactivated the target.
		n := fmt.Sprintf("rs%d", i)
		u, err := r.c.CreateUser(ctx, &core.CreateUserRequest{Username: n + "user", Email: n + "user@x.io", Password: svPassword})
		require.NoError(t, err)
		g, err := r.c.CreateGroup(ctx, w.adminID, &core.CreateGroupRequest{Name: n + "group"})
		require.NoError(t, err)
		role, _, err := r.c.CreateRole(ctx, w.adminID, n+"role", "role-shape probe", nil)
		require.NoError(t, err)
		w.ids["user"], w.ids["group"] = u.ID, g.ID
		path := w.awPaths(rt.Path)[0]

		call := func(k int, project, env uint) (int, string) {
			code, resp := awDo(r, rt.Method, w.tokens["admin"], path, roleShapeBody(t, w, 3*i+k, role, project, env))
			if code == http.StatusUnauthorized {
				w.revive(t, "admin")
			}
			return code, resp
		}
		probeCode, probeResp := call(0, 0, x)
		for _, s := range roleShapeGrants(t, r, role.ID) {
			if s.project == 0 && s.environment != 0 {
				violations = append(violations, fmt.Sprintf("%s wrote %s (status %d)", rt.key(), s, probeCode))
			}
		}
		call(1, p, x)
		call(2, 0, 0)
		var envHonoured, globalHonoured bool
		for _, s := range roleShapeGrants(t, r, role.ID) {
			envHonoured = envHonoured || (s.project == p && s.environment == x)
			globalHonoured = globalHonoured || (s.project == 0 && s.environment == 0)
		}
		if !envHonoured || !globalHonoured {
			continue
		}
		expressible = append(expressible, rt.key())
		if probeCode != http.StatusBadRequest || !strings.Contains(probeResp, roleShapeClientMessage) {
			violations = append(violations, fmt.Sprintf("%s answered {0, %d} with %d, want 400 %q: %.200s",
				rt.key(), x, probeCode, roleShapeClientMessage, probeResp))
		}
	}

	t.Logf("walked %d POST/PUT/PATCH routes; those that accept a caller-chosen {project_id, environment_id} grant scope: %s",
		len(mutating), strings.Join(expressible, ", "))
	for _, want := range roleShapeRouteFloor {
		require.Truef(t, slices.Contains(expressible, want),
			"non-vacuity: %s did not honour both controls, so the walk never tested it (derived set: %v)", want, expressible)
	}
	for _, v := range violations {
		t.Error(v)
	}
}
