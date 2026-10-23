package grpc_test

// role_grant_env_without_project_walk_test.go — ROLE-SHAPE-1 (#2857 follow-up):
// no RPC creates or changes a role assignment at {project_id: 0,
// environment_id: X}. The gRPC twin of server/http
// TestEveryRoleGrantRouteRefusesEnvironmentWithoutProject; read that file's
// header for the shape and the decision.
//
// The method set is derived, not listed: walkMethods reads every RPC the live
// server registers. Every unary method except the read verbs and the verbs that
// can only take a grant away (Delete/Remove/Revoke, which would also delete the
// walk's own canary project) is called by the global admin three times, with a
// fresh target user, group and custom role, every request built by requestFor
// with the scope fields set to:
//
//	probe    {project_id: 0, environment_id: X}  X = an environment of project P
//	ctl-env  {project_id: P, environment_id: X}
//	ctl-glob {project_id: 0, environment_id: 0}
//
// Oracle: (1) no method leaves a grant row at {0, X != 0}, whatever it returns;
// (2) a method that wrote both control grants ({P, X} and {0, 0}) can express
// the shape, and must refuse the probe with InvalidArgument and core's client
// message. Non-vacuity: roleShapeRPCFloor must be in the derived set of (2).
//
// Not covered: streaming RPCs (none takes a grant scope) and a scope carried in
// a field not named project_id/environment_id ((1) still holds such a method).

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// roleShapeRPCFloor are the RPCs known to accept a caller-chosen
// {project_id, environment_id} grant scope.
var roleShapeRPCFloor = []string{"keyorix.v1.RoleService/AssignRole"}

// roleShapeRPCRemovalVerbs only take grants (and other objects) away.
var roleShapeRPCRemovalVerbs = []string{"Delete", "Remove", "Revoke"}

type rpcGrantScope struct {
	table                string
	project, environment uint
}

func (s rpcGrantScope) String() string {
	return fmt.Sprintf("%s{%d,%d}", s.table, s.project, s.environment)
}

func (w *walkWorld) grantsOfRole(t *testing.T, roleID uint) []rpcGrantScope {
	t.Helper()
	var out []rpcGrantScope
	var users []models.UserRole
	require.NoError(t, w.db.Where("role_id = ?", roleID).Find(&users).Error)
	for _, g := range users {
		out = append(out, rpcGrantScope{"user_roles", g.ProjectID, g.EnvironmentID})
	}
	var groups []models.GroupRole
	require.NoError(t, w.db.Where("role_id = ?", roleID).Find(&groups).Error)
	for _, g := range groups {
		out = append(out, rpcGrantScope{"group_roles", g.ProjectID, g.EnvironmentID})
	}
	var machines []models.MachineIdentityRole
	require.NoError(t, w.db.Where("role_id = ?", roleID).Find(&machines).Error)
	for _, g := range machines {
		out = append(out, rpcGrantScope{"machine_identity_roles", g.ProjectID, g.EnvironmentID})
	}
	return out
}

func TestEveryRoleGrantRPCRefusesEnvironmentWithoutProject(t *testing.T) {
	forEachWalkBackend(t, func(t *testing.T, w *walkWorld) {
		ctx := context.Background()
		p, x := w.ids.canaryProject, w.ids.canaryEnv
		semantic := w.ids.variants()[0].bind
		conn := w.dial(t)
		t.Cleanup(func() { _ = conn.Close() })

		var walked int
		var expressible, violations []string
		for i, m := range w.methods {
			if m.stream() || m.isRead() || hasVerb(m.name, roleShapeRPCRemovalVerbs) {
				continue
			}
			walked++
			n := fmt.Sprintf("rsrpc%d", i)
			u, err := w.core.CreateUser(ctx, &core.CreateUserRequest{Username: n + "user", Email: n + "user@example.com", Password: walkPassword})
			require.NoError(t, err)
			g, err := w.core.CreateGroup(ctx, w.adminID, &core.CreateGroupRequest{Name: n + "group"})
			require.NoError(t, err)
			role, _, err := w.core.CreateRole(ctx, w.adminID, n+"role", "role-shape probe", nil)
			require.NoError(t, err)

			try := func(project, env uint) error {
				bind := func(msg, field string) uint64 {
					switch {
					case field == "project_id":
						return uint64(project)
					case field == "environment_id":
						return uint64(env)
					case field == "role_id" || (field == "id" && strings.Contains(msg, "Role")):
						return uint64(role.ID)
					case field == "user_id" || (field == "id" && strings.Contains(msg, "User")):
						return uint64(u.ID)
					case field == "group_id" || (field == "id" && strings.Contains(msg, "Group")):
						return uint64(g.ID)
					}
					return semantic(msg, field)
				}
				req := requestFor(m.input, bind)
				for _, name := range []protoreflect.Name{"role", "role_name"} {
					if fd := m.input.Fields().ByName(name); fd != nil && fd.Kind() == protoreflect.StringKind && !fd.IsList() {
						req.Set(fd, protoreflect.ValueOfString(role.Name))
					}
				}
				res := call(t, conn, m, w.admin, req)
				if status.Code(res.err) == codes.Unauthenticated {
					sess, _, lerr := w.core.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
					require.NoError(t, lerr)
					w.admin = sess.SessionToken
				}
				return res.err
			}

			probeErr := try(0, x)
			for _, s := range w.grantsOfRole(t, role.ID) {
				if s.project == 0 && s.environment != 0 {
					violations = append(violations, fmt.Sprintf("%s wrote %s (%v)", m.key(), s, status.Code(probeErr)))
				}
			}
			_ = try(p, x)
			_ = try(0, 0)
			var envHonoured, globalHonoured bool
			for _, s := range w.grantsOfRole(t, role.ID) {
				envHonoured = envHonoured || (s.project == p && s.environment == x)
				globalHonoured = globalHonoured || (s.project == 0 && s.environment == 0)
			}
			if !envHonoured || !globalHonoured {
				continue
			}
			expressible = append(expressible, m.key())
			if status.Code(probeErr) != codes.InvalidArgument || !strings.Contains(status.Convert(probeErr).Message(), "environment_id requires project_id") {
				violations = append(violations, fmt.Sprintf("%s answered {0, %d} with %v, want InvalidArgument %q",
					m.key(), x, probeErr, "environment_id requires project_id"))
			}
		}

		t.Logf("walked %d unary write RPCs; those that accept a caller-chosen {project_id, environment_id} grant scope: %s",
			walked, strings.Join(expressible, ", "))
		for _, want := range roleShapeRPCFloor {
			require.Truef(t, slices.Contains(expressible, want),
				"non-vacuity: %s did not honour both controls, so the walk never tested it (derived set: %v)", want, expressible)
		}
		for _, v := range violations {
			t.Error(v)
		}
	})
}
