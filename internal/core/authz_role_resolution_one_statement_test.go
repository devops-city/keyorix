package core

// authz_role_resolution_one_statement_test.go — PERF-FIX-6 (collapse C4 of
// SESSION-PERF-FIX-3's plan).
//
// A role-based authorization decision resolved the principal's roles in
// several statements: for a user, the direct role ids, the group role ids, the
// admin-bypass flag, and (non-admin) the role->permission cache generation;
// for a machine, the role ids and the generation. Each principal kind now
// reads all of that in ONE statement (storage.ResolveUserPermissionAt /
// ResolveMachinePermissionAt).
//
// TestAuthorizeRoleResolution_Equivalence is the behaviour pin: for every case
// it records the decision of Authorize, AuthorizePrincipal and
// principalHasScopedPermission, cold and warm. It uses nothing the change
// added, and it passes unchanged on the code before the change and after it:
// that is the before/after equivalence. _MutationsSeenOnNextCall changes the
// world after a warm decision (role revoked, permission removed or added,
// group deleted, machine role revoked) and checks the very next decision.
// _CrossReplica does both across two Postgres replicas (two pools, two
// caches), including writes racing Authorize calls. _OneStatement is the
// red/green: before, a warm decision issued 2-4 statements; after, 1.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// c4World is one database and a function that opens another, independent
// replica on it (own *gorm.DB pool, own LocalStorage caches, own core).
type c4World struct {
	t       *testing.T
	db      *gorm.DB
	core    *KeyorixCore
	replica func() (*KeyorixCore, *gorm.DB)
}

func newC4World(t *testing.T, backend string) *c4World {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	var open func() *gorm.DB
	switch backend {
	case "sqlite":
		path := filepath.Join(t.TempDir(), "c4.db")
		open = func() *gorm.DB {
			db, err := gorm.Open(sqlite.Open("file:"+path+sqliteProdPragmas), &gorm.Config{Logger: logger.Discard})
			require.NoError(t, err)
			t.Cleanup(func() {
				if sqlDB, err := db.DB(); err == nil {
					_ = sqlDB.Close()
				}
			})
			return db
		}
	case "postgres":
		dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
		open = func() *gorm.DB { return pgOpen(t, dsn) }
	default:
		t.Fatalf("unknown backend %q", backend)
	}
	db := open()
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	w := &c4World{t: t, db: db, core: NewKeyorixCore(localstore.NewLocalStorage(db))}
	w.replica = func() (*KeyorixCore, *gorm.DB) {
		rdb := open()
		return NewKeyorixCore(localstore.NewLocalStorage(rdb)), rdb
	}
	return w
}

func c4Backends(t *testing.T) []string {
	t.Helper()
	if os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
		t.Log("KEYORIX_TEST_PG_DSN not set: Postgres leg skipped")
		return []string{"sqlite"}
	}
	return []string{"sqlite", "postgres"}
}

var c4Seq atomic.Int64

func (w *c4World) name(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, c4Seq.Add(1))
}

func (w *c4World) permission(name string) *models.Permission {
	w.t.Helper()
	p, err := w.core.storage.CreatePermission(context.Background(), &models.Permission{Name: name, Resource: "c4", Action: name})
	require.NoError(w.t, err)
	return p
}

func (w *c4World) role(bypass bool, perms ...*models.Permission) *models.Role {
	w.t.Helper()
	ctx := context.Background()
	n, err := identity.NewFoldedName(w.name("c4-role"))
	require.NoError(w.t, err)
	r, err := w.core.storage.CreateRole(ctx, n, "")
	require.NoError(w.t, err)
	for _, p := range perms {
		require.NoError(w.t, w.core.storage.AssignPermissionToRole(ctx, r.ID, p.ID))
	}
	if bypass {
		require.NoError(w.t, w.core.storage.SetRoleBypassesPermissionChecks(ctx, r.ID, true))
	}
	return r
}

func (w *c4World) user() *models.User {
	w.t.Helper()
	n := w.name("c4-user")
	u, err := w.core.storage.CreateUser(context.Background(), &models.User{
		Username: n, UsernameFolded: n, Email: n + "@example.com", EmailFolded: n + "@example.com",
		IsActive: true, AccountState: "active",
	})
	require.NoError(w.t, err)
	return u
}

func (w *c4World) group() *models.Group {
	w.t.Helper()
	n := w.name("c4-group")
	g, err := w.core.storage.CreateGroup(context.Background(), &models.Group{Name: n, NameFolded: n})
	require.NoError(w.t, err)
	return g
}

func (w *c4World) project() *models.Project {
	w.t.Helper()
	p, err := w.core.storage.CreateProject(context.Background(), &models.Project{Name: w.name("c4-project")})
	require.NoError(w.t, err)
	return p
}

func (w *c4World) env(projectID uint) *models.Environment {
	w.t.Helper()
	e, err := w.core.storage.CreateEnvironment(context.Background(), &models.Environment{ProjectID: projectID, Name: w.name("c4-env")})
	require.NoError(w.t, err)
	return e
}

func (w *c4World) machine(projectID uint) *models.MachineIdentity {
	w.t.Helper()
	m, err := w.core.storage.CreateMachineIdentity(context.Background(), &models.MachineIdentity{
		ProjectID: projectID, Name: w.name("c4-machine"), IdentityType: "other", State: "active",
	})
	require.NoError(w.t, err)
	return m
}

// c4Check is one decision to pin: who, which permission, at which scope.
type c4Check struct {
	name      string
	machine   bool
	principal uint
	perm      string
	scope     Scope
	pat       *PATRestriction
	want      bool
}

// decide evaluates check through every role-based decision entry point that
// applies to its principal kind, and fails unless all of them agree with want.
func c4Decide(t *testing.T, c *KeyorixCore, check c4Check, pass string) {
	t.Helper()
	ctx := context.Background()
	if check.pat != nil {
		ctx = WithPATRestriction(ctx, check.pat)
	}
	if check.machine {
		got, err := c.AuthorizePrincipal(ctx, ActorTypeMachine, check.principal, check.perm, check.scope)
		require.NoError(t, err, "%s (%s): AuthorizePrincipal(machine)", check.name, pass)
		require.Equal(t, check.want, got, "%s (%s): AuthorizePrincipal(machine)", check.name, pass)
		return
	}
	got, err := c.Authorize(ctx, check.principal, check.perm, check.scope)
	require.NoError(t, err, "%s (%s): Authorize", check.name, pass)
	require.Equal(t, check.want, got, "%s (%s): Authorize", check.name, pass)
	got, err = c.AuthorizePrincipal(ctx, ActorTypeUser, check.principal, check.perm, check.scope)
	require.NoError(t, err, "%s (%s): AuthorizePrincipal(user)", check.name, pass)
	require.Equal(t, check.want, got, "%s (%s): AuthorizePrincipal(user)", check.name, pass)
	if check.pat == nil {
		// principalHasScopedPermission ignores the caller's PAT by design, so it
		// is pinned only on the cases without one.
		got, err = c.principalHasScopedPermission(ctx, check.principal, check.perm, check.scope)
		require.NoError(t, err, "%s (%s): principalHasScopedPermission", check.name, pass)
		require.Equal(t, check.want, got, "%s (%s): principalHasScopedPermission", check.name, pass)
	}
}

// c4Fixture is the world the equivalence table runs against.
type c4Fixture struct {
	pRead, pWrite, pOther         *models.Permission
	rRead, rWrite, rBypass, rNone *models.Role
	p1, p2, pDel                  *models.Project
	e1a, e1b, eDel                *models.Environment
}

func buildC4Fixture(w *c4World) (*c4Fixture, []c4Check) {
	t := w.t
	ctx := context.Background()
	s := w.core.storage
	f := &c4Fixture{}
	f.pRead, f.pWrite, f.pOther = w.permission(w.name("c4.read")), w.permission(w.name("c4.write")), w.permission(w.name("c4.other"))
	f.rRead = w.role(false, f.pRead)
	f.rWrite = w.role(false, f.pWrite)
	f.rBypass = w.role(true) // admin-bypass role bundling no permissions
	f.rNone = w.role(false)  // a role bundling nothing
	f.p1, f.p2, f.pDel = w.project(), w.project(), w.project()
	f.e1a, f.e1b, f.eDel = w.env(f.p1.ID), w.env(f.p1.ID), w.env(f.p1.ID)

	g := Scope{}
	at := func(p *models.Project) Scope { return Scope{ProjectID: p.ID} }
	atEnv := func(p *models.Project, e *models.Environment) Scope {
		return Scope{ProjectID: p.ID, EnvironmentID: e.ID}
	}
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	R, W, O := f.pRead.Name, f.pWrite.Name, f.pOther.Name

	var checks []c4Check
	add := func(name string, principal uint, perm string, scope Scope, want bool) {
		checks = append(checks, c4Check{name: name, principal: principal, perm: perm, scope: scope, want: want})
	}
	addM := func(name string, principal uint, perm string, scope Scope, want bool) {
		checks = append(checks, c4Check{name: name, machine: true, principal: principal, perm: perm, scope: scope, want: want})
	}

	// Global admin-bypass role: every permission, every scope.
	admin := w.user()
	require.NoError(t, s.AssignRole(ctx, admin.ID, f.rBypass.ID, g))
	add("global bypass: unbundled perm at global", admin.ID, O, g, true)
	add("global bypass: unbundled perm at project", admin.ID, R, at(f.p1), true)
	add("global bypass: unbundled perm at env", admin.ID, W, atEnv(f.p1, f.e1a), true)
	checks = append(checks, c4Check{name: "global bypass: PAT scoped to another project denies first",
		principal: admin.ID, perm: R, scope: at(f.p1), pat: &PATRestriction{ProjectID: f.p2.ID}, want: false})
	checks = append(checks, c4Check{name: "global bypass: PAT allowing the scope",
		principal: admin.ID, perm: R, scope: at(f.p1), pat: &PATRestriction{ProjectID: f.p1.ID}, want: true})

	// Project-scoped admin-bypass role: bypass only inside that project.
	projAdmin := w.user()
	require.NoError(t, s.AssignRole(ctx, projAdmin.ID, f.rBypass.ID, at(f.p1)))
	add("project bypass: inside the project", projAdmin.ID, O, at(f.p1), true)
	add("project bypass: env of the project", projAdmin.ID, O, atEnv(f.p1, f.e1b), true)
	add("project bypass: other project", projAdmin.ID, O, at(f.p2), false)
	add("project bypass: global", projAdmin.ID, O, g, false)

	// Direct project role.
	direct := w.user()
	require.NoError(t, s.AssignRole(ctx, direct.ID, f.rRead.ID, at(f.p1)))
	add("direct project role: bundled perm at project", direct.ID, R, at(f.p1), true)
	add("direct project role: bundled perm at env", direct.ID, R, atEnv(f.p1, f.e1a), true)
	add("direct project role: unbundled perm", direct.ID, W, at(f.p1), false)
	add("direct project role: other project", direct.ID, R, at(f.p2), false)
	add("direct project role: global", direct.ID, R, g, false)

	// Direct environment role.
	envUser := w.user()
	require.NoError(t, s.AssignRole(ctx, envUser.ID, f.rRead.ID, atEnv(f.p1, f.e1a)))
	add("direct env role: that env", envUser.ID, R, atEnv(f.p1, f.e1a), true)
	add("direct env role: sibling env", envUser.ID, R, atEnv(f.p1, f.e1b), false)
	add("direct env role: project level", envUser.ID, R, at(f.p1), false)

	// Direct global role.
	globalUser := w.user()
	require.NoError(t, s.AssignRole(ctx, globalUser.ID, f.rRead.ID, g))
	add("direct global role: global", globalUser.ID, R, g, true)
	add("direct global role: project", globalUser.ID, R, at(f.p2), true)
	add("direct global role: unbundled", globalUser.ID, W, at(f.p2), false)

	// A role bundling nothing.
	noneUser := w.user()
	require.NoError(t, s.AssignRole(ctx, noneUser.ID, f.rNone.ID, at(f.p1)))
	add("empty role: denies", noneUser.ID, R, at(f.p1), false)

	// Group role, global membership.
	g1 := w.group()
	require.NoError(t, s.AssignRoleToGroup(ctx, g1.ID, f.rWrite.ID, at(f.p1)))
	groupUser := w.user()
	require.NoError(t, s.AddUserToGroup(ctx, groupUser.ID, g1.ID, 0))
	add("group role: bundled perm at project", groupUser.ID, W, at(f.p1), true)
	add("group role: bundled perm at env", groupUser.ID, W, atEnv(f.p1, f.e1b), true)
	add("group role: unbundled perm", groupUser.ID, R, at(f.p1), false)
	add("group role: other project", groupUser.ID, W, at(f.p2), false)

	// Group membership scoped to another project: the group's p1 role does not apply.
	scopedMember := w.user()
	require.NoError(t, s.AddUserToGroup(ctx, scopedMember.ID, g1.ID, f.p2.ID))
	add("membership scoped to p2: group role at p1 does not apply", scopedMember.ID, W, at(f.p1), false)
	add("membership scoped to p2: nothing at p2", scopedMember.ID, W, at(f.p2), false)

	// Membership scoped to the role's own project: applies there.
	scopedMember1 := w.user()
	require.NoError(t, s.AddUserToGroup(ctx, scopedMember1.ID, g1.ID, f.p1.ID))
	add("membership scoped to p1: group role at p1 applies", scopedMember1.ID, W, at(f.p1), true)

	// Direct + group roles together: the union decides.
	both := w.user()
	require.NoError(t, s.AssignRole(ctx, both.ID, f.rRead.ID, at(f.p1)))
	require.NoError(t, s.AddUserToGroup(ctx, both.ID, g1.ID, 0))
	add("direct+group: direct perm", both.ID, R, at(f.p1), true)
	add("direct+group: group perm", both.ID, W, at(f.p1), true)
	add("direct+group: neither", both.ID, O, at(f.p1), false)

	// Same role held directly and via a group (duplicate role id).
	dup := w.user()
	require.NoError(t, s.AssignRole(ctx, dup.ID, f.rWrite.ID, at(f.p1)))
	require.NoError(t, s.AddUserToGroup(ctx, dup.ID, g1.ID, 0))
	add("same role direct and via group", dup.ID, W, at(f.p1), true)

	// Admin-bypass role via a group.
	gAdm := w.group()
	require.NoError(t, s.AssignRoleToGroup(ctx, gAdm.ID, f.rBypass.ID, at(f.p1)))
	groupAdmin := w.user()
	require.NoError(t, s.AddUserToGroup(ctx, groupAdmin.ID, gAdm.ID, 0))
	add("group bypass: inside the project", groupAdmin.ID, O, at(f.p1), true)
	add("group bypass: other project", groupAdmin.ID, O, at(f.p2), false)

	// Soft-deleted group: confers nothing.
	gDel := w.group()
	require.NoError(t, s.AssignRoleToGroup(ctx, gDel.ID, f.rRead.ID, at(f.p1)))
	gDelAdm := w.group()
	require.NoError(t, s.AssignRoleToGroup(ctx, gDelAdm.ID, f.rBypass.ID, g))
	delGroupUser := w.user()
	require.NoError(t, s.AddUserToGroup(ctx, delGroupUser.ID, gDel.ID, 0))
	require.NoError(t, s.AddUserToGroup(ctx, delGroupUser.ID, gDelAdm.ID, 0))
	require.NoError(t, s.DeleteGroup(ctx, gDel.ID))
	require.NoError(t, s.DeleteGroup(ctx, gDelAdm.ID))
	add("deleted group: its role confers nothing", delGroupUser.ID, R, at(f.p1), false)
	add("deleted group: its bypass role confers nothing", delGroupUser.ID, O, g, false)

	// Expired grants.
	expired := w.user()
	require.NoError(t, s.AssignRoleWithExpiry(ctx, expired.ID, f.rRead.ID, at(f.p1), past))
	require.NoError(t, s.AssignRoleWithExpiry(ctx, expired.ID, f.rBypass.ID, g, past))
	add("expired direct grants: deny", expired.ID, R, at(f.p1), false)
	notYet := w.user()
	require.NoError(t, s.AssignRoleWithExpiry(ctx, notYet.ID, f.rRead.ID, at(f.p1), future))
	add("unexpired time-bound grant: allow", notYet.ID, R, at(f.p1), true)
	gExp := w.group()
	require.NoError(t, s.AssignRoleToGroupWithExpiry(ctx, gExp.ID, f.rRead.ID, at(f.p1), past))
	expiredGroupUser := w.user()
	require.NoError(t, s.AddUserToGroup(ctx, expiredGroupUser.ID, gExp.ID, 0))
	add("expired group grant: deny", expiredGroupUser.ID, R, at(f.p1), false)

	// No roles at all.
	nobody := w.user()
	add("no roles: global", nobody.ID, R, g, false)
	add("no roles: project", nobody.ID, R, at(f.p1), false)
	add("unknown user id", nobody.ID+100000, R, at(f.p1), false)

	// Account state is not part of role resolution: the auth layer refuses a
	// suspended or deleted account before any authorization runs. Pinned as it is.
	suspended := w.user()
	require.NoError(t, s.AssignRole(ctx, suspended.ID, f.rRead.ID, at(f.p1)))
	require.NoError(t, s.SetAccountState(ctx, suspended.ID, "suspended", time.Now()))
	add("suspended user: role resolution unchanged", suspended.ID, R, at(f.p1), true)
	deletedUser := w.user()
	require.NoError(t, s.AssignRole(ctx, deletedUser.ID, f.rRead.ID, at(f.p1)))
	require.NoError(t, s.DeleteUser(ctx, deletedUser.ID))
	// DeleteUser is a soft delete that keeps the user_roles rows (for restore).
	add("deleted user: role rows still resolve", deletedUser.ID, R, at(f.p1), true)

	// Soft-deleted project / environment: a role scoped to it confers nothing there.
	delProjUser := w.user()
	require.NoError(t, s.AssignRole(ctx, delProjUser.ID, f.rRead.ID, at(f.pDel)))
	delEnvUser := w.user()
	require.NoError(t, s.AssignRole(ctx, delEnvUser.ID, f.rRead.ID, atEnv(f.p1, f.eDel)))
	gDelScope := w.group()
	require.NoError(t, s.AssignRoleToGroup(ctx, gDelScope.ID, f.rRead.ID, at(f.pDel)))
	delProjGroupUser := w.user()
	require.NoError(t, s.AddUserToGroup(ctx, delProjGroupUser.ID, gDelScope.ID, 0))

	// Machines: role-only, never an admin bypass.
	mRead := w.machine(f.p1.ID)
	require.NoError(t, s.AssignMachineRole(ctx, mRead.ID, f.rRead.ID, at(f.p1)))
	addM("machine project role: bundled perm", mRead.ID, R, at(f.p1), true)
	addM("machine project role: env", mRead.ID, R, atEnv(f.p1, f.e1a), true)
	addM("machine project role: unbundled perm", mRead.ID, W, at(f.p1), false)
	addM("machine project role: other project", mRead.ID, R, at(f.p2), false)
	addM("machine project role: global", mRead.ID, R, g, false)
	mEnv := w.machine(f.p1.ID)
	require.NoError(t, s.AssignMachineRole(ctx, mEnv.ID, f.rRead.ID, atEnv(f.p1, f.e1a)))
	addM("machine env role: that env", mEnv.ID, R, atEnv(f.p1, f.e1a), true)
	addM("machine env role: sibling env", mEnv.ID, R, atEnv(f.p1, f.e1b), false)
	mBypass := w.machine(f.p1.ID)
	require.NoError(t, s.AssignMachineRole(ctx, mBypass.ID, f.rBypass.ID, at(f.p1)))
	addM("machine holding a bypass role: no bypass", mBypass.ID, R, at(f.p1), false)
	mBypassRead := w.machine(f.p1.ID)
	require.NoError(t, s.AssignMachineRole(ctx, mBypassRead.ID, f.rBypass.ID, at(f.p1)))
	require.NoError(t, s.AssignMachineRole(ctx, mBypassRead.ID, f.rRead.ID, at(f.p1)))
	addM("machine bypass+read: bundled perm", mBypassRead.ID, R, at(f.p1), true)
	addM("machine bypass+read: unbundled perm", mBypassRead.ID, O, at(f.p1), false)
	mNone := w.machine(f.p1.ID)
	addM("machine without roles", mNone.ID, R, at(f.p1), false)
	addM("unknown machine id", mNone.ID+100000, R, at(f.p1), false)
	mDel := w.machine(f.pDel.ID)
	require.NoError(t, s.AssignMachineRole(ctx, mDel.ID, f.rRead.ID, at(f.pDel)))
	mDelEnv := w.machine(f.p1.ID)
	require.NoError(t, s.AssignMachineRole(ctx, mDelEnv.ID, f.rRead.ID, atEnv(f.p1, f.eDel)))
	// A machine id equal to a user id must not pick up that user's roles (the
	// admin user's global bypass); no machine holds a global role.
	addM("machine id equal to an admin user id", admin.ID, O, g, false)

	require.NoError(t, s.DeleteProject(ctx, f.pDel.ID))
	require.NoError(t, s.DeleteEnvironment(ctx, f.eDel.ID))
	add("deleted project: direct role there", delProjUser.ID, R, at(f.pDel), false)
	add("deleted env: direct role there", delEnvUser.ID, R, atEnv(f.p1, f.eDel), false)
	add("deleted project: group role there", delProjGroupUser.ID, R, at(f.pDel), false)
	addM("deleted project: machine role there", mDel.ID, R, at(f.pDel), false)
	addM("deleted env: machine role there", mDelEnv.ID, R, atEnv(f.p1, f.eDel), false)

	return f, checks
}

func TestAuthorizeRoleResolution_Equivalence(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			_, checks := buildC4Fixture(w)
			// Three passes: cold caches, then warm twice.
			for _, pass := range []string{"cold", "warm", "warm again"} {
				for _, check := range checks {
					c4Decide(t, w.core, check, pass)
				}
			}
			// A second replica (own pool, own caches) agrees.
			other, _ := w.replica()
			for _, check := range checks {
				c4Decide(t, other, check, "replica")
			}
		})
	}
}

// TestAuthorizeRoleResolution_MutationsSeenOnNextCall: every change below
// commits after a warm decision, and the very next decision on the same
// replica must reflect it. The role->permission cache never answers across a
// permission change; role membership is never cached.
func TestAuthorizeRoleResolution_MutationsSeenOnNextCall(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			c4RunMutations(t, w, w.core, w.core)
		})
	}
}

// c4RunMutations warms decisions on reader, applies each change through
// writer, and checks reader's next decision.
func c4RunMutations(t *testing.T, w *c4World, reader, writer *KeyorixCore) {
	ctx := context.Background()
	s := writer.storage
	pRead := w.permission(w.name("c4.read"))
	pWrite := w.permission(w.name("c4.write"))
	rRead := w.role(false, pRead)
	rBypass := w.role(true)
	p1 := w.project()
	at := Scope{ProjectID: p1.ID}

	warm := func(check c4Check) {
		t.Helper()
		for _, pass := range []string{"warm-up 1", "warm-up 2"} {
			c4Decide(t, reader, check, pass)
		}
	}
	after := func(check c4Check, change string) {
		t.Helper()
		c4Decide(t, reader, check, "next call after "+change)
		c4Decide(t, reader, check, "second call after "+change)
	}

	// Direct role revoked.
	u := w.user()
	require.NoError(t, s.AssignRole(ctx, u.ID, rRead.ID, at))
	warm(c4Check{name: "direct role", principal: u.ID, perm: pRead.Name, scope: at, want: true})
	require.NoError(t, s.RemoveRole(ctx, u.ID, rRead.ID, at))
	after(c4Check{name: "direct role revoked", principal: u.ID, perm: pRead.Name, scope: at, want: false}, "RemoveRole")
	require.NoError(t, s.AssignRole(ctx, u.ID, rRead.ID, at))
	after(c4Check{name: "direct role re-granted", principal: u.ID, perm: pRead.Name, scope: at, want: true}, "AssignRole")

	// Permission removed from / added to the role (role->permission cache).
	warm(c4Check{name: "write not bundled", principal: u.ID, perm: pWrite.Name, scope: at, want: false})
	require.NoError(t, s.AssignPermissionToRole(ctx, rRead.ID, pWrite.ID))
	after(c4Check{name: "write bundled", principal: u.ID, perm: pWrite.Name, scope: at, want: true}, "AssignPermissionToRole")
	require.NoError(t, s.RemovePermissionFromRole(ctx, rRead.ID, pWrite.ID))
	after(c4Check{name: "write unbundled again", principal: u.ID, perm: pWrite.Name, scope: at, want: false}, "RemovePermissionFromRole")
	require.NoError(t, s.RemovePermissionFromRole(ctx, rRead.ID, pRead.ID))
	after(c4Check{name: "read unbundled", principal: u.ID, perm: pRead.Name, scope: at, want: false}, "RemovePermissionFromRole")
	require.NoError(t, s.AssignPermissionToRole(ctx, rRead.ID, pRead.ID))
	after(c4Check{name: "read bundled again", principal: u.ID, perm: pRead.Name, scope: at, want: true}, "AssignPermissionToRole")

	// Admin-bypass role granted and revoked.
	warm(c4Check{name: "no bypass yet", principal: u.ID, perm: pWrite.Name, scope: at, want: false})
	require.NoError(t, s.AssignRole(ctx, u.ID, rBypass.ID, at))
	after(c4Check{name: "bypass granted", principal: u.ID, perm: pWrite.Name, scope: at, want: true}, "AssignRole(bypass)")
	require.NoError(t, s.RemoveRole(ctx, u.ID, rBypass.ID, at))
	after(c4Check{name: "bypass revoked", principal: u.ID, perm: pWrite.Name, scope: at, want: false}, "RemoveRole(bypass)")

	// Group: role removed from the group, member removed, group deleted.
	g := w.group()
	require.NoError(t, s.AssignRoleToGroup(ctx, g.ID, rRead.ID, at))
	gu := w.user()
	require.NoError(t, s.AddUserToGroup(ctx, gu.ID, g.ID, 0))
	warm(c4Check{name: "group role", principal: gu.ID, perm: pRead.Name, scope: at, want: true})
	require.NoError(t, s.RemoveRoleFromGroup(ctx, g.ID, rRead.ID, at))
	after(c4Check{name: "group role removed", principal: gu.ID, perm: pRead.Name, scope: at, want: false}, "RemoveRoleFromGroup")
	require.NoError(t, s.AssignRoleToGroup(ctx, g.ID, rRead.ID, at))
	after(c4Check{name: "group role back", principal: gu.ID, perm: pRead.Name, scope: at, want: true}, "AssignRoleToGroup")
	require.NoError(t, s.RemoveUserFromGroup(ctx, gu.ID, g.ID, 0))
	after(c4Check{name: "member removed", principal: gu.ID, perm: pRead.Name, scope: at, want: false}, "RemoveUserFromGroup")
	require.NoError(t, s.AddUserToGroup(ctx, gu.ID, g.ID, 0))
	after(c4Check{name: "member back", principal: gu.ID, perm: pRead.Name, scope: at, want: true}, "AddUserToGroup")
	require.NoError(t, s.DeleteGroup(ctx, g.ID))
	after(c4Check{name: "group deleted", principal: gu.ID, perm: pRead.Name, scope: at, want: false}, "DeleteGroup")

	// Machine role revoked, permission removed from the machine's role.
	m := w.machine(p1.ID)
	rMachine := w.role(false, pRead)
	require.NoError(t, s.AssignMachineRole(ctx, m.ID, rMachine.ID, at))
	warm(c4Check{name: "machine role", machine: true, principal: m.ID, perm: pRead.Name, scope: at, want: true})
	require.NoError(t, s.RemovePermissionFromRole(ctx, rMachine.ID, pRead.ID))
	after(c4Check{name: "machine role unbundled", machine: true, principal: m.ID, perm: pRead.Name, scope: at, want: false}, "RemovePermissionFromRole")
	require.NoError(t, s.AssignPermissionToRole(ctx, rMachine.ID, pRead.ID))
	after(c4Check{name: "machine role bundled again", machine: true, principal: m.ID, perm: pRead.Name, scope: at, want: true}, "AssignPermissionToRole")
	require.NoError(t, s.RemoveMachineRole(ctx, m.ID, rMachine.ID, at))
	after(c4Check{name: "machine role revoked", machine: true, principal: m.ID, perm: pRead.Name, scope: at, want: false}, "RemoveMachineRole")
	require.NoError(t, s.AssignMachineRole(ctx, m.ID, rMachine.ID, at))
	after(c4Check{name: "machine role back", machine: true, principal: m.ID, perm: pRead.Name, scope: at, want: true}, "AssignMachineRole")
}

// TestAuthorizeRoleResolution_CrossReplica: replica A decides, replica B (own
// pool, own caches) writes. Sequential: A's next decision sees every write B
// committed. Racing: while B grants/revokes a role and adds/removes a
// permission, A decides in a loop; every decision that STARTED after B's write
// returned must match the post-write state (no stale cache entry, no
// generation read that lags the role ids it validates).
func TestAuthorizeRoleResolution_CrossReplica(t *testing.T) {
	setup := newC4World(t, "postgres")
	a, _ := setup.replica()
	b, _ := setup.replica()

	t.Run("sequential", func(t *testing.T) {
		c4RunMutations(t, setup, a, b)
	})

	t.Run("racing", func(t *testing.T) {
		ctx := context.Background()
		s := b.storage
		pRead := setup.permission(setup.name("c4.read"))
		rRead := setup.role(false, pRead)
		p1 := setup.project()
		at := Scope{ProjectID: p1.ID}
		u := setup.user()
		m := setup.machine(p1.ID)

		type sample struct {
			start time.Time
			got   bool
		}
		race := func(t *testing.T, name string, machine bool, write func() error, wantAfter bool) {
			t.Helper()
			var (
				mu      sync.Mutex
				samples []sample
				stop    atomic.Bool
				wg      sync.WaitGroup
			)
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for !stop.Load() {
						start := time.Now()
						var got bool
						var err error
						if machine {
							got, err = a.AuthorizePrincipal(ctx, ActorTypeMachine, m.ID, pRead.Name, at)
						} else {
							got, err = a.Authorize(ctx, u.ID, pRead.Name, at)
						}
						if err != nil {
							t.Errorf("%s: decision error: %v", name, err)
							return
						}
						mu.Lock()
						samples = append(samples, sample{start, got})
						mu.Unlock()
					}
				}()
			}
			time.Sleep(20 * time.Millisecond)
			require.NoError(t, write(), name)
			committed := time.Now()
			time.Sleep(40 * time.Millisecond)
			stop.Store(true)
			wg.Wait()
			after := 0
			for _, smp := range samples {
				if smp.start.After(committed) {
					after++
					if smp.got != wantAfter {
						t.Fatalf("%s: a decision started %v after the write committed answered %v, want %v",
							name, smp.start.Sub(committed), smp.got, wantAfter)
					}
				}
			}
			require.Positive(t, after, "%s: no decision started after the write (harness did not race)", name)
			// And the next decision, sequentially.
			principal := u.ID
			if machine {
				principal = m.ID
			}
			c4Decide(t, a, c4Check{name: name, machine: machine, principal: principal,
				perm: pRead.Name, scope: at, want: wantAfter}, "after race")
		}

		for i := 0; i < 3; i++ {
			race(t, "grant role", false, func() error { return s.AssignRole(ctx, u.ID, rRead.ID, at) }, true)
			race(t, "remove permission", false, func() error { return s.RemovePermissionFromRole(ctx, rRead.ID, pRead.ID) }, false)
			race(t, "add permission", false, func() error { return s.AssignPermissionToRole(ctx, rRead.ID, pRead.ID) }, true)
			race(t, "revoke role", false, func() error { return s.RemoveRole(ctx, u.ID, rRead.ID, at) }, false)
			race(t, "grant machine role", true, func() error { return s.AssignMachineRole(ctx, m.ID, rRead.ID, at) }, true)
			race(t, "remove permission (machine)", true, func() error { return s.RemovePermissionFromRole(ctx, rRead.ID, pRead.ID) }, false)
			race(t, "add permission (machine)", true, func() error { return s.AssignPermissionToRole(ctx, rRead.ID, pRead.ID) }, true)
			race(t, "revoke machine role", true, func() error { return s.RemoveMachineRole(ctx, m.ID, rRead.ID, at) }, false)
		}
	})
}

// c4StatementCounter counts the statements a *gorm.DB issues while on.
type c4StatementCounter struct {
	mu    sync.Mutex
	on    bool
	stmts []string
}

func c4CountStatements(t *testing.T, db *gorm.DB) *c4StatementCounter {
	t.Helper()
	c := &c4StatementCounter{}
	rec := func(db *gorm.DB) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.on {
			c.stmts = append(c.stmts, db.Statement.SQL.String())
		}
	}
	cb := db.Callback()
	name := fmt.Sprintf("c4count%d", c4Seq.Add(1))
	require.NoError(t, cb.Query().After("gorm:query").Register(name+":q", rec))
	require.NoError(t, cb.Row().After("gorm:row").Register(name+":row", rec))
	require.NoError(t, cb.Raw().After("gorm:raw").Register(name+":raw", rec))
	return c
}

func (c *c4StatementCounter) during(fn func()) []string {
	c.mu.Lock()
	c.on, c.stmts = true, nil
	c.mu.Unlock()
	fn()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.on = false
	return append([]string(nil), c.stmts...)
}

// TestAuthorizeRoleResolution_OneStatement is the red/green: a warm
// role-based decision reads the principal's roles, the admin-bypass flag and
// the role->permission generation in ONE statement. Before the change: user
// with a non-admin role 4 (direct ids, group ids, bypass flag, generation),
// user with an admin role 3, machine 2 (ids, generation).
func TestAuthorizeRoleResolution_OneStatement(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			s := w.core.storage
			pRead := w.permission(w.name("c4.read"))
			rRead := w.role(false, pRead)
			rBypass := w.role(true)
			p1 := w.project()
			at := Scope{ProjectID: p1.ID}
			g := w.group()
			require.NoError(t, s.AssignRoleToGroup(ctx, g.ID, rRead.ID, at))
			member := w.user()
			require.NoError(t, s.AssignRole(ctx, member.ID, rRead.ID, at))
			require.NoError(t, s.AddUserToGroup(ctx, member.ID, g.ID, 0))
			admin := w.user()
			require.NoError(t, s.AssignRole(ctx, admin.ID, rBypass.ID, Scope{}))
			m := w.machine(p1.ID)
			require.NoError(t, s.AssignMachineRole(ctx, m.ID, rRead.ID, at))

			counter := c4CountStatements(t, w.db)
			for _, tc := range []struct {
				name   string
				decide func() (bool, error)
			}{
				{"user with roles (direct + group)", func() (bool, error) { return w.core.Authorize(ctx, member.ID, pRead.Name, at) }},
				{"user with an admin-bypass role", func() (bool, error) { return w.core.Authorize(ctx, admin.ID, pRead.Name, at) }},
				{"machine", func() (bool, error) {
					return w.core.AuthorizePrincipal(ctx, ActorTypeMachine, m.ID, pRead.Name, at)
				}},
			} {
				// Warm the role->permission cache.
				for i := 0; i < 2; i++ {
					ok, err := tc.decide()
					require.NoError(t, err)
					require.True(t, ok, tc.name)
				}
				var ok bool
				var err error
				stmts := counter.during(func() { ok, err = tc.decide() })
				require.NoError(t, err)
				require.True(t, ok, tc.name)
				t.Logf("%s: %d statement(s) for a warm decision", tc.name, len(stmts))
				if len(stmts) != 1 {
					t.Errorf("%s: a warm decision must resolve roles, bypass flag and generation in ONE statement; got %d:\n%s",
						tc.name, len(stmts), strings.Join(stmts, "\n"))
				}
			}
		})
	}
}
