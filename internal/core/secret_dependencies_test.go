package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// edge is a terse constructor for the pure-helper tests.
func edge(dependent, dependsOn uint) *models.SecretDependency {
	return &models.SecretDependency{DependentSecretID: dependent, DependsOnSecretID: dependsOn}
}

func TestDependencyReachable(t *testing.T) {
	t.Parallel()
	// 1→2→3 (1 depends on 2 depends on 3), plus 4→2.
	edges := []*models.SecretDependency{edge(1, 2), edge(2, 3), edge(4, 2)}
	assert.True(t, dependencyReachable(edges, 1, 3), "1 transitively depends on 3")
	assert.True(t, dependencyReachable(edges, 1, 2))
	assert.False(t, dependencyReachable(edges, 3, 1), "3 does not depend on 1")
	assert.True(t, dependencyReachable(edges, 4, 3), "4→2→3 reachable")
	assert.False(t, dependencyReachable(edges, 2, 4), "2 does not reach 4")
}

func TestTransitiveDependents(t *testing.T) {
	t.Parallel()
	// 3 is depended on by 2 and 4; 2 is depended on by 1. So rotating 3 impacts 2,4 (depth1) then 1 (depth2).
	edges := []*models.SecretDependency{edge(1, 2), edge(2, 3), edge(4, 3)}
	got, truncated := transitiveDependents(edges, 3)
	require.Len(t, got, 3)
	assert.False(t, truncated)
	// BFS order: depth-1 dependents of 3 first (2,4 sorted), then 1.
	assert.Equal(t, uint(2), got[0].id)
	assert.Equal(t, 1, got[0].depth)
	assert.Equal(t, uint(4), got[1].id)
	assert.Equal(t, 1, got[1].depth)
	assert.Equal(t, uint(1), got[2].id)
	assert.Equal(t, 2, got[2].depth)

	// A leaf nobody depends on has no impact.
	leaf, leafTruncated := transitiveDependents(edges, 1)
	assert.Empty(t, leaf)
	assert.False(t, leafTruncated)
}

// TestTransitiveDependents_DepthCapped is the resource-exhaustion regression:
// a chain deeper than maxDependencyBFSDepth must stop at the cap and report
// Truncated, not silently walk the entire graph.
func TestTransitiveDependents_DepthCapped(t *testing.T) {
	t.Parallel()
	// Chain: 2 depends on 1, 3 depends on 2, ... 16 depends on 15 -- 15 hops
	// deep, well past maxDependencyBFSDepth (10).
	edges := make([]*models.SecretDependency, 0, 15)
	for i := uint(1); i <= 15; i++ {
		edges = append(edges, edge(i+1, i))
	}
	got, truncated := transitiveDependents(edges, 1)
	assert.True(t, truncated, "a chain past maxDependencyBFSDepth must be flagged truncated")
	require.Len(t, got, maxDependencyBFSDepth, "BFS must stop expanding at maxDependencyBFSDepth")
	for _, n := range got {
		assert.LessOrEqual(t, n.depth, maxDependencyBFSDepth)
	}
}

// TestTransitiveDependents_NodeCapped is the breadth counterpart to the depth
// cap: depth alone doesn't bound total node count (#G44's reasoning, shared
// with blastBFS) -- a single secret with a very wide fan-out of direct
// dependents must still be capped at maxDependencyBFSNodes.
func TestTransitiveDependents_NodeCapped(t *testing.T) {
	t.Parallel()
	const fanOut = maxDependencyBFSNodes + 500
	edges := make([]*models.SecretDependency, 0, fanOut)
	for i := range uint(fanOut) {
		// Each of these directly depends on secret 1 -- all at depth 1.
		edges = append(edges, edge(i+2, 1))
	}
	got, truncated := transitiveDependents(edges, 1)
	assert.True(t, truncated, "fan-out past maxDependencyBFSNodes must be flagged truncated")
	assert.Len(t, got, maxDependencyBFSNodes, "BFS must stop at maxDependencyBFSNodes regardless of depth")
}

// TestTransitiveDependents_NotTruncatedWithinBounds is the negative
// counterpart: a graph within both caps must not be flagged truncated.
func TestTransitiveDependents_NotTruncatedWithinBounds(t *testing.T) {
	t.Parallel()
	edges := make([]*models.SecretDependency, 0, 5)
	for i := uint(1); i <= 5; i++ {
		edges = append(edges, edge(i+1, i))
	}
	got, truncated := transitiveDependents(edges, 1)
	assert.False(t, truncated)
	require.Len(t, got, 5)
}

func TestTopologicalRotationOrder(t *testing.T) {
	t.Parallel()
	// Diamond: 1 depends on 2 and 3; both 2 and 3 depend on 4.
	// Safe rotation = dependencies first: 4 before {2,3} before 1.
	edges := []*models.SecretDependency{edge(1, 2), edge(1, 3), edge(2, 4), edge(3, 4)}
	order, ok := topologicalRotationOrder(edges)
	require.True(t, ok)
	require.Equal(t, []uint{4, 2, 3, 1}, order, "4 first, then 2,3 (sorted), then 1")

	// Determinism: same input → same order.
	order2, _ := topologicalRotationOrder(edges)
	assert.Equal(t, order, order2)
}

func TestTopologicalRotationOrderDetectsCycle(t *testing.T) {
	t.Parallel()
	// A hand-built cycle 1→2→1 (the add path prevents this; the sort must still flag it).
	edges := []*models.SecretDependency{edge(1, 2), edge(2, 1)}
	_, ok := topologicalRotationOrder(edges)
	assert.False(t, ok, "a cyclic graph yields no complete ordering")
}

// --- integration tests against a real in-memory store ---

// depTestActors are the caller identities used throughout this file's real-SQLite
// tests; newDepCore grants each one global admin. #G32: every G32 member now
// independently authorizes each peer secret it discloses/mutates, so a caller with no
// RBAC grant at all would fail on any two-secret operation — these tests are about the
// dependency-graph shape (cycles, environment scoping, soft-delete cascade), not
// authorization, so the fixture actors are granted global admin to keep that
// orthogonal. The peer-authorization-gap regression tests live in
// secret_dependencies_authz_test.go, with a deliberately unprivileged actor.
var depTestActors = []uint{1, 10}

func newDepCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// #370: DeleteSecret now revokes ShareRecord rows in the same transaction as the
	// secret's own soft-delete, so ShareRecord must be migrated even though these
	// tests never create a share directly.
	// SecretACL is included because DeleteSecret also revokes ACL rows in the same tx.
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretDependency{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{}, &models.ShareRecord{}, &models.SecretACL{},
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.MachineIdentityRole{},
	))
	// Live parent projects (1, 2) + environment (1): RestoreSecret refuses to restore a
	// secret into a soft-deleted parent, so the dependency-cascade tests need them present.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	// ADR-084: the bypass is now the structural BypassesPermissionChecks flag.
	role := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(role).Error)
	for _, actor := range depTestActors {
		require.NoError(t, db.Create(&models.UserRole{UserID: actor, RoleID: role.ID, ProjectID: 0, EnvironmentID: 0}).Error)
	}
	now := time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

// mkSecret inserts a secret node (environment 1) and returns its id.
func mkSecret(t *testing.T, db *gorm.DB, projectID uint, name string) uint {
	return mkSecretEnv(t, db, projectID, 1, name)
}

// mkSecretEnv inserts a secret node in a specific environment and returns its id.
func mkSecretEnv(t *testing.T, db *gorm.DB, projectID, environmentID uint, name string) uint {
	t.Helper()
	s := &models.SecretNode{ProjectID: projectID, EnvironmentID: environmentID, Name: name, IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	return s.ID
}

func TestAddSecretDependency_Validation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newDepCore(t)
	dbPass := mkSecret(t, db, 1, "db-password")
	appTok := mkSecret(t, db, 1, "app-token")
	otherProj := mkSecret(t, db, 2, "other-secret")

	t.Run("happy path", func(t *testing.T) {
		got, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, appTok, dbPass, "app token derives from db password", 0)
		require.NoError(t, err)
		assert.Equal(t, appTok, got.DependentSecretID)
		assert.Equal(t, dbPass, got.DependsOnSecretID)
		assert.Equal(t, uint(1), got.ProjectID)
	})

	t.Run("self-dependency rejected", func(t *testing.T) {
		_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, dbPass, dbPass, "", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "itself")
	})

	t.Run("cross-project rejected", func(t *testing.T) {
		_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, appTok, otherProj, "", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "same project")
	})

	t.Run("duplicate rejected", func(t *testing.T) {
		_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, appTok, dbPass, "", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("cycle rejected", func(t *testing.T) {
		// appTok already depends on dbPass; making dbPass depend on appTok is a cycle.
		_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, dbPass, appTok, "", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cycle")
	})

	t.Run("missing dependency target rejected with an opaque error (no existence oracle)", func(t *testing.T) {
		_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, appTok, 9999, "", 0)
		require.Error(t, err)
		// Must NOT reveal whether 9999 exists / what it is — same message as a cross-scope
		// target, so the caller can't enumerate secret IDs across scopes.
		assert.NotContains(t, err.Error(), "9999")
		assert.Contains(t, err.Error(), "same project and environment")
	})
}

// TestAddSecretDependency_MachineAndUserAttributionDistinguishable is the
// #1623 regression: a dependency edge created by machine identity N and one
// created by user N must be distinguishable when read back. Before this fix,
// CreatedBy stored actorID verbatim regardless of actor kind -- User.ID and
// MachineIdentity.ID are independent auto-increment sequences that can
// collide on the same numeric value, so a machine-created edge and a
// user-created edge with the same numeric ID were indistinguishable, and a
// forensic query resolving CreatedBy against the users table would name a
// real human who did nothing.
func TestAddSecretDependency_MachineAndUserAttributionDistinguishable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newDepCore(t)

	// A role with an EXPLICIT secrets.write permission, granted identically to
	// a user and a machine identity sharing the same numeric ID -- avoids
	// relying on the admin-role bypass, which machine principals never get
	// (ADR-030's no-bypass property, pinned by TestMachineIdentity_NoAdminBypass_RealDB).
	perm := &models.Permission{Name: "secrets.write", Resource: "secrets", Action: "write"}
	require.NoError(t, db.Create(perm).Error)
	role := &models.Role{Name: "secret-writer"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	const collidingID = 7 // the SAME numeric ID, deliberately, for both actor kinds
	require.NoError(t, db.Create(&models.UserRole{UserID: collidingID, RoleID: role.ID, ProjectID: 1, EnvironmentID: 1}).Error)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}))
	require.NoError(t, db.Create(&models.MachineIdentity{ID: collidingID, ProjectID: 1, Name: "ci", State: "active"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: collidingID, RoleID: role.ID, ProjectID: 1, EnvironmentID: 1}).Error)

	// Two independent secret pairs (a dependency edge's (dependent, depends_on)
	// pair is unique per project) -- one edge attributed to the human actor,
	// one to the machine actor holding the colliding ID.
	humanDependent := mkSecret(t, db, 1, "human-app")
	humanDependsOn := mkSecret(t, db, 1, "human-db")
	machineDependent := mkSecret(t, db, 1, "machine-app")
	machineDependsOn := mkSecret(t, db, 1, "machine-db")

	humanEdge, err := c.AddSecretDependency(ctx, ActorTypeUser, collidingID, humanDependent, humanDependsOn, "human-created", 0)
	require.NoError(t, err)
	machineEdge, err := c.AddSecretDependency(ctx, ActorTypeMachine, collidingID, machineDependent, machineDependsOn, "machine-created", collidingID)
	require.NoError(t, err)

	// The two rows must be distinguishable despite sharing the same raw
	// numeric ID -- the whole point of the companion field.
	assert.Equal(t, uint(collidingID), humanEdge.CreatedBy, "the human actor's real User.ID")
	assert.Zero(t, humanEdge.CreatedByMachineIdentityID, "no machine involved in the human-created edge")
	assert.Zero(t, machineEdge.CreatedBy, "must NOT be stamped with the machine's raw ID -- that is #1623's exact bug")
	assert.Equal(t, uint(collidingID), machineEdge.CreatedByMachineIdentityID, "the machine actor's real MachineIdentity.ID")

	// Positive control: reading back via storage reproduces the same split --
	// this isn't just an in-memory return-value artifact.
	rows, err := c.storage.ListSecretDependenciesForProject(ctx, 1)
	require.NoError(t, err)
	var rereadHuman, rereadMachine *models.SecretDependency
	for _, r := range rows {
		switch r.ID {
		case humanEdge.ID:
			rereadHuman = r
		case machineEdge.ID:
			rereadMachine = r
		}
	}
	require.NotNil(t, rereadHuman)
	require.NotNil(t, rereadMachine)
	assert.Equal(t, uint(collidingID), rereadHuman.CreatedBy, "user attribution still resolves correctly on read-back")
	assert.Zero(t, rereadHuman.CreatedByMachineIdentityID)
	assert.Zero(t, rereadMachine.CreatedBy)
	assert.Equal(t, uint(collidingID), rereadMachine.CreatedByMachineIdentityID)
}

// A dependency must stay within one environment — authorization is environment-
// granular, so a cross-environment edge would let an env-scoped caller reference a
// secret in another environment of the same project.
func TestAddSecretDependency_CrossEnvironmentRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newDepCore(t)
	staging := mkSecretEnv(t, db, 1, 1, "app-token")     // project 1, env 1
	prod := mkSecretEnv(t, db, 1, 2, "prod-db-password") // project 1, env 2
	_, err := c.AddSecretDependency(ctx, ActorTypeUser, 10, staging, prod, "", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment")
}

// Removal is scoped to the focal secret: the edge must reference it, so a caller
// authorized only on another secret cannot delete an unrelated edge.
func TestRemoveSecretDependency_RequiresFocalReference(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newDepCore(t)
	a := mkSecret(t, db, 1, "a")
	b := mkSecret(t, db, 1, "b")
	other := mkSecret(t, db, 1, "other")
	e, err := c.AddSecretDependency(ctx, ActorTypeUser, 1, a, b, "", 0)
	require.NoError(t, err)

	// 'other' is not part of edge a→b → removal scoped to 'other' is rejected.
	err = c.RemoveSecretDependency(ctx, ActorTypeUser, 1, other, e.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not reference")

	// Scoped to the dependent secret 'a' → allowed.
	require.NoError(t, c.RemoveSecretDependency(ctx, ActorTypeUser, 1, a, e.ID))
}

// Defence-in-depth: even if a cross-environment edge is somehow present (here inserted
// directly, bypassing the add guard), the read paths must not surface the other
// environment's secret — they filter to the focal secret's environment independently.
func TestSecretDependencyReadsFilterByEnvironment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newDepCore(t)
	envA := mkSecretEnv(t, db, 1, 1, "env-a-secret")
	envB := mkSecretEnv(t, db, 1, 2, "env-b-secret")
	// Forge a cross-environment edge (env-A depends on env-B) directly in storage,
	// bypassing the add-time guard. The endpoints span two environments.
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID: 1, DependentSecretID: envA, DependsOnSecretID: envB,
	}).Error)

	deps, err := c.ListSecretDependencies(ctx, ActorTypeUser, 1, envA)
	require.NoError(t, err)
	assert.Empty(t, deps.DependsOn, "a cross-environment edge must not appear in env-A's view")

	impact, err := c.GetSecretImpact(ctx, ActorTypeUser, 1, envB)
	require.NoError(t, err)
	assert.Empty(t, impact.Affected, "impact from env-B must not cross into env-A via a forged edge")
}

func TestSecretDependencyImpactAndOrderAndRemove(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newDepCore(t)
	root := mkSecret(t, db, 1, "root-ca")
	mid := mkSecret(t, db, 1, "intermediate")
	leaf := mkSecret(t, db, 1, "service-cert")

	// service-cert depends on intermediate depends on root-ca.
	_, err := c.AddSecretDependency(ctx, ActorTypeUser, 1, mid, root, "", 0)
	require.NoError(t, err)
	e2, err := c.AddSecretDependency(ctx, ActorTypeUser, 1, leaf, mid, "", 0)
	require.NoError(t, err)

	// Impact of rotating root-ca: intermediate (depth1) then service-cert (depth2).
	impact, err := c.GetSecretImpact(ctx, ActorTypeUser, 1, root)
	require.NoError(t, err)
	require.Len(t, impact.Affected, 2)
	assert.Equal(t, "intermediate", impact.Affected[0].SecretName)
	assert.Equal(t, 1, impact.Affected[0].Depth)
	assert.Equal(t, "service-cert", impact.Affected[1].SecretName)
	assert.Equal(t, 2, impact.Affected[1].Depth)

	// Rotation order: root-ca, intermediate, service-cert.
	order, err := c.GetProjectRotationOrder(ctx, 1)
	require.NoError(t, err)
	require.Len(t, order.Order, 3)
	assert.Equal(t, []string{"root-ca", "intermediate", "service-cert"},
		[]string{order.Order[0].SecretName, order.Order[1].SecretName, order.Order[2].SecretName})

	// List from the middle secret: depends on root, depended on by leaf.
	view, err := c.ListSecretDependencies(ctx, ActorTypeUser, 1, mid)
	require.NoError(t, err)
	require.Len(t, view.DependsOn, 1)
	assert.Equal(t, "root-ca", view.DependsOn[0].SecretName)
	require.Len(t, view.Dependents, 1)
	assert.Equal(t, "service-cert", view.Dependents[0].SecretName)

	// Remove the leaf→mid edge; impact of root shrinks to just intermediate.
	require.NoError(t, c.RemoveSecretDependency(ctx, ActorTypeUser, 1, leaf, e2.ID))
	impact, err = c.GetSecretImpact(ctx, ActorTypeUser, 1, root)
	require.NoError(t, err)
	require.Len(t, impact.Affected, 1)
	assert.Equal(t, "intermediate", impact.Affected[0].SecretName)
}

// --- concurrency: #260 ---

// TestAddSecretDependency_ConcurrentRaceCannotPersistACycle empirically reproduces
// #260: two goroutines racing to add A→B and B→A in the same project must never
// BOTH succeed — that would persist a 2-node cycle that GetProjectRotationOrder
// (and, transitively, the deployment-wide rotation-plan roll-up) hard-errors on
// forever, with nothing else able to detect or heal the stuck edge. Repeated across
// many fresh secret pairs on a single-connection DB (forcing the two goroutines'
// individual statements to interleave through the same connection, the same
// technique that originally reproduced the race deterministically) so the narrow
// pre-fix race window is reliably exercised, not just occasionally hit.
func TestAddSecretDependency_ConcurrentRaceCannotPersistACycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newDepCore(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	const iterations = 50
	for i := range iterations {
		a := mkSecret(t, db, 1, fmt.Sprintf("a-%d", i))
		b := mkSecret(t, db, 1, fmt.Sprintf("b-%d", i))

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, results[0] = c.AddSecretDependency(ctx, ActorTypeUser, 1, a, b, "", 0)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, results[1] = c.AddSecretDependency(ctx, ActorTypeUser, 1, b, a, "", 0)
		}()
		close(start)
		wg.Wait()

		successes := 0
		for _, e := range results {
			if e == nil {
				successes++
			}
		}
		require.Equal(t, 1, successes,
			"iteration %d: exactly one of A→B / B→A must win the race — both winning would persist a cycle, both losing would lose a legitimate edge", i)

		// No cycle was persisted: rotation ordering for the project must still succeed.
		_, err := c.GetProjectRotationOrder(ctx, 1)
		require.NoError(t, err, "iteration %d: no lingering cycle in the persisted graph", i)
	}
}
