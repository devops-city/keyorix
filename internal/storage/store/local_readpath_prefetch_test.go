package store

// PERF-FIX-2: a machine-token secret read answers the node stamp, the machine's
// roles and the schedule/version generation from ONE statement when the request
// declared them (storage.ReadPathPrefetch), and answers exactly what the
// separate statements answer. Every fact is still read live on every request,
// the trigger proof stays in the stamp statement, and nothing is parked unless
// the node cache hit is confirmed.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type prefetchWorld struct {
	ppWorld
	scope   storage.Scope
	machine uint
	secret  *models.SecretNode
	perm    string
}

func newPrefetchWorld(t *testing.T, backend string) prefetchWorld {
	return newPrefetchWorldWith(t, backend, nil)
}

// newPrefetchWorldWith runs prep on the migrated store before the world's rows
// are created.
func newPrefetchWorldWith(t *testing.T, backend string, prep func(*LocalStorage)) prefetchWorld {
	t.Helper()
	ls, _ := newPrincipalPermStorage(t, backend)
	require.NoError(t, ls.db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{}, &models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{}))
	if prep != nil {
		prep(ls)
	}
	require.NoError(t, EnsureSecretNodeCacheEpoch(ls.db))
	w := ppWorld{t: t, ls: ls}
	ctx := context.Background()
	p := w.project()
	e := w.env(p)
	sc := storage.Scope{ProjectID: p, EnvironmentID: e}
	pr := w.perm()
	role := w.role(false, pr)
	mid := w.machine(p)
	require.NoError(t, ls.AssignMachineRole(ctx, mid, role.ID, sc))
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: w.name("pf-secret"), ProjectID: p, EnvironmentID: e, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: sec.ID, VersionNumber: 1, CreatedAt: time.Now()})
	require.NoError(t, err)
	require.NoError(t, ls.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{SecretNodeID: sec.ID, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC"}))
	return prefetchWorld{ppWorld: w, scope: sc, machine: mid, secret: sec, perm: pr.Name}
}

// gateReads is what a machine value read asks storage, in order.
func (w prefetchWorld) gateReads(ctx context.Context) (*models.SecretNode, *storage.PrincipalPermission, *storage.SecretScheduleAndLatestVersion) {
	w.t.Helper()
	node, err := w.ls.GetSecret(ctx, w.secret.ID)
	require.NoError(w.t, err)
	sc := storage.Scope{ProjectID: node.ProjectID, EnvironmentID: node.EnvironmentID}
	perm, err := w.ls.ResolveMachinePermissionAt(ctx, w.machine, sc, w.perm)
	require.NoError(w.t, err)
	state, err := w.ls.GetSecretScheduleAndLatestVersion(ctx, w.secret.ID)
	require.NoError(w.t, err)
	return node, perm, state
}

func TestReadPathPrefetch_OneStatementSameAnswers(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			ctx := context.Background()
			counter := ppCountStatements(t, w.ls.db)

			// Warm every cache with the classic path, and take its answers.
			w.gateReads(ctx)
			var wantNode *models.SecretNode
			var wantPerm *storage.PrincipalPermission
			var wantState *storage.SecretScheduleAndLatestVersion
			classic := counter.during(func() { wantNode, wantPerm, wantState = w.gateReads(ctx) })
			require.Len(t, classic, 3, "classic: stamp, roles, schedule+version generation: %v", classic)

			pctx := storage.NewReadPathPrefetch(ctx, w.machine, true)
			var node *models.SecretNode
			var perm *storage.PrincipalPermission
			var state *storage.SecretScheduleAndLatestVersion
			folded := counter.during(func() { node, perm, state = w.gateReads(pctx) })
			require.Len(t, folded, 1, "prefetch: one statement for all three reads: %v", folded)

			require.Equal(t, wantNode.ID, node.ID)
			requireSamePrincipalPermission(t, *wantPerm, perm, "prefetched roles")
			require.True(t, perm.HasPermission)
			require.Equal(t, wantState.Schedule.AllowedDays, state.Schedule.AllowedDays)
			require.NotNil(t, state.LatestVersion)
			require.Equal(t, wantState.LatestVersion.ID, state.LatestVersion.ID)
			require.NoError(t, state.LatestVersionErr)

			// Taken once: a second ask is a real read, not a replay.
			again := counter.during(func() {
				_, err := w.ls.ResolveMachinePermissionAt(pctx, w.machine, w.scope, w.perm)
				require.NoError(t, err)
			})
			require.Len(t, again, 1)
		})
	}
}

func TestReadPathPrefetch_MetadataOnlyDoesNotReadScheduleOrVersions(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			ctx := context.Background()
			w.gateReads(ctx)
			counter := ppCountStatements(t, w.ls.db)
			pctx := storage.NewReadPathPrefetch(ctx, w.machine, false)
			stmts := counter.during(func() {
				_, perm, _ := w.gateReads(pctx)
				require.True(t, perm.HasPermission)
			})
			// stamp+roles folded; the schedule/version read keeps its own statement.
			require.Len(t, stmts, 2, "%v", stmts)
		})
	}
}

// A role revoked between two requests is seen on the very next one: the folded
// statement reads the machine's roles live, every request.
func TestReadPathPrefetch_RevokedRoleIsSeenOnTheNextRequest(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			ctx := context.Background()
			_, perm, _ := w.gateReads(storage.NewReadPathPrefetch(ctx, w.machine, true))
			require.True(t, perm.HasPermission, "precondition: allowed while the role is held")

			require.NoError(t, w.ls.db.Where("machine_identity_id = ?", w.machine).Delete(&models.MachineIdentityRole{}).Error)

			_, perm, _ = w.gateReads(storage.NewReadPathPrefetch(ctx, w.machine, true))
			require.Empty(t, perm.RoleIDs)
			require.False(t, perm.HasPermission, "a revoked role must deny on the very next request")
		})
	}
}

// A node that changed since it was cached is not a hit, so nothing is parked and
// the roles are read for the NEW scope, never the cached one.
func TestReadPathPrefetch_StaleNodeParksNothing(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			ctx := context.Background()
			w.gateReads(ctx) // warm the node cache at the original scope

			other := w.project()
			otherEnv := w.env(other)
			require.NoError(t, w.ls.db.Model(&models.SecretNode{}).Where("id = ?", w.secret.ID).
				Updates(map[string]any{"project_id": other, "environment_id": otherEnv}).Error)

			pctx := storage.NewReadPathPrefetch(ctx, w.machine, true)
			node, perm, _ := w.gateReads(pctx)
			require.Equal(t, other, node.ProjectID, "the live node, not the cached one")
			require.Empty(t, perm.RoleIDs, "the machine holds no role at the secret's new scope")
			require.False(t, perm.HasPermission)
		})
	}
}

// Parked roles are only handed to the same machine at the same scope.
func TestReadPathPrefetch_NotServedToAnotherPrincipalOrScope(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			ctx := context.Background()
			w.gateReads(ctx)
			pctx := storage.NewReadPathPrefetch(ctx, w.machine, false)
			_, err := w.ls.GetSecret(pctx, w.secret.ID)
			require.NoError(t, err)

			counter := ppCountStatements(t, w.ls.db)
			stranger := w.machine2()
			stmts := counter.during(func() {
				perm, err := w.ls.ResolveMachinePermissionAt(pctx, stranger, w.scope, w.perm)
				require.NoError(t, err)
				require.Empty(t, perm.RoleIDs, "another machine must not inherit the prefetched roles")
			})
			require.Len(t, stmts, 1, "its own read, not the parked one")
			stmts = counter.during(func() {
				perm, err := w.ls.ResolveMachinePermissionAt(pctx, w.machine, storage.Scope{ProjectID: w.scope.ProjectID, EnvironmentID: w.scope.EnvironmentID + 999}, w.perm)
				require.NoError(t, err)
				require.Empty(t, perm.RoleIDs, "another scope must not inherit the prefetched roles")
			})
			require.Len(t, stmts, 1)
		})
	}
}

func (w prefetchWorld) machine2() uint { return w.ppWorld.machine(w.scope.ProjectID) }

// The trigger proof still rides in the stamp statement, per read: a trigger
// dropped under a warm store is a MISS on the prefetching path too.
func TestReadPathPrefetch_TriggerDroppedWhileWarmIsAMissNotAStaleHit(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			ctx := context.Background()
			w.gateReads(ctx)
			_, cached := w.ls.secretMetaCache.getNode(w.secret.ID)
			require.True(t, cached, "the entry must be warm")

			drop := "DROP TRIGGER " + SecretNodeCacheEpochTrigger
			if backend == "postgres" {
				drop += " ON secret_nodes"
			}
			require.NoError(t, w.ls.db.Exec(drop).Error)
			require.NoError(t, w.ls.db.Model(&models.SecretNode{}).Where("id = ?", w.secret.ID).
				UpdateColumn("status", "suspended").Error)

			pctx := storage.NewReadPathPrefetch(ctx, w.machine, true)
			node, err := w.ls.GetSecret(pctx, w.secret.ID)
			require.NoError(t, err)
			require.Equal(t, "suspended", node.Status, "a warm entry was served after its trigger was dropped")
		})
	}
}
