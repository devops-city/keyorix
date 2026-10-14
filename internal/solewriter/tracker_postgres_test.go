package solewriter

// tracker_postgres_test.go — the tracker against the database: every write
// path that moves the write epoch (the database's own account of a fenced
// write) must also move the tracker's generation before the call returns. The
// trigger is the oracle for the tracker's SQL classification.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// serverStorage builds the storage a single-writer server builds: after
// Start, so every pool is tagged and traced.
func (w *swWorld) serverStorage() storage.Storage {
	w.t.Helper()
	st, err := kxstorage.NewStorageFactory().CreateStorage(w.cfg)
	require.NoError(w.t, err)
	return st
}

// TestTracker_EveryEpochMoveIsAWriteTheTrackerSaw drives the storage writes
// behind every end-of-access path of a machine-token read, plus the read
// path's own bookkeeping, through the server's storage. Red without the
// tracer installed (config.SetSoleWriterQueryTracer), or with a fenced table's
// writes classified as other writes.
func TestTracker_EveryEpochMoveIsAWriteTheTrackerSaw(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	w := newSWWorld(t)
	g := w.start(Options{})
	tr := g.Tracker()
	st := w.serverStorage()
	ctx := context.Background()

	step := func(name string, bookkeeping bool, op func() error) {
		t.Helper()
		e0, g0 := w.epoch(w.foreign), tr.Gen()
		require.NoError(t, op(), name)
		e1, g1 := w.epoch(w.foreign), tr.Gen()
		require.Zero(t, tr.Inflight(), "%s: a write is still counted in flight after the call returned", name)
		if bookkeeping {
			require.Equal(t, e0, e1, "%s: bookkeeping moved the epoch", name)
			require.Equal(t, g0, g1, "%s: bookkeeping flushed the caches", name)
			return
		}
		require.NotEqual(t, e0, e1, "%s: precondition: the write must reach a fenced table", name)
		require.NotEqual(t, g0, g1, "%s: the epoch moved (%d -> %d) but the tracker did not see the write", name, e0, e1)
	}

	var (
		proj    *models.Project
		env     *models.Environment
		mi      *models.MachineIdentity
		cred    *models.MachineIdentityCredential
		role    *models.Role
		perm    *models.Permission
		secret  *models.SecretNode
		err     error
		roleSeq = fmt.Sprintf("tr-%d", time.Now().UnixNano())
	)
	step("create project", false, func() error { proj, err = st.CreateProject(ctx, &models.Project{Name: roleSeq}); return err })
	step("create environment", false, func() error {
		env, err = st.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
		return err
	})
	step("create machine identity", false, func() error {
		mi, err = st.CreateMachineIdentity(ctx, &models.MachineIdentity{ProjectID: proj.ID, Name: roleSeq, State: "active"})
		return err
	})
	step("mint credential", false, func() error {
		cred, err = st.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{MachineIdentityID: mi.ID, Name: "c", TokenHash: "h" + roleSeq, TokenPrefix: "kx"})
		return err
	})
	step("touch last_used_at", true, func() error {
		return st.TouchMachineIdentityCredential(ctx, cred.ID, time.Now(), time.Minute)
	})
	step("create role", false, func() error {
		n, nerr := identity.NewFoldedName(roleSeq)
		if nerr != nil {
			return nerr
		}
		role, err = st.CreateRole(ctx, n, "")
		return err
	})
	step("create permission", false, func() error {
		perm, err = st.CreatePermission(ctx, &models.Permission{Name: roleSeq + ".read", Resource: "tr", Action: "read"})
		return err
	})
	step("grant permission to role", false, func() error { return st.AssignPermissionToRole(ctx, role.ID, perm.ID) })
	scope := storage.Scope{ProjectID: proj.ID, EnvironmentID: env.ID}
	step("assign machine role", false, func() error { return st.AssignMachineRole(ctx, mi.ID, role.ID, scope) })
	step("create secret", false, func() error {
		secret, err = st.CreateSecret(ctx, &models.SecretNode{Name: roleSeq, ProjectID: proj.ID, EnvironmentID: env.ID, Status: "active", Type: "kv"})
		return err
	})
	step("set access schedule", false, func() error {
		return st.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{SecretNodeID: secret.ID, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC"})
	})
	step("update secret", false, func() error {
		secret.Description = "changed"
		_, err := st.UpdateSecret(ctx, secret)
		return err
	})
	step("remove permission from role", false, func() error { return st.RemovePermissionFromRole(ctx, role.ID, perm.ID) })
	step("remove machine role", false, func() error { return st.RemoveMachineRole(ctx, mi.ID, role.ID, scope) })
	step("revoke credential", false, func() error { return st.RevokeMachineIdentityCredential(ctx, proj.ID, cred.ID) })
	step("suspend machine identity", false, func() error {
		mi.State = "suspended"
		_, err := st.TransitionMachineIdentityState(ctx, mi, "active")
		return err
	})
	step("delete secret", false, func() error { return st.DeleteSecret(ctx, secret.ID) })
	step("delete project", false, func() error { return st.DeleteProject(ctx, proj.ID) })

	time.Sleep(3 * PollInterval)
	require.Zero(t, g.UnattributedBumps(), "the canary must not fire for writes the tracker saw")
}

// TestTracker_CanaryCatchesAWriteTheTrackerMissed: a tagged session the
// tracker does not watch (standing in for a write path the classification
// misses) moves the epoch; within two polls the canary counts it and flushes.
func TestTracker_CanaryCatchesAWriteTheTrackerMissed(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	tr := g.Tracker()
	// A tagged session (the fence lets it write) with the tracer removed.
	cc, err := config.ResolvePostgresConnConfig(&w.cfg.Storage.Database)
	require.NoError(t, err)
	cc.Tracer = nil
	db := stdlibOpen(cc)
	t.Cleanup(func() { _ = db.Close() })
	g0 := tr.Gen()
	_, err = db.ExecContext(context.Background(), "UPDATE roles SET description = description")
	require.NoError(t, err)
	require.Eventually(t, func() bool { return g.UnattributedBumps() == 1 }, 3*time.Second, 20*time.Millisecond)
	require.Greater(t, tr.Gen(), g0, "the canary must flush every entry")
	require.EqualValues(t, 1, g.Status().UnattributedBumps)
}

// TestFencedTables_NoCascadeFromUnfencedParent: a foreign key that cascades
// (or nulls/defaults) from an unfenced parent into a fenced table would let a
// write to the parent change a fenced row without naming it, unseen by the
// tracker. The migrated schema has none.
func TestFencedTables_NoCascadeFromUnfencedParent(t *testing.T) {
	w := newSWWorld(t)
	require.Empty(t, cascadesIntoFencedTables(t, w), "the migrated schema must have no cascade from an unfenced parent into a fenced table")

	// Calibration: the check fires on a real cascade (this schema only).
	require.NoError(t, w.foreign.Exec("CREATE TABLE sw_calibration_parent (id integer PRIMARY KEY)").Error)
	require.NoError(t, w.foreign.Exec("ALTER TABLE environments ADD COLUMN sw_calibration_id integer REFERENCES sw_calibration_parent (id) ON DELETE SET NULL").Error)
	require.Len(t, cascadesIntoFencedTables(t, w), 1, "calibration: a SET NULL cascade into environments must be reported")
}

// cascadesIntoFencedTables lists foreign keys whose ON DELETE/UPDATE action
// (cascade, set null, set default) changes a fenced child from an unfenced
// parent.
func cascadesIntoFencedTables(t *testing.T, w *swWorld) []string {
	t.Helper()
	var rows []struct{ Child, Parent, Name string }
	require.NoError(t, w.foreign.Raw(`SELECT c.relname AS child, p.relname AS parent, con.conname AS name
FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_class p ON p.oid = con.confrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE con.contype = 'f' AND n.nspname = current_schema()
  AND (con.confdeltype IN ('c','n','d') OR con.confupdtype IN ('c','n','d'))`).Scan(&rows).Error)
	fenced := map[string]bool{}
	for _, n := range FencedTableNames() {
		fenced[n] = true
	}
	var out []string
	for _, r := range rows {
		if fenced[r.Child] && !fenced[r.Parent] {
			out = append(out, fmt.Sprintf("%s: %s -> %s", r.Name, r.Parent, r.Child))
		}
	}
	return out
}

// TestTracker_TransactionEndsTheWriteNotItsFirstStatement: inside a
// transaction the write stays in flight until COMMIT, and the generation moves
// only then. If BEGIN were not seen, the generation would move at the first
// statement, before the change is visible to other sessions, and a fill in
// between would store pre-commit data at the new generation.
func TestTracker_TransactionEndsTheWriteNotItsFirstStatement(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	w := newSWWorld(t)
	g := w.start(Options{})
	tr := g.Tracker()
	st := w.serverStorage()
	ctx := context.Background()
	g0 := tr.Gen()
	require.NoError(t, st.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, err := tx.CreateProject(ctx, &models.Project{Name: fmt.Sprintf("tx-%d", time.Now().UnixNano())}); err != nil {
			return err
		}
		require.EqualValues(t, 1, tr.Inflight(), "inside the transaction the write must be in flight")
		require.Equal(t, g0, tr.Gen(), "the generation must not move before COMMIT")
		require.False(t, tr.Valid(g0), "no entry may be served while the write is in flight")
		return nil
	}))
	require.Zero(t, tr.Inflight())
	require.NotEqual(t, g0, tr.Gen(), "COMMIT must move the generation")

	// A rolled-back write also ends (and moves the generation: harmless).
	g1 := tr.Gen()
	_ = st.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, err := tx.CreateProject(ctx, &models.Project{Name: fmt.Sprintf("rb-%d", time.Now().UnixNano())}); err != nil {
			return err
		}
		return fmt.Errorf("roll back")
	})
	require.Zero(t, tr.Inflight(), "a rolled-back write must not stay in flight")
	require.NotEqual(t, g1, tr.Gen())
}
