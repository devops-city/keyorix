package solewriter

// tracker_postgres_test.go — the tracker against the database: every write
// path that moves the write epoch (the database's own account of a fenced
// write) must also move the tracker's generation before the call returns. The
// trigger is the oracle for the tracker's SQL classification.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

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

	// The tracker's commit count, not Gen: the running poller also moves Gen
	// (Flush) on every epoch move it sees, so a Gen change after a step would
	// not prove the tracker itself saw the write.
	step := func(name string, bookkeeping bool, op func() error) {
		t.Helper()
		e0, c0 := w.epoch(w.foreign), tr.commits.Load()
		require.NoError(t, op(), name)
		e1, c1 := w.epoch(w.foreign), tr.commits.Load()
		require.Zero(t, tr.Inflight(), "%s: a write is still counted in flight after the call returned", name)
		if bookkeeping {
			require.Equal(t, e0, e1, "%s: bookkeeping moved the epoch", name)
			require.Equal(t, c0, c1, "%s: bookkeeping counted as a fenced write", name)
			return
		}
		require.NotEqual(t, e0, e1, "%s: precondition: the write must reach a fenced table", name)
		require.Greater(t, c1, c0, "%s: the epoch moved (%d -> %d) but the tracker did not see the write", name, e0, e1)
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
// misses) moves the epoch; the poll that sees it flushes, and within two polls
// the canary counts it.
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
	// A row it reaches: the guards are per row, so a zero-row write moves nothing.
	_, err = db.ExecContext(context.Background(), "UPDATE projects SET name = name")
	require.NoError(t, err)
	require.Eventually(t, func() bool { return g.UnattributedBumps() == 1 }, 3*time.Second, 20*time.Millisecond)
	require.Greater(t, tr.Gen(), g0, "the epoch move must flush every entry")
	require.EqualValues(t, 1, g.Status().UnattributedBumps)
	require.Equal(t, StateAuthoritative, g.Status().State, "one unattributed bump keeps the guard authoritative")

	// A second one: a write path the tracker keeps missing. Confirming until
	// restart (docs/specs/single-writer-cache.md, failure table).
	_, err = db.ExecContext(context.Background(), "UPDATE projects SET name = name")
	require.NoError(t, err)
	require.Eventually(t, func() bool { return g.UnattributedBumps() == 2 }, 3*time.Second, 20*time.Millisecond)
	st := g.Status()
	require.Equal(t, StateConfirming, st.State, "repeated unattributed bumps must leave the authoritative state")
	require.Contains(t, st.Reason, "without a write this server accounts for")
	require.False(t, g.Authoritative())
}

// TestTracker_GuardOwnFenceIsNotCounted: the holder connection's fence DDL
// and holder/epoch rows are not server writes (REVIEW finding 7: counting
// them made the canary call a miss explained).
func TestTracker_GuardOwnFenceIsNotCounted(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	require.Zero(t, g.Tracker().commits.Load(), "the guard's own boot was counted as fenced writes")
	time.Sleep(3 * PollInterval)
	require.Zero(t, g.UnattributedBumps())
}

// TestTracker_ConnectionDeathDuringAReadEndsTheWrite: a connection inside a
// fenced write that dies during a read (or any statement) must not stay in
// flight: that would keep every cache off and the canary blind for good.
func TestTracker_ConnectionDeathDuringAReadEndsTheWrite(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	tr := g.Tracker()
	ctx := context.Background()
	cc, err := config.ResolvePostgresConnConfig(&w.cfg.Storage.Database) // tagged and traced, as the server's pools
	require.NoError(t, err)
	conn, err := pgx.ConnectConfig(ctx, cc)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	_, err = conn.Exec(ctx, "BEGIN")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "UPDATE roles SET description = description")
	require.NoError(t, err)
	require.EqualValues(t, 1, tr.Inflight())
	require.NoError(t, w.foreign.Exec("SELECT pg_terminate_backend(?)", conn.PgConn().PID()).Error)
	_, err = conn.Exec(ctx, "SELECT 1")
	require.Error(t, err, "the read must fail on the terminated connection")
	require.True(t, conn.IsClosed())
	require.Zero(t, tr.Inflight(), "a dead connection's write must not stay in flight")
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
	// Commit counts, not Gen alone: the running poller also moves Gen.
	g0, c0 := tr.Gen(), tr.commits.Load()
	require.NoError(t, st.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, err := tx.CreateProject(ctx, &models.Project{Name: fmt.Sprintf("tx-%d", time.Now().UnixNano())}); err != nil {
			return err
		}
		require.EqualValues(t, 1, tr.Inflight(), "inside the transaction the write must be in flight")
		require.Equal(t, c0, tr.commits.Load(), "the write must not count as finished before COMMIT")
		require.False(t, tr.Valid(g0), "no entry may be served while the write is in flight")
		return nil
	}))
	require.Zero(t, tr.Inflight())
	require.Equal(t, c0+1, tr.commits.Load(), "COMMIT must end the write")
	require.False(t, tr.Valid(g0), "COMMIT must move the generation")

	// A rolled-back write also ends (and moves the generation: harmless).
	g1, c1 := tr.Gen(), tr.commits.Load()
	_ = st.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, err := tx.CreateProject(ctx, &models.Project{Name: fmt.Sprintf("rb-%d", time.Now().UnixNano())}); err != nil {
			return err
		}
		return fmt.Errorf("roll back")
	})
	require.Zero(t, tr.Inflight(), "a rolled-back write must not stay in flight")
	require.Equal(t, c1+1, tr.commits.Load())
	require.False(t, tr.Valid(g1))
}

// TestTracker_SavepointRollbackDoesNotEndTheTransaction: a failed nested GORM
// transaction rolls back to its savepoint and the outer transaction goes on.
// Its fenced write must stay in flight until the outer COMMIT, and the COMMIT
// must move the generation; an entry filled in between must not survive it
// (REVIEW-SINGLE-WRITER-1 F3). ROLLBACK ... AND CHAIN ends one transaction
// and starts the next at once, so a write after it is in flight until that
// one ends too.
func TestTracker_SavepointRollbackDoesNotEndTheTransaction(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	tr := g.Tracker()
	own := w.own()
	var midInflight int64
	var midGen, midCommits uint64
	require.NoError(t, own.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error; err != nil {
			return err
		}
		require.Error(t, tx.Transaction(func(*gorm.DB) error { return errors.New("a best-effort step fails") }))
		midInflight, midGen, midCommits = tr.Inflight(), tr.Gen(), tr.commits.Load()
		return nil
	}))
	require.True(t, w.revoked())
	require.EqualValues(t, 1, midInflight, "after ROLLBACK TO SAVEPOINT the outer transaction's write must still be in flight")
	require.Zero(t, tr.Inflight())
	require.Equal(t, midCommits+1, tr.commits.Load(), "the outer COMMIT (not the savepoint rollback) must end the write")
	require.False(t, tr.Valid(midGen), "an entry filled before the revoking COMMIT must not be served after it")

	// AND CHAIN: the chained transaction's write is in flight until it ends.
	require.NoError(t, own.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("ROLLBACK AND CHAIN").Error; err != nil {
			return err
		}
		if err := tx.Exec("UPDATE roles SET description = description").Error; err != nil {
			return err
		}
		g1 := tr.Gen()
		require.EqualValues(t, 1, tr.Inflight(), "a write in the chained transaction must be in flight until it commits")
		require.False(t, tr.Valid(g1))
		return nil
	}))
	require.Zero(t, tr.Inflight())
	time.Sleep(3 * PollInterval)
	require.Zero(t, g.UnattributedBumps())
}

// TestPoll_EveryEpochMoveFlushes: a write that passed the fence with a copied
// tag, committed in the same poll window as one of the server's own writes,
// must still invalidate what was filled before it. The poller is driven by
// hand so the two writes always share a window (REVIEW-SINGLE-WRITER-1 F4:
// the canary counted the move as explained by the server's commit and nothing
// was flushed).
func TestPoll_EveryEpochMoveFlushes(t *testing.T) {
	w := newSWWorld(t)
	ctx := context.Background()
	g, err := Start(ctx, w.cfg, Options{SkipPresenceCensus: true, LockWait: 500 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(g.Close)
	require.NoError(t, g.InstallFence(ctx))
	require.NoError(t, g.Settle(ctx)) // one poll; no poller goroutine runs
	tr := g.Tracker()

	require.NoError(t, w.own().Exec("UPDATE roles SET description = description").Error) // the server's own write
	fillGen := tr.Gen()                                                                  // an entry filled now, before the foreign write
	require.True(t, tr.Valid(fillGen))
	stolen := w0open(t, w.dsn) // no tracer, no tag of its own
	require.NoError(t, stolen.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT set_config(?, ?, true)", config.SoleWriterSessionSetting, g.nonce).Error; err != nil {
			return err
		}
		return tx.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", w.credID).Error
	}))
	require.True(t, w.revoked(), "the copied tag passed the fence")
	for range 3 {
		g.pollOnce(ctx)
	}
	require.False(t, tr.Valid(fillGen), "an entry filled before a foreign epoch move must not be served after the poll that saw it")
}
