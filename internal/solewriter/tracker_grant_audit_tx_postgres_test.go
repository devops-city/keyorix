package solewriter

// tracker_grant_audit_tx_postgres_test.go — AUDIT-TX-2: a grant-shaped
// mutation now carries its audit row in the same transaction
// (internal/core/mutation_audit_tx.go), the shape #3297 gave secret mutations.
// For each fenced grant (a permission bundled into a role, a machine identity's
// role grant, a machine credential) the tracker must see the grant plus its
// audit append as ONE fenced write that ends at the COMMIT or ROLLBACK, not at
// the append's savepoint; a rolled-back grant must not move the epoch.
// The transactions below have the statement shape core runs: the grant first
// (itself a nested savepoint), the audit append last, through the
// transaction-scoped store.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestTracker_GrantWithItsAuditRowIsOneFencedWrite(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	w := newSWWorld(t)
	g := w.start(Options{})
	tr := g.Tracker()
	st := w.serverStorage()
	ctx := context.Background()

	tag := fmt.Sprintf("ga-%d", time.Now().UnixNano())
	proj, err := st.CreateProject(ctx, &models.Project{Name: tag})
	require.NoError(t, err)
	mi, err := st.CreateMachineIdentity(ctx, &models.MachineIdentity{ProjectID: proj.ID, Name: tag, State: "active"})
	require.NoError(t, err)
	n, err := identity.NewFoldedName(tag)
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, n, "")
	require.NoError(t, err)

	auditRow := func(eventType, description string) *models.AuditEvent {
		ok, pid := true, proj.ID
		return &models.AuditEvent{EventType: eventType, ProjectID: &pid, Description: description,
			Success: &ok, EventTime: time.Now().UTC(), ActorType: "user"}
	}
	count := func(table string) int64 {
		var c int64
		require.NoError(t, w.foreign.Table(table).Count(&c).Error)
		return c
	}

	grants := []struct {
		name, eventType, table string
		write                  func(tx storage.Storage, seq int) error
	}{
		{"permission into role", "permission.assigned", "role_permissions", func(tx storage.Storage, seq int) error {
			perm, err := tx.CreatePermission(ctx, &models.Permission{Name: fmt.Sprintf("%s.p%d", tag, seq), Resource: "ga", Action: "read"})
			if err != nil {
				return err
			}
			return tx.AssignPermissionToRole(ctx, role.ID, perm.ID)
		}},
		{"machine role", "machine_identity.role_granted", "machine_identity_roles", func(tx storage.Storage, seq int) error {
			n, err := identity.NewFoldedName(fmt.Sprintf("%s-r%d", tag, seq))
			if err != nil {
				return err
			}
			r, err := tx.CreateRole(ctx, n, "")
			if err != nil {
				return err
			}
			return tx.AssignMachineRole(ctx, mi.ID, r.ID, storage.Scope{ProjectID: proj.ID})
		}},
		{"machine credential", "machine_identity.token_issued", "machine_identity_credentials", func(tx storage.Storage, seq int) error {
			_, err := tx.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
				MachineIdentityID: mi.ID, Name: fmt.Sprintf("c%d", seq), TokenHash: fmt.Sprintf("h%s-%d", tag, seq), TokenPrefix: "kx"})
			return err
		}},
	}
	for i, gr := range grants {
		t.Run(gr.name, func(t *testing.T) {
			// Committed: in flight from the grant through the audit append, ended
			// (and the generation moved) by the COMMIT alone.
			e0, g0, c0, rows0 := w.epoch(w.foreign), tr.Gen(), tr.commits.Load(), count(gr.table)
			var midInflight int64
			var midCommits uint64
			require.NoError(t, st.WithTransaction(ctx, func(tx storage.Storage) error {
				if err := gr.write(tx, 2*i); err != nil {
					return err
				}
				if err := tx.LogAuditEvent(ctx, auditRow(gr.eventType, "granted "+gr.name)); err != nil {
					return err
				}
				midInflight, midCommits = tr.Inflight(), tr.commits.Load()
				return nil
			}))
			require.EqualValues(t, 1, midInflight, "after the audit append (its savepoint released) the grant must still be in flight")
			require.Equal(t, c0, midCommits, "the audit append's savepoint must not count as the end of the write")
			require.Zero(t, tr.Inflight())
			require.Equal(t, c0+1, tr.commits.Load(), "the COMMIT must end the combined write, once")
			require.False(t, tr.Valid(g0), "an entry filled before the COMMIT must not be served after it")
			require.NotEqual(t, e0, w.epoch(w.foreign), "precondition: the combined transaction reached a fenced table")
			require.Equal(t, rows0+1, count(gr.table))

			// The append fails inside its savepoint (Postgres rejects a NUL byte
			// in text): the whole transaction rolls back. The write ends once,
			// the generation moves, the epoch does not, the grant is gone.
			e1, g1, c1, rows1 := w.epoch(w.foreign), tr.Gen(), tr.commits.Load(), count(gr.table)
			err := st.WithTransaction(ctx, func(tx storage.Storage) error {
				if err := gr.write(tx, 2*i+1); err != nil {
					return err
				}
				return tx.LogAuditEvent(ctx, auditRow(gr.eventType, "nul\x00byte"))
			})
			require.Error(t, err, "precondition: the audit append must fail")
			require.Zero(t, tr.Inflight(), "a rolled-back combined write must not stay in flight")
			require.Equal(t, c1+1, tr.commits.Load())
			require.False(t, tr.Valid(g1))
			require.Equal(t, e1, w.epoch(w.foreign), "a rolled-back grant must not move the epoch")
			require.Equal(t, rows1, count(gr.table), "the grant must roll back with its failed audit row")
		})
	}

	time.Sleep(3 * PollInterval)
	require.Zero(t, g.UnattributedBumps(), "the canary must not fire for writes the tracker saw")
}
