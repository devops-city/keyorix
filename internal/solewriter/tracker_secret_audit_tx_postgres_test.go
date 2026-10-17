package solewriter

// tracker_secret_audit_tx_postgres_test.go — AUDIT-MUTATION-TX-1: a secret
// mutation now carries its audit row in the same transaction (internal/core,
// secret_mutation_audit.go). The tracker must see that combined transaction as
// ONE fenced write that ends at its COMMIT or ROLLBACK, not at the audit
// append's savepoint: the append runs as a nested GORM transaction, so it
// issues SAVEPOINT / RELEASE (or ROLLBACK TO) plus the chain's advisory lock
// and INSERTs into unfenced tables (audit_events, secret_access_logs). The
// transaction below has the exact statement shape core runs: the secret write
// first, the audit append last, through the transaction-scoped store.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestTracker_SecretMutationWithItsAuditRowIsOneFencedWrite(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	w := newSWWorld(t)
	g := w.start(Options{})
	tr := g.Tracker()
	st := w.serverStorage()
	ctx := context.Background()

	tag := fmt.Sprintf("sa-%d", time.Now().UnixNano())
	proj, err := st.CreateProject(ctx, &models.Project{Name: tag})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{Name: tag, ProjectID: proj.ID, EnvironmentID: env.ID, Status: "active", Type: "kv", IsSecret: true})
	require.NoError(t, err)

	auditRow := func(description string) (*models.AuditEvent, *models.SecretAccessLog) {
		ok, sid, pid := true, secret.ID, proj.ID
		return &models.AuditEvent{EventType: "secret.updated", SecretNodeID: &sid, ProjectID: &pid, Description: description,
				Success: &ok, EventTime: time.Now().UTC(), ActorType: "user"},
			&models.SecretAccessLog{SecretNodeID: secret.ID, AccessedBy: "admin", AccessTime: time.Now().UTC(), Action: "update"}
	}
	description := func() string {
		var d string
		require.NoError(t, w.foreign.Raw("SELECT description FROM secret_nodes WHERE id = ?", secret.ID).Scan(&d).Error)
		return d
	}

	// Committed: in flight from the secret write through the audit append, ended
	// (and the generation moved, flushing every cache entry filled before it) by
	// the COMMIT alone.
	e0, g0, c0 := w.epoch(w.foreign), tr.Gen(), tr.commits.Load()
	var midInflight int64
	var midCommits uint64
	require.NoError(t, st.WithTransaction(ctx, func(tx storage.Storage) error {
		d := "committed with its audit row"
		if _, err := tx.UpdateSecretFields(ctx, secret.ID, storage.SecretFieldUpdate{Description: &d}); err != nil {
			return err
		}
		ev, al := auditRow("User admin updated secret " + tag)
		if err := tx.LogAuditEventWithAccessLog(ctx, ev, al); err != nil {
			return err
		}
		midInflight, midCommits = tr.Inflight(), tr.commits.Load()
		return nil
	}))
	require.EqualValues(t, 1, midInflight, "after the audit append (its savepoint released) the secret write must still be in flight")
	require.Equal(t, c0, midCommits, "the audit append's savepoint must not count as the end of the write")
	require.Zero(t, tr.Inflight())
	require.Equal(t, c0+1, tr.commits.Load(), "the COMMIT must end the combined write, once")
	require.False(t, tr.Valid(g0), "an entry filled before the COMMIT must not be served after it")
	require.NotEqual(t, e0, w.epoch(w.foreign), "precondition: the combined transaction reached a fenced table")
	require.Equal(t, "committed with its audit row", description())

	// Audit append fails inside its savepoint (Postgres rejects a NUL byte in
	// text): ROLLBACK TO SAVEPOINT, then the whole transaction rolls back. The
	// write still ends exactly once, the generation still moves, and the epoch
	// does not (its trigger's bump rolled back with the secret write).
	e1, g1, c1 := w.epoch(w.foreign), tr.Gen(), tr.commits.Load()
	err = st.WithTransaction(ctx, func(tx storage.Storage) error {
		d := "must roll back"
		if _, err := tx.UpdateSecretFields(ctx, secret.ID, storage.SecretFieldUpdate{Description: &d}); err != nil {
			return err
		}
		ev, al := auditRow("nul\x00byte")
		return tx.LogAuditEventWithAccessLog(ctx, ev, al)
	})
	require.Error(t, err, "precondition: the audit append must fail")
	require.Zero(t, tr.Inflight(), "a rolled-back combined write must not stay in flight")
	require.Equal(t, c1+1, tr.commits.Load())
	require.False(t, tr.Valid(g1))
	require.Equal(t, e1, w.epoch(w.foreign), "a rolled-back write must not move the epoch")
	require.Equal(t, "committed with its audit row", description(), "the secret write must roll back with its failed audit row")

	time.Sleep(3 * PollInterval)
	require.Zero(t, g.UnattributedBumps(), "the canary must not fire for writes the tracker saw")
}
