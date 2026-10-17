package core

// SUSPEND-AUDIT-LOUD on PostgreSQL: the owed secret.suspended row of a plain suspend
// refused by the audit log is written exactly once when several replicas (own
// connection pools, same schema) backfill at the same time. The claim (a DELETE)
// and the append share a transaction, so the losers' DELETE waits for the winner's
// commit and then matches nothing.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestSuspendSecret_PlainSuspendAuditOwed_ConcurrentBackfillWritesOnce_Postgres(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
		&models.SecretAccessLog{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{},
		&models.PendingAuditEvent{},
	))
	replica := func() *KeyorixCore {
		c := NewKeyorixCore(store.NewLocalStorage(pgOpen(t, dsn)))
		c.now = time.Now
		return c
	}
	a := replica()

	p, err := a.storage.CreateProject(ctx, &models.Project{Name: "owed-pg"})
	require.NoError(t, err)
	e, err := a.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)
	const secrets = 3
	ids := make([]uint, 0, secrets)
	for i := range secrets {
		s, err := a.storage.CreateSecret(ctx, &models.SecretNode{
			Name: "owed-" + string(rune('a'+i)), ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1,
			IsSecret: true, Status: SecretStatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		ids = append(ids, s.ID)
	}

	require.NoError(t, db.Exec(`CREATE FUNCTION refuse_suspend_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.event_type = 'secret.suspended' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$`).Error)
	require.NoError(t, db.Exec(`CREATE TRIGGER refuse_suspend_audit BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION refuse_suspend_audit()`).Error)
	for _, id := range ids {
		_, err := a.SuspendSecret(ctx, id, 1, "pg outage")
		require.NoError(t, err, "revocation is never failed by the audit log")
	}
	var suspended, pending int64
	require.NoError(t, db.Model(&models.SecretNode{}).Where("status = ?", SecretStatusSuspended).Count(&suspended).Error)
	require.NoError(t, db.Model(&models.PendingAuditEvent{}).Count(&pending).Error)
	require.Equal(t, int64(secrets), suspended)
	require.Equal(t, int64(secrets), pending, "every missing row is recorded with its suspension")

	require.NoError(t, db.Exec(`DROP TRIGGER refuse_suspend_audit ON audit_events`).Error)
	const replicas = 4
	cores := make([]*KeyorixCore, replicas)
	for i := range cores {
		cores[i] = replica()
	}
	var wg sync.WaitGroup
	written := make([]int, replicas)
	errs := make([]error, replicas)
	start := make(chan struct{})
	for i, c := range cores {
		wg.Go(func() {
			<-start
			written[i], errs[i] = c.BackfillPendingAuditEvents(ctx)
		})
	}
	close(start)
	wg.Wait()
	total := 0
	for i := range cores {
		require.NoError(t, errs[i], "replica %d", i)
		total += written[i]
	}
	assert.Equal(t, secrets, total, "the replicas together write each owed row once")
	for _, id := range ids {
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).
			Where("event_type = ? AND secret_node_id = ?", EventSecretSuspended, id).Count(&n).Error)
		assert.Equal(t, int64(1), n, "secret %d: exactly one secret.suspended row", id)
	}
	require.NoError(t, db.Model(&models.PendingAuditEvent{}).Count(&pending).Error)
	assert.Zero(t, pending)
	v, err := a.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, "the audit chain verifies after a concurrent backfill")
}
