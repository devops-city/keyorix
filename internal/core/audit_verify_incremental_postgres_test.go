// audit_verify_incremental_postgres_test.go — incremental audit-chain
// verification on PostgreSQL, across two replicas with their own connection
// pools (docs/specs/audit-incremental-verification.md §3, §8).
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newIncrementalPGReplica(t *testing.T, dsn string, clk *incrClock) *KeyorixCore {
	t.Helper()
	c := NewKeyorixCore(store.NewLocalStorage(pgOpen(t, dsn)))
	c.now = clk.now
	c.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	c.SetAuditIncrementalVerification(24*time.Hour, 3)
	c.auditVerifyMinWidth = 1
	return c
}

// The rolling cycle proves the chain on PG, a replica reading the same signed
// state agrees, an old-segment tamper is caught within one cycle, and a full
// job running on one replica is reported as running (not interrupted) by the
// other, whose own start returns that job instead of a second one.
func TestIncrementalVerify_Postgres(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{},
	))
	clk := &incrClock{t: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)}
	a := newIncrementalPGReplica(t, dsn, clk)
	b := newIncrementalPGReplica(t, dsn, clk)

	logIncrEvents(t, a, clk, 30)
	_, _, err := a.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusNotProven, incrVerify(t, b).Status)

	completed := false
	for range 3 {
		clk.advance()
		logIncrEvents(t, a, clk, 2)
		res, err := a.RunAuditVerificationTick(ctx)
		require.NoError(t, err)
		completed = res.CycleCompleted
	}
	require.True(t, completed)
	assert.Equal(t, AuditVerifyStatusValid, incrVerify(t, b).Status, "the other replica reads the same signed state")

	// Cross-replica job exclusion: hold the job lock as replica a would while
	// running; b must see it as running and not start a second job.
	require.NoError(t, a.updateAuditVerifyState(ctx, func(st *auditVerifyState) *auditVerifyFailure {
		st.Job = &auditVerifyJob{ID: "job-on-a", State: AuditVerifyJobRunning, StartedAt: clk.t}
		return nil
	}))
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.storage.WithSchedulerLock(ctx, AuditVerifyJobLockKey, func(context.Context) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	j, err := b.AuditFullVerificationJob(ctx, "job-on-a")
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyJobRunning, j.State)
	id, started, err := b.StartAuditFullVerification(ctx)
	require.NoError(t, err)
	assert.False(t, started)
	assert.Equal(t, "job-on-a", id)
	close(release)
	<-done
	j, err = b.AuditFullVerificationJob(ctx, "job-on-a")
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyJobInterrupted, j.State, "nobody holds the lock any more")

	tamperDescription(t, db, 4)
	n, r := runTicksUntilBroken(t, a, clk, 4)
	require.NotZero(t, n)
	require.NotNil(t, r.FirstBrokenID)
	assert.Equal(t, uint(4), *r.FirstBrokenID)
	assert.Equal(t, AuditVerifyStatusBroken, incrVerify(t, b).Status)
}
