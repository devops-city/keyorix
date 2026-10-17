package core

// SUSPEND-AUDIT-LOUD: a plain suspend is never blocked or delayed by the audit log
// (revocation first), but its secret.suspended row is never silently lost either.
// The suspension and a pending_audit_events record commit together; the row is then
// written (and the record claimed) in one transaction, and when the audit log refuses
// it the failure is logged, counted and visible, and the backfill writes the row
// exactly once when the audit log recovers.

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newOwedAuditWorld(t *testing.T) *projectSuspendWorld {
	t.Helper()
	w := newProjectSuspendWorld(t)
	require.NoError(t, w.db.AutoMigrate(&models.PendingAuditEvent{}, &models.SystemMetadata{}, &models.AuditCheckpoint{}))
	return w
}

// refuseSuspendAudit makes the audit log refuse secret.suspended rows until the
// returned func is called.
func refuseSuspendAudit(t *testing.T, w *projectSuspendWorld) (recover func()) {
	t.Helper()
	require.NoError(t, w.db.Exec(fmt.Sprintf(
		`CREATE TRIGGER refuse_suspend_audit BEFORE INSERT ON audit_events WHEN NEW.event_type = '%s' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`,
		EventSecretSuspended)).Error)
	return func() { require.NoError(t, w.db.Exec(`DROP TRIGGER IF EXISTS refuse_suspend_audit`).Error) }
}

func (w *projectSuspendWorld) pending(t *testing.T) []models.PendingAuditEvent {
	t.Helper()
	var out []models.PendingAuditEvent
	require.NoError(t, w.db.Order("id").Find(&out).Error)
	return out
}

// captureOwedAuditLog returns everything the standard logger writes until the test ends.
func captureOwedAuditLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func (w *projectSuspendWorld) chainValid(t *testing.T) {
	t.Helper()
	v, err := w.c.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	assert.True(t, v.Valid, "the audit chain must verify after owed rows are written")
}

// Not parallel: captures the global logger and reads the process-wide counter.
func TestSuspendSecret_PlainSuspendAuditIsOwed(t *testing.T) {
	ctx := context.Background()

	t.Run("audit log works: one row, nothing left pending", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		id := w.secret(t, "ok", 1, SecretStatusActive, false)
		_, err := w.c.SuspendSecret(ctx, id, 1, "maintenance")
		require.NoError(t, err)
		require.Len(t, w.events(t, EventSecretSuspended), 1)
		assert.Empty(t, w.pending(t))
		assert.Equal(t, int64(0), w.c.OwedAuditStatus(ctx).Pending)
		w.chainValid(t)
	})

	t.Run("audit log refuses: suspended at once, loud, owed row pending", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		id := w.secret(t, "leaked", 1, SecretStatusActive, false)
		logs := captureOwedAuditLog(t)
		before := w.c.OwedAuditStatus(ctx).Failures
		defer refuseSuspendAudit(t, w)()

		_, err := w.c.SuspendSecret(ctx, id, 1, "breach response")
		require.NoError(t, err, "revocation is never failed by the audit log")
		assert.Equal(t, SecretStatusSuspended, w.stored(t, id).Status)
		suspendedRefusal(t, w.c, id)

		assert.Empty(t, w.events(t, EventSecretSuspended))
		p := w.pending(t)
		require.Len(t, p, 1, "the missing row must be recorded, not lost")
		assert.Equal(t, EventSecretSuspended, p[0].EventType)
		assert.Contains(t, p[0].Event, "breach response")
		assert.Equal(t, 1, p[0].Attempts)
		assert.NotEmpty(t, p[0].LastError)

		st := w.c.OwedAuditStatus(ctx)
		assert.Equal(t, int64(1), st.Pending)
		assert.Equal(t, before+1, st.Failures, "every failure is counted")
		assert.Contains(t, logs.String(), `SECURITY: audit event "secret.suspended" could not be written after its effect committed; queued for backfill`)
		assert.Contains(t, logs.String(), "breach response", "the log line carries the details")
	})

	t.Run("backfill writes the owed row exactly once when the audit log recovers", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		id := w.secret(t, "later", 1, SecretStatusActive, false)
		recoverAudit := refuseSuspendAudit(t, w)
		_, err := w.c.SuspendSecret(ctx, id, 7, "incident 42")
		require.NoError(t, err)

		n, err := w.c.BackfillPendingAuditEvents(ctx)
		require.Error(t, err, "while the audit log still refuses, the pass reports it")
		assert.Zero(t, n)
		require.Len(t, w.pending(t), 1, "a refused backfill keeps the record")
		assert.Equal(t, 2, w.pending(t)[0].Attempts)

		recoverAudit()
		n, err = w.c.BackfillPendingAuditEvents(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		evs := w.events(t, EventSecretSuspended)
		require.Len(t, evs, 1)
		assert.Contains(t, evs[0].Description, "incident 42")
		assert.Contains(t, evs[0].Description, "recorded late")
		require.NotNil(t, evs[0].UserID)
		assert.Equal(t, uint(7), *evs[0].UserID, "the backfilled row keeps the actor")
		require.NotNil(t, evs[0].SecretNodeID)
		assert.Equal(t, id, *evs[0].SecretNodeID)
		assert.Empty(t, w.pending(t))
		assert.Equal(t, int64(0), w.c.OwedAuditStatus(ctx).Pending)

		n, err = w.c.BackfillPendingAuditEvents(ctx)
		require.NoError(t, err)
		assert.Zero(t, n, "a second pass writes nothing")
		assert.Len(t, w.events(t, EventSecretSuspended), 1)
		w.chainValid(t)
	})

	t.Run("an owed row already claimed is never written twice", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		id := w.secret(t, "raced", 1, SecretStatusActive, false)
		recoverAudit := refuseSuspendAudit(t, w)
		_, err := w.c.SuspendSecret(ctx, id, 1, "")
		require.NoError(t, err)
		recoverAudit()
		p := w.pending(t)
		require.Len(t, p, 1)
		// A writer that lost the claim (another replica committed first) writes nothing.
		ev := buildAuditEvent(ctx, EventSecretSuspended, nil, nil, nil, "", "x", "")
		wrote, err := w.c.appendOwedAudit(ctx, p[0].ID+1000, ev)
		require.NoError(t, err, "a lost claim is not an error")
		assert.False(t, wrote)
		assert.Empty(t, w.events(t, EventSecretSuspended))
	})

	t.Run("the pending record cannot be written: still suspended, row still written", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		id := w.secret(t, "norecord", 1, SecretStatusActive, false)
		logs := captureOwedAuditLog(t)
		require.NoError(t, w.db.Migrator().DropTable(&models.PendingAuditEvent{}))

		_, err := w.c.SuspendSecret(ctx, id, 1, "")
		require.NoError(t, err)
		assert.Equal(t, SecretStatusSuspended, w.stored(t, id).Status)
		assert.Len(t, w.events(t, EventSecretSuspended), 1)
		assert.Contains(t, logs.String(), "applying the effect without that record")
	})

	t.Run("record and audit both fail: still suspended, logged as not queued, counted", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		id := w.secret(t, "both", 1, SecretStatusActive, false)
		logs := captureOwedAuditLog(t)
		before := w.c.OwedAuditStatus(ctx).Failures
		require.NoError(t, w.db.Migrator().DropTable(&models.PendingAuditEvent{}))
		defer refuseSuspendAudit(t, w)()

		_, err := w.c.SuspendSecret(ctx, id, 1, "")
		require.NoError(t, err, "revocation is never failed by the audit log")
		assert.Equal(t, SecretStatusSuspended, w.stored(t, id).Status)
		assert.Equal(t, before+1, w.c.OwedAuditStatus(ctx).Failures)
		assert.Equal(t, int64(-1), w.c.OwedAuditStatus(ctx).Pending, "an unreadable count is reported as unknown, not zero")
		assert.True(t, strings.Contains(logs.String(), "NOT queued for backfill"), logs.String())
	})

	t.Run("a plain project freeze owes each secret's row the same way", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		a := w.secret(t, "a", 1, SecretStatusActive, false)
		b := w.secret(t, "b", 1, SecretStatusActive, false)
		defer refuseSuspendAudit(t, w)()

		n, err := w.c.SuspendProjectSecrets(ctx, w.projectID, 1, "freeze")
		require.NoError(t, err)
		assert.Equal(t, 2, n)
		assert.Equal(t, SecretStatusSuspended, w.stored(t, a).Status)
		assert.Equal(t, SecretStatusSuspended, w.stored(t, b).Status)
		assert.Len(t, w.pending(t), 2)
	})
}
