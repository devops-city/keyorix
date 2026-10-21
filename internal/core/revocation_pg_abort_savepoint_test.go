package core

// revocation_pg_abort_savepoint_test.go -- REVIEW-3482 item 2.
//
// SuspendUser (setAccountStateInTx) and UpdateUser's deactivation treat the session
// and PAT cleanup inside their transaction as best-effort: the error is ignored or
// recorded and the transaction carries on. On PostgreSQL a failed statement aborts
// the transaction, so an ignored error rolled the whole revocation back at COMMIT
// (pgx: "commit unexpectedly resulted in rollback"). faultstorage cannot show this:
// it injects an error without touching the database. A BEFORE DELETE trigger that
// raises makes PostgreSQL itself fail the statement.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func failSessionDeletesOnPostgres(t *testing.T, w *txClosureWorld) {
	t.Helper()
	require.NoError(t, w.db.Exec(`CREATE OR REPLACE FUNCTION review3482_refuse_session_delete() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'review3482: session delete refused'; END $$ LANGUAGE plpgsql`).Error)
	require.NoError(t, w.db.Exec(`CREATE TRIGGER review3482_refuse_session_delete BEFORE DELETE ON sessions
FOR EACH ROW EXECUTE FUNCTION review3482_refuse_session_delete()`).Error)
	t.Cleanup(func() {
		_ = w.db.Exec(`DROP TRIGGER IF EXISTS review3482_refuse_session_delete ON sessions`).Error
		_ = w.db.Exec(`DROP FUNCTION IF EXISTS review3482_refuse_session_delete()`).Error
	})
}

func TestRevocation_BestEffortCleanupFailureOnPostgres_RevocationStillCommits(t *testing.T) {
	t.Run("suspend", func(t *testing.T) {
		w := newPostgresWorld(t)
		id := w.seedDeactivationTarget(t, "pgabort-suspend")
		failSessionDeletesOnPostgres(t, w)
		err := w.c.SuspendUser(context.Background(), 0, id)
		require.NoError(t, err, "a suspend must not be rolled back by a best-effort session cleanup failure")
		var after models.User
		require.NoError(t, w.db.First(&after, id).Error)
		require.Equal(t, AccountSuspended, after.AccountState, "the suspension must have committed")
		require.Equal(t, int64(1), w.auditCount(t, "account.suspended")+w.pendingCount(t), "its audit row is written or owed")
	})
	t.Run("update-user-deactivate", func(t *testing.T) {
		w := newPostgresWorld(t)
		id := w.seedDeactivationTarget(t, "pgabort-deact")
		failSessionDeletesOnPostgres(t, w)
		off := false
		_, err := w.c.UpdateUser(context.Background(), &UpdateUserRequest{ID: id, IsActive: &off})
		require.NoError(t, err, "a deactivation must not be rolled back by a best-effort session cleanup failure")
		var after models.User
		require.NoError(t, w.db.First(&after, id).Error)
		require.False(t, after.IsActive, "the deactivation must have committed")
		require.Equal(t, int64(1), w.auditCount(t, EventUserDeactivationCleanupFailed), "the cleanup failure is audited")
	})
}
