// local_audit_chain_pipeline_commit_failure_test.go — PERF-TESTS-1: the one
// flight-2 failure the pipeline tests do not cover. Every INSERT succeeds and
// COMMIT itself fails (a deferred constraint trigger that raises at commit).
// The batch must error for every waiter, write nothing, release KEYAUDIT and
// leave the connection idle. pg-gated (KEYORIX_TEST_PG_DSN).
package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommitBatch_PostgresCommitFailsAfterInserts(t *testing.T) {
	ctx := context.Background()
	ls, _ := pipelinePGStore(t)
	require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(2, "before")))
	require.NoError(t, ls.db.Exec(`CREATE FUNCTION kx_fail_at_commit() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'kx commit-time failure'; END $$ LANGUAGE plpgsql`).Error)
	require.NoError(t, ls.db.Exec(`CREATE CONSTRAINT TRIGGER kx_fail_at_commit AFTER INSERT ON audit_events
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kx_fail_at_commit()`).Error)

	// Through commitAuditBatch (retry + bisection): each of the 3 waiters
	// must be told its event was not recorded.
	errs := ls.commitAuditBatch(buildMultiRowBatch(3, "doomed"))
	require.Len(t, errs, 3)
	for i, err := range errs {
		require.Error(t, err, "waiter %d was told its audit event was recorded", i)
	}

	// Checked from another session BEFORE the pool's connection is used again,
	// as in the sibling tests: an idle connection left inside the transaction
	// would keep holding KEYAUDIT.
	other, err := pgx.Connect(ctx, os.Getenv("KEYORIX_TEST_PG_DSN"))
	require.NoError(t, err)
	defer func() { _ = other.Close(ctx) }()
	var got bool
	require.NoError(t, other.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", int64(auditAdvisoryLockKey)).Scan(&got))
	require.True(t, got, "KEYAUDIT still held after a failed COMMIT")
	_, err = other.Exec(ctx, "SELECT pg_advisory_unlock($1)", int64(auditAdvisoryLockKey))
	require.NoError(t, err)

	requireConnIdle(t, ls)
	events, _ := loadAuditRows(t, ls)
	assert.Len(t, events, 2, "a failed COMMIT must leave no row behind")

	require.NoError(t, ls.db.Exec("DROP TRIGGER kx_fail_at_commit ON audit_events").Error)
	require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(3, "after")))
	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	assert.Equal(t, int64(5), v.ChainedEvents)
}
