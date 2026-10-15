// local_audit_chain_pipeline_plans_test.go — the first flight's head read and
// id allocation stay cheap on the Postgres server: the head read reuses its
// cached plan, and the id sequence is looked up once per statement rather than
// once per allocated id. pg-gated (KEYORIX_TEST_PG_DSN).
package store

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// The pipeline runs on the pool's one connection, so that connection's
// pg_prepared_statements shows how Postgres planned the cached head read on
// each flight. A head read with a bound LIMIT gets custom plans: always its
// first five, and on a large audit_events every one, because the generic plan
// is costed for a tenth of the table and never wins (seen at ~150k rows: one
// planning per flight). With the LIMIT in its text it has no parameters, so
// it is planned once and reused from the first flight on.
func TestCommitBatchAttempt_PostgresHeadReadReusesItsPlan(t *testing.T) {
	ls, _ := pipelinePGStore(t)
	ctx := context.Background()
	const flights = 8
	for i := range flights {
		ls.invalidateAuditChainHead() // the head read is the two-flight path's
		require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(1+i%3, "plans")))
	}
	var rows []struct {
		Statement    string
		GenericPlans int64
		CustomPlans  int64
	}
	require.NoError(t, ls.db.Raw("SELECT statement, generic_plans, custom_plans FROM pg_prepared_statements").Scan(&rows).Error)
	found := false
	for _, r := range rows {
		if !strings.Contains(r.Statement, "ORDER BY id DESC LIMIT 1") || strings.Contains(r.Statement, "CASE") {
			continue
		}
		found = true
		assert.Zero(t, r.CustomPlans, "the chain-head read was re-planned on every flight: %q", r.Statement)
		assert.GreaterOrEqual(t, r.GenericPlans, int64(flights), "the chain-head read did not run from its cached plan: %q", r.Statement)
	}
	require.True(t, found, "no cached chain-head read on the flusher's connection: %+v", rows)
}

// pg_get_serial_sequence scans pg_depend. If the planner pulls the allocation
// statement's subquery up into the outer query, it runs once per allocated id
// (tens of microseconds each) instead of once per statement; OFFSET 0 is what
// stops that. Counted from the server's own per-transaction scan statistics,
// so it does not depend on how EXPLAIN prints the plan.
func TestAuditAllocateIDsSQL_PostgresLooksUpTheSequenceOnce(t *testing.T) {
	ls, _ := pipelinePGStore(t)
	const n = 50
	require.NoError(t, ls.db.Transaction(func(tx *gorm.DB) error {
		var before int64
		if err := tx.Raw("SELECT COALESCE(idx_scan, 0) + seq_scan FROM pg_stat_xact_sys_tables WHERE relname = 'pg_depend'").Scan(&before).Error; err != nil {
			return err
		}
		var ids []int64
		if err := tx.Raw(auditAllocateIDsSQL, "audit_events", n).Scan(&ids).Error; err != nil {
			return err
		}
		require.Len(t, ids, n)
		var after int64
		if err := tx.Raw("SELECT COALESCE(idx_scan, 0) + seq_scan FROM pg_stat_xact_sys_tables WHERE relname = 'pg_depend'").Scan(&after).Error; err != nil {
			return err
		}
		assert.Equal(t, int64(1), after-before, "allocating %d ids scanned pg_depend %d times: the sequence lookup runs per id", n, after-before)
		return nil
	}))
}
