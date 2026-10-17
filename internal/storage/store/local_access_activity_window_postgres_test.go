// local_access_activity_window_postgres_test.go — the LastUser*Activity lookup on
// a large audit_events table in PostgreSQL: the plan stays on the existing
// (project_id, event_time) index, bounded below by the window start, and the rows
// the executor reads stay at the size of the window, not of the table.
// pg-gated (KEYORIX_TEST_PG_DSN).
package store

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLastUserActivity_PostgresBoundedPlan(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a 240k-row audit table")
	}
	ctx := context.Background()
	ls, _ := pipelinePGStore(t)
	since := time.Now().UTC().AddDate(0, 0, -90).Truncate(time.Second)
	seedBigAuditTable(t, ls, since)
	require.NoError(t, ls.db.Exec("ANALYZE audit_events").Error)

	got, err := ls.LastUserSecretActivity(ctx, bigProject, since)
	require.NoError(t, err)
	assert.Len(t, got, 25)
	for uid, at := range got {
		assert.False(t, at.Before(since), "user %d: %v is older than the window start %v", uid, at, since)
	}

	var lines []string
	require.NoError(t, ls.db.Raw("EXPLAIN (ANALYZE, TIMING OFF, COSTS OFF) "+lastActivitySQL(ls, since)).Scan(&lines).Error)
	plan := strings.Join(lines, "\n")
	t.Logf("plan:\n%s", plan)

	assert.NotContains(t, plan, "Seq Scan", "no full table scan")
	assert.Contains(t, plan, "idx_audit_events_project_event_time", "must use the existing (project_id, event_time) index")
	assert.Regexp(t, regexp.MustCompile(`(?s)Index Cond: .*project_id = .*event_time >=`), plan, "the index range must be bounded below by the window start")

	// Rows examined: the largest "actual rows" of any node must be the window's size,
	// not the table's (240k).
	most := 0
	for _, m := range regexp.MustCompile(`actual rows=(\d+)`).FindAllStringSubmatch(plan, -1) {
		n, err := strconv.Atoi(m[1])
		require.NoError(t, err)
		most = max(most, n)
	}
	assert.LessOrEqual(t, most, rowsExaminedLimit(), "a node read %d rows; the window holds %d for this project", most, bigInWindowRows)
}
