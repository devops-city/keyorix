package store

// audit_list_query_plan_test.go — every statement GetAuditLogs issues for the
// audit list, search and export views is served by its index on SQLite AND
// Postgres, with no full sort (docs/specs/audit-list-keyset.md §5.1). The SQL
// EXPLAINed is the SQL production code issued (captured from gorm), not a copy.
//
// Postgres runs the EXPLAIN with enable_seqscan=off and enable_bitmapscan=off.
// On a test-sized table the planner prefers a scan of the few matching rows
// plus a sort whatever indexes exist (TestAnomalyQueries_UseTheirIndexes's
// reason for skipping Postgres). That plan is right for a few rows and ruinous
// for millions, and only real statistics tell the two apart. With both scans
// priced out, what is left is the ordered index paths. The test therefore pins
// that the expected index exists and serves the order without a full sort; a
// missing or wrong index shows up as a Sort node or a plan without that index.
// What it does not pin is the planner's choice on a real table. AUDIT-SCALE-1
// measured those plans at 10M rows (docs/specs/audit-list-keyset.md §1).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

func (c *anomalySQLCapture) reset() {
	c.mu.Lock()
	c.stmt = nil
	c.mu.Unlock()
}

const auditPlanRows = 3000

type auditPlanWorld struct {
	db  *gorm.DB
	ls  *LocalStorage
	cap *anomalySQLCapture
	pg  bool
}

// newAuditPlanWorld is audit_events (+ users, for the actor-name subquery)
// with the production index step applied and a few rows in it.
func newAuditPlanWorld(t *testing.T, pg bool) *auditPlanWorld {
	t.Helper()
	cap := &anomalySQLCapture{Interface: logger.Discard}
	var db *gorm.DB
	var err error
	if pg {
		// Its own database, not a schema: the index build takes the
		// database-wide audit index build lock, which other packages' tests
		// take too when they run at the same time (#3295).
		db, err = gorm.Open(postgres.Open(pgdsn.IsolatedDatabase(t, pgTestDSN(t), "store_audit_plan")), &gorm.Config{Logger: cap})
		require.NoError(t, err)
		t.Cleanup(func() {
			if sqlDB, e := db.DB(); e == nil {
				_ = sqlDB.Close()
			}
		})
	} else {
		db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: cap})
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))
	if pg {
		sqlDB, err := db.DB()
		require.NoError(t, err)
		require.NoError(t, BuildAuditListIndexesPostgres(context.Background(), sqlDB, false, t.Logf))
	} else {
		require.NoError(t, EnsureAuditListIndexesSQLite(db, t.Logf))
	}
	// A month of events, one every 15 minutes, ids in time order: enough rows
	// that a time window is a real range of the table, so the planner's choice
	// between the indexes reflects the query shape, not a tie on a toy table.
	base := time.Now().UTC().Add(-auditPlanRows * 15 * time.Minute)
	rows := make([]*models.AuditEvent, 0, auditPlanRows)
	for i := range auditPlanRows {
		// 50 projects and 300 secrets: one project or secret is a small slice of
		// the table, as in a real deployment, so its composite is the cheaper plan.
		p, s, m := uint(1+i%50), uint(1+i%300), uint(1+i%20)
		ok := i%4 != 0
		rows = append(rows, &models.AuditEvent{
			EventType: "secret.read", ProjectID: &p, SecretNodeID: &s, MachineIdentityID: &m,
			IPAddress: "203.0.113.7", Success: &ok, EventTime: base.Add(time.Duration(i) * 15 * time.Minute),
		})
	}
	require.NoError(t, db.CreateInBatches(rows, 500).Error)
	if pg {
		require.NoError(t, db.Exec("ANALYZE audit_events").Error)
	}
	return &auditPlanWorld{db: db, ls: NewLocalStorage(db), cap: cap, pg: pg}
}

func (w *auditPlanWorld) explain(t *testing.T, sql string) string {
	t.Helper()
	if !w.pg {
		return explainSQLite(t, w.db, sql)
	}
	var lines []string
	require.NoError(t, w.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL enable_seqscan = off").Error; err != nil {
			return err
		}
		if err := tx.Exec("SET LOCAL enable_bitmapscan = off").Error; err != nil {
			return err
		}
		rows, err := tx.Raw("EXPLAIN " + sql).Rows()
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			lines = append(lines, line)
		}
		return rows.Err()
	}))
	return strings.Join(lines, "\n")
}

// requireIndexServed: the plan uses index and never sorts the matching rows.
// A Postgres Incremental Sort (the id tie-break within one event_time on a
// two-column composite) is allowed; a full Sort is not.
func (w *auditPlanWorld) requireIndexServed(t *testing.T, name, sql, index string) {
	t.Helper()
	plan := w.explain(t, sql)
	require.Contains(t, plan, index, "%s must use %s\nSQL: %s\nplan:\n%s", name, index, sql, plan)
	if !w.pg {
		require.NotContains(t, plan, "TEMP B-TREE", "%s sorts in a temp b-tree\nSQL: %s\nplan:\n%s", name, sql, plan)
		return
	}
	for line := range strings.SplitSeq(plan, "\n") {
		// A plan node reads "Sort  (cost=..."; its "Sort Key: ..." detail line
		// belongs to whichever sort node (Incremental Sort included) owns it.
		node := strings.TrimLeft(line, " ->")
		require.False(t, strings.HasPrefix(node, "Sort  ("), "%s has a full Sort node\nSQL: %s\nplan:\n%s", name, sql, plan)
	}
}

func runAuditListPlanCases(t *testing.T, pg bool) {
	w := newAuditPlanWorld(t, pg)
	ctx := context.Background()
	u := func(v uint) *uint { return &v }
	str := func(v string) *string { return &v }
	f := false
	now := time.Now().UTC()
	weekAgo := now.Add(-7 * 24 * time.Hour)
	cursor := &storage.AuditCursor{EventTime: now.Add(-15 * 24 * time.Hour), ID: 1500}

	const (
		timeIdx    = "idx_audit_events_event_time_id"
		projectIdx = "idx_audit_events_project_event_time"
		secretIdx  = "idx_audit_events_secret_event_time"
	)
	pkIdx := "INTEGER PRIMARY KEY"
	if pg {
		pkIdx = "audit_events_pkey"
	}

	// Newest-first reads: the page statement (ORDER BY event_time DESC, id DESC).
	newestFirst := []struct {
		name   string
		filter storage.AuditFilter
		index  string
	}{
		{"logs page 1", storage.AuditFilter{}, timeIdx},
		{"logs page 3 (offset)", storage.AuditFilter{Page: 3, PageSize: 10}, timeIdx},
		{"logs cursor page", storage.AuditFilter{Before: cursor}, timeIdx},
		{"logs project_id", storage.AuditFilter{ProjectID: u(2)}, projectIdx},
		{"logs project_id cursor page", storage.AuditFilter{ProjectID: u(2), Before: cursor}, projectIdx},
		{"logs / search secret_id (per-secret trail)", storage.AuditFilter{SecretID: u(3)}, secretIdx},
		{"secret_id cursor page", storage.AuditFilter{SecretID: u(3), Before: cursor}, secretIdx},
		{"time window", storage.AuditFilter{StartTime: &weekAgo, EndTime: &now}, timeIdx},
		{"action", storage.AuditFilter{Action: str("secret.read")}, timeIdx},
		{"user_id", storage.AuditFilter{UserID: u(7)}, timeIdx},
		{"actor_type", storage.AuditFilter{ActorType: str("machine_identity")}, timeIdx},
		{"search actor name", storage.AuditFilter{ActorUsername: str("ali")}, timeIdx},
		{"search ip", storage.AuditFilter{IPAddress: str("203.0.113.7")}, timeIdx},
		{"search success=false", storage.AuditFilter{Success: &f}, timeIdx},
		{"search resource_type", storage.AuditFilter{ResourceType: str("secret")}, timeIdx},
		{"export.csv batch (since/until, cursor)", storage.AuditFilter{StartTime: &weekAgo, EndTime: &now, Before: cursor, Count: storage.AuditCountNone}, timeIdx},
		{"export.csv batch (project)", storage.AuditFilter{ProjectID: u(1), Before: cursor, Count: storage.AuditCountNone}, projectIdx},
	}
	for _, c := range newestFirst {
		c.filter.Count = storage.AuditCountCapped
		w.cap.reset()
		_, _, err := w.ls.GetAuditLogs(ctx, &c.filter)
		require.NoError(t, err, c.name)
		w.requireIndexServed(t, c.name, w.cap.find(t, "ORDER BY event_time DESC, id DESC"), c.index)
	}

	// The bounded count of a filter with its own index uses that index (an
	// unfiltered one is a LIMIT over any scan, bounded by the cap either way).
	w.cap.reset()
	_, _, err := w.ls.GetAuditLogs(ctx, &storage.AuditFilter{ProjectID: u(2), Count: storage.AuditCountCapped})
	require.NoError(t, err)
	w.requireIndexServed(t, "capped count, project_id", w.cap.find(t, "count(*)", "capped"), projectIdx)

	// SIEM export with since: the start id comes from the time index, the page
	// is a primary-key range.
	w.cap.reset()
	_, _, err = w.ls.GetAuditLogs(ctx, &storage.AuditFilter{Ascending: true, StartTime: &weekAgo, PageSize: 100, Count: storage.AuditCountNone})
	require.NoError(t, err)
	w.requireIndexServed(t, "export since: MIN(id) over event_time >= since", w.cap.find(t, "MIN(id + 0)"), timeIdx)
	w.requireIndexServed(t, "export since: page", w.cap.find(t, "id >=", "ORDER BY id ASC"), pkIdx)

	// No exact COUNT(*) over the filter unless asked: capped and none modes
	// never issue a bare count.
	for _, mode := range []storage.AuditCountMode{storage.AuditCountCapped, storage.AuditCountNone} {
		w.cap.reset()
		_, _, err := w.ls.GetAuditLogs(ctx, &storage.AuditFilter{Action: str("secret.read"), Count: mode})
		require.NoError(t, err)
		w.cap.mu.Lock()
		for _, s := range w.cap.stmt {
			if strings.Contains(strings.ToLower(s), "count(") {
				require.Contains(t, s, "capped", "mode %d issued an unbounded count: %s", mode, s)
			}
		}
		w.cap.mu.Unlock()
	}
}

func TestAuditListQueries_UseTheirIndexes_SQLite(t *testing.T) { runAuditListPlanCases(t, false) }

func TestAuditListQueries_UseTheirIndexes_Postgres(t *testing.T) { runAuditListPlanCases(t, true) }

// TestGetAuditLogs_CappedCount: exact up to the cap, cap+1 above it.
func TestGetAuditLogs_CappedCount(t *testing.T) {
	w := newAuditPlanWorld(t, false)
	ctx := context.Background()
	_, n, err := w.ls.GetAuditLogs(ctx, &storage.AuditFilter{Count: storage.AuditCountCapped})
	require.NoError(t, err)
	require.EqualValues(t, auditPlanRows, n, "below the cap the capped count is exact")

	// Above the cap: insert cap rows in one statement.
	require.NoError(t, w.db.Exec(`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < ?)
		INSERT INTO audit_events (event_type, event_time) SELECT 'secret.read', ? FROM seq`, storage.AuditCountCap, time.Now().UTC()).Error)
	_, n, err = w.ls.GetAuditLogs(ctx, &storage.AuditFilter{Count: storage.AuditCountCapped})
	require.NoError(t, err)
	require.EqualValues(t, storage.AuditCountCap+1, n, "above the cap the count stops at cap+1")
	_, n, err = w.ls.GetAuditLogs(ctx, &storage.AuditFilter{})
	require.NoError(t, err)
	require.EqualValues(t, storage.AuditCountCap+auditPlanRows, n, "the default stays the exact count")
	_, n, err = w.ls.GetAuditLogs(ctx, &storage.AuditFilter{Count: storage.AuditCountNone})
	require.NoError(t, err)
	require.Zero(t, n)
}
