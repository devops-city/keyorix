// recover_admin_alert_scan_test.go — the recover_admin_alert job must read
// O(rows added since its last run), not O(audit_events) (AUDIT-SCAN-FIX-1).
//
// The job filters on event_type, which has no index. Its high-water mark used to
// advance only when an event matched, so an install that never used recover-admin
// re-walked the whole table every 10 minutes (and held a read snapshot while it
// did). These tests drive RunRecoverAdminAlerting against a large synthetic
// audit_events table and observe the statements it really issues: the id range
// bound into the list query and that query's plan.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"

	kxstorage "github.com/keyorixhq/keyorix/internal/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scanProbe records every SELECT against audit_events that filters on
// event_type (the job's list query) with its bound arguments.
type scanProbe struct {
	mu    sync.Mutex
	stmts []probedStmt
}

type probedStmt struct {
	sql  string
	vars []any
}

func (p *scanProbe) install(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Callback().Query().After("gorm:query").Register("scanprobe", func(tx *gorm.DB) {
		sql := tx.Statement.SQL.String()
		if !strings.HasPrefix(sql, "SELECT") || !strings.Contains(sql, "audit_events") || !strings.Contains(sql, "event_type") {
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.stmts = append(p.stmts, probedStmt{sql: sql, vars: append([]any(nil), tx.Statement.Vars...)})
	}))
}

func (p *scanProbe) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stmts = nil
}

func (p *scanProbe) snapshot() []probedStmt {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]probedStmt(nil), p.stmts...)
}

// numericVars returns the integer-valued bound arguments, in order. The list
// query binds (event_type, afterID, upToID, limit): the id range is the first
// two integers after the string.
func (s probedStmt) numericVars() []int64 {
	var out []int64
	for _, v := range s.vars {
		switch n := v.(type) {
		case uint:
			out = append(out, int64(n))
		case int:
			out = append(out, int64(n))
		case int64:
			out = append(out, n)
		}
	}
	return out
}

// bulkInsertAuditRows adds n audit rows of eventType in one statement.
func bulkInsertAuditRows(t *testing.T, db *gorm.DB, n int, eventType string) {
	t.Helper()
	if db.Dialector.Name() == "postgres" {
		require.NoError(t, db.Exec(
			`INSERT INTO audit_events (event_type, description, success, actor_type, event_time)
			 SELECT ?, 'synthetic', true, 'user', now() FROM generate_series(1, ?)`, eventType, n).Error)
		return
	}
	// SQLite has no generate_series: a recursive CTE yields the same n rows.
	require.NoError(t, db.Exec(
		`WITH RECURSIVE seq(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM seq WHERE i < ?)
		 INSERT INTO audit_events (event_type, description, success, actor_type, event_time)
		 SELECT ?, 'synthetic', 1, 'user', CURRENT_TIMESTAMP FROM seq`, n, eventType).Error)
}

// explainListQuery returns the query plan of a recorded list statement.
func explainListQuery(t *testing.T, db *gorm.DB, s probedStmt) string {
	t.Helper()
	var plan []string
	if db.Dialector.Name() == "postgres" {
		require.NoError(t, db.Raw("EXPLAIN "+s.sql, s.vars...).Scan(&plan).Error)
	} else {
		var rows []struct{ Detail string }
		require.NoError(t, db.Raw("EXPLAIN QUERY PLAN "+s.sql, s.vars...).Scan(&rows).Error)
		for _, r := range rows {
			plan = append(plan, r.Detail)
		}
	}
	return strings.Join(plan, "\n")
}

func runScanBoundedScenario(t *testing.T, db *gorm.DB, bigRows int) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SystemMetadata{}, &models.NotificationChannel{}))

	received := make(chan struct{}, 16)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.httpClient = &http.Client{Transport: &fakeWebhookTransport{called: received}}
	ctx := context.Background()
	require.NoError(t, db.Create(&models.NotificationChannel{
		Name: "ops-webhook", Type: "webhook", URLEnc: plaintextURLEnc("https://fake-webhook.test/hook"), Enabled: true,
	}).Error)

	probe := &scanProbe{}
	probe.install(t, db)

	mark := func() string {
		var m models.SystemMetadata
		if err := db.Where("key = ?", recoverAdminAlertHighWaterKey).Take(&m).Error; err != nil {
			return ""
		}
		return m.Value
	}
	maxID := func() int64 {
		var id int64
		require.NoError(t, db.Raw("SELECT COALESCE(MAX(id), 0) FROM audit_events").Scan(&id).Error)
		return id
	}

	// A large audit history that never used recover-admin.
	bulkInsertAuditRows(t, db, bigRows, "secret.read")
	big := maxID()
	require.EqualValues(t, bigRows, big)

	// Run 1: the one-off catch-up. Nothing matches, yet the mark must now sit at
	// the highest id examined, and the scan must be bounded by it.
	n, err := c.RunRecoverAdminAlerting(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, fmt.Sprint(big), mark(), "mark advances to the highest audit id examined even though nothing matched")
	// The catch-up walks the existing rows in short id windows (no long read
	// snapshot), each bounded on both sides and together covering (0, big].
	first := probe.snapshot()
	require.Len(t, first, (bigRows+recoverAdminAlertScanWindow-1)/recoverAdminAlertScanWindow)
	prev := int64(0)
	for _, s := range first {
		assert.Contains(t, s.sql, "id <=", "the scan is bounded above by the id read at job start")
		nums := s.numericVars()
		require.GreaterOrEqual(t, len(nums), 2, "bound args: %v", s.vars)
		assert.Equal(t, prev, nums[0], "windows are contiguous")
		assert.LessOrEqual(t, nums[1]-nums[0], int64(recoverAdminAlertScanWindow))
		prev = nums[1]
	}
	assert.Equal(t, big, prev, "the windows end at the highest id read at job start")

	// Run 2 with no new audit rows: no list query at all.
	probe.reset()
	n, err = c.RunRecoverAdminAlerting(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Empty(t, probe.snapshot(), "a run with no new audit rows reads no audit rows")

	// New traffic: 5 ordinary rows, one recover-admin use, 4 more ordinary rows.
	bulkInsertAuditRows(t, db, 5, "secret.read")
	bulkInsertAuditRows(t, db, 1, recoverAdminAuditEventType)
	bulkInsertAuditRows(t, db, 4, "secret.read")
	top := maxID()
	require.EqualValues(t, big+10, top)

	probe.reset()
	n, err = c.RunRecoverAdminAlerting(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the recover-admin use is alerted")
	assert.Len(t, received, 1, "exactly one webhook call for it")
	assert.Equal(t, fmt.Sprint(top), mark())

	second := probe.snapshot()
	require.Len(t, second, 1)
	nums := second[0].numericVars()
	require.GreaterOrEqual(t, len(nums), 2, "bound args: %v", second[0].vars)
	assert.Equal(t, []int64{big, top}, nums[:2],
		"the second run reads exactly the id range (previous mark, new max], i.e. the 10 new rows, not the %d old ones", bigRows)

	// The plan of that exact statement is a primary-key range with both bounds,
	// so the work is proportional to the 10 rows, not to the table.
	plan := explainListQuery(t, db, second[0])
	t.Logf("plan:\n%s", plan)
	if db.Dialector.Name() == "postgres" {
		assert.Contains(t, plan, "audit_events_pkey")
		assert.Contains(t, plan, "id >")
		assert.Contains(t, plan, "id <=")
		assert.NotContains(t, plan, "Seq Scan")
	} else {
		assert.Contains(t, plan, "USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)")
	}

	// And it is alerted once: the next run has nothing new.
	probe.reset()
	n, err = c.RunRecoverAdminAlerting(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Len(t, received, 1, "no duplicate alert on a later run or restart")
	assert.Empty(t, probe.snapshot())
}

func TestRunRecoverAdminAlerting_LargeAuditTable_SecondRunReadsOnlyNewRows(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	runScanBoundedScenario(t, db, 300_000)
}

func TestRunRecoverAdminAlerting_LargeAuditTable_SecondRunReadsOnlyNewRows_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgOpen(t, pgIsolatedSchemaDSN(t, base))
	require.NoError(t, kxstorage.MigrateExisting(db))
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	runScanBoundedScenario(t, db, 300_000)
}

// TestRunRecoverAdminAlerting_ManyUsesAcrossWindows_EachAlertedExactlyOnce: more
// recover-admin uses than one batch, spread over several scan windows, with
// ordinary rows between them. Across runs every use is alerted exactly once, in
// order, none skipped (the full-batch and window boundaries lose nothing).
func TestRunRecoverAdminAlerting_ManyUsesAcrossWindows_EachAlertedExactlyOnce(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SystemMetadata{}, &models.NotificationChannel{}))

	var mu sync.Mutex
	seen := map[uint]int{}
	tr := &fakeWebhookTransport{capture: func(body []byte) {
		var p struct {
			ID uint `json:"audit_event_id"`
		}
		require.NoError(t, json.Unmarshal(body, &p))
		mu.Lock()
		seen[p.ID]++
		mu.Unlock()
	}}
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.httpClient = &http.Client{Transport: tr}
	require.NoError(t, db.Create(&models.NotificationChannel{
		Name: "ops-webhook", Type: "webhook", URLEnc: plaintextURLEnc("https://fake-webhook.test/hook"), Enabled: true,
	}).Error)

	// 250 uses packed into one window (more than one batch of 200, so a batch is
	// full and the rest must wait for the next run), then 3 more separated by
	// ~150k ordinary rows (each in a later scan window).
	const dense, sparse = 250, 3
	const uses = dense + sparse
	for range dense {
		bulkInsertAuditRows(t, db, 5, "secret.read")
		bulkInsertAuditRows(t, db, 1, recoverAdminAuditEventType)
	}
	for range sparse {
		bulkInsertAuditRows(t, db, recoverAdminAlertScanWindow+recoverAdminAlertScanWindow/2, "secret.read")
		bulkInsertAuditRows(t, db, 1, recoverAdminAuditEventType)
	}

	ctx := context.Background()
	total := 0
	var counts []int
	for range 10 {
		n, err := c.RunRecoverAdminAlerting(ctx)
		require.NoError(t, err)
		counts = append(counts, n)
		total += n
		if n == 0 {
			break
		}
	}
	assert.Equal(t, uses, total, "runs: %v", counts)
	assert.Equal(t, 0, counts[len(counts)-1], "the last run finds nothing new: %v", counts)
	assert.Len(t, seen, uses, "every use alerted")
	for id, n := range seen {
		assert.Equal(t, 1, n, "audit event %d alerted %d times", id, n)
	}
}
