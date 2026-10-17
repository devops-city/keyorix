// local_access_activity_window_test.go — RECERT-BOUND-1 item 2/3: the
// LastUser*Activity lookups look back over the recertification period only.
// Boundary semantics run on SQLite here; the plan and rows-examined checks run on
// SQLite and, when KEYORIX_TEST_PG_DSN is set, on PostgreSQL
// (local_access_activity_window_postgres_test.go).
package store

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// activityLookups pairs each lookup with an event type it counts.
var activityLookups = []struct {
	name      string
	eventType string
	call      func(*LocalStorage, context.Context, uint, time.Time) (map[uint]time.Time, error)
}{
	{"LastUserSecretActivity", "secret.read", (*LocalStorage).LastUserSecretActivity},
	{"LastUserSecretReadActivity", "secret.read", (*LocalStorage).LastUserSecretReadActivity},
	{"LastUserSecretWriteActivity", "secret.updated", (*LocalStorage).LastUserSecretWriteActivity},
	{"LastUserRoleManagementActivity", "role.assigned", (*LocalStorage).LastUserRoleManagementActivity},
	{"LastUserSecretDeletionActivity", "secret.deleted", (*LocalStorage).LastUserSecretDeletionActivity},
}

// Period boundary: an event exactly at `since` is inside the window, one second
// older is outside, and a user whose only activity is outside is absent ("no
// activity within the review period"), not reported with an old timestamp.
func TestLastUserActivity_PeriodBoundary(t *testing.T) {
	ctx := context.Background()
	since := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	for _, lk := range activityLookups {
		t.Run(lk.name, func(t *testing.T) {
			ls := newAccessActivityStore(t)
			insertAuditEvent(t, ls, 1, 10, lk.eventType, since)                        // on the boundary: in
			insertAuditEvent(t, ls, 2, 10, lk.eventType, since.Add(-time.Second))      // one second too old: out
			insertAuditEvent(t, ls, 3, 10, lk.eventType, since.Add(time.Second))       // in
			insertAuditEvent(t, ls, 4, 10, lk.eventType, since.Add(-time.Hour))        // old...
			insertAuditEvent(t, ls, 4, 10, lk.eventType, since.Add(time.Hour))         // ...but also recent: the recent one
			insertAuditEvent(t, ls, 5, 10, lk.eventType, since.Add(-400*24*time.Hour)) // far too old: out

			got, err := lk.call(ls, ctx, 10, since)
			require.NoError(t, err)
			assert.Equal(t, since, got[1].UTC(), "an event exactly at the window start is inside it")
			assert.NotContains(t, got, uint(2), "an event one second before the window start is outside it")
			assert.Equal(t, since.Add(time.Second), got[3].UTC())
			assert.Equal(t, since.Add(time.Hour), got[4].UTC(), "the newest in-window event wins")
			assert.NotContains(t, got, uint(5), "activity older than the period is not 'last activity'")
			assert.Len(t, got, 3)
		})
	}
}

// The window never exceeds the hard maximum, whatever the caller passes: a zero
// or older `since` is raised to ActivityLookbackMaxDays.
func TestLastUserActivity_HardMaximum(t *testing.T) {
	ctx := context.Background()
	ls := newAccessActivityStore(t)
	now := time.Now().UTC()
	insertAuditEvent(t, ls, 1, 10, "secret.read", now.AddDate(0, 0, -(storage.ActivityLookbackMaxDays-5)))
	insertAuditEvent(t, ls, 2, 10, "secret.read", now.AddDate(0, 0, -(storage.ActivityLookbackMaxDays+5)))

	for name, since := range map[string]time.Time{
		"zero":        {},
		"ten years":   now.AddDate(-10, 0, 0),
		"max + 1 d":   now.AddDate(0, 0, -(storage.ActivityLookbackMaxDays + 1)),
		"exactly max": storage.ActivityLookbackSince(now, storage.ActivityLookbackMaxDays),
	} {
		got, err := ls.LastUserSecretActivity(ctx, 10, since)
		require.NoError(t, err, name)
		assert.Contains(t, got, uint(1), name)
		assert.NotContains(t, got, uint(2), "%s: an event older than the hard maximum must not be returned", name)
	}
}

func TestActivityLookbackDays(t *testing.T) {
	assert.Equal(t, storage.ActivityLookbackDefaultDays, storage.ActivityLookbackDays(0))
	assert.Equal(t, storage.ActivityLookbackDefaultDays, storage.ActivityLookbackDays(-7))
	assert.Equal(t, 30, storage.ActivityLookbackDays(30))
	assert.Equal(t, storage.ActivityLookbackMaxDays, storage.ActivityLookbackDays(storage.ActivityLookbackMaxDays))
	assert.Equal(t, storage.ActivityLookbackMaxDays, storage.ActivityLookbackDays(5000))
}

// ---- large audit table: the bounded plan ------------------------------------

const (
	bigOldRows      = 200_000 // older than any window
	bigNoiseRows    = 40_000  // other project, in window
	bigInWindowRows = 60      // the project under test, in window
	bigProject      = 7
)

// seedBigAuditTable fills audit_events with a long history of the project (older
// than the window), unrelated noise in another project, and a handful of in-window
// events for the project, then builds the list indexes the way the server does.
func seedBigAuditTable(t *testing.T, ls *LocalStorage, since time.Time) {
	t.Helper()
	const batch = 2000
	insert := func(n int, project uint, base time.Time, step time.Duration, eventType string) {
		rows := make([]models.AuditEvent, 0, batch)
		flush := func() {
			if len(rows) == 0 {
				return
			}
			require.NoError(t, ls.db.CreateInBatches(&rows, 500).Error)
			rows = rows[:0]
		}
		for i := range n {
			uid, pid := uint(1+i%25), project
			ok := true
			rows = append(rows, models.AuditEvent{
				EventType: eventType, UserID: &uid, ProjectID: &pid, Success: &ok,
				EventTime: base.Add(time.Duration(i) * step),
			})
			if len(rows) == batch {
				flush()
			}
		}
		flush()
	}
	insert(bigOldRows, bigProject, since.AddDate(-2, 0, 0), time.Minute, "secret.read")
	insert(bigNoiseRows, bigProject+1, since.Add(time.Hour), time.Second, "secret.read")
	insert(bigInWindowRows, bigProject, since.Add(2*time.Hour), time.Minute, "secret.read")
	require.NoError(t, EnsureAuditListIndexesSQLite(ls.db, t.Logf))
}

// lastActivitySQL is the SQL of the lookup with its bound values inlined, for EXPLAIN.
func lastActivitySQL(ls *LocalStorage, since time.Time) string {
	return ls.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		var rows []struct {
			UserID    uint
			EventTime time.Time
		}
		return lastActivityQuery(tx, bigProject, accessActivityEventTypes, since).Find(&rows)
	})
}

func TestLastUserActivity_SQLiteBoundedPlan(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a 240k-row audit table")
	}
	ctx := context.Background()
	ls := newAccessActivityStore(t)
	since := time.Now().UTC().AddDate(0, 0, -90).Truncate(time.Second)
	seedBigAuditTable(t, ls, since)

	got, err := ls.LastUserSecretActivity(ctx, bigProject, since)
	require.NoError(t, err)
	assert.Len(t, got, 25, "every user has in-window activity")
	for uid, at := range got {
		assert.False(t, at.Before(since), "user %d: %v is older than the window start %v", uid, at, since)
	}

	var plan []struct{ Detail string }
	require.NoError(t, ls.db.Raw("EXPLAIN QUERY PLAN "+lastActivitySQL(ls, since)).Scan(&plan).Error)
	var lines []string
	for _, p := range plan {
		lines = append(lines, p.Detail)
	}
	text := strings.Join(lines, "\n")
	t.Logf("plan:\n%s", text)
	assert.Contains(t, text, "USING INDEX idx_audit_events_project_event_time", "must use the existing (project_id, event_time) index")
	assert.Regexp(t, regexp.MustCompile(`project_id=\? AND event_time>`), text, "the index range must be bounded below by the window start")
	assert.NotRegexp(t, regexp.MustCompile(`SCAN audit_events( |$)`), text, "no full table scan")
}

// rowsExaminedLimit is the most rows any plan node may read for the lookup: the
// window's own rows plus slack, never the table.
func rowsExaminedLimit() int { return bigInWindowRows + 200 }
