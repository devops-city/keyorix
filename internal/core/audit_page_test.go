package core

// audit_page_test.go — ListAuditPage over a real LocalStorage on SQLite and
// Postgres (docs/specs/audit-list-keyset.md §5.2–5.4): a cursor walk returns
// every row exactly once in (event_time DESC, id DESC) order, including rows
// that share a timestamp and rows inserted while the walk runs; the offset cap
// and malformed cursors are refused; totals are capped unless asked for.

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

type auditPageWorld struct {
	db *gorm.DB
	c  *KeyorixCore
}

func newAuditPageWorld(t *testing.T, pg bool) *auditPageWorld {
	t.Helper()
	var db *gorm.DB
	if pg {
		// Its own database, not a schema: the index build below takes the
		// database-wide audit index build lock, which other packages' tests
		// take too when they run at the same time (#3295).
		db = pgOpen(t, pgdsn.IsolatedDatabase(t, pgTestDSN(t), "core_audit_page"))
	} else {
		var err error
		db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	if pg {
		sqlDB, err := db.DB()
		require.NoError(t, err)
		require.NoError(t, store.BuildAuditListIndexesPostgres(context.Background(), sqlDB, false, t.Logf))
	} else {
		require.NoError(t, store.EnsureAuditListIndexesSQLite(db, t.Logf))
	}
	return &auditPageWorld{db: db, c: &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}}
}

func (w *auditPageWorld) insert(t *testing.T, at time.Time, project uint) uint {
	t.Helper()
	e := &models.AuditEvent{EventType: "secret.read", EventTime: at, ProjectID: &project}
	require.NoError(t, w.db.Create(e).Error)
	return e.ID
}

// orderedIDs is the reference order: one read of the whole table.
func (w *auditPageWorld) orderedIDs(t *testing.T, project *uint) []uint {
	t.Helper()
	q := w.db.Model(&models.AuditEvent{})
	if project != nil {
		q = q.Where("project_id = ?", *project)
	}
	var ids []uint
	require.NoError(t, q.Order("event_time DESC, id DESC").Pluck("id", &ids).Error)
	return ids
}

// walk pages through ListAuditPage: the first page by offset, then by cursor
// until next_cursor is empty. between runs after every page.
func (w *auditPageWorld) walk(t *testing.T, filter storage.AuditFilter, limit int, between func()) []uint {
	t.Helper()
	var ids []uint
	cursor := ""
	for range 10_000 {
		page, err := w.c.ListAuditPage(context.Background(), AuditPageRequest{Filter: filter, Limit: limit, Cursor: cursor})
		require.NoError(t, err)
		require.LessOrEqual(t, len(page.Events), limit)
		for _, e := range page.Events {
			ids = append(ids, e.ID)
		}
		if page.NextCursor == "" {
			return ids
		}
		require.NotEmpty(t, page.Events, "a page with a next cursor has rows")
		cursor = page.NextCursor
		if between != nil {
			between()
		}
	}
	t.Fatal("walk did not terminate")
	return nil
}

func runAuditPageCursorCases(t *testing.T, pg bool) {
	t.Run("equal timestamps: no gap, no duplicate, at every page size", func(t *testing.T) {
		w := newAuditPageWorld(t, pg)
		// Three timestamps with sub-microsecond parts (SQLite keeps them;
		// Postgres rounds to the microsecond), 250 rows inserted in random
		// time order, so id order and time order disagree.
		base := time.Now().UTC().Truncate(time.Second)
		stamps := []time.Time{base.Add(123456789), base.Add(-time.Minute + 5), base.Add(-time.Hour + 999)}
		r := rand.New(rand.NewPCG(1, 2))
		for i := range 250 {
			w.insert(t, stamps[r.IntN(len(stamps))], uint(1+i%2))
		}
		want := w.orderedIDs(t, nil)
		for _, size := range []int{1, 7, 50} {
			require.Equal(t, want, w.walk(t, storage.AuditFilter{}, size, nil), "page size %d", size)
		}
		p := uint(2)
		require.Equal(t, w.orderedIDs(t, &p), w.walk(t, storage.AuditFilter{ProjectID: &p}, 7, nil), "project filter")
	})

	t.Run("rows inserted during the walk: none repeats, older ones are found, newer ones are not", func(t *testing.T) {
		w := newAuditPageWorld(t, pg)
		base := time.Now().UTC().Add(-time.Hour)
		for i := range 60 {
			w.insert(t, base.Add(time.Duration(i)*time.Second), 1)
		}
		initial := w.orderedIDs(t, nil)
		var older, newer []uint
		n := 0
		got := w.walk(t, storage.AuditFilter{}, 7, func() {
			n++
			// One row newer than everything (above the walk's position) and
			// one older than everything (below it).
			newer = append(newer, w.insert(t, time.Now().UTC().Add(time.Duration(n)*time.Millisecond), 1))
			older = append(older, w.insert(t, base.Add(-time.Duration(n)*time.Minute), 1))
		})
		seen := map[uint]int{}
		for _, id := range got {
			seen[id]++
			require.Equal(t, 1, seen[id], "id %d returned twice", id)
		}
		for _, id := range initial {
			require.Equal(t, 1, seen[id], "id %d present at the start was skipped", id)
		}
		for _, id := range older {
			require.Equal(t, 1, seen[id], "id %d inserted below the cursor was not returned", id)
		}
		for _, id := range newer {
			require.Zero(t, seen[id], "id %d inserted above the cursor was returned", id)
		}
	})

	t.Run("offset cap and malformed cursors", func(t *testing.T) {
		w := newAuditPageWorld(t, pg)
		w.insert(t, time.Now().UTC(), 1)
		ctx := context.Background()
		_, err := w.c.ListAuditPage(ctx, AuditPageRequest{Offset: AuditOffsetCap - 50, Limit: 50})
		require.NoError(t, err, "a page ending exactly at the cap is allowed")
		for _, off := range []int{AuditOffsetCap - 49, AuditOffsetCap, 1 << 40, -1} {
			_, err := w.c.ListAuditPage(ctx, AuditPageRequest{Offset: off, Limit: 50})
			require.ErrorIs(t, err, ErrAuditOffsetBeyondCap, "offset %d", off)
		}
		for _, bad := range []string{"x", "!!!", "djEuMS4w" /* v1.1.0: id 0 */, "djIuMS4x" /* v2 */, "djEuYS4x" /* non-numeric time */} {
			_, err := w.c.ListAuditPage(ctx, AuditPageRequest{Cursor: bad, Limit: 50})
			require.True(t, errors.Is(err, ErrInvalidAuditCursor), "cursor %q: %v", bad, err)
		}
	})

	t.Run("totals: capped by default, exact on request, none on cursor pages", func(t *testing.T) {
		w := newAuditPageWorld(t, pg)
		base := time.Now().UTC().Add(-time.Hour)
		for i := range 30 {
			w.insert(t, base.Add(time.Duration(i)*time.Second), 1)
		}
		ctx := context.Background()
		first, err := w.c.ListAuditPage(ctx, AuditPageRequest{Limit: 10})
		require.NoError(t, err)
		require.True(t, first.HasTotal)
		require.True(t, first.TotalExact)
		require.EqualValues(t, 30, first.Total)
		require.NotEmpty(t, first.NextCursor)

		last, err := w.c.ListAuditPage(ctx, AuditPageRequest{Offset: 20, Limit: 10})
		require.NoError(t, err)
		require.Len(t, last.Events, 10)
		require.Empty(t, last.NextCursor, "the last offset page has no next cursor")

		next, err := w.c.ListAuditPage(ctx, AuditPageRequest{Limit: 10, Cursor: first.NextCursor})
		require.NoError(t, err)
		require.False(t, next.HasTotal, "a cursor page runs no count")
		withTotal, err := w.c.ListAuditPage(ctx, AuditPageRequest{Limit: 10, Cursor: first.NextCursor, IncludeTotal: true})
		require.NoError(t, err)
		require.True(t, withTotal.HasTotal)
		require.True(t, withTotal.TotalExact)
		require.EqualValues(t, 30, withTotal.Total)
	})
}

func TestListAuditPage_SQLite(t *testing.T) { runAuditPageCursorCases(t, false) }

func TestListAuditPage_Postgres(t *testing.T) { runAuditPageCursorCases(t, true) }

// TestListAuditPage_TotalAboveTheCap: more matches than AuditOffsetCap reads
// as (AuditOffsetCap, not exact) with a next cursor, and include_total counts
// them all.
func TestListAuditPage_TotalAboveTheCap(t *testing.T) {
	w := newAuditPageWorld(t, false)
	require.NoError(t, w.db.Exec(`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < ?)
		INSERT INTO audit_events (event_type, event_time) SELECT 'secret.read', ? FROM seq`, AuditOffsetCap+5, time.Now().UTC()).Error)
	ctx := context.Background()
	page, err := w.c.ListAuditPage(ctx, AuditPageRequest{Offset: AuditOffsetCap - 100, Limit: 100})
	require.NoError(t, err)
	require.False(t, page.TotalExact)
	require.EqualValues(t, AuditOffsetCap, page.Total)
	require.NotEmpty(t, page.NextCursor, "the last reachable offset page still leads on by cursor")
	exact, err := w.c.ListAuditPage(ctx, AuditPageRequest{Limit: 100, IncludeTotal: true})
	require.NoError(t, err)
	require.True(t, exact.TotalExact)
	require.EqualValues(t, AuditOffsetCap+5, exact.Total)
}

func TestAuditCursor_RoundTripsTheRowPosition(t *testing.T) {
	at := time.Date(2026, 10, 14, 19, 47, 34, 10250001, time.UTC)
	cur, err := DecodeAuditCursor(EncodeAuditCursor(&models.AuditEvent{ID: 42, EventTime: at}))
	require.NoError(t, err)
	require.Equal(t, uint(42), cur.ID)
	require.True(t, cur.EventTime.Equal(at))
	require.Equal(t, time.UTC, cur.EventTime.Location(), "UTC, as stored (SQLite compares the text form)")
}

// The fixed message must agree with the cap it names.
func TestAuditOffsetCapMessage_NamesTheCap(t *testing.T) {
	require.Contains(t, AuditOffsetCapMessage, strconv.Itoa(AuditOffsetCap))
}

// TestListAuditPage_OffsetNearMaxIntIsRefused: Offset+Limit must not wrap. An
// offset just under math.MaxInt plus a limit used to overflow negative, pass
// the cap check and send a deep OFFSET to storage.
func TestListAuditPage_OffsetNearMaxIntIsRefused(t *testing.T) {
	w := newAuditPageWorld(t, false)
	w.insert(t, time.Now().UTC(), 1)
	ctx := context.Background()
	for _, req := range []AuditPageRequest{
		{Offset: math.MaxInt - 50, Limit: 100},
		{Offset: math.MaxInt, Limit: 1},
		{Offset: AuditOffsetCap, Limit: 1},
		{Offset: -1, Limit: 100},
		{Offset: 0, Limit: AuditOffsetCap + 1},
		{Offset: 0, Limit: math.MaxInt},
	} {
		_, err := w.c.ListAuditPage(ctx, req)
		require.ErrorIs(t, err, ErrAuditOffsetBeyondCap, "offset %d limit %d", req.Offset, req.Limit)
	}
	_, err := w.c.ListAuditPage(ctx, AuditPageRequest{Offset: AuditOffsetCap - 100, Limit: 100})
	require.NoError(t, err, "the last page inside the cap")
	// A cursor page with an absurd limit must not wrap Limit+1 either.
	page, err := w.c.ListAuditPage(ctx, AuditPageRequest{Limit: 10})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	_, err = w.c.ListAuditPage(ctx, AuditPageRequest{Limit: math.MaxInt, Cursor: EncodeAuditCursor(page.Events[0])})
	require.ErrorIs(t, err, ErrAuditOffsetBeyondCap)
}
