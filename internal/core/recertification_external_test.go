package core_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func hasOpenCampaign(campaigns []*core.CampaignWithProgress) bool {
	for _, c := range campaigns {
		if c.Campaign.State == core.CampaignStateOpen {
			return true
		}
	}
	return false
}

// A never-reviewed project with an admin gets one reminder; a second run does not
// re-notify (the admin still holds an unread one).
func TestRunScheduledRecertification_RemindsAndDedupes(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)
	require.NoError(t, h.DB.AutoMigrate(&models.Notification{}))

	ctx := context.Background()
	h.CreateTestUser(t, "carol", 20)
	h.AssignUserRole(t, 20, 2, uptr(2)) // admin on project 2 (role 2 = "admin")

	res, err := h.CoreService.RunScheduledRecertification(ctx, 90, false)
	require.NoError(t, err)
	assert.Equal(t, 0, res.Opened, "auto_open off → nothing opened")
	assert.GreaterOrEqual(t, res.Reminded, 1, "project 2's admin is reminded")

	// The admin holds an unread recertification reminder for project 2.
	notes, err := h.CoreService.Storage().ListNotifications(ctx, 20, true, 100)
	require.NoError(t, err)
	found := false
	for _, n := range notes {
		if n.Type == core.NotificationRecertificationDue && n.ProjectID != nil && *n.ProjectID == 2 {
			found = true
		}
	}
	assert.True(t, found, "carol has an unread recertification reminder for project 2")

	res2, err := h.CoreService.RunScheduledRecertification(ctx, 90, false)
	require.NoError(t, err)
	assert.Equal(t, 0, res2.Reminded, "an unread reminder suppresses a duplicate")
}

// With auto_open on, an overdue project (last campaign closed > cadence ago) gets a
// fresh open campaign, while a recently-reviewed project does not.
func TestRunScheduledRecertification_AutoOpensOverdueNotRecent(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)
	require.NoError(t, h.DB.AutoMigrate(&models.Notification{}))

	ctx := context.Background()
	now := time.Now()
	oldClosed := now.AddDate(0, 0, -200)   // overdue under a 90-day cadence
	recentClosed := now.AddDate(0, 0, -10) // within the cadence

	require.NoError(t, h.DB.Create(&models.AccessReviewCampaign{
		ProjectID: 2, Name: "old", State: core.CampaignStateClosed, ClosedAt: &oldClosed,
	}).Error)
	require.NoError(t, h.DB.Create(&models.AccessReviewCampaign{
		ProjectID: 3, Name: "recent", State: core.CampaignStateClosed, ClosedAt: &recentClosed,
	}).Error)

	res, err := h.CoreService.RunScheduledRecertification(ctx, 90, true)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, res.Opened, 1)

	camps2, err := h.CoreService.ListAccessReviewCampaigns(ctx, 2)
	require.NoError(t, err)
	assert.True(t, hasOpenCampaign(camps2), "overdue project 2 gets a fresh open campaign")

	camps3, err := h.CoreService.ListAccessReviewCampaigns(ctx, 3)
	require.NoError(t, err)
	assert.False(t, hasOpenCampaign(camps3), "recently-reviewed project 3 is left alone")
}

// #237: a campaign that was force-closed with pending items (ForcedIncomplete) must
// not let a recent ClosedAt hide how stale the review actually is — the cadence
// anchors to when the campaign was OPENED, not when it was hastily closed. A
// genuinely completed close (ForcedIncomplete=false) with the same old open time but
// a recent close is, by contrast, a real completed review and must NOT be due.
func TestRunScheduledRecertification_ForcedIncompleteAnchorsToOpenTime(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)
	require.NoError(t, h.DB.AutoMigrate(&models.Notification{}))

	ctx := context.Background()
	now := time.Now()
	openedLongAgo := now.AddDate(0, 0, -200) // opened well outside a 90-day cadence
	closedRecently := now.AddDate(0, 0, -5)  // but closed just now

	// Project 2: opened long ago, force-closed recently while items were still
	// pending — an abandoned/rushed cycle. Despite the recent ClosedAt, it must
	// still be treated as overdue.
	require.NoError(t, h.DB.Create(&models.AccessReviewCampaign{
		ProjectID: 2, Name: "abandoned", State: core.CampaignStateClosed,
		CreatedAt: openedLongAgo, ClosedAt: &closedRecently, ForcedIncomplete: true,
	}).Error)

	// Project 3: same open/close timestamps, but every item was actually decided
	// (ForcedIncomplete=false) — a genuine, if belated, completed review. The
	// recent ClosedAt legitimately resets the cadence clock.
	require.NoError(t, h.DB.Create(&models.AccessReviewCampaign{
		ProjectID: 3, Name: "completed", State: core.CampaignStateClosed,
		CreatedAt: openedLongAgo, ClosedAt: &closedRecently, ForcedIncomplete: false,
	}).Error)

	res, err := h.CoreService.RunScheduledRecertification(ctx, 90, true)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, res.Opened, 1)

	camps2, err := h.CoreService.ListAccessReviewCampaigns(ctx, 2)
	require.NoError(t, err)
	assert.True(t, hasOpenCampaign(camps2), "an abandoned force-close doesn't hide behind a recent ClosedAt")

	camps3, err := h.CoreService.ListAccessReviewCampaigns(ctx, 3)
	require.NoError(t, err)
	assert.False(t, hasOpenCampaign(camps3), "a genuinely completed close resets the cadence clock at ClosedAt")
}

// queryCounter tallies the SELECT queries GORM executes against each table, via the
// same "gorm:query" callback hook GORM itself uses to run queries — a precise,
// non-flaky substitute for a timing-based assertion.
type queryCounter struct {
	mu      sync.Mutex
	byTable map[string]int
}

func attachQueryCounter(t *testing.T, db *gorm.DB) *queryCounter {
	qc := &queryCounter{byTable: map[string]int{}}
	err := db.Callback().Query().After("gorm:query").Register("test:count_queries", func(tx *gorm.DB) {
		qc.mu.Lock()
		defer qc.mu.Unlock()
		table := ""
		if tx.Statement != nil {
			table = tx.Statement.Table
		}
		qc.byTable[table]++
	})
	require.NoError(t, err)
	return qc
}

func (qc *queryCounter) count(table string) int {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	return qc.byTable[table]
}

// #238: RunScheduledRecertification used to fetch a project's ENTIRE historical
// campaign+item corpus (ListAccessReviewCampaigns, then ListAccessReviewItems for
// EVERY campaign returned) on every scheduler tick, for every project — cost that
// grew unboundedly with a deployment's accumulated campaign history rather than with
// what a tick actually needs to decide. This proves the fixed tick's campaign lookup
// executes the same number of queries against access_review_campaigns/
// access_review_items whether a project has 5 or 100 historical (closed) campaigns —
// a query COUNT assertion, not a timing one, so it can't flake under load.
func TestRunScheduledRecertification_CampaignQueryCostDoesNotScaleWithHistory(t *testing.T) {
	t.Parallel()
	runTickAndCountCampaignQueries := func(historicalCampaigns int) (campaignQueries, itemQueries int) {
		h := testhelper.NewRBACTestHelper(t)
		defer h.Cleanup()
		migrateCampaignTables(t, h)
		require.NoError(t, h.DB.AutoMigrate(&models.Notification{}))

		ctx := context.Background()
		now := time.Now()

		// A pile of ancient, irrelevant history for project 2 — the deeper past a
		// correctly-scoped scheduler tick has no reason to ever reload.
		for i := range historicalCampaigns {
			closedAt := now.AddDate(0, 0, -1000-i)
			require.NoError(t, h.DB.Create(&models.AccessReviewCampaign{
				ProjectID: 2, Name: fmt.Sprintf("historical-%d", i),
				State: core.CampaignStateClosed, CreatedAt: closedAt, ClosedAt: &closedAt,
			}).Error)
		}
		// The one campaign that's actually relevant to this tick's decision: recent
		// enough that project 2 is not overdue.
		recent := now.AddDate(0, 0, -10)
		require.NoError(t, h.DB.Create(&models.AccessReviewCampaign{
			ProjectID: 2, Name: "recent", State: core.CampaignStateClosed,
			CreatedAt: recent, ClosedAt: &recent,
		}).Error)

		qc := attachQueryCounter(t, h.DB)
		_, err := h.CoreService.RunScheduledRecertification(ctx, 90, true)
		require.NoError(t, err)
		return qc.count("access_review_campaigns"), qc.count("access_review_items")
	}

	smallCampaignQueries, smallItemQueries := runTickAndCountCampaignQueries(5)
	largeCampaignQueries, largeItemQueries := runTickAndCountCampaignQueries(100)

	assert.Equal(t, smallCampaignQueries, largeCampaignQueries,
		"campaign-table query count must not scale with a project's historical campaign count")
	assert.Equal(t, smallItemQueries, largeItemQueries,
		"item-table query count must not scale with a project's historical campaign count")

	// 3 seeded projects x 2 targeted single-row lookups each (GetOpenAccessReviewCampaign
	// + GetLatestClosedAccessReviewCampaign) = 6 — not the old N+1 shape, where the
	// campaign-table query count would stay small but the item-table query count
	// would grow by one per historical campaign returned.
	assert.Equal(t, 6, smallCampaignQueries, "expected exactly two targeted campaign lookups per project")
	assert.Equal(t, 0, smallItemQueries, "no open campaign exists, so no item query should run at all")
}
