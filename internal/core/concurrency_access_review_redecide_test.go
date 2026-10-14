package core_test

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_DecideAccessReviewItem_OnlyOneDecisionWins drives the FULL
// DecideAccessReviewItem path (#319) — not just the storage layer — from many
// concurrent reviewers deciding the SAME pending item. DecideAccessReviewItem's own
// pending pre-check is a plain read, wide open to a race between the read and the
// eventual persist (the decision action itself runs in between); the guarantee this
// asserts is the one that actually matters end-to-end: exactly one decision is ever
// recorded and every other caller gets a clear rejection — never a silently
// overwritten compliance record, and never a panic or generic 500.
func TestConcurrency_DecideAccessReviewItem_OnlyOneDecisionWins(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "arc.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.AuditEvent{}, &models.UserRole{}, &models.GroupRole{}, &models.Group{}))

	const proj = uint(2)
	campaign := &models.AccessReviewCampaign{ProjectID: proj, Name: "race", State: core.CampaignStateOpen}
	require.NoError(t, db.Create(campaign).Error)
	// PrincipalType "role" (neither "user" nor "group") sidesteps the self-certification
	// checks, which aren't what this test is about. A real role assignment backs the
	// item so AttestAccessReviewGrant's live re-verification (#209) finds a genuine
	// grant to certify.
	require.NoError(t, db.Create(&models.UserRole{UserID: 999, RoleID: 1, ProjectID: proj}).Error)
	item := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "role", PrincipalID: 999, RoleID: 1, Source: "role", Decision: core.ReviewItemPending}
	require.NoError(t, db.Create(item).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	const reviewers = 24
	var succeeded atomic.Int64
	var rejected atomic.Int64
	unexpected := make(chan error, reviewers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range reviewers {
		wg.Add(1)
		actorID := uint(100 + i) // distinct attributable human reviewers, none is the item's principal
		go func(actorID uint) {
			defer wg.Done()
			<-start
			decErr := c.DecideAccessReviewItem(ctx, actorID, proj, campaign.ID, item.ID, "attest", "concurrent review")
			switch {
			case decErr == nil:
				succeeded.Add(1)
			case strings.Contains(decErr.Error(), "already been decided"):
				rejected.Add(1)
			default:
				unexpected <- decErr
			}
		}(actorID)
	}
	close(start) // release every reviewer at once
	wg.Wait()
	close(unexpected)
	for e := range unexpected {
		require.NoError(t, e, "every losing decision must fail with the clear 'already decided' error, nothing else")
	}

	assert.Equal(t, int64(1), succeeded.Load(), "exactly one concurrent decision may be recorded")
	assert.Equal(t, int64(reviewers-1), rejected.Load(), "every other concurrent decision must be rejected, not silently applied")

	var got models.AccessReviewItem
	require.NoError(t, db.First(&got, item.ID).Error)
	assert.Equal(t, core.ReviewItemAttested, got.Decision, "the single winning decision must be the one persisted")
}
