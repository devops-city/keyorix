// concurrency_access_review_campaign_close_test.go — regression coverage for #343
// (extends the still-unfixed #237): a campaign force-close racing a concurrent item
// decision must not land a fresh decision into a campaign whose evidence snapshot was
// supposed to be frozen at close time, and the close transition itself must be atomic.
package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateAccessReviewItem_RejectsWhenCampaignClosedConcurrently deterministically
// reproduces the #343 exploit trace at the layer where the guarantee actually lives:
// DecideAccessReviewItem's own pre-check (item pending, campaign open) is a plain
// read, so a concurrent force-close can land BETWEEN that read and the persist. This
// simulates exactly that window — the campaign closes after the "read" but before the
// persist — and asserts the persist itself (not the earlier in-memory pre-check)
// rejects it: the campaign is the frozen source of truth, so "closed" wins over a
// decision racing through the same instant.
func TestUpdateAccessReviewItem_RejectsWhenCampaignClosedConcurrently(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	campaign := &models.AccessReviewCampaign{ProjectID: 1, Name: "race", State: accessReviewCampaignOpen}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "role", Source: "role", Decision: accessReviewItemPending}
	require.NoError(t, db.Create(item).Error)

	// A reviewer's DecideAccessReviewItem call has already read the item (pending)
	// and the campaign (open) at this point, and is about to persist an "attest".

	// A concurrent force-close lands first and commits.
	require.NoError(t, db.Model(&models.AccessReviewCampaign{}).
		Where("id = ?", campaign.ID).
		Update("state", "closed").Error)

	// The reviewer's decision, computed against the now-stale "open" read, attempts
	// to persist. It must be rejected — not silently applied to a frozen campaign.
	decided := &models.AccessReviewItem{ID: item.ID, CampaignID: campaign.ID, PrincipalType: "role", Source: "role", Decision: "attested"}
	ok, err := ls.UpdateAccessReviewItem(ctx, decided)
	require.NoError(t, err, "a lost race is reported via the bool, not an error")
	assert.False(t, ok, "a decision racing a concurrent close must be rejected — closed means frozen")

	var got models.AccessReviewItem
	require.NoError(t, db.First(&got, item.ID).Error)
	assert.Equal(t, accessReviewItemPending, got.Decision, "the item must remain untouched — no decision lands into a closed campaign")
}

// TestUpdateAccessReviewItem_SucceedsWhileCampaignOpen is the control case: with no
// racing close, a decision on a pending item in an open campaign still persists
// normally (the new campaign-open condition must not be a false-positive block).
func TestUpdateAccessReviewItem_SucceedsWhileCampaignOpen(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	campaign := &models.AccessReviewCampaign{ProjectID: 1, Name: "no-race", State: accessReviewCampaignOpen}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "role", Source: "role", Decision: accessReviewItemPending}
	require.NoError(t, db.Create(item).Error)

	decided := &models.AccessReviewItem{ID: item.ID, CampaignID: campaign.ID, PrincipalType: "role", Source: "role", Decision: "attested"}
	ok, err := ls.UpdateAccessReviewItem(ctx, decided)
	require.NoError(t, err)
	assert.True(t, ok, "a decision against a still-open campaign must succeed")

	var got models.AccessReviewItem
	require.NoError(t, db.First(&got, item.ID).Error)
	assert.Equal(t, "attested", got.Decision)
}

// TestConcurrency_UpdateAccessReviewCampaign_OnlyOneCloseWins drives real concurrent
// close attempts (file-backed SQLite, WAL, genuine multi-connection contention)
// against the SAME open campaign and asserts the conditional UPDATE lets exactly one
// win — the close-transition analogue of #319's item-level guarantee.
func TestConcurrency_UpdateAccessReviewCampaign_OnlyOneCloseWins(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}))
	ls := NewLocalStorage(db)

	campaign := &models.AccessReviewCampaign{ProjectID: 1, Name: "double-close", State: accessReviewCampaignOpen}
	require.NoError(t, db.Create(campaign).Error)

	const racers = 32
	var succeeded atomic.Int64
	errs := make(chan error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		closerID := uint(200 + i)
		go func(closerID uint) {
			defer wg.Done()
			<-start
			candidate := &models.AccessReviewCampaign{ID: campaign.ID, ProjectID: 1, Name: "double-close", State: "closed", ClosedBy: closerID}
			ok, err := ls.UpdateAccessReviewCampaign(context.Background(), candidate)
			if err != nil {
				errs <- err
				return
			}
			if ok {
				succeeded.Add(1)
			}
		}(closerID)
	}
	close(start) // release every racer at once
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, int64(1), succeeded.Load(), "exactly one concurrent close may win — never zero, never more than one")

	var got models.AccessReviewCampaign
	require.NoError(t, db.First(&got, campaign.ID).Error)
	assert.Equal(t, "closed", got.State, "the winning close must have been persisted")
}
