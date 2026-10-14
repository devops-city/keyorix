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

// TestUpdateAccessReviewItem_RejectsSecondDecision proves UpdateAccessReviewItem is a
// conditional UPDATE (`WHERE decision = 'pending'`), not the prior unconditional Save:
// once an item has been decided, a second call attempting a DIFFERENT decision must be
// rejected (ok == false, item unchanged) rather than silently overwriting it — the
// exact "revoke persisted, then attest overwrites it" corruption in #319.
func TestUpdateAccessReviewItem_RejectsSecondDecision(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	campaign := &models.AccessReviewCampaign{State: accessReviewCampaignOpen}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "role", Source: "role", Decision: "pending"}
	require.NoError(t, db.Create(item).Error)

	// Call 1: revoke really "wins" the decision.
	item.Decision = "revoked"
	ok, err := ls.UpdateAccessReviewItem(ctx, item)
	require.NoError(t, err)
	assert.True(t, ok, "the first decision on a pending item must succeed")

	// Call 2: a later/racing attest must NOT silently overwrite the persisted revoke.
	overwrite := &models.AccessReviewItem{ID: item.ID, CampaignID: campaign.ID, PrincipalType: "role", Source: "role", Decision: "attested"}
	ok, err = ls.UpdateAccessReviewItem(ctx, overwrite)
	require.NoError(t, err, "a lost race is reported via the bool, not an error")
	assert.False(t, ok, "a second decision on an already-decided item must be rejected")

	var got models.AccessReviewItem
	require.NoError(t, db.First(&got, item.ID).Error)
	assert.Equal(t, "revoked", got.Decision, "the original decision must survive untouched — no silent overwrite")
}

// TestConcurrency_AccessReviewItem_OnlyOneDecisionWins drives real concurrent decisions
// (file-backed SQLite, WAL, genuine multi-connection contention) against the SAME
// pending item and asserts the conditional UPDATE lets exactly one of them win — never
// zero (a would-be deadlock/starvation bug) and never more than one (the #319
// corruption: two decisions both "succeeding" and the later silently clobbering the
// earlier one).
func TestConcurrency_AccessReviewItem_OnlyOneDecisionWins(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}))
	ls := NewLocalStorage(db)

	campaign := &models.AccessReviewCampaign{State: accessReviewCampaignOpen}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "role", Source: "role", Decision: "pending"}
	require.NoError(t, db.Create(item).Error)

	const racers = 32
	var succeeded atomic.Int64
	errs := make(chan error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		decision := "attested"
		if i%2 == 0 {
			decision = "revoked"
		}
		go func(decision string) {
			defer wg.Done()
			<-start
			candidate := &models.AccessReviewItem{ID: item.ID, CampaignID: campaign.ID, PrincipalType: "role", Source: "role", Decision: decision}
			ok, err := ls.UpdateAccessReviewItem(context.Background(), candidate)
			if err != nil {
				errs <- err
				return
			}
			if ok {
				succeeded.Add(1)
			}
		}(decision)
	}
	close(start) // release every racer at once
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, int64(1), succeeded.Load(), "exactly one concurrent decision may win — never zero, never more than one")

	var got models.AccessReviewItem
	require.NoError(t, db.First(&got, item.ID).Error)
	assert.NotEqual(t, "pending", got.Decision, "the winning decision must have been persisted")
}
