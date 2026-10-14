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

// TestConcurrency_DecideAccessReviewItem_RejectsWhenRacingClose drives the FULL
// DecideAccessReviewItem and CloseAccessReviewCampaign paths (#343, extending #237) —
// not just the storage layer — with many concurrent reviewers deciding the SAME
// pending item racing against a concurrent force-close of the campaign. It proves the
// end-to-end guarantee: a decision can never land in a campaign that has already
// closed, and a close can never silently coexist with a decision that raced through
// the same instant undetected. Every outcome must be one of: exactly one decision
// succeeds (and the close either wins outright or loses to that legitimate decision,
// in which case it must be retried by a caller), or the close wins and every decision
// is cleanly rejected as "campaign is closed" — never a silent overwrite, panic, or
// generic 500.
func TestConcurrency_DecideAccessReviewItem_RejectsWhenRacingClose(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "arc-close-race.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.AuditEvent{}, &models.UserRole{}, &models.GroupRole{}, &models.Group{}))

	const proj = uint(2)
	campaign := &models.AccessReviewCampaign{ProjectID: proj, Name: "close-race", State: core.CampaignStateOpen}
	require.NoError(t, db.Create(campaign).Error)
	// A real role assignment behind the item, so AttestAccessReviewGrant's live
	// re-verification (#209) finds a genuine grant to certify — this test exercises
	// the decide/close concurrency race, not attestation validity, so the grant just
	// needs to actually exist.
	require.NoError(t, db.Create(&models.UserRole{UserID: 999, RoleID: 1, ProjectID: proj}).Error)
	item := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "role", PrincipalID: 999, RoleID: 1, Source: "role", Decision: core.ReviewItemPending}
	require.NoError(t, db.Create(item).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	const reviewers = 16
	var decideSucceeded atomic.Int64
	var decideRejectedDecided atomic.Int64
	var decideRejectedClosed atomic.Int64
	var closeSucceeded atomic.Int64
	var closeRejected atomic.Int64
	unexpected := make(chan error, reviewers+1)
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
				decideSucceeded.Add(1)
			case strings.Contains(decErr.Error(), "already been decided"):
				decideRejectedDecided.Add(1)
			case strings.Contains(decErr.Error(), "campaign is closed"):
				decideRejectedClosed.Add(1)
			default:
				unexpected <- decErr
			}
		}(actorID)
	}

	// One racer force-closes the campaign at the same instant.
	wg.Go(func() {
		<-start
		_, closeErr := c.CloseAccessReviewCampaign(ctx, 1, 0, proj, campaign.ID, true)
		switch {
		case closeErr == nil:
			closeSucceeded.Add(1)
		case strings.Contains(closeErr.Error(), "already closed"):
			closeRejected.Add(1)
		default:
			unexpected <- closeErr
		}
	})

	close(start) // release every racer at once
	wg.Wait()
	close(unexpected)
	for e := range unexpected {
		require.NoError(t, e, "every rejection must be a clean, expected error — nothing else")
	}

	// The close is a single-shot operation against a single campaign: it must
	// succeed exactly once (there's only one closer racer here, but the underlying
	// guarantee — proven exhaustively by the store-level concurrency test — is that
	// it can never succeed twice).
	assert.Equal(t, int64(1), closeSucceeded.Load(), "the force-close must succeed exactly once")
	assert.Equal(t, int64(0), closeRejected.Load())

	// At most one decision may ever be recorded.
	assert.LessOrEqual(t, decideSucceeded.Load(), int64(1), "at most one concurrent decision may be recorded")
	assert.Equal(t, reviewers, int(decideSucceeded.Load()+decideRejectedDecided.Load()+decideRejectedClosed.Load()),
		"every reviewer call must land in exactly one clean outcome bucket")

	// Final state consistency: the campaign is closed, and the item's decision state
	// must be exactly consistent with what "closed means frozen" requires — if a
	// decision won the race, it must have committed before the close (the atomic
	// UPDATE guarantees this); the campaign closing afterward doesn't retroactively
	// unfreeze or corrupt it.
	var gotCampaign models.AccessReviewCampaign
	require.NoError(t, db.First(&gotCampaign, campaign.ID).Error)
	assert.Equal(t, core.CampaignStateClosed, gotCampaign.State)

	var gotItem models.AccessReviewItem
	require.NoError(t, db.First(&gotItem, item.ID).Error)
	if decideSucceeded.Load() == 1 {
		assert.Equal(t, core.ReviewItemAttested, gotItem.Decision, "the single winning decision must be the one persisted")
	} else {
		assert.Equal(t, core.ReviewItemPending, gotItem.Decision, "no decision won the race — the item must remain untouched, frozen exactly as the close left it")
	}
}
