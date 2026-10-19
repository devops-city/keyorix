package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceCreateAccessReviewItemsStorage makes CreateAccessReviewItems fail
// once, mirroring the failOnceStorage idiom from #2295.
func failOnceCreateAccessReviewItemsStorage(inner storage.Storage, armed *bool) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		CreateAccessReviewItems: func(next storage.Storage, ctx context.Context, items []*models.AccessReviewItem) error {
			if *armed {
				*armed = false
				return errors.New("injected fault: CreateAccessReviewItems")
			}
			return next.CreateAccessReviewItems(ctx, items)
		},
	})
}

// TestOpenAccessReviewCampaign_ItemsFailureRollsBackCampaign is the red-proof
// for Session O's O3 access-review-campaign fix: a failure creating the
// snapshot items must roll back the campaign row too -- not the pre-fix
// behavior where an EMPTY, orphaned campaign was left committed, reading as
// "0 pending, fully reviewed" (looks complete) rather than what it actually
// is (a snapshot that never finished).
func TestOpenAccessReviewCampaign_ItemsFailureRollsBackCampaign(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "review-proj", Description: "d"})
	require.NoError(t, err)
	u, err := st.CreateUser(ctx, foldedTestUser(t, "reviewee", "reviewee@example.com"))
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, 1, proj.ID, u.ID, "project_viewer", false))

	armed := true
	c.storage = failOnceCreateAccessReviewItemsStorage(st, &armed)

	_, err = c.OpenAccessReviewCampaign(ctx, 1, 0, proj.ID, "Q1")
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")

	campaigns, cerr := st.ListAccessReviewCampaigns(ctx, proj.ID)
	require.NoError(t, cerr)
	assert.Empty(t, campaigns, "a failed item snapshot must roll back the campaign row too -- no empty orphaned campaign")

	// Retry (fault disarmed) must fully succeed with its items.
	res, err := c.OpenAccessReviewCampaign(ctx, 1, 0, proj.ID, "Q1")
	require.NoError(t, err)
	assert.NotZero(t, res.Progress.Total, "a successful retry must have snapshot items")
}
