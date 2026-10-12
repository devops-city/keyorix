package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// shareViews does a user/group lookup per distinct recipient and creator, so it refuses
// a batch over maxShareViewBatchSize instead of running them all (CWE-400), and does not
// truncate: the list fails, it is never silently shortened.
func TestShareViews_RefusesOversizedBatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, _ := mustShare(t)

	over := make([]*models.ShareRecord, maxShareViewBatchSize+1)
	for i := range over {
		over[i] = &models.ShareRecord{SecretID: 1, RecipientID: uint(i + 1), OwnerID: 1, Permission: "read"}
	}
	views, err := c.shareViews(ctx, over)
	require.ErrorIs(t, err, ErrShareListOverCap)
	assert.Nil(t, views)
}

func TestShareViews_AcceptsBatchAtTheLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, _ := mustShare(t)

	// One distinct recipient, so the batch at the limit costs one lookup.
	atLimit := make([]*models.ShareRecord, maxShareViewBatchSize)
	for i := range atLimit {
		atLimit[i] = &models.ShareRecord{SecretID: 1, RecipientID: 2, OwnerID: 1, Permission: "read"}
	}
	views, err := c.shareViews(ctx, atLimit)
	require.NoError(t, err)
	assert.Len(t, views, maxShareViewBatchSize)
}
