// share_clock_regression_test.go — #1653 (follow-up to #1632): exploit-shaped
// tests for share-active resolution's (shareActive/activeShares,
// permissions.go) defense against a backward-stepped host clock.
// ListSecretShares/ListSharesByUser/etc. read time.Now() internally (via
// shareEffectiveNow) rather than accepting it as a parameter, so — same
// technique as the RBAC cluster's and Connect grant's own regression tests —
// this seeds shareClockWatermark directly (an unexported field, accessible
// from this package) to simulate "this process has already observed a later
// real time," then calls the real, unmodified ListSecretShares.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newShareClockRegressionCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	return c, db
}

// TestListSecretShares_ClockSteppedBackward_ExpiredShareStaysExcluded is the
// exploit-shaped test: a ShareRecord whose ExpiresAt already elapsed
// relative to a time this process has previously observed must not be
// resurrected merely because the real time.Now() reading right now looks
// earlier than that watermark.
func TestListSecretShares_ClockSteppedBackward_ExpiredShareStaysExcluded(t *testing.T) {
	t.Parallel()
	c, db := newShareClockRegressionCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "s", Type: "generic"}).Error)

	future := time.Now().Add(24 * time.Hour)
	c.shareClockWatermark = future

	// Genuinely expired relative to the watermark, but NOT expired relative
	// to the real, un-mocked time.Now() this test actually runs at.
	expiry := time.Now().Add(time.Hour)
	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: 1, OwnerID: 1, RecipientID: 2, Permission: "read", ExpiresAt: &expiry,
	}).Error)

	shares, err := c.ListSecretShares(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, shares, "a share already expired relative to a time this process has previously observed must not be resurrected by a real clock reading that looks earlier")
}

// TestListSecretShares_ClockSteppedBackward_LegitimatelyLiveShareStillResolves
// is the positive control: a share genuinely still live even past the
// watermark must still resolve normally.
func TestListSecretShares_ClockSteppedBackward_LegitimatelyLiveShareStillResolves(t *testing.T) {
	t.Parallel()
	c, db := newShareClockRegressionCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "s", Type: "generic"}).Error)

	future := time.Now().Add(24 * time.Hour)
	c.shareClockWatermark = future

	stillLive := future.Add(24 * time.Hour)
	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: 1, OwnerID: 1, RecipientID: 2, Permission: "read", ExpiresAt: &stillLive,
	}).Error)

	shares, err := c.ListSecretShares(ctx, 1)
	require.NoError(t, err)
	require.Len(t, shares, 1, "a share genuinely live past the watermark must still resolve")
}

// TestShareEffectiveNow_ClampsBackwardReadingToWatermark is a direct unit
// test of the clamp itself.
func TestShareEffectiveNow_ClampsBackwardReadingToWatermark(t *testing.T) {
	t.Parallel()
	c := &KeyorixCore{now: time.Now}
	watermark := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	c.shareClockWatermark = watermark

	c.now = func() time.Time { return watermark.Add(-time.Hour) }
	assert.Equal(t, watermark, c.shareEffectiveNow(), "a backward-looking reading must clamp up to the watermark")

	forward := watermark.Add(time.Hour)
	c.now = func() time.Time { return forward }
	assert.Equal(t, forward, c.shareEffectiveNow(), "a forward reading must pass through unchanged and advance the watermark")
	assert.Equal(t, forward, c.shareClockWatermark)
}
