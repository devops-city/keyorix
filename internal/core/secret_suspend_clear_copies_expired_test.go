package core

// #3215 review point 1: the server judges expiry before suspension, so a secret that is
// BOTH expired and suspended with the clear-synced-copies marker must still carry the
// marker on its (SecretExpired) refusal, or the operator and k8s-sync keep the copies
// the user was told would be cleared. An expired secret that is not suspended, or is
// suspended without the marker, must never carry it.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func expireSecretNow(t *testing.T, db *gorm.DB, id uint) {
	t.Helper()
	// Save, not Update: the write must run the model's BeforeSave hook (the
	// BeforeSave-bypass guard in internal/storage/models forbids raw Expiration writes).
	var node models.SecretNode
	require.NoError(t, db.First(&node, id).Error)
	past := time.Now().Add(-time.Hour)
	node.Expiration = &past
	require.NoError(t, db.Save(&node).Error)
}

func readRefusal(t *testing.T, c *KeyorixCore, id uint, wantCode string) SecretReadRefusal {
	t.Helper()
	_, err := c.GetSecretValue(context.Background(), id)
	require.Error(t, err)
	refusal, ok := ClassifySecretReadRefusal(err)
	require.True(t, ok, "must classify as a refusal, got %v", err)
	require.Equal(t, wantCode, refusal.Code)
	return refusal
}

func TestSecretReadRefusal_ClearSyncedCopiesWhenExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("expired and suspended with the marker: the expired refusal carries it", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecretWithOptions(ctx, id, 1, "leaked", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		expireSecretNow(t, db, id)
		assert.True(t, readRefusal(t, c, id, SecretReadRefusalCodeExpired).ClearSyncedCopies)
	})

	t.Run("expired only: no marker, keep + warn policy unchanged", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		expireSecretNow(t, db, id)
		assert.False(t, readRefusal(t, c, id, SecretReadRefusalCodeExpired).ClearSyncedCopies)
	})

	t.Run("expired and suspended without the marker: no marker", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecret(ctx, id, 1, "maintenance")
		require.NoError(t, err)
		expireSecretNow(t, db, id)
		assert.False(t, readRefusal(t, c, id, SecretReadRefusalCodeExpired).ClearSyncedCopies)
	})

	t.Run("expired and a stale marker on a resumed (active) secret: no marker", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecretWithOptions(ctx, id, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		_, err = c.ResumeSecret(ctx, id, 1)
		require.NoError(t, err)
		expireSecretNow(t, db, id)
		assert.False(t, readRefusal(t, c, id, SecretReadRefusalCodeExpired).ClearSyncedCopies)
	})

	t.Run("suspended with the marker, not expired: unchanged", func(t *testing.T) {
		c, id, _ := newSuspendFixture(t)
		_, err := c.SuspendSecretWithOptions(ctx, id, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		assert.True(t, suspendedRefusal(t, c, id).ClearSyncedCopies)
	})
}
