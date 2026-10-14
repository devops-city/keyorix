package core

// SUSPEND-PURGE-1: the per-suspension "also clear the copies synced to Kubernetes
// clusters" choice. The marker is stored with the suspension, shows up on the
// SecretSuspended refusal (where the operator and k8s-sync read it), is audited, and
// is removed by resume.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func suspendedRefusal(t *testing.T, c *KeyorixCore, id uint) SecretReadRefusal {
	t.Helper()
	_, err := c.GetSecretValue(context.Background(), id)
	require.Error(t, err)
	refusal, ok := ClassifySecretReadRefusal(err)
	require.True(t, ok, "a suspended read must classify as a refusal, got %v", err)
	require.Equal(t, SecretReadRefusalCodeSuspended, refusal.Code)
	return refusal
}

func suspendAuditDescriptions(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var evs []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretSuspended).Order("id").Find(&evs).Error)
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Description)
	}
	return out
}

func TestSuspendSecret_ClearSyncedCopies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("plain suspend carries no marker", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		s, err := c.SuspendSecret(ctx, id, 1, "maintenance")
		require.NoError(t, err)
		assert.False(t, s.SuspendClearSyncedCopies)
		assert.False(t, suspendedRefusal(t, c, id).ClearSyncedCopies)
		for _, d := range suspendAuditDescriptions(t, db) {
			assert.NotContains(t, d, "clear_synced_copies")
		}
	})

	t.Run("the flag is stored, reaches the refusal and is audited", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		s, err := c.SuspendSecretWithOptions(ctx, id, 1, "leaked in CI logs", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		assert.True(t, s.SuspendClearSyncedCopies)

		stored, err := c.storage.GetSecret(ctx, id)
		require.NoError(t, err)
		assert.True(t, stored.SuspendClearSyncedCopies, "persisted, not just on the returned struct")
		assert.True(t, suspendedRefusal(t, c, id).ClearSyncedCopies)

		descs := suspendAuditDescriptions(t, db)
		require.Len(t, descs, 1)
		assert.Contains(t, descs[0], "clear_synced_copies=true")
		assert.Contains(t, descs[0], "leaked in CI logs")
	})

	t.Run("resume removes the marker and reads work again", func(t *testing.T) {
		c, id, _ := newSuspendFixture(t)
		_, err := c.SuspendSecretWithOptions(ctx, id, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)

		s, err := c.ResumeSecret(ctx, id, 1)
		require.NoError(t, err)
		assert.False(t, s.SuspendClearSyncedCopies)
		stored, err := c.storage.GetSecret(ctx, id)
		require.NoError(t, err)
		assert.False(t, stored.SuspendClearSyncedCopies, "a later plain suspension must not inherit the old choice")
		_, err = c.GetSecretValue(ctx, id)
		require.NoError(t, err)

		_, err = c.SuspendSecret(ctx, id, 1, "again")
		require.NoError(t, err)
		assert.False(t, suspendedRefusal(t, c, id).ClearSyncedCopies)
	})

	t.Run("flag on an already-suspended secret upgrades it, audited", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecret(ctx, id, 1, "")
		require.NoError(t, err)
		require.False(t, suspendedRefusal(t, c, id).ClearSyncedCopies)

		_, err = c.SuspendSecretWithOptions(ctx, id, 1, "now known leaked", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		assert.True(t, suspendedRefusal(t, c, id).ClearSyncedCopies)

		descs := suspendAuditDescriptions(t, db)
		require.Len(t, descs, 2, "the upgrade is its own audited decision")
		assert.Contains(t, descs[1], "clear_synced_copies=true")
	})

	t.Run("a later plain suspend never downgrades the marker", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecretWithOptions(ctx, id, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		_, err = c.SuspendSecret(ctx, id, 2, "")
		require.NoError(t, err)
		_, err = c.SuspendSecretWithOptions(ctx, id, 2, "", SuspendOptions{ClearSyncedCopies: true}) // repeat: no-op
		require.NoError(t, err)

		assert.True(t, suspendedRefusal(t, c, id).ClearSyncedCopies)
		assert.Len(t, suspendAuditDescriptions(t, db), 1, "no duplicate audit for a no-op")
	})
}
