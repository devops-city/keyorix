package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ClearMaxReads (#3172) is the explicit way to remove a read limit: MaxReads keeps
// its min=1 rule, so "0 = unlimited" cannot ride on it.
func TestUpdateSecret_ClearMaxReads(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	limit := 3

	t.Run("clear removes the read limit", func(t *testing.T) {
		store := new(MockStorage)
		saved := captureSecretFieldUpdate(store, &models.SecretNode{ID: 1, Name: "x", MaxReads: &limit})
		c := NewKeyorixCore(store)
		got, err := c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: 1, ClearMaxReads: true, UpdatedBy: "t"})
		require.NoError(t, err)
		require.True(t, saved.SetMaxReads, "clearing must actually write the column")
		require.Nil(t, saved.MaxReads)
		require.Nil(t, got.MaxReads)
	})

	t.Run("no clear flag leaves the limit out of the UPDATE", func(t *testing.T) {
		store := new(MockStorage)
		saved := captureSecretFieldUpdate(store, &models.SecretNode{ID: 1, Name: "x", MaxReads: &limit})
		c := NewKeyorixCore(store)
		_, err := c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: 1, UpdatedBy: "t"})
		require.NoError(t, err)
		require.False(t, saved.SetMaxReads)
	})

	t.Run("max_reads together with clear is rejected", func(t *testing.T) {
		store := new(MockStorage)
		captureSecretFieldUpdate(store, &models.SecretNode{ID: 1, Name: "x", MaxReads: &limit})
		c := NewKeyorixCore(store)
		n := 5
		_, err := c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: 1, MaxReads: &n, ClearMaxReads: true, UpdatedBy: "t"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("clearing an existing limit is a lifecycle change, clearing none is not", func(t *testing.T) {
		store := new(MockStorage)
		store.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, MaxReads: &limit}, nil)
		store.On("GetSecret", mock.Anything, uint(2)).Return(&models.SecretNode{ID: 2}, nil)
		c := NewKeyorixCore(store)
		require.Equal(t, SecretActionUpdateLifecycle,
			c.updateSecretAction(context.Background(), &UpdateSecretRequest{ID: 1, ClearMaxReads: true}))
		require.Equal(t, SecretActionUpdate,
			c.updateSecretAction(context.Background(), &UpdateSecretRequest{ID: 2, ClearMaxReads: true}))
	})
}
