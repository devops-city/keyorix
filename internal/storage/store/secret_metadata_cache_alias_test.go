package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// A caller that wipes or decrypts the returned version in place must not be
// able to corrupt the cached entry the next reader is served (#2764 review,
// non-blocking item 2). Covers both publish paths (the miss that fills the
// cache, then the hit) and both mutable byte fields.
func TestGetLatestSecretVersion_ReturnedCopyDoesNotAliasCache(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: created.ID, VersionNumber: 1, CreatedAt: time.Now(),
		EncryptedValue: []byte("ciphertext"), EncryptionMetadata: models.JSON(`{"k":"v"}`),
	})
	require.NoError(t, err)

	wipe := func(v *models.SecretVersion) {
		for i := range v.EncryptedValue {
			v.EncryptedValue[i] = 0
		}
		for i := range v.EncryptionMetadata {
			v.EncryptionMetadata[i] = 0
		}
	}

	miss, err := ls.GetLatestSecretVersion(ctx, created.ID) // fills the cache
	require.NoError(t, err)
	wipe(miss)

	hit1, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, []byte("ciphertext"), hit1.EncryptedValue, "wiping the miss-path result corrupted the cached entry")
	require.Equal(t, models.JSON(`{"k":"v"}`), hit1.EncryptionMetadata)
	wipe(hit1)

	hit2, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, []byte("ciphertext"), hit2.EncryptedValue, "wiping a hit-path result corrupted the cached entry")
	require.Equal(t, models.JSON(`{"k":"v"}`), hit2.EncryptionMetadata)
}
