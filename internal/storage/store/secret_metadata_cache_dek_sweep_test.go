package store

// DEK-rotation sweep vs. the read-path value cache (STORAGE-2 item 2, the gap
// named in secret_metadata_cache.go's header since #2764).
//
// internal/encryption.SweepAllTables rewrites secret_versions.encrypted_value
// (and encryption_metadata) in place. The latest-version cache's generation is
// (count, max(version_number), sum(read_count)) and the sweep moves none of
// those, so a warm entry keeps serving the PRE-sweep ciphertext. This file
// pins what that does and does not mean:
//
//   - the cached ciphertext is under the OLD DEK, a fresh read is under the NEW
//     DEK, and both decode to the SAME plaintext with their own DEK;
//   - the only process that can hold a warm entry across a sweep is one that
//     still holds the old DEK in memory (the DEK is unwrapped once per process,
//     at Initialize), so the entry is decryptable by exactly the process that
//     caches it — never by a process that has only the new key;
//   - the entry is bounded by secretMetaCacheTTL and by process lifetime, so
//     the old-DEK ciphertext copy cannot outlive the old-DEK key material in
//     the same process;
//   - a restarted/second process (cold cache) reads the new ciphertext.
//
// A server on the same key directory cannot be running during a sweep (it holds
// dek.lock exclusively for its lifetime, server/main.go), so the same-host case
// has no warm cache at all; the cross-host case (replica B on another host,
// sharing only the database) is the one modelled below by a second
// LocalStorage on the same *gorm.DB. That replica is already unable to decrypt
// any NON-cached post-sweep row until restarted, independent of this cache, so
// the cache neither creates nor widens that hazard.
//
// If this test goes red because the sweep or the cache changed, the gap needs
// re-deciding (e.g. a secret_versions.cache_epoch trigger), not the test
// loosening.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func newSweepTestEncSvc(t *testing.T) *encryption.EncryptionService {
	t.Helper()
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)
	svc, err := encryption.NewEncryptionService(dek)
	require.NoError(t, err)
	return svc
}

func decryptVersion(t *testing.T, svc *encryption.EncryptionService, v *models.SecretVersion, aad []byte) ([]byte, error) {
	t.Helper()
	enc, err := encryption.DeserializeEncryptedData(v.EncryptedValue)
	require.NoError(t, err)
	return svc.DecryptWithAAD(enc, aad)
}

func TestDEKSweep_WarmLatestVersionCacheServesOldCiphertextSamePlaintext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	replicaA := newCacheTestStorage(t)
	require.NoError(t, replicaA.db.AutoMigrate(
		&models.APIToken{}, &models.APIClient{}, &models.PasswordReset{}, &models.MFASecret{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.NotificationChannel{},
	))
	replicaB := NewLocalStorage(replicaA.db) // second replica: own cache, same database

	oldSvc := newSweepTestEncSvc(t)
	newSvc := newSweepTestEncSvc(t)

	node, err := replicaA.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 7, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	aad := encryption.SecretAAD(node.ID, node.ProjectID, 1)
	const plaintext = "the-secret-value"
	enc, err := oldSvc.EncryptWithAAD([]byte(plaintext), "v1", aad)
	require.NoError(t, err)
	blob, err := encryption.SerializeEncryptedData(enc)
	require.NoError(t, err)
	meta, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)
	_, err = replicaA.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: node.ID, VersionNumber: 1, CreatedAt: time.Now(),
		EncryptedValue: blob, EncryptionMetadata: models.JSON(meta),
	})
	require.NoError(t, err)

	// Both replicas warm their caches under the OLD DEK.
	warmA, err := replicaA.GetLatestSecretVersion(ctx, node.ID)
	require.NoError(t, err)
	warmB, err := replicaB.GetLatestSecretVersion(ctx, node.ID)
	require.NoError(t, err)
	require.Equal(t, blob, warmA.EncryptedValue)
	require.Equal(t, blob, warmB.EncryptedValue)

	// The sweep, as the stopped-server CLI runs it: one transaction on the raw DB.
	res, err := encryption.SweepAllTables(replicaA.db, oldSvc, newSvc, "v2", false)
	require.NoError(t, err)
	require.Equal(t, 1, res.SecretVersionsSwept)

	var live models.SecretVersion
	require.NoError(t, replicaA.db.Where("secret_node_id = ?", node.ID).First(&live).Error)
	require.NotEqual(t, blob, live.EncryptedValue, "the sweep must have rewritten the stored ciphertext")

	for name, ls := range map[string]*LocalStorage{"replicaA": replicaA, "replicaB": replicaB} {
		cached, err := ls.GetLatestSecretVersion(ctx, node.ID)
		require.NoError(t, err, name)

		// THE NAMED GAP, pinned: the warm entry is the pre-sweep ciphertext.
		require.Equal(t, blob, cached.EncryptedValue,
			"%s: the sweep changed no term of the versions generation, so the warm entry is expected to survive; "+
				"if this fails the cache now invalidates on sweep and the header gap note in secret_metadata_cache.go is obsolete", name)

		// ... which is still correct for the only holder of this entry: the
		// process that has the old DEK. Same plaintext, no disclosure.
		got, err := decryptVersion(t, oldSvc, cached, aad)
		require.NoError(t, err, name)
		require.Equal(t, plaintext, string(got), name)

		// A holder with only the new key cannot read it: fail closed, never wrong data.
		_, err = decryptVersion(t, newSvc, cached, aad)
		require.Error(t, err, name)
	}

	// A cold reader (restart, or a replica that never warmed) sees the new ciphertext.
	cold := NewLocalStorage(replicaA.db)
	fresh, err := cold.GetLatestSecretVersion(ctx, node.ID)
	require.NoError(t, err)
	require.Equal(t, live.EncryptedValue, fresh.EncryptedValue)
	got, err := decryptVersion(t, newSvc, fresh, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(got))
	_, err = decryptVersion(t, oldSvc, fresh, aad)
	require.Error(t, err, "post-sweep ciphertext must not decrypt under the retired DEK")

	// Bound: once the TTL passes, the old-DEK ciphertext copy leaves process memory.
	future := time.Now().Add(secretMetaCacheTTL + time.Second)
	replicaB.secretMetaCache.now = func() time.Time { return future }
	expired, err := replicaB.GetLatestSecretVersion(ctx, node.ID)
	require.NoError(t, err)
	require.Equal(t, live.EncryptedValue, expired.EncryptedValue,
		"after secretMetaCacheTTL the entry must be re-read, so retired-DEK ciphertext cannot stay resident longer than the TTL")
}
