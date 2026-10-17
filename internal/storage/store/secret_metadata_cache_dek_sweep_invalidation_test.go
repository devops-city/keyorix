package store

// DEK-SWEEP-CACHE-1: the DEK-rotation sweep must invalidate the read-path
// latest-version cache (the gap named in secret_metadata_cache.go since #2764).
//
// internal/encryption.SweepAllTables rewrites secret_versions.encrypted_value
// and encryption_metadata in place. This file states what a read after the
// sweep must see, for both outcomes of the rotation:
//
//	(a) the old key is still retained by the reading process: the read must
//	    return the NEW ciphertext (not the pre-sweep copy), and whatever it
//	    returns must decode to the one plaintext, never to other data;
//	(b) the old key is destroyed and the process holds only the new key (what
//	    Service.RotateDEKWithSweep leaves behind in its own process): the read
//	    must return ciphertext the new key opens. A pre-sweep copy under the
//	    destroyed key would fail to decrypt, i.e. a value that was readable a
//	    moment ago turns into a decrypt error until the TTL passes.
//
// Both run on SQLite and on Postgres, on one node and with a second replica
// (own LocalStorage, own cache, same database). The single_writer case is in
// internal/solewriter (it needs the real fence), see
// sweep_cache_postgres_test.go there.
//
// Fail-closed is asserted alongside: a ciphertext under a key the reader does
// not hold must stay an error, never plaintext.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const sweepCachePlaintext = "the-secret-value"

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

// sweepCacheWorld is one secret with one version encrypted under oldSvc, warm in
// every replica's cache.
type sweepCacheWorld struct {
	db       *gorm.DB
	replicas map[string]*LocalStorage
	nodeID   uint
	aad      []byte
	oldBlob  []byte
	oldSvc   *encryption.EncryptionService
	newSvc   *encryption.EncryptionService
}

// sweepCacheBackends runs fn once per backend with a fresh world. Postgres is
// skipped without KEYORIX_TEST_PG_DSN. The sweep tables beyond secret_versions
// are migrated because SweepAllTables reads every one of them.
func sweepCacheBackends(t *testing.T, fn func(t *testing.T, w *sweepCacheWorld)) {
	t.Helper()
	tables := []any{
		&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.Project{},
		&models.APIToken{}, &models.APIClient{}, &models.PasswordReset{}, &models.MFASecret{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.NotificationChannel{},
	}
	t.Run("sqlite", func(t *testing.T) {
		a := newCacheTestStorage(t)
		require.NoError(t, a.db.AutoMigrate(tables...))
		fn(t, newSweepCacheWorld(t, a.db, map[string]*LocalStorage{
			"replicaA": a,
			"replicaB": NewLocalStorage(a.db), // second replica: own cache, same database
		}))
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
		setup := pgOpen(t, dsn)
		require.NoError(t, setup.AutoMigrate(tables...))
		require.NoError(t, EnsureSecretNodeCacheEpoch(setup))
		fn(t, newSweepCacheWorld(t, setup, map[string]*LocalStorage{
			"replicaA": NewLocalStorage(pgOpen(t, dsn)),
			"replicaB": NewLocalStorage(pgOpen(t, dsn)), // own pool: a separate server process
		}))
	})
}

func newSweepCacheWorld(t *testing.T, db *gorm.DB, replicas map[string]*LocalStorage) *sweepCacheWorld {
	t.Helper()
	ctx := context.Background()
	w := &sweepCacheWorld{db: db, replicas: replicas, oldSvc: newSweepTestEncSvc(t), newSvc: newSweepTestEncSvc(t)}

	node, err := replicas["replicaA"].CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 7, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	w.nodeID = node.ID
	w.aad = encryption.SecretAAD(node.ID, node.ProjectID, 1)

	enc, err := w.oldSvc.EncryptWithAAD([]byte(sweepCachePlaintext), "v1", w.aad)
	require.NoError(t, err)
	w.oldBlob, err = encryption.SerializeEncryptedData(enc)
	require.NoError(t, err)
	meta, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)
	_, err = replicas["replicaA"].CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: node.ID, VersionNumber: 1, CreatedAt: time.Now(),
		EncryptedValue: w.oldBlob, EncryptionMetadata: models.JSON(meta),
	})
	require.NoError(t, err)

	// Both replicas warm their caches under the OLD DEK.
	for name, ls := range replicas {
		warm, err := ls.GetLatestSecretVersion(ctx, w.nodeID)
		require.NoError(t, err, name)
		require.Equal(t, w.oldBlob, warm.EncryptedValue, name)
	}
	return w
}

// sweep runs the rotation's sweep the way RotateDEKWithSweep does: one
// transaction on the raw database handle, committed on success.
func (w *sweepCacheWorld) sweep(t *testing.T) (rewritten []byte) {
	t.Helper()
	var res *encryption.SweepResult
	require.NoError(t, w.db.Transaction(func(tx *gorm.DB) error {
		var err error
		res, err = encryption.SweepAllTables(tx, w.oldSvc, w.newSvc, "v2", false)
		return err
	}))
	require.Equal(t, 1, res.SecretVersionsSwept)
	var live models.SecretVersion
	require.NoError(t, w.db.Where("secret_node_id = ?", w.nodeID).First(&live).Error)
	require.NotEqual(t, w.oldBlob, live.EncryptedValue, "the sweep must have rewritten the stored ciphertext")
	return live.EncryptedValue
}

// TestDEKSweepCache_OldKeyRetained is outcome (a).
func TestDEKSweepCache_OldKeyRetained(t *testing.T) {
	sweepCacheBackends(t, func(t *testing.T, w *sweepCacheWorld) {
		ctx := context.Background()
		rewritten := w.sweep(t)

		for name, ls := range w.replicas {
			got, err := ls.GetLatestSecretVersion(ctx, w.nodeID)
			require.NoError(t, err, name)

			// Whatever is served decodes to the one plaintext with its own key and
			// to nothing else: stale-but-same-plaintext is harmless on its own,
			// which is why this is asserted before the freshness check.
			stale := string(got.EncryptedValue) == string(w.oldBlob)
			svc := w.newSvc
			if stale {
				svc = w.oldSvc
			}
			pt, err := decryptVersion(t, svc, got, w.aad)
			require.NoError(t, err, name)
			require.Equal(t, sweepCachePlaintext, string(pt), name)

			assert.True(t, bytes.Equal(rewritten, got.EncryptedValue),
				"%s: the sweep rewrote secret_versions.encrypted_value but a warm entry still serves the pre-sweep ciphertext", name)
		}
	})
}

// TestDEKSweepCache_OldKeyDestroyed is outcome (b): the reading process holds
// only the new key once the old one is wiped.
func TestDEKSweepCache_OldKeyDestroyed(t *testing.T) {
	sweepCacheBackends(t, func(t *testing.T, w *sweepCacheWorld) {
		ctx := context.Background()
		w.sweep(t)
		w.oldSvc.WipeDEK()

		for name, ls := range w.replicas {
			got, err := ls.GetLatestSecretVersion(ctx, w.nodeID)
			require.NoError(t, err, name)

			// Fail closed, whatever the cache did: a ciphertext the reader's key
			// does not open is an error, never plaintext and never other data.
			if string(got.EncryptedValue) == string(w.oldBlob) {
				pt, derr := decryptVersion(t, w.newSvc, got, w.aad)
				require.Error(t, derr, "%s: pre-sweep ciphertext must not open under the new key", name)
				require.Empty(t, pt, name)
			}

			pt, err := decryptVersion(t, w.newSvc, got, w.aad)
			assert.NoError(t, err,
				"%s: after the old key is destroyed a read must return ciphertext the new key opens; the warm entry still holds the pre-sweep copy", name)
			if err == nil {
				assert.Equal(t, sweepCachePlaintext, string(pt), name)
			}
		}
	})
}

// TestDEKSweepCache_StaleKeyHolderFailsClosed pins that invalidation does not
// turn into a fallback: a replica that still holds only the OLD key (not
// restarted after a sweep) now reads the rewritten ciphertext at once, and
// decrypting it is an error with no plaintext, on every read, with the cache
// warm or cold. The storage layer never serves the pre-sweep copy to paper over
// it, and nothing here retries under another key.
func TestDEKSweepCache_StaleKeyHolderFailsClosed(t *testing.T) {
	sweepCacheBackends(t, func(t *testing.T, w *sweepCacheWorld) {
		ctx := context.Background()
		rewritten := w.sweep(t)

		for name, ls := range w.replicas {
			for attempt := range 3 { // first read refills the cache, later ones hit it
				got, err := ls.GetLatestSecretVersion(ctx, w.nodeID)
				require.NoError(t, err, "%s attempt %d", name, attempt)
				require.True(t, bytes.Equal(rewritten, got.EncryptedValue), "%s attempt %d: stale copy served", name, attempt)

				pt, derr := decryptVersion(t, w.oldSvc, got, w.aad)
				require.Error(t, derr, "%s attempt %d: the retired key must not open post-sweep ciphertext", name, attempt)
				require.Empty(t, pt, "%s attempt %d: a failed decrypt must yield no plaintext", name, attempt)
			}
		}
	})
}
