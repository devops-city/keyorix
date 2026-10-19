package solewriter

// sweep_cache_postgres_test.go — DEK-SWEEP-CACHE-1, the single_writer case.
//
// The DEK-rotation sweep (internal/encryption.SweepAllTables, run by the
// separate `keyorix-server admin encryption rotate` process) rewrites
// secret_versions.encrypted_value in place, and secret_versions is a fenced
// table. This pins the three things single_writer contributes:
//
//  1. while the holder lives the fence refuses the sweep, so the rows the
//     holder's caches were filled from are unchanged and nothing can diverge;
//  2. once the holder is gone the sweep runs, and the fence's epoch moves with
//     it (the next boot's authoritative caches start cold from that epoch);
//  3. a store that outlives its holder with a warm latest-version entry reads
//     the rewritten ciphertext, not the pre-sweep copy.
//
// pg-gated (KEYORIX_TEST_PG_DSN), not parallel (session tag is process-wide).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newSweepSvc(t *testing.T) *encryption.EncryptionService {
	t.Helper()
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)
	svc, err := encryption.NewEncryptionService(dek)
	require.NoError(t, err)
	return svc
}

func TestSingleWriter_DEKSweepVsLatestVersionCache(t *testing.T) {
	w := newSWWorld(t)
	ctx := context.Background()
	oldSvc, newSvc := newSweepSvc(t), newSweepSvc(t)

	var project models.Project
	require.NoError(t, w.foreign.First(&project).Error)

	g := w.start(Options{})
	srv := store.NewLocalStorage(w.own()) // the holder's own, tagged session

	node, err := srv.CreateSecret(ctx, &models.SecretNode{Name: "sweep-cache", ProjectID: project.ID, EnvironmentID: 0, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	aad := encryption.SecretAAD(node.ID, node.ProjectID, 1)
	enc, err := oldSvc.EncryptWithAAD([]byte("the-secret-value"), "v1", aad)
	require.NoError(t, err)
	oldBlob, err := encryption.SerializeEncryptedData(enc)
	require.NoError(t, err)
	meta, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)
	_, err = srv.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: node.ID, VersionNumber: 1, CreatedAt: time.Now(),
		EncryptedValue: oldBlob, EncryptionMetadata: models.JSON(meta),
	})
	require.NoError(t, err)
	warm, err := srv.GetLatestSecretVersion(ctx, node.ID)
	require.NoError(t, err)
	require.Equal(t, oldBlob, warm.EncryptedValue)

	sweep := func() error {
		return w.foreign.Transaction(func(tx *gorm.DB) error {
			_, err := encryption.SweepAllTables(tx, oldSvc, newSvc, "v2", false)
			return err
		})
	}

	// 1. The holder lives: the sweep is refused, the row is untouched.
	e0 := w.epoch(w.foreign)
	requireFenced(t, sweep(), "DEK sweep while the holder lives")
	var live models.SecretVersion
	require.NoError(t, w.foreign.Where("secret_node_id = ?", node.ID).First(&live).Error)
	require.Equal(t, oldBlob, live.EncryptedValue, "the refused sweep must not have rewritten the row")
	require.Equal(t, e0, w.epoch(w.foreign))

	// 2. The holder is gone: the sweep runs and the epoch moves.
	g.Close()
	require.Eventually(t, func() bool { return sweep() == nil }, 5*time.Second, 50*time.Millisecond,
		"after the holder is gone the fence must let the sweep through")
	require.NoError(t, w.foreign.Where("secret_node_id = ?", node.ID).First(&live).Error)
	require.NotEqual(t, oldBlob, live.EncryptedValue, "the sweep must have rewritten the row")
	require.Greater(t, w.epoch(w.foreign), e0, "the sweep's writes must move the fence epoch")

	// 3. A cold boot reads the rewritten ciphertext; so must a store that kept
	// a warm entry across the sweep.
	cold := store.NewLocalStorage(w.foreign)
	fresh, err := cold.GetLatestSecretVersion(ctx, node.ID)
	require.NoError(t, err)
	require.Equal(t, live.EncryptedValue, fresh.EncryptedValue)

	got, err := srv.GetLatestSecretVersion(ctx, node.ID)
	require.NoError(t, err)
	require.True(t, bytes.Equal(live.EncryptedValue, got.EncryptedValue),
		"the warm entry held across the sweep must not serve the pre-sweep ciphertext")
}
