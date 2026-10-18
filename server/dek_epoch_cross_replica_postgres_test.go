package main

// dek_epoch_cross_replica_postgres_test.go: two server replicas on one
// PostgreSQL database, each with its OWN key directory (ADR-039's "no shared
// filesystem needed" topology, or two hosts each holding a copy of dek.key).
// dek.lock is a per-host flock, so it cannot tell replica B that replica A's
// host rotated the DEK. These tests pin what must hold anyway: no replica ever
// commits a row the database's current DEK cannot decrypt.
//
// Gated on KEYORIX_TEST_PG_DSN (key=value form), like every other Postgres test
// in this package.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const dekEpochPassphrase = "dek-epoch-cross-replica-passphrase"

// dekEpochReplicaConfig is a postgres config whose key files live under keyDir
// (absolute paths, so the replica's key directory is independent of the cwd).
func dekEpochReplicaConfig(dsn, keyDir string) *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	cfg.Storage.Database.MaxOpenConns = 5
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.DEKPath = filepath.Join(keyDir, "dek.key")
	cfg.Storage.Encryption.SaltPath = filepath.Join(keyDir, "kek.salt")
	return cfg
}

// dekEpochSetup creates an isolated database with the full schema, generates the
// key set in keysA and copies it to keysB (the operator's "same keys on every
// replica" step), and seeds one secret node.
func dekEpochSetup(t *testing.T) (dsn, keysA, keysB string, db *gorm.DB, node *models.SecretNode) {
	t.Helper()
	dsn = adminPgIsolatedDatabaseDSN(t, adminPgTestDSN(t))
	t.Setenv("KEYORIX_MASTER_PASSWORD", dekEpochPassphrase)

	keysA = filepath.Join(t.TempDir(), "keys")
	keysB = filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.MkdirAll(keysA, 0o700))
	require.NoError(t, os.MkdirAll(keysB, 0o700))

	st, err := appstorage.NewStorageFactory().CreateStorage(dekEpochReplicaConfig(dsn, keysA))
	require.NoError(t, err, "migrate schema")
	if c, ok := st.(interface{ Close() error }); ok {
		_ = c.Close()
	}

	gen := encryption.NewService(&dekEpochReplicaConfig(dsn, keysA).Storage.Encryption, ".")
	require.NoError(t, gen.Initialize(dekEpochPassphrase))
	gen.Shutdown()
	for _, f := range []string{"dek.key", "kek.salt"} {
		b, err := os.ReadFile(filepath.Join(keysA, f))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(keysB, f), b, 0o600))
	}

	db = openTestSecretsDBPostgres(t, dsn)
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	node = &models.SecretNode{ProjectID: 1, Name: "dek-epoch-node", IsSecret: true}
	require.NoError(t, db.Create(node).Error)
	return dsn, keysA, keysB, db, node
}

// writeVersion is one replica's secret write: encrypt under the replica's
// in-memory DEK, then insert through the replica's own connection pool.
func writeVersion(svc *encryption.Service, db *gorm.DB, node *models.SecretNode, version int, value string) (uint, error) {
	aad := encryption.SecretAAD(node.ID, node.ProjectID, version)
	enc, meta, err := svc.EncryptSecretWithAAD([]byte(value), aad)
	if err != nil {
		return 0, err
	}
	v := &models.SecretVersion{SecretNodeID: node.ID, VersionNumber: version, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}
	if err := db.Create(v).Error; err != nil {
		return 0, err
	}
	return v.ID, nil
}

// undecryptableUnder returns every secret_versions row of node that keyDir's
// DEK cannot decrypt.
func undecryptableUnder(t *testing.T, dsn, keyDir string, db *gorm.DB, node *models.SecretNode) []int {
	t.Helper()
	svc := encryption.NewService(&dekEpochReplicaConfig(dsn, keyDir).Storage.Encryption, ".")
	require.NoError(t, svc.Initialize(dekEpochPassphrase))
	defer svc.Shutdown()
	var rows []models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", node.ID).Order("id").Find(&rows).Error)
	var bad []int
	for _, r := range rows {
		if _, err := svc.DecryptSecretWithAAD(r.EncryptedValue, encryption.SecretAAD(node.ID, node.ProjectID, r.VersionNumber)); err != nil {
			bad = append(bad, r.VersionNumber)
		}
	}
	return bad
}

// copyKeys is the operator distributing the rotated key set to another replica:
// the replica's old dek.key is replaced, so its old DEK is gone for good.
func copyKeys(t *testing.T, from, to string) {
	t.Helper()
	for _, f := range []string{"dek.key", "kek.salt"} {
		b, err := os.ReadFile(filepath.Join(from, f))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(to, f), b, 0o600))
	}
}

// TestDEKEpoch_StaleReplicaRestartAfterRotation_Postgres: replica B is stopped
// (as the rotation runbook requires), host A rotates the DEK, and B is started
// again before its key directory got the new dek.key. B must refuse to start:
// otherwise it serves writes under the old DEK, and once the operator copies
// the new key set to B those versions are undecryptable for good.
func TestDEKEpoch_StaleReplicaRestartAfterRotation_Postgres(t *testing.T) {
	dsn, keysA, keysB, db, node := dekEpochSetup(t)
	cfgA := dekEpochReplicaConfig(dsn, keysA)
	cfgB := dekEpochReplicaConfig(dsn, keysB)

	b, err := initializeEncryption(cfgB, nil)
	require.NoError(t, err, "replica B first boot")
	_, err = writeVersion(b, db, node, 1, "before-rotation")
	require.NoError(t, err)
	b.Shutdown()

	require.NoError(t, encryptionops.RotateWithConfig(cfgA, true, false, crypto.PassphraseSource{}), "rotate on host A")

	b2, err := initializeEncryption(cfgB, nil)
	if err != nil {
		require.ErrorContains(t, err, "DEK", "replica B refused, but not for the DEK mismatch")
		t.Logf("replica B with the stale dek.key refused to start: %v", err)
		require.Empty(t, undecryptableUnder(t, dsn, keysA, db, node), "rows the active DEK cannot decrypt")
		return
	}
	_, werr := writeVersion(b2, db, node, 2, "written-by-stale-replica")
	b2.Shutdown()
	copyKeys(t, keysA, keysB) // "retire" B's old DEK: the documented key distribution step
	bad := undecryptableUnder(t, dsn, keysA, db, node)
	t.Fatalf("replica B started with a dek.key that is not the database's DEK (write err=%v); versions undecryptable under the active DEK after the old one was retired: %v", werr, bad)
}

// TestDEKEpoch_LiveReplicaWritesDuringRotation_Postgres: replica B keeps
// serving writes while host A rotates. In production `admin encryption rotate`
// refuses while any server holds the database presence lock; this is the case
// where that guard is not there (--force, an old binary, or a presence lock
// lost under a pooler). Every row committed by any replica must still decrypt
// under the database's active DEK after the rotation.
func TestDEKEpoch_LiveReplicaWritesDuringRotation_Postgres(t *testing.T) {
	dsn, keysA, keysB, db, node := dekEpochSetup(t)
	cfgA := dekEpochReplicaConfig(dsn, keysA)
	cfgB := dekEpochReplicaConfig(dsn, keysB)

	b, err := initializeEncryption(cfgB, nil)
	require.NoError(t, err, "replica B boot")
	defer b.Shutdown()
	bDB := openTestSecretsDBPostgres(t, dsn)
	defer func() {
		if s, err := bDB.DB(); err == nil {
			_ = s.Close()
		}
	}()

	var (
		version     atomic.Int64
		okBefore    atomic.Int64
		okAfter     atomic.Int64
		refusedLate atomic.Int64
		rotated     atomic.Bool
		stop        = make(chan struct{})
		wg          sync.WaitGroup
		mu          sync.Mutex
		otherErrs   []error
	)
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			n := int(version.Add(1))
			_, err := writeVersion(b, bDB, node, n, "live-write")
			switch {
			case err == nil && rotated.Load():
				okAfter.Add(1)
			case err == nil:
				okBefore.Add(1)
			case errors.Is(err, encryption.ErrDEKWriteFenced):
				refusedLate.Add(1)
			default:
				mu.Lock()
				otherErrs = append(otherErrs, err)
				mu.Unlock()
			}
			time.Sleep(5 * time.Millisecond)
		}
	})

	time.Sleep(200 * time.Millisecond)
	require.NoError(t, encryptionops.RotateWithConfig(cfgA, true, false, crypto.PassphraseSource{}), "rotate on host A")
	rotated.Store(true)
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()

	t.Logf("replica B: %d writes before the rotation returned, %d after, %d refused by the DEK write fence, %d other errors",
		okBefore.Load(), okAfter.Load(), refusedLate.Load(), len(otherErrs))
	require.Positive(t, okBefore.Load(), "replica B never wrote: the test exercised nothing")
	for _, e := range otherErrs {
		// Only the fence (or the sweep's table lock timing out a writer) may stop a write.
		require.True(t, strings.Contains(e.Error(), "lock") || strings.Contains(e.Error(), "fenced"), "unexpected write error: %v", e)
	}

	copyKeys(t, keysA, keysB) // retire the old DEK everywhere
	bad := undecryptableUnder(t, dsn, keysA, db, node)
	require.Empty(t, bad, "DATA LOSS: versions committed by replica B that the active DEK cannot decrypt")
}
