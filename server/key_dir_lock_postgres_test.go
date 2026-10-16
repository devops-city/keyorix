package main

// key_dir_lock_postgres_test.go: storage.encryption.key_dir_lock (docs/multi-replica-keys.md).
// Each "replica" is its own initializeEncryption call with its own encryption.Service
// and its own database connections, against one isolated PostgreSQL database and,
// unless the test says otherwise, one shared key directory -- the shape of two pods
// on a ReadWriteMany keys volume. Gated on KEYORIX_TEST_PG_DSN.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func keyDirLockCfg(dsn, keyDir, mode string) *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	cfg.Storage.Encryption = config.EncryptionConfig{
		Enabled:    true,
		DEKPath:    filepath.Join(keyDir, "data.key"),
		SaltPath:   filepath.Join(keyDir, "kek.salt"),
		KeyDirLock: mode,
	}
	return cfg
}

// bootReplica is the start-up order main() uses: shared presence lock first,
// then initializeEncryption. The returned stop releases both.
func bootReplica(t *testing.T, cfg *config.Config) (*encryption.Service, func(), error) {
	t.Helper()
	presence, err := serverguard.AcquirePresence(cfg)
	if err != nil {
		return nil, func() {}, err
	}
	svc, err := initializeEncryption(cfg, nil)
	if err != nil {
		_ = presence.Release()
		return nil, func() {}, err
	}
	return svc, func() { svc.Shutdown(); _ = presence.Release() }, nil
}

// Red premise for the Helm replicas > 1 path (#3305): with the default flock a second
// server on the same key directory cannot start while the first runs.
func TestKeyDirLock_Flock_SecondReplicaOnSharedKeyDirRefuses(t *testing.T) {
	dsn := adminPgIsolatedDatabaseDSN(t, adminPgTestDSN(t))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "key-dir-lock-test-passphrase")
	keyDir := t.TempDir()

	_, stopA, err := bootReplica(t, keyDirLockCfg(dsn, keyDir, ""))
	if err != nil {
		t.Fatalf("replica A: %v", err)
	}
	defer stopA()
	_, stopB, err := bootReplica(t, keyDirLockCfg(dsn, keyDir, ""))
	defer stopB()
	if err == nil || !strings.Contains(err.Error(), "encryption key lock") {
		t.Fatalf("replica B on the same key directory with flock: want the key-lock refusal, got %v", err)
	}
}

// key_dir_lock: database: two replicas starting at once on one FRESH shared key
// directory both start, on the same DEK (what A encrypts B decrypts), and neither
// creates dek.lock.
func TestKeyDirLock_Database_TwoReplicasShareOneFreshKeyDir(t *testing.T) {
	dsn := adminPgIsolatedDatabaseDSN(t, adminPgTestDSN(t))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "key-dir-lock-test-passphrase")
	keyDir := t.TempDir()

	var wg sync.WaitGroup
	svcs := make([]*encryption.Service, 2)
	stops := make([]func(), 2)
	errs := make([]error, 2)
	for i := range svcs {
		wg.Go(func() {
			svcs[i], stops[i], errs[i] = bootReplica(t, keyDirLockCfg(dsn, keyDir, config.KeyDirLockDatabase))
		})
	}
	wg.Wait()
	for i := range svcs {
		defer stops[i]()
		if errs[i] != nil {
			t.Fatalf("replica %d: %v", i, errs[i])
		}
	}
	aad := encryption.SecretAAD(1, 1, 1)
	ct, meta, err := svcs[0].EncryptSecretWithAAD([]byte("shared-dek-probe"), aad)
	if err != nil {
		t.Fatalf("encrypt on replica 0: %v", err)
	}
	_ = meta
	pt, err := svcs[1].DecryptSecretWithAAD(ct, aad)
	if err != nil || string(pt) != "shared-dek-probe" {
		t.Fatalf("replica 1 cannot read replica 0's write (two DEKs?): pt=%q err=%v", pt, err)
	}
	if _, err := os.Stat(filepath.Join(keyDir, "dek.lock")); !os.IsNotExist(err) {
		t.Fatalf("dek.lock exists in database mode (stat err=%v): the server must not use a key-directory flock", err)
	}

	// A key-changing admin command is still kept out while the replicas run: the
	// presence lock both hold shared.
	if _, err := serverguard.AcquireExclusive(keyDirLockCfg(dsn, keyDir, config.KeyDirLockDatabase)); err == nil || !serverguard.IsLockHeld(err) {
		t.Fatalf("admin exclusive lock with live replicas: want lock-held refusal, got %v", err)
	}
}

// key_dir_lock: database boots from a key directory it cannot write to (keys
// delivered read-only, e.g. a mounted Secret), once the key files exist.
func TestKeyDirLock_Database_ReadOnlyKeyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dsn := adminPgIsolatedDatabaseDSN(t, adminPgTestDSN(t))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "key-dir-lock-test-passphrase")
	keyDir := t.TempDir()

	_, stop, err := bootReplica(t, keyDirLockCfg(dsn, keyDir, config.KeyDirLockDatabase))
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	stop()
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Chmod(filepath.Join(keyDir, e.Name()), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(keyDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keyDir, 0o700) })

	_, stop, err = bootReplica(t, keyDirLockCfg(dsn, keyDir, config.KeyDirLockDatabase))
	if err != nil {
		t.Fatalf("boot from a read-only key directory: %v", err)
	}
	stop()

	// The default flock mode cannot: it must create dek.lock.
	_, stop, err = bootReplica(t, keyDirLockCfg(dsn, keyDir, ""))
	stop()
	if err == nil {
		t.Fatal("flock mode booted from a read-only key directory; the comparison above proves nothing")
	}
}

// key_dir_lock: database refuses to generate a new DEK into an empty key
// directory when the database already holds secret versions (a replica given
// its own empty volume instead of the shared one), and writes no key file.
func TestKeyDirLock_Database_RefusesNewDEKOverEncryptedData(t *testing.T) {
	dsn := adminPgIsolatedDatabaseDSN(t, adminPgTestDSN(t))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "key-dir-lock-test-passphrase")
	sharedDir := t.TempDir()
	_, stop, err := bootReplica(t, keyDirLockCfg(dsn, sharedDir, config.KeyDirLockDatabase))
	if err != nil {
		t.Fatalf("replica A: %v", err)
	}
	defer stop()

	db := openTestSecretsDBPostgres(t, dsn)
	node := &models.SecretNode{ProjectID: 1, Name: "kdl-probe", IsSecret: true}
	if err := db.Create(node).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: []byte("x")}).Error; err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		_ = sqlDB.Close()
	}

	ownDir := t.TempDir()
	_, stopB, err := bootReplica(t, keyDirLockCfg(dsn, ownDir, config.KeyDirLockDatabase))
	stopB()
	if err == nil || !strings.Contains(err.Error(), "refusing to generate a new DEK") {
		t.Fatalf("replica B with an empty key directory: want refusal, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(ownDir, "data.key")); !os.IsNotExist(err) {
		t.Fatalf("a DEK was written to the empty directory (stat err=%v)", err)
	}
}
