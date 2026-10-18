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
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
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

// keyDirLockDSN returns an isolated PostgreSQL database with the full schema.
// main() creates the storage (running the migrations) before initializeEncryption,
// and the DEK epoch guard reads system_metadata, so the tests do the same.
func keyDirLockDSN(t *testing.T) string {
	t.Helper()
	dsn := adminPgIsolatedDatabaseDSN(t, adminPgTestDSN(t))
	st, err := appstorage.NewStorageFactory().CreateStorage(keyDirLockCfg(dsn, t.TempDir(), ""))
	if err != nil {
		t.Fatalf("migrate schema: %v", err)
	}
	if c, ok := st.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	return dsn
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
	dsn := keyDirLockDSN(t)
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
	dsn := keyDirLockDSN(t)
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
	dsn := keyDirLockDSN(t)
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
	dsn := keyDirLockDSN(t)
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

// Fresh database, no secret yet, two replicas with SEPARATE empty key directories:
// the second must be refused before it writes any key file. The recorded DEK epoch
// (not secret_versions) is what tells it a sibling already generated the DEK.
func TestKeyDirLock_Database_SecondReplicaOwnEmptyDirRefusedOnFreshDatabase(t *testing.T) {
	dsn := keyDirLockDSN(t)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "key-dir-lock-test-passphrase")

	_, stopA, err := bootReplica(t, keyDirLockCfg(dsn, t.TempDir(), config.KeyDirLockDatabase))
	if err != nil {
		t.Fatalf("replica A: %v", err)
	}
	defer stopA()

	ownDir := t.TempDir()
	_, stopB, err := bootReplica(t, keyDirLockCfg(dsn, ownDir, config.KeyDirLockDatabase))
	stopB()
	if err == nil || !strings.Contains(err.Error(), "refusing to generate a new DEK") {
		t.Fatalf("replica B with its own empty key directory on a fresh database: want refusal, got %v", err)
	}
	if entries, rerr := os.ReadDir(ownDir); rerr != nil || len(entries) != 0 {
		t.Fatalf("replica B wrote key files before being refused: entries=%v err=%v", entries, rerr)
	}
}

// A database-mode server records its mode where server/admin reads it for --force.
func TestKeyDirLock_Database_RecordsModeForAdminForce(t *testing.T) {
	dsn := keyDirLockDSN(t)
	cfg := keyDirLockCfg(dsn, t.TempDir(), config.KeyDirLockDatabase)
	if err := recordKeyDirLockMode(cfg); err != nil {
		t.Fatal(err)
	}
	if err := recordKeyDirLockMode(cfg); err != nil {
		t.Fatalf("second boot must upsert, got %v", err)
	}
	db := openTestSecretsDBPostgres(t, dsn)
	var got string
	if err := db.Raw(`SELECT value FROM system_metadata WHERE "key" = ?`, config.KeyDirLockModeMetadataKey).Scan(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got != config.KeyDirLockDatabase {
		t.Fatalf("recorded mode = %q, want %q", got, config.KeyDirLockDatabase)
	}
	if sqlDB, e := db.DB(); e == nil {
		_ = sqlDB.Close()
	}
}

// Concurrent start (HA-READY-1 review (b)): two replicas, each with its OWN empty
// key directory, start together on one fresh database. Only one may generate the
// DEK; the other must be refused before it writes a key file. The first seeds the
// DEK epoch before it releases the key-initialisation lock
// (initializeKeysAndStartEpochGuard), so the second, waiting on that lock, finds
// the epoch.
//
// The interleaving is forced, not left to timing: the test holds system_metadata
// in SHARE mode, which blocks the epoch INSERT but not the reads, so replica A
// stops exactly at its epoch seed while replica B is already starting. With the
// seed inside the lock, B waits on the lock meanwhile. With the seed after the
// release (the defect), B takes the lock, finds no epoch and writes a second DEK
// into its own directory while A is still blocked; that is what the test catches.
func TestKeyDirLock_Database_ConcurrentStartOwnEmptyDirsSeedsEpochUnderLock(t *testing.T) {
	dsn := keyDirLockDSN(t)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "key-dir-lock-test-passphrase")
	dirA, dirB := t.TempDir(), t.TempDir()

	db := openTestSecretsDBPostgres(t, dsn)
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}()
	hold := db.Begin()
	if err := hold.Exec("LOCK TABLE system_metadata IN SHARE MODE").Error; err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = hold.Rollback().Error
		}
	}
	defer release()

	type result struct {
		stop func()
		err  error
	}
	boot := func(dir string) chan result {
		ch := make(chan result, 1)
		go func() {
			_, stop, err := bootReplica(t, keyDirLockCfg(dsn, dir, config.KeyDirLockDatabase))
			ch <- result{stop, err}
		}()
		return ch
	}
	nonEmpty := func(dir string) bool {
		entries, err := os.ReadDir(dir)
		return err == nil && len(entries) > 0
	}
	waitFor := func(d time.Duration, cond func() bool) bool {
		for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if cond() {
				return true
			}
		}
		return cond()
	}

	chA := boot(dirA)
	if !waitFor(30*time.Second, func() bool { return nonEmpty(dirA) }) {
		release()
		t.Fatalf("replica A wrote no key files: %v", (<-chA).err)
	}
	// A has generated its keys and is about to seed (or blocked seeding) the epoch.
	chB := boot(dirB)
	// Several key-initialisation lock polls: long enough for B to take the lock if
	// A had released it.
	wroteEarly := waitFor(2*time.Second, func() bool { return nonEmpty(dirB) })
	release()

	resA, resB := <-chA, <-chB
	resA.stop()
	resB.stop()
	if resA.err != nil {
		t.Fatalf("replica A: %v", resA.err)
	}
	if wroteEarly || nonEmpty(dirB) {
		entries, _ := os.ReadDir(dirB)
		t.Fatalf("replica B generated its own key files while replica A had not yet recorded the DEK epoch (two DEKs for one deployment): entries=%v, B err=%v", entries, resB.err)
	}
	if resB.err == nil || !strings.Contains(resB.err.Error(), "refusing to generate a new DEK") {
		t.Fatalf("replica B with its own empty key directory: want the new-DEK refusal, got %v", resB.err)
	}
}
