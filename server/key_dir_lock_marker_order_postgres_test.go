package main

// The key_dir_lock: database marker must be in the database before key
// initialisation, not after initializeCoreService returns (HA-READY-1 review):
// main() takes the presence lock before initializeCoreService, and key init can
// wait up to keyInitLockWait on a sibling, so a marker written afterwards leaves
// a window in which a flock-config `admin --force` is not refused. Gated on
// KEYORIX_TEST_PG_DSN.

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
)

func TestInitializeCoreService_DatabaseKeyDirLock_RecordsModeBeforeKeyInit(t *testing.T) {
	initI18n(t)
	dsn := keyDirLockDSN(t)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "key-dir-lock-test-passphrase")
	cfg := keyDirLockCfg(dsn, t.TempDir(), config.KeyDirLockDatabase)

	// A sibling replica holds the key-initialisation lock: initializeCoreService
	// gets through CreateStorage and then waits inside key initialisation.
	held := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- serverguard.WithKeyInitLock(cfg, time.Minute, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	select {
	case <-held:
	case err := <-lockDone:
		t.Fatalf("could not take the key-initialisation lock: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("timed out taking the key-initialisation lock")
	}
	released := false
	releaseLock := func() {
		if !released {
			released = true
			close(release)
		}
	}
	defer releaseLock()

	type bootResult struct{ err error }
	booted := make(chan bootResult, 1)
	go func() {
		_, enc, err := initializeCoreService(cfg)
		if enc != nil {
			enc.Shutdown()
		}
		booted <- bootResult{err}
	}()

	db := openTestSecretsDBPostgres(t, dsn)
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}()
	recorded := func() bool {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM system_metadata WHERE "key" = ? AND value = ?`,
			config.KeyDirLockModeMetadataKey, config.KeyDirLockDatabase).Scan(&n).Error; err != nil {
			t.Fatalf("read the marker: %v", err)
		}
		return n > 0
	}
	deadline := time.Now().Add(30 * time.Second)
	for !recorded() {
		if time.Now().After(deadline) {
			releaseLock()
			<-booted
			t.Fatal("key_dir_lock marker not recorded while the boot is still inside key initialisation: " +
				"`admin --force` from a flock-config admin would not be refused in that window")
		}
		select {
		case r := <-booted:
			t.Fatalf("initializeCoreService returned (%v) while the key-initialisation lock was held", r.err)
		case <-time.After(100 * time.Millisecond):
		}
	}

	// The boot is still waiting on the lock; it finishes once the sibling lets go.
	select {
	case r := <-booted:
		t.Fatalf("initializeCoreService returned (%v) while the key-initialisation lock was held", r.err)
	default:
	}
	releaseLock()
	if err := <-lockDone; err != nil {
		t.Fatalf("key-initialisation lock holder: %v", err)
	}
	if r := <-booted; r.err != nil {
		t.Fatalf("initializeCoreService after the lock was released: %v", r.err)
	}
}
