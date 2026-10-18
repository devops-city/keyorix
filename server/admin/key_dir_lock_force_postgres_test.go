package admin

// --force must refuse from what the database records about its replicas
// (config.KeyDirLockModeMetadataKey), not only from the admin command's own
// config. Gated on KEYORIX_TEST_PG_DSN.

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestAcquireDatabaseLock_ForceRefusedWhenDatabaseRecordsKeyDirLockMode(t *testing.T) {
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	adminCfg := &config.Config{} // no key_dir_lock: the admin's own config does not say database
	adminCfg.Storage.Type = "postgres"
	adminCfg.Storage.Database.DSN = dsn

	st, err := appstorage.NewStorageFactory().CreateStorage(adminCfg)
	if err != nil {
		t.Fatalf("migrate schema: %v", err)
	}
	if c, ok := st.(interface{ Close() error }); ok {
		defer func() { _ = c.Close() }()
	}

	// A live replica: it holds the shared presence lock.
	replica, err := serverguard.AcquirePresence(adminCfg)
	if err != nil {
		t.Fatalf("replica presence: %v", err)
	}
	defer replica.Release() //nolint:errcheck

	forceFlag = true
	defer func() { forceFlag = false }()

	// Control: nothing recorded, config says nothing -- the documented --force
	// override still applies (single-writer and flock deployments).
	lock, err := acquireDatabaseLock(adminCfg)
	if err != nil {
		t.Fatalf("control: --force with no recorded mode must proceed, got %v", err)
	}
	if lock != nil {
		t.Fatalf("control: expected nil lock, got %v", lock)
	}

	// The replica recorded database mode at boot.
	db := pgAdminRawOpen(t, dsn)
	if err := db.Create(&models.SystemMetadata{Key: config.KeyDirLockModeMetadataKey, Value: config.KeyDirLockDatabase}).Error; err != nil {
		t.Fatal(err)
	}
	lock, err = acquireDatabaseLock(adminCfg)
	if err == nil {
		t.Fatalf("--force proceeded against a database whose replicas recorded key_dir_lock: database (lock=%v)", lock)
	}
	if !strings.Contains(err.Error(), "--force cannot override it") {
		t.Fatalf("unexpected refusal wording: %v", err)
	}
}
