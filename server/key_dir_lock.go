package main

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// keyInitLockWait bounds how long a replica waits for a sibling holding the
// key-initialisation lock (first-boot key generation or rotation crash
// recovery, each well under a minute) before it gives up and exits.
const keyInitLockWait = 2 * time.Minute

// initializeKeys runs svc.Initialize with initializeEncryption's error wording.
func initializeKeys(svc *encryption.Service, passphrase, providerType string) error {
	if err := svc.Initialize(passphrase); err != nil {
		if providerType == "" || providerType == "password" {
			// Name the source (BOOT-REFUSALS-1 item 7): with several ways to pass the
			// passphrase, "wrong passphrase" alone does not say which one was read.
			return fmt.Errorf("KEK derivation from the master passphrase read from %s failed: %w", masterPassphraseSource.Describe("KEYORIX_MASTER_PASSWORD"), err)
		}
		return fmt.Errorf("KEK from key provider %q failed: %w", providerType, err)
	}
	return nil
}

// initializeKeysUnderDatabaseLock runs boot (rotation crash recovery, then
// Initialize) for storage.encryption.key_dir_lock: database
// (docs/multi-replica-keys.md). No key-directory flock is taken, at boot or
// afterwards:
//
//   - Two replicas starting on one fresh shared key directory serialise on the
//     key-initialisation advisory lock (serverguard.WithKeyInitLock). The first
//     generates the key files; the second waits, then finds and loads them.
//   - Key-changing admin commands (rotate, rotate-kek, migrate-provider,
//     restore, ...) are kept out for the server's lifetime by the shared
//     server-presence lock main() took before this runs: they need it
//     exclusively. --force cannot bypass it in this mode (server/admin).
//
// It also refuses first-boot key generation when the database already holds
// encrypted secret versions. Under the flock a replica with its own empty key
// directory (a per-pod volume, a Secret that failed to mount) could not reach
// this point next to a sibling on the shared directory; here it can, and
// generating a new DEK would split the deployment into replicas writing under
// two DEKs.
func initializeKeysUnderDatabaseLock(cfg *config.Config, svc *encryption.Service, boot func() error) error {
	return serverguard.WithKeyInitLock(cfg, keyInitLockWait, func() error {
		if !svc.WrappedDEKExists() {
			if err := refuseKeyGenerationOverEncryptedData(cfg); err != nil {
				return err
			}
		}
		return boot()
	})
}

// recordKeyDirLockMode writes the database-mode marker server/admin reads to
// refuse --force (config.KeyDirLockModeMetadataKey). Only database-mode servers
// call it; a failure is fatal for the boot, because an unrecorded database-mode
// replica would leave --force available against it.
func recordKeyDirLockMode(cfg *config.Config) error {
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database to record the key_dir_lock mode: %w", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		defer func() { _ = sqlDB.Close() }()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now()
	return db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemMetadata{Key: config.KeyDirLockModeMetadataKey, Value: config.KeyDirLockDatabase, UpdatedAt: now}).Error
}

// refuseKeyGenerationOverEncryptedData returns an error when cfg's database
// already holds at least one secret version. Called only when the wrapped DEK
// is missing, i.e. when Initialize would generate a new one.
//
// Two signals: the recorded DEK epoch (set by the first replica's boot, so it
// also catches a deployment with no secret yet), and secret_versions, where
// every secret value lives. A database with encrypted MFA or dynamic-secret rows
// but neither is not caught. Two replicas with separate empty key directories
// booting at the same instant, before the first has recorded its epoch, are
// still only stopped by the epoch guard (StartDEKEpochGuard) after the loser
// wrote its key files.
func refuseKeyGenerationOverEncryptedData(cfg *config.Config) error {
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database to check for existing encrypted data: %w", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		defer func() { _ = sqlDB.Close() }()
	}
	// A recorded DEK epoch means a replica already generated this deployment's
	// DEK (before any secret exists too). A replica with its own empty key
	// directory must stop here, before Initialize writes a second set of key
	// files that the epoch guard would only reject afterwards.
	if db.Migrator().HasTable(&models.SystemMetadata{}) {
		var epoch bool
		if err := db.Raw(`SELECT EXISTS (SELECT 1 FROM system_metadata WHERE "key" = ?)`, encryption.DEKEpochMetadataKey).Scan(&epoch).Error; err != nil {
			return fmt.Errorf("failed to check for an existing DEK epoch: %w", err)
		}
		if epoch {
			return fmt.Errorf("no wrapped DEK at %q, but the database already records a DEK epoch (another replica generated the deployment's DEK): refusing to generate a new DEK. "+
				"With storage.encryption.key_dir_lock: database every replica must read the same key files (one shared volume, or the same mounted Secret); "+
				"copy the key set from a running replica or restore it from backup (docs/multi-replica-keys.md)", cfg.Storage.Encryption.DEKPath)
		}
	}
	if !db.Migrator().HasTable(&models.SecretVersion{}) {
		return nil
	}
	// Raw, not db.Model: GORM's soft-delete scope would skip deleted rows, which
	// are still encrypted under the existing DEK.
	var exists bool
	if err := db.Raw("SELECT EXISTS (SELECT 1 FROM secret_versions)").Scan(&exists).Error; err != nil {
		return fmt.Errorf("failed to check for existing encrypted data: %w", err)
	}
	if exists {
		return fmt.Errorf("no wrapped DEK at %q, but the database already holds encrypted secret versions: refusing to generate a new DEK. "+
			"With storage.encryption.key_dir_lock: database every replica must read the same key files (one shared volume, or the same mounted Secret); "+
			"copy the key set from a running replica or restore it from backup (docs/multi-replica-keys.md)", cfg.Storage.Encryption.DEKPath)
	}
	return nil
}
