package main

import (
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"gorm.io/gorm"
)

// masterPassphraseSource holds --passphrase-fd/--passphrase-file/--passphrase-stdin
// once main() parses flags. Zero value (all unset) makes initializeEncryption fall
// back to KEYORIX_MASTER_PASSWORD, matching this binary's historical behavior --
// including under `go test`, which never calls main() and so never touches this var.
var masterPassphraseSource crypto.PassphraseSource

// initializeEncryption sources the KEK per the configured key provider (ADR-038)
// and returns an initialized encryption.Service. If encryption is disabled in
// config, it returns nil without error. For the default "password" provider it
// requires a master passphrase, sourced per ADR-099 (masterPassphraseSource --
// --passphrase-fd, then --passphrase-file, then --passphrase-stdin, then
// KEYORIX_MASTER_PASSWORD as the weakest fallback); for the "file"/"env"
// providers the KEK comes from key material elsewhere, so no passphrase is
// needed. auditSink, if non-nil, is wired before Initialize so that a
// key_provider.fallbacks chain actually downgrading KEK strength on THIS boot
// (not just one the config permits) is recorded as a queryable audit event
// rather than only a log line — pass store.LogAuditEvent once storage is
// available; nil is fine (tests, or contexts without a live audit trail) and
// falls back to logging only.
func initializeEncryption(cfg *config.Config, auditSink encryption.AuditSink) (*encryption.Service, error) {
	if !cfg.Storage.Encryption.Enabled {
		encryption.RegisterDisabledMetrics()
		return nil, nil
	}

	providerType := cfg.Storage.Encryption.KeyProvider.Type
	var passphrase string
	if providerType == "" || providerType == "password" {
		passphraseBytes, err := crypto.ResolvePassphrase(masterPassphraseSource, "KEYORIX_MASTER_PASSWORD")
		if err != nil {
			return nil, fmt.Errorf(
				"encryption is enabled with the password key provider but no master passphrase is "+
					"available (%w); set KEYORIX_MASTER_PASSWORD, pass --passphrase-fd/--passphrase-file/"+
					"--passphrase-stdin, or configure storage.encryption.key_provider (file/env/aws-kms)", err)
		}
		defer crypto.WipeBytes(passphraseBytes)
		passphrase = string(passphraseBytes)
	}

	// Always ".". An absolute dek_path/salt_path is reconciled by
	// NewKeyManager (normalizeKeyPaths), which is where every other
	// encryption.NewService caller benefits from it too -- the six CLI call
	// sites included, so `keyorix-server admin encryption ...` can operate on the same key
	// files this server just created.
	//
	// This previously set baseDir="" for an absolute DEKPath, meaning "the
	// path is self-contained, no base-dir restriction". No securefiles
	// primitive implements that convention: isPathInsideBase resolves "" to
	// the working directory and rejected the key file as outside it, so a
	// deployment configuring an absolute key path could never complete
	// first-boot key generation.
	baseDir := "."
	svc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	encryption.RegisterMetrics(svc)
	if auditSink != nil {
		svc.SetAuditSink(auditSink)
	}
	// Acquire the exclusive DEK lock BEFORE Initialize, not after. Initialize
	// performs first-boot key generation (ensureSaltExists/ensureWrappedDEKExists
	// in keymanager_lifecycle.go), which is an unlocked check-then-write: two
	// processes racing a shared, fresh key directory (e.g. two HA replicas'
	// simultaneous first boot) could each pass the not-exists check before
	// either wrote, silently clobbering or interleaving each other's salt/DEK
	// files. That failure is not even immediate — it surfaces as a delayed,
	// confusing "wrong passphrase or corrupted key file" on a LATER restart,
	// not a clear error at the moment of the actual race. Holding the exclusive
	// DEK lock — the same lock this server keeps for its whole lifetime anyway,
	// so DEK rotation (a separate CLI process) can never promote a new DEK
	// while this server still has the old one cached in memory (#92) — across
	// the ENTIRE first-boot sequence closes the race at its root: whichever
	// process wins the flock proceeds, the other is refused immediately with a
	// clear lock-contention error, before it ever touches a key file. Refuses
	// to start if another live holder (another server instance, or an
	// in-progress rotation) already has it.
	//
	// storage.encryption.key_dir_lock: database (several replicas on PostgreSQL,
	// docs/multi-replica-keys.md) takes no flock: the same steps run under a
	// PostgreSQL advisory lock instead (initializeKeysUnderDatabaseLock).
	if !cfg.Storage.Encryption.KeyDirLockIsDatabase() {
		if err := svc.AcquireExclusiveKeyLock(); err != nil {
			return nil, fmt.Errorf("failed to acquire the encryption key lock: %w", err)
		}
	}
	// Recover any interrupted DEK-sweep rotation BEFORE Initialize, so Initialize loads the
	// correct (possibly just-promoted) active DEK. Runs under the key lock (above, or the
	// database one). For a local backend it consults the DB's redo marker to decide whether to promote
	// the pending DEK (a rotation that committed its re-encryption sweep but crashed before the
	// dek.key file rename) or discard a stray pending file; for remote storage there is no
	// local sweep, so it falls back to the leftover-cleanup behavior.
	// bootKeys returns the database handle the DEK epoch guard keeps (nil for
	// remote storage).
	bootKeys := func() (*gorm.DB, error) {
		if cfg.Storage.Type == "remote" {
			svc.CleanPendingDEK()
			return nil, initializeKeys(svc, passphrase, providerType)
		}
		recoverDB, derr := appstorage.OpenGormDB(cfg)
		if derr != nil {
			return nil, fmt.Errorf("failed to open database for DEK-rotation crash recovery: %w", derr)
		}
		if rerr := svc.RecoverInterruptedRotation(recoverDB); rerr != nil {
			closeGormDB(recoverDB)
			return nil, fmt.Errorf("DEK-rotation crash recovery failed: %w", rerr)
		}
		if err := initializeKeys(svc, passphrase, providerType); err != nil {
			closeGormDB(recoverDB)
			return nil, err
		}
		return recoverDB, nil
	}
	// Then the cross-replica DEK epoch guard, under the same key lock
	// (initializeKeysAndStartEpochGuard).
	if err := initializeKeysAndStartEpochGuard(cfg, svc, bootKeys); err != nil {
		return nil, err
	}

	kekSource := providerType
	if kekSource == "" {
		kekSource = "password"
	}
	log.Printf("Encryption initialised — KEK source: %s, key version: %s", kekSource, svc.GetKeyVersion())
	return svc, nil
}
