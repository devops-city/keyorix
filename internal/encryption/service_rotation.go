// service_rotation.go — DEK rotation, key ops, and shutdown for Service.
//
// RotateDEKWithSweep, ValidateKeyFiles, FixKeyFilePermissions,
// GetKeyVersion, CleanPendingDEK, Shutdown.
// For encrypt/decrypt see service.go.
package encryption

import (
	"errors"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// dekRotationPromotePendingKey is the system_metadata key of the DEK-sweep rotation redo
// marker. It is written INSIDE the sweep's re-encryption transaction (so it becomes durable
// atomically with the rows moving to the new DEK) and cleared once the new DEK file is
// promoted. Its presence at startup means: the sweep committed (rows are under the NEW DEK)
// but the dek.key.pending → dek.key promotion may not have completed — crash recovery must
// finish it. Its value is the new key version, for the recovery log line. Not secret.
const dekRotationPromotePendingKey = "dek_rotation.promote_pending"

// RotateDEKWithSweep performs a true DEK rotation with a full re-encryption
// sweep of all DEK-encrypted database rows (ADR-010).
//
// The DB transaction is owned here: committed on sweep success, rolled back on
// any failure. The old DEK remains active if anything fails. This is a
// write-locking operation — avoid accepting write traffic during the sweep.
//
// Returns the completed SweepResult so callers (the rotate CLI) can report every
// field of it to the operator, not just the subset logged below.
func (s *Service) RotateDEKWithSweep(passphrase string, db *gorm.DB) (*SweepResult, error) {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return nil, fmt.Errorf("encryption service not initialized")
	}
	s.mu.RUnlock()

	// Refuse to rotate against a live server (#92): if a server holding this DEK
	// is running, promoting a new DEK here would leave it silently encrypting new
	// writes under the OLD key and unable to decrypt rows the sweep re-encrypts,
	// until its next restart — a permanent-loss window if that restart is delayed
	// or never happens. AcquireExclusiveKeyLock is released by the deferred
	// Shutdown() the CLI already calls after this function returns.
	if err := s.AcquireExclusiveKeyLock(); err != nil {
		return nil, fmt.Errorf("refusing to rotate: %w — stop the running server before rotating", err)
	}

	// Ensure the redo-marker table exists before the sweep transaction writes it (the marker
	// is the crash-consistency mechanism — ADR-010). Idempotent: a no-op on a fully-migrated
	// production DB, where system_metadata already exists (bootstrap marker, audit high-water).
	// Keeping it here makes the rotation self-contained so the marker never depends on external
	// migration ordering.
	if err := db.AutoMigrate(&models.SystemMetadata{}); err != nil {
		return nil, fmt.Errorf("ensure rotation redo-marker table: %w", err)
	}

	var sweepResult *SweepResult
	sweepFn := func(oldSvc, newSvc *EncryptionService, newKeyVersion string) (err error) {
		// Cross-replica DEK epoch (#3337, dek_epoch.go; PostgreSQL only): fence
		// every replica's encrypted writes before the sweep, and lift the fence
		// again if the rotation fails before its transaction commits. Registered
		// before the recover below, so it runs after it and sees the panic's err.
		var fence *rotationEpochFence
		if dekEpochApplies(db) {
			if fence, err = fenceDEKEpochForRotation(db, oldSvc); err != nil {
				return err
			}
			defer func() {
				if err != nil {
					fence.lift(db)
				}
			}()
		}
		tx := db.Begin()
		if tx.Error != nil {
			return fmt.Errorf("failed to begin transaction: %w", tx.Error)
		}
		// Named return + explicit assignment here (not a bare "if recover() != nil"): with an
		// unnamed return, recovering from a panic makes this closure return nil regardless of
		// what panicked, so RotateDEKWithSweep below would see err == nil and promote the new
		// DEK / wipe the old one / delete backups even though the sweep transaction was rolled
		// back and the rows never moved to the new DEK. See
		// docs/findings/2026-09-20-FINDING-sweepfn-panic-recovery-swallows-failure.md.
		committed := false
		defer func() {
			if r := recover(); r != nil {
				if committed {
					// Rows and marker are under the new DEK: keep its pending file.
					err = fmt.Errorf("re-encryption sweep panicked after its commit: %v: %w", r, errSweepOutcomeUnknown)
					return
				}
				tx.Rollback()
				err = fmt.Errorf("re-encryption sweep panicked: %v", r)
			}
		}()

		if fence != nil {
			if err := fence.lockSweptTables(tx); err != nil {
				tx.Rollback()
				return err
			}
		}
		result, err := SweepAllTables(tx, oldSvc, newSvc, newKeyVersion, false)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("sweep failed: %w", err)
		}
		if fence != nil {
			// Same transaction as the re-encryption: the epoch names the new DEK
			// exactly when the rows are under it.
			if err := fence.commitNewEpoch(tx, newSvc); err != nil {
				tx.Rollback()
				return err
			}
		}
		// Write-ahead redo marker (crash-consistency, ADR-010): in the SAME transaction as
		// the row re-encryption, record that a new DEK version is committed and its on-disk
		// promotion is pending. This commits atomically with the rows — so if we crash in the
		// window between this commit and the dek.key.pending → dek.key rename that
		// keyManager.RotateDEKWithSweep does next, startup recovery (RecoverInterruptedRotation)
		// sees the marker and finishes the promotion instead of discarding the new DEK. The
		// pending DEK file was already fsync'd (data + dir entry) before this commit, so the
		// invariant "marker durable ⇒ new DEK durably present" always holds.
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
		}).Create(&models.SystemMetadata{Key: dekRotationPromotePendingKey, Value: newKeyVersion}).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to write DEK-rotation redo marker: %w", err)
		}
		if err := tx.Commit().Error; err != nil {
			// A failed COMMIT does not say the transaction did not commit (the
			// connection can drop after the server committed): keep the new DEK.
			return fmt.Errorf("failed to commit sweep transaction: %w (%w)", err, errSweepOutcomeUnknown)
		}
		committed = true

		// Log (and, via the returned SweepResult, report to the CLI operator) every
		// field of the result — not just the original 5 of 8 "Swept" counts. The 3
		// previously-omitted fields here (mfa_secrets, dynamic_secret_configs,
		// dynamic_secret_leases) are exactly the tables #422's sweep-gap fix added;
		// silently under-reporting them left an operator with no visibility into
		// whether that fix's own sweeps ran, even after the data itself was safe.
		log.Printf("✅ Sweep committed: %d secret_versions, %d api_tokens, %d api_clients, %d password_resets, %d mfa_secrets, %d dynamic_secret_configs, %d dynamic_secret_leases, %d notification_channels re-encrypted (%d legacy AAD upgraded)",
			result.SecretVersionsSwept, result.APITokensSwept,
			result.APIClientsSwept, result.AccountResetsSwept, result.MFASecretsSwept,
			result.DynamicSecretConfigsSwept, result.DynamicSecretLeasesSwept,
			result.NotificationChannelsSwept, result.LegacyAADUpgraded)
		sweepResult = result
		return nil
	}

	if err := s.keyManager.RotateDEKWithSweep(passphrase, sweepFn); err != nil {
		return nil, fmt.Errorf("DEK rotation with sweep failed: %w", err)
	}

	// The new DEK is now the active file. Clear the redo marker so a later startup does not
	// treat this completed rotation as interrupted. Best-effort: if it fails (or a crash
	// lands between the rename above and here), recovery still no-ops safely — it finds the
	// marker but no pending file (already renamed away) and just clears it then.
	if err := db.Where("key = ?", dekRotationPromotePendingKey).Delete(&models.SystemMetadata{}).Error; err != nil {
		log.Printf("[WARN] DEK rotation completed but failed to clear the redo marker (harmless — recovery will clear it): %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	dek := s.keyManager.GetDEK()
	encSvc, err := NewEncryptionService(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to recreate encryption service after rotation: %w", err)
	}
	// The old encryption service wraps the now-superseded DEK (a distinct copy from
	// s.keyManager.GetDEK(), not the km.currentDEK slice the key manager itself
	// already wipes) and is about to be discarded — wipe its DEK copy from memory
	// here, like every other DEK-bearing variable in this package.
	if s.encryptionService != nil {
		s.encryptionService.WipeDEK()
	}
	s.encryptionService = encSvc
	return sweepResult, nil
}

// PreviewRotationSweep performs a READ-ONLY dry run of the same table/row
// traversal RotateDEKWithSweep's sweep uses, so an operator can see exactly what a
// real rotation would touch — table names and row counts — before committing to
// that write-locking, irreversible operation.
//
// It makes NO changes whatsoever: the current encryption service is used as BOTH
// oldSvc and newSvc (no new DEK is generated, nothing is written to the key
// directory), SweepAllTables is invoked with dryRun=true (which skips every
// per-row Updates() write while still performing every SELECT/decrypt/re-encrypt/
// count step, so the preview is accurate and would surface a row that couldn't be
// decrypted), and the wrapping transaction is unconditionally rolled back —
// never committed — regardless of outcome.
func (s *Service) PreviewRotationSweep(db *gorm.DB) (*SweepResult, error) {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return nil, fmt.Errorf("encryption service not initialized")
	}
	svc := s.encryptionService
	keyVersion := s.keyManager.GetKeyVersion()
	s.mu.RUnlock()

	tx := db.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}
	// Always rolled back — a dry run must never persist anything, no matter what.
	defer tx.Rollback()
	defer func() {
		if recover() != nil {
			tx.Rollback()
		}
	}()

	result, err := SweepAllTables(tx, svc, svc, keyVersion, true)
	if err != nil {
		return nil, fmt.Errorf("dry-run sweep preview failed: %w", err)
	}
	return result, nil
}

// UpgradeAuthAAD re-encrypts every legacy (pre-#94), no-AAD row in the AAD-bound auth
// tables (mfa_secrets, dynamic_secret_configs, dynamic_secret_leases) UNDER THE
// CURRENT DEK — no key rotation involved. Rows already AAD-bound are re-encrypted
// too (a fresh nonce, same AAD), so the sweep is idempotent and safe to re-run.
//
// This exists so closing the #94 AAD-transplant exposure for these tables doesn't
// require an operator to perform a full, write-locking DEK rotation (RotateDEKWithSweep)
// — a live install can run this on its own schedule (or a one-off CLI invocation)
// while the DEK stays exactly as it was. secret_versions rows are NOT touched here:
// they've been AAD-bound since the M2 migration and are only ever upgraded as a
// side effect of a real DEK rotation's sweep.
//
// The DB transaction is owned here, matching RotateDEKWithSweep: committed on
// success, rolled back on any failure.
func (s *Service) UpgradeAuthAAD(db *gorm.DB) (*SweepResult, error) {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return nil, fmt.Errorf("encryption service not initialized")
	}
	svc := s.encryptionService
	keyVersion := s.keyManager.GetKeyVersion()
	s.mu.RUnlock()

	tx := db.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}
	defer func() {
		if recover() != nil {
			tx.Rollback()
		}
	}()

	result := &SweepResult{}
	sweptMFA, legacyMFA, err := sweepMFASecrets(tx, svc, svc, keyVersion, false)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("mfa_secrets AAD upgrade failed: %w", err)
	}
	result.MFASecretsSwept = sweptMFA
	result.LegacyAADUpgraded += legacyMFA

	sweptDynConfigs, legacyDynConfigs, err := sweepDynamicSecretConfigs(tx, svc, svc, keyVersion, false)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("dynamic_secret_configs AAD upgrade failed: %w", err)
	}
	result.DynamicSecretConfigsSwept = sweptDynConfigs
	result.LegacyAADUpgraded += legacyDynConfigs

	sweptDynLeases, legacyDynLeases, err := sweepDynamicSecretLeases(tx, svc, svc, keyVersion, false)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("dynamic_secret_leases AAD upgrade failed: %w", err)
	}
	result.DynamicSecretLeasesSwept = sweptDynLeases
	result.LegacyAADUpgraded += legacyDynLeases

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit AAD upgrade transaction: %w", err)
	}
	log.Printf("✅ AAD upgrade committed: %d mfa_secrets, %d dynamic_secret_configs, %d dynamic_secret_leases re-encrypted (%d legacy AAD upgraded)",
		result.MFASecretsSwept, result.DynamicSecretConfigsSwept, result.DynamicSecretLeasesSwept, result.LegacyAADUpgraded)
	return result, nil
}

// RotateKEKPassphrase changes the master passphrase without re-encrypting the
// database. It re-wraps the current DEK under a new KEK derived from
// newPassphrase + a fresh random salt. The DEK value is unchanged, so all
// existing ciphertext stays valid. Evidence-signing and audit-checkpoint key
// fingerprints will change because those keys are KEK-derived.
//
// The old passphrase is verified against the on-disk wrapped DEK before any
// file is modified. The server must be stopped (exclusive key lock must not
// be held by another process) before running this command.
func (s *Service) RotateKEKPassphrase(oldPassphrase, newPassphrase string) error {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return fmt.Errorf("encryption service not initialized")
	}
	s.mu.RUnlock()

	// Self-enforce the same exclusive server-vs-CLI lock RotateDEKWithSweep and
	// RewrapDEKWithProvider already take internally, rather than relying solely on
	// the CLI caller (rotate-kek) to acquire it first, as defense in depth.
	// Idempotent — a no-op if this Service (or its caller) already holds it.
	if err := s.AcquireExclusiveKeyLock(); err != nil {
		return fmt.Errorf("refusing to rotate KEK: %w — stop the running server before rotating", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyManager.RotateKEKPassphrase(oldPassphrase, newPassphrase)
}

// RewrapDEKWithProvider re-wraps the in-memory DEK with a KEK from newProvider and
// atomically replaces the on-disk wrapped DEK (ADR-041 KEK-provider migration). The
// DEK value is unchanged, so every existing ciphertext stays valid — only the
// wrapping key changes; no data is re-encrypted and no DB lock is taken. The
// service must already be Initialized with the CURRENT provider. The caller should
// then verify the new provider unwraps the DEK before discarding the previous
// wrapped-DEK backup.
func (s *Service) RewrapDEKWithProvider(newProvider crypto.KeyProvider) error {
	s.mu.RLock()
	if !s.initialized {
		s.mu.RUnlock()
		return fmt.Errorf("encryption service not initialized")
	}
	s.mu.RUnlock()

	// Refuse to re-wrap against a live server (#92, mirroring RotateDEKWithSweep):
	// without this, a concurrent `migrate-provider` run and a live server (or a
	// concurrent rotation) could race on the same dek.key.pending → dek.key path.
	// AcquireExclusiveKeyLock is released by the deferred Shutdown() the CLI
	// already calls after this function returns.
	if err := s.AcquireExclusiveKeyLock(); err != nil {
		return fmt.Errorf("refusing to re-wrap DEK: %w — stop the running server before migrating the KEK provider", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyManager.RewrapDEK(newProvider)
}

// ValidateKeyFiles validates encryption key files exist with correct
// permissions -- the DEK/salt (ADR-004) plus any KeyProviderConfig-driven key
// material (TPM/cloud-KMS wrapped-KEK blob, Shamir share files) s.config
// declares; see internal/keyfiles.Registry.
func (s *Service) ValidateKeyFiles() error {
	return s.keyManager.ValidateKeyFiles(s.config)
}

// FixKeyFilePermissions fixes key file permissions to 0600, for the same set
// ValidateKeyFiles checks.
func (s *Service) FixKeyFilePermissions() error {
	return s.keyManager.FixKeyFilePermissions(s.config)
}

// GetKeyVersion returns the current key version string.
func (s *Service) GetKeyVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.initialized {
		return "unknown"
	}
	return s.keyManager.GetKeyVersion()
}

// CleanPendingDEK removes a leftover dek.key.pending file from an interrupted rotation.
// Call at startup before Initialize.
func (s *Service) CleanPendingDEK() {
	s.keyManager.CleanPendingDEK()
}

// RecoverInterruptedRotation completes or discards an interrupted DEK-sweep rotation
// (ADR-010) using the write-ahead redo marker in system_metadata. It MUST run at startup,
// BEFORE Initialize (so Initialize then loads whichever DEK this settles on), while holding
// the exclusive key lock, and it needs a DB handle for the local (sqlite/postgres) backend
// the sweep runs against.
//
//   - marker PRESENT  ⇒ the sweep's transaction committed, so the DB rows are already under
//     the NEW DEK. Promote dek.key.pending → dek.key (PromotePendingDEK is idempotent: a
//     no-op if the rename already happened), then clear the marker. This is the fix for the
//     crash window between the sweep commit and the file rename — without it CleanPendingDEK
//     would discard the only copy of the new DEK and every swept row would be unrecoverable.
//   - marker ABSENT   ⇒ no committed sweep. Any dek.key.pending is a leftover from a
//     pre-commit crash (or an interrupted KEK-rotation/rewrap, which keep the SAME DEK), so
//     discard it — the existing CleanPendingDEK behavior, which is correct there.
//
// Deterministic, no data-probing: the marker either committed with the rows or it did not.
func (s *Service) RecoverInterruptedRotation(db *gorm.DB) error {
	if db == nil {
		// No local DB to consult (e.g. remote storage): fall back to the leftover-cleanup
		// behavior. A remote backend does not run this sweep, so no marker can exist.
		s.CleanPendingDEK()
		return nil
	}
	// On a brand-new install the schema may not be migrated yet; no table ⇒ no marker.
	if !db.Migrator().HasTable(&models.SystemMetadata{}) {
		s.CleanPendingDEK()
		return nil
	}

	var m models.SystemMetadata
	err := db.Where("key = ?", dekRotationPromotePendingKey).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		s.CleanPendingDEK() // no committed rotation → discard any stray pending file
		return nil
	}
	if err != nil {
		return fmt.Errorf("read DEK-rotation redo marker: %w", err)
	}

	// Marker present ⇒ the sweep committed under a new DEK. Finish the promotion.
	if err := s.keyManager.PromotePendingDEK(); err != nil {
		return fmt.Errorf("recover interrupted DEK rotation (promote): %w", err)
	}
	if err := db.Where("key = ?", dekRotationPromotePendingKey).Delete(&models.SystemMetadata{}).Error; err != nil {
		return fmt.Errorf("recover interrupted DEK rotation (clear marker): %w", err)
	}
	log.Printf("recovered interrupted DEK rotation: promoted pending DEK to active (new key version %s)", m.Value)
	return nil
}

// AcquireExclusiveKeyLock takes an exclusive, non-blocking OS advisory lock on
// the key directory, so no OTHER process using the same DEK — another server
// instance, or a concurrent rotation — can hold it at the same time (#92). The
// server calls this BEFORE Initialize (not after — see server/main.go's
// initializeEncryption), so first-boot key generation itself
// (ensureSaltExists/ensureWrappedDEKExists in keymanager_lifecycle.go, an
// unlocked check-then-write) is race-protected too, not just steady-state DEK
// access; the lock is then held for the server's whole lifetime. Rotation
// calls it at the start of RotateDEKWithSweep, after its own Initialize has
// already run (held only for the sweep). Either way it is released by
// Shutdown. Deliberately does NOT require the Service to be initialized: the
// lock only needs keyManager.baseDir, which is fixed at construction
// (NewService/NewKeyManager), so it can be taken before any key material
// exists on disk — unlike AcquireSharedKeyLock, which is only ever used after
// Initialize by read-only CLI commands. Idempotent: a second call while
// already held by this Service is a no-op.
func (s *Service) AcquireExclusiveKeyLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serverLock != nil {
		return nil
	}
	f, err := acquireExclusiveKeyLock(s.keyManager.baseDir, s.keyManager.dekPath)
	if err != nil {
		return err
	}
	s.serverLock = f
	return nil
}

// WrappedDEKExists reports whether the wrapped DEK file is already on disk, i.e.
// whether Initialize will load existing key material rather than generate it.
// Read it before Initialize (AuthEncryption.WrappedDEKExists is the same check).
func (s *Service) WrappedDEKExists() bool {
	return s.keyManager.wrappedDEKExists()
}

// AcquireSharedKeyLock takes a shared, non-blocking OS advisory lock on the same
// key-directory lock file AcquireExclusiveKeyLock uses (#196). It is for local,
// short-lived CLI commands that read (or, for upgrade-aad, write under) the
// CURRENT DEK without themselves rotating it — status/validate/fix-perms/
// upgrade-aad/init. Unlike AcquireExclusiveKeyLock, any number of Services can
// hold the shared lock at the same time, so ordinary concurrent CLI invocations
// never contend with each other over it — but it is refused outright while a
// live server or an in-progress rotation/migrate-provider holds the lock
// exclusively, so those commands fail fast instead of racing a DEK that's
// concurrently being replaced. Released by Shutdown, same as the exclusive
// lock. Idempotent: a second call while this Service already holds either kind
// of lock is a no-op.
func (s *Service) AcquireSharedKeyLock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		return fmt.Errorf("encryption service not initialized")
	}
	if s.serverLock != nil {
		return nil
	}
	f, err := acquireSharedKeyLock(s.keyManager.baseDir, s.keyManager.dekPath)
	if err != nil {
		return err
	}
	s.serverLock = f
	return nil
}

// Shutdown cleanly wipes the DEK from memory and releases the exclusive key
// lock, if this Service was holding one.
func (s *Service) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch != nil {
		s.epoch.close()
		s.epoch = nil
	}
	if s.keyManager != nil {
		s.keyManager.Wipe()
	}
	// s.keyManager.Wipe() only zeroes km.currentDEK — s.encryptionService.dek is a
	// separate copy (made via s.keyManager.GetDEK() in Initialize/RotateDEKWithSweep)
	// and was never wiped, unlike every other DEK-bearing variable in this package.
	if s.encryptionService != nil {
		s.encryptionService.WipeDEK()
		s.encryptionService = nil
	}
	releaseKeyLock(s.serverLock)
	s.serverLock = nil
	s.initialized = false
}

// AcquireKeyFileReadLock holds the key-file REWRITE lock (<dek_path>.lock,
// see keymanager_filelock.go) in SHARED mode and returns its release func.
// While it is held, no key-file rewriter (DEK rotation and its re-encryption
// sweep, KEK-passphrase rotation, provider migration) can write -- each takes
// that lock exclusively for its whole write -- so a caller reading the key
// files and a database snapshot under it gets a mutually consistent pair.
//
// It is NOT the server-vs-CLI dek.lock (AcquireExclusiveKeyLock/
// AcquireSharedKeyLock) and does not conflict with a live server, which
// holds dek.lock for its lifetime but never rewrites key files after
// startup. Its one caller is `admin backup`'s live-server path (#2602).
// Deliberately does NOT require the Service to be initialized: it needs only
// the configured key paths, and its caller never initializes against the
// live key directory.
func (s *Service) AcquireKeyFileReadLock() (release func(), err error) {
	if s.keyManager.configErr != nil {
		return nil, s.keyManager.configErr
	}
	l, err := s.keyManager.tryAcquireSharedKeyLock()
	if err != nil {
		return nil, err
	}
	return l.release, nil
}
