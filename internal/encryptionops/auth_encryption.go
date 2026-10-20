// auth_encryption.go — the testable core of `encryption auth-encryption
// status/enable/rotate/migrate/validate`.
package encryptionops

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

func openDatabase(cfg *config.Config) (*gorm.DB, error) {
	// Honor cfg.Storage.Type via the storage package instead of hardwiring SQLite
	// (ADR-049). OpenGormDB does not migrate — these auth-encryption operations
	// run against an already-initialized database.
	return storage.OpenGormDB(cfg)
}

func ShowAuthEncryptionStats(db *gorm.DB, encryptionEnabled bool) error {
	fmt.Println("\n📊 Authentication Data Statistics")
	fmt.Println("-" + string(make([]rune, 32)))

	var apiClientCount, encryptedAPIClientCount int64
	db.Model(&models.APIClient{}).Count(&apiClientCount)
	if encryptionEnabled {
		db.Model(&models.APIClient{}).Where("encrypted_client_secret IS NOT NULL").Count(&encryptedAPIClientCount)
	}
	fmt.Printf("🔑 API Clients: %d total", apiClientCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedAPIClientCount)
	}
	fmt.Println()

	// Sessions have no encrypted-count: the live write path only ever hashes
	// session tokens, never encrypts them, so there is nothing to report (#1641).
	var sessionCount int64
	db.Model(&models.Session{}).Count(&sessionCount)
	fmt.Printf("🎫 Sessions: %d total\n", sessionCount)

	var apiTokenCount, encryptedAPITokenCount int64
	db.Model(&models.APIToken{}).Count(&apiTokenCount)
	if encryptionEnabled {
		db.Model(&models.APIToken{}).Where("encrypted_token IS NOT NULL").Count(&encryptedAPITokenCount)
	}
	fmt.Printf("🎟️  API Tokens: %d total", apiTokenCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedAPITokenCount)
	}
	fmt.Println()

	var resetTokenCount, encryptedResetTokenCount int64
	db.Model(&models.PasswordReset{}).Count(&resetTokenCount)
	if encryptionEnabled {
		db.Model(&models.PasswordReset{}).Where("encrypted_token IS NOT NULL").Count(&encryptedResetTokenCount)
	}
	fmt.Printf("🔄 Reset Tokens: %d total", resetTokenCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedResetTokenCount)
	}
	fmt.Println()

	return nil
}

// AuthStatusWithConfig is the testable core of `encryption auth-encryption
// status`. Read-only.
func AuthStatusWithConfig(cfg *config.Config, passSrc crypto.PassphraseSource) error {
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	if cfg.Storage.Encryption.Enabled && !authEnc.WrappedDEKExists() {
		return missingKeysError(cfg, ".")
	}
	passphrase, _ := MasterPassphrase(cfg, passSrc)
	if err := authEnc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}
	// #292/G62: take the same cross-process shared DEK lock the sibling DEK
	// operations (status/validate/fix-perms/upgrade-aad) already require, so this
	// fails fast instead of racing a concurrent migrate-provider/rotate.
	if err := authEnc.AcquireSharedKeyLock(); err != nil {
		authEnc.Shutdown()
		return fmt.Errorf("%w — a live server or an in-progress rotation/migrate-provider is using this key directory; stop it or wait for it to finish, then retry", err)
	}
	defer authEnc.Shutdown()
	status := authEnc.GetAuthEncryptionStatus()

	fmt.Println("🔐 Authentication Encryption Status")
	fmt.Println("=" + string(make([]rune, 35)))
	if status["enabled"].(bool) {
		fmt.Println("✅ Status: ENABLED")
	} else {
		fmt.Println("❌ Status: DISABLED")
	}
	if status["initialized"].(bool) {
		fmt.Println("✅ Initialized: YES")
		if keyVersion, ok := status["key_version"]; ok {
			fmt.Printf("🔑 Key Version: %s\n", keyVersion)
		}
	} else {
		fmt.Println("❌ Initialized: NO")
	}
	if err := ShowAuthEncryptionStats(db, status["enabled"].(bool)); err != nil {
		fmt.Printf("⚠️  Warning: Could not retrieve statistics: %v\n", err)
	}
	return nil
}

// EnableAuthEncryptionWithConfig is the testable core of `encryption
// auth-encryption enable`.
func EnableAuthEncryptionWithConfig(cfg *config.Config, force bool, passSrc crypto.PassphraseSource) error {
	if !cfg.Storage.Encryption.Enabled && !force {
		return fmt.Errorf("encryption is disabled in configuration. Enable it in config or use --force flag")
	}
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	// #2915: "already enabled" is read from disk BEFORE Initialize — a fresh
	// AuthEncryption is never initialized, so IsInitialized() here could never be
	// true. Initialize (which verifies the passphrase against the existing DEK) and
	// the lock still run; only the final message differs.
	alreadyEnabled := cfg.Storage.Encryption.Enabled && authEnc.WrappedDEKExists() && !force
	passphrase, _ := MasterPassphrase(cfg, passSrc)
	if err := authEnc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}
	// #292/G62: take the same cross-process shared DEK lock the sibling DEK
	// operations (status/validate/fix-perms/upgrade-aad) already require, so this
	// fails fast instead of racing a concurrent migrate-provider/rotate.
	if err := authEnc.AcquireSharedKeyLock(); err != nil {
		authEnc.Shutdown()
		return fmt.Errorf("%w — a live server or an in-progress rotation/migrate-provider is using this key directory; stop it or wait for it to finish, then retry", err)
	}
	defer authEnc.Shutdown()
	if alreadyEnabled {
		fmt.Println("✅ Authentication encryption is already enabled")
		return nil
	}
	fmt.Println("✅ Authentication encryption enabled successfully")
	fmt.Println("🔑 New authentication tokens will be encrypted")
	fmt.Println("💡 Use 'auth-encryption migrate' to encrypt existing plaintext data")
	return nil
}

// RotateAuthEncryptionWithConfig is the testable core of `encryption
// auth-encryption rotate`. Delegates to AuthEncryption.RotateAuthEncryption, a
// true DEK rotation (RotateDEKWithSweep) covering every DEK-encrypted table,
// not just auth-specific ones.
//
// Fixes Finding S13 (docs/cli-split-inventory.md §8): the original CLI
// command took no lock at all at this call site and never called Shutdown()
// on its AuthEncryption, unlike its 4 siblings (status/enable/migrate/
// validate), which all explicitly acquire a lock and defer Shutdown. In
// practice RotateDEKWithSweep already takes the exclusive lock internally
// (idempotent — see Service.AcquireExclusiveKeyLock's doc comment), so the
// original gap was inconsistency and an unreleased-until-process-exit lock
// handle, not an actual unguarded rotation — but "happens to be safe because
// the process exits immediately after" is not a property this admin
// subcommand tree should depend on. This now acquires the exclusive lock
// explicitly, before calling RotateAuthEncryption, so a live server is
// refused with a clear message before any work starts (mirroring
// RotateWithConfig's own explicit call ahead of RotateDEKWithSweep's
// redundant internal one), and releases it deterministically via a deferred
// Shutdown.
//
// Crash safety: identical to RotateWithConfig (same underlying
// RotateDEKWithSweep sweep-transaction + redo-marker mechanism, ADR-010) — a
// kill at any point leaves exactly one of the old or new DEK consistently
// active and every row decryptable under it.
func RotateAuthEncryptionWithConfig(cfg *config.Config, confirm bool, passSrc crypto.PassphraseSource) error {
	if !confirm {
		return fmt.Errorf("key rotation requires --confirm flag. This operation will re-encrypt all authentication data")
	}
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	passphrase, _ := MasterPassphrase(cfg, passSrc)
	authEnc, err := openAuthKeyWriter(cfg, db, passphrase, "rotate")
	if err != nil {
		return err
	}
	defer authEnc.Shutdown()

	fmt.Println("🔄 Starting authentication encryption key rotation...")
	if err := authEnc.RotateAuthEncryption(passphrase); err != nil {
		return fmt.Errorf("failed to rotate auth encryption keys: %w", err)
	}
	fmt.Println("✅ Authentication encryption key rotation completed successfully")
	fmt.Println("🔑 All authentication data has been re-encrypted with new keys")
	return nil
}

// MigrateAuthDataWithConfig is the testable core of `encryption
// auth-encryption migrate`.
func MigrateAuthDataWithConfig(cfg *config.Config, dryRun bool, passSrc crypto.PassphraseSource) error {
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	// migrate writes under the current DEK without rotating it, exactly like
	// upgrade-aad: exclusive, after crash recovery, so it never writes under a
	// DEK an interrupted rotation has already retired (#292/G62 took only the
	// shared lock).
	passphrase, _ := MasterPassphrase(cfg, passSrc)
	authEnc, err := openAuthKeyWriter(cfg, db, passphrase, "migrate authentication data")
	if err != nil {
		return err
	}
	defer authEnc.Shutdown()

	if dryRun {
		fmt.Println("🔍 DRY RUN: Analyzing authentication data for migration...")
	} else {
		fmt.Println("🔄 Migrating authentication data to encrypted storage...")
	}

	// Sessions, API clients, and API tokens are deliberately NOT run through
	// this migration — their columns hold a SHA-256 hash, never plaintext (see
	// models.Session/APIClient/APIToken), so there is no plaintext state for
	// this migration to move out of them. A prior version of this file DID
	// migrate them, treating the hash as if it were a real secret and then
	// NULLing the column in the same update — for sessions that mass-
	// invalidated every logged-in user session while reporting success. See
	// git history for the removed migrateSessions/migrateAPIClients/
	// migrateAPITokens if this ever needs revisiting.
	if err := MigratePasswordResetTokens(db, authEnc, dryRun); err != nil {
		return fmt.Errorf("failed to migrate password reset tokens: %w", err)
	}

	if dryRun {
		fmt.Println("✅ Dry run completed. Use without --dry-run to perform actual migration")
	} else {
		fmt.Println("✅ Authentication data migration completed successfully")
	}
	return nil
}

func MigratePasswordResetTokens(db *gorm.DB, authEnc *encryption.AuthEncryption, dryRun bool) error {
	var resets []models.PasswordReset
	if err := db.Where("token != '' AND encrypted_token IS NULL").Find(&resets).Error; err != nil {
		return err
	}
	fmt.Printf("🔄 Found %d password reset tokens to migrate\n", len(resets))
	if dryRun {
		return nil
	}
	for _, reset := range resets {
		enc, meta, err := authEnc.EncryptPasswordResetToken(reset.Token, reset.UserID)
		if err != nil {
			return fmt.Errorf("failed to encrypt password reset token %d: %w", reset.ID, err)
		}
		// The plaintext column is cleared (set to NULL, not "") in the same update
		// as the encrypted write, and NULL — not "" — avoids colliding with the
		// unique index on this column when a second row is migrated (NULL is
		// exempt from uniqueness checks on every backend this targets).
		if err := db.Model(&reset).Updates(map[string]any{
			"encrypted_token": enc,
			"token_metadata":  meta,
			"token":           nil,
		}).Error; err != nil {
			return fmt.Errorf("failed to update password reset token %d: %w", reset.ID, err)
		}
	}
	return nil
}

// ValidateAuthEncryptionWithConfig is the testable core of `encryption
// auth-encryption validate`. Read-only.
func ValidateAuthEncryptionWithConfig(cfg *config.Config, verbose bool, passSrc crypto.PassphraseSource) error {
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	if cfg.Storage.Encryption.Enabled && !authEnc.WrappedDEKExists() {
		return missingKeysError(cfg, ".")
	}
	passphrase, _ := MasterPassphrase(cfg, passSrc)
	if err := authEnc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}
	// #292/G62: take the same cross-process shared DEK lock the sibling DEK
	// operations (status/validate/fix-perms/upgrade-aad) already require, so this
	// fails fast instead of racing a concurrent migrate-provider/rotate.
	if err := authEnc.AcquireSharedKeyLock(); err != nil {
		authEnc.Shutdown()
		return fmt.Errorf("%w — a live server or an in-progress rotation/migrate-provider is using this key directory; stop it or wait for it to finish, then retry", err)
	}
	defer authEnc.Shutdown()

	fmt.Println("🔍 Validating authentication encryption...")

	var unmigrated int

	// Sessions, API clients, and API tokens are deliberately not validated
	// here, for the identical reason MigrateAuthDataWithConfig skips them —
	// their columns always hold a hash, never plaintext, so there is no
	// "unmigrated plaintext" state to detect. A prior version queried them
	// anyway and reported a permanent false positive on every row.
	n, err := ValidatePasswordResetTokens(db, authEnc, verbose)
	if err != nil {
		return fmt.Errorf("password reset token validation failed: %w", err)
	}
	unmigrated += n

	// A non-zero unmigrated count is reported per-row above and turns this
	// into a non-zero exit rather than a silent pass (#292).
	if unmigrated > 0 {
		fmt.Printf("❌ %d authentication row(s) still hold a plaintext value with no encrypted counterpart — run `auth-encryption migrate`\n", unmigrated)
		return fmt.Errorf("%d authentication row(s) need migration to encrypted storage", unmigrated)
	}

	fmt.Println("✅ All authentication encryption validation checks passed")
	return nil
}

func ValidatePasswordResetTokens(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) (int, error) {
	var resets []models.PasswordReset
	if err := db.Where("encrypted_token IS NOT NULL").Find(&resets).Error; err != nil {
		return 0, err
	}
	if verbose {
		fmt.Printf("🔄 Validating %d encrypted password reset tokens...\n", len(resets))
	}
	for _, reset := range resets {
		if _, err := authEnc.DecryptPasswordResetToken(reset.EncryptedToken, []byte(reset.TokenMetadata), reset.UserID); err != nil {
			return 0, fmt.Errorf("failed to decrypt password reset token %d: %w", reset.ID, err)
		}
		if verbose {
			fmt.Printf("  ✅ Reset Token %d: OK\n", reset.ID)
		}
	}

	var unmigrated []models.PasswordReset
	if err := db.Where("token != '' AND token IS NOT NULL AND encrypted_token IS NULL").Find(&unmigrated).Error; err != nil {
		return 0, err
	}
	for _, reset := range unmigrated {
		fmt.Printf("  ⚠️  Reset Token %d: plaintext token with no encrypted counterpart — needs migration\n", reset.ID)
	}
	return len(unmigrated), nil
}

// openAuthKeyWriter is openKeyWriter for the auth-encryption commands that
// rotate the DEK or write under it (rotate, migrate): the exclusive key lock,
// DEK-rotation crash recovery, existing keys only, then Initialize. The caller
// must Shutdown the returned handler.
func openAuthKeyWriter(cfg *config.Config, db *gorm.DB, passphrase, what string) (*encryption.AuthEncryption, error) {
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	if err := authEnc.AcquireExclusiveKeyLock(); err != nil {
		return nil, fmt.Errorf("refusing to %s: %w — stop the running server before running it", what, err)
	}
	if err := authEnc.RecoverInterruptedRotation(); err != nil {
		authEnc.Shutdown()
		return nil, fmt.Errorf("DEK-rotation crash recovery failed: %w", err)
	}
	if cfg.Storage.Encryption.Enabled && !authEnc.WrappedDEKExists() {
		authEnc.Shutdown()
		return nil, missingKeysError(cfg, ".")
	}
	if err := authEnc.Initialize(passphrase); err != nil {
		authEnc.Shutdown()
		return nil, fmt.Errorf("failed to initialize auth encryption: %w", err)
	}
	return authEnc, nil
}
