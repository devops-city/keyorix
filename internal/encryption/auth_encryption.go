// auth_encryption.go — AuthEncryption struct, constructor, and per-token-type encrypt/decrypt.
//
// Thin typed wrappers over Service.EncryptSecret/DecryptSecret for each auth token category.
// For rotation see auth_encryption_rotate.go.
//
// Each encrypt/decrypt method now accepts the owning user/token ID as AAD so a
// database-WRITE attacker cannot transplant an encrypted token blob between rows
// (AUTH-CRYPTO-001/002). Legacy rows encrypted without AAD (pre-fix) are decrypted
// via the fallback path in DecryptSecretWithAAD — the warning log on that path drives
// re-encryption in the next M2 sweep. New tokens are always sealed with AAD.
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"gorm.io/gorm"
)

// AuthEncryption handles encryption for authentication-related data.
type AuthEncryption struct {
	service *Service
	db      *gorm.DB
}

// NewAuthEncryption creates a new AuthEncryption handler.
func NewAuthEncryption(cfg *config.EncryptionConfig, baseDir string, db *gorm.DB) *AuthEncryption {
	return &AuthEncryption{
		service: NewService(cfg, baseDir),
		db:      db,
	}
}

// Initialize initialises the underlying encryption service.
// passphrase is forwarded to the key manager for KEK derivation — never stored.
func (ae *AuthEncryption) Initialize(passphrase string) error {
	if !ae.service.IsEnabled() {
		return nil
	}
	return ae.service.Initialize(passphrase)
}

// WrappedDEKExists reports whether the wrapped DEK file is already on disk, i.e.
// whether Initialize will load existing key material rather than generate it.
// Meant to be read BEFORE Initialize (#2915): IsInitialized is always false on a
// freshly constructed AuthEncryption, so it cannot answer "was this already set up".
func (ae *AuthEncryption) WrappedDEKExists() bool {
	return ae.service.keyManager.wrappedDEKExists()
}

// AcquireSharedKeyLock takes the same cross-process shared DEK lock
// (Service.AcquireSharedKeyLock, #196) the DEK-focused local CLI commands
// (status/validate/fix-perms/upgrade-aad) already require, for the sibling
// auth-encryption commands (status/enable/migrate/validate) that read (or, for
// migrate, write under) the CURRENT DEK without themselves rotating it. Refused
// while a live server or an in-progress rotation/migrate-provider holds the lock
// exclusively, so those commands fail fast instead of racing a DEK that's
// concurrently being replaced. A no-op when encryption is disabled, matching
// Initialize's own no-op in that case (there is no DEK to guard).
func (ae *AuthEncryption) AcquireSharedKeyLock() error {
	if !ae.service.IsEnabled() {
		return nil
	}
	return ae.service.AcquireSharedKeyLock()
}

// AcquireExclusiveKeyLock takes the same cross-process exclusive DEK lock
// (Service.AcquireExclusiveKeyLock) that RotateAuthEncryption's underlying
// RotateDEKWithSweep already takes internally. Calling it explicitly here,
// before RotateAuthEncryption, makes `auth-encryption rotate`'s locking
// behavior symmetric with the DEK-focused `encryption rotate` (which also
// acquires it explicitly ahead of RotateDEKWithSweep's own internal,
// idempotent call) instead of relying solely on that internal call --
// Finding S13 (docs/cli-split-inventory.md §8): the original CLI command
// took no lock at all at this layer, unlike its 4 siblings
// (status/enable/migrate/validate), which all call AcquireSharedKeyLock
// explicitly before doing their own work. A no-op when encryption is
// disabled, matching AcquireSharedKeyLock's own no-op in that case.
func (ae *AuthEncryption) AcquireExclusiveKeyLock() error {
	if !ae.service.IsEnabled() {
		return nil
	}
	return ae.service.AcquireExclusiveKeyLock()
}

// RecoverInterruptedRotation runs Service.RecoverInterruptedRotation against this
// handler's database. A command that rotates or writes under the DEK calls it
// after AcquireExclusiveKeyLock and before Initialize, so a rotation killed
// between its sweep commit and the dek.key.pending rename is finished, never
// discarded (INV-ENCRYPTION-pending-dek-kept-after-commit). A no-op when
// encryption is disabled.
func (ae *AuthEncryption) RecoverInterruptedRotation() error {
	if !ae.service.IsEnabled() {
		return nil
	}
	return ae.service.RecoverInterruptedRotation(ae.db)
}

// Shutdown releases resources held by the underlying encryption Service —
// wiping the DEK from memory and releasing the key lock if AcquireSharedKeyLock
// (or Initialize's own exclusive-lock paths, e.g. via RotateAuthEncryption) took
// one. Safe to call even if encryption is disabled or Initialize was never
// called.
func (ae *AuthEncryption) Shutdown() {
	ae.service.Shutdown()
}

// GetAuthEncryptionStatus returns the current authentication encryption status.
func (ae *AuthEncryption) GetAuthEncryptionStatus() map[string]any {
	status := map[string]any{
		"enabled":     ae.service.IsEnabled(),
		"initialized": ae.service.IsInitialized(),
	}
	if ae.service.IsInitialized() {
		status["key_version"] = ae.service.GetKeyVersion()
	}
	return status
}

// EncryptClientSecret encrypts an API client secret.
func (ae *AuthEncryption) EncryptClientSecret(plainSecret string) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		return []byte(plainSecret), nil, nil
	}
	enc, meta, err := ae.service.EncryptSecret([]byte(plainSecret))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt client secret: %w", err)
	}
	return enc, meta, nil
}

// DecryptClientSecret decrypts an API client secret.
func (ae *AuthEncryption) DecryptClientSecret(encryptedData, metadata []byte) (string, error) {
	if !ae.service.IsEnabled() {
		return string(encryptedData), nil
	}
	plain, err := ae.service.DecryptSecret(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt client secret: %w", err)
	}
	return string(plain), nil
}

// EncryptAPIToken encrypts an API token bound to the issuing user (AUTH-CRYPTO-002).
func (ae *AuthEncryption) EncryptAPIToken(plainToken string, userID uint) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		return []byte(plainToken), nil, nil
	}
	enc, meta, err := ae.service.EncryptSecretWithAAD([]byte(plainToken), APITokenAAD(userID))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt API token: %w", err)
	}
	return enc, meta, nil
}

// DecryptAPIToken decrypts an API token. Legacy rows fall back via DecryptSecretWithAAD.
func (ae *AuthEncryption) DecryptAPIToken(encryptedData, metadata []byte, userID uint) (string, error) {
	if !ae.service.IsEnabled() {
		return string(encryptedData), nil
	}
	plain, err := ae.service.DecryptSecretWithAAD(encryptedData, APITokenAAD(userID))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API token: %w", err)
	}
	return string(plain), nil
}

// EncryptPasswordResetToken encrypts a password reset token bound to the owning user.
func (ae *AuthEncryption) EncryptPasswordResetToken(plainToken string, userID uint) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		return []byte(plainToken), nil, nil
	}
	enc, meta, err := ae.service.EncryptSecretWithAAD([]byte(plainToken), PasswordResetTokenAAD(userID))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt password reset token: %w", err)
	}
	return enc, meta, nil
}

// DecryptPasswordResetToken decrypts a password reset token. Legacy rows fall back.
func (ae *AuthEncryption) DecryptPasswordResetToken(encryptedData, metadata []byte, userID uint) (string, error) {
	if !ae.service.IsEnabled() {
		return string(encryptedData), nil
	}
	plain, err := ae.service.DecryptSecretWithAAD(encryptedData, PasswordResetTokenAAD(userID))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password reset token: %w", err)
	}
	return string(plain), nil
}
