// Package encryptionops holds the "testable core" of every `encryption`
// family operation (ADR-108 §B3, docs/cli-split-inventory.md §7 PR 12): DEK
// rotation, KEK-provider migration, KEK-passphrase rotation, and
// authentication-data encryption. Both the old dual-mode CLI
// (internal/cli/encryption) and the new `keyorix-server admin encryption`
// subcommand tree (server/admin) call into this package so the actual
// operations exist exactly once — this package has no cobra or
// internal/cli/common dependency, only explicit parameters, so either caller
// can wire its own flags/output on top of it.
//
// Every exported *WithConfig function takes an explicit *config.Config plus
// whatever confirm/dry-run/passphrase-source values its caller resolved from
// its own flags — no package-level state, no config loading, no flag
// parsing. Validation gates (encryption disabled, remote storage, missing
// --confirm) return before any key-file or database work, so unit tests
// don't need real key files or a database for the negative paths.
package encryptionops

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/storage"
	"gorm.io/gorm"
)

// MasterPassphraseEnvVar is the environment variable carrying the CURRENT
// master passphrase — the weakest of ADR-099's sourcing options, kept as the
// last-resort fallback behind src's FD/file/stdin precedence.
const MasterPassphraseEnvVar = "KEYORIX_MASTER_PASSWORD" // #nosec G101 -- env var name, not a credential

// NewMasterPassphraseEnvVar is the environment variable carrying a NEW master
// passphrase, for the commands (rotate-kek, migrate-provider) that change it.
const NewMasterPassphraseEnvVar = "KEYORIX_NEW_MASTER_PASSWORD" // #nosec G101 -- env var name, not a credential

// MasterPassphrase resolves the current master passphrase per ADR-099's
// precedence (src's FD, then file, then stdin, then MasterPassphraseEnvVar as
// the weakest fallback). It is required only for the default "password" key
// provider; with the file/env/kms/etc. providers (ADR-038/041) the KEK comes
// from key material elsewhere, so it returns "" without error and
// Service.Initialize sources the KEK from the provider instead. The single
// chokepoint every function in this package calls through, so sourcing and
// wiping apply everywhere uniformly.
func MasterPassphrase(cfg *config.Config, src crypto.PassphraseSource) (string, error) {
	if t := cfg.Storage.Encryption.KeyProvider.Type; t != "" && t != "password" {
		return "", nil
	}
	passphraseBytes, err := crypto.ResolvePassphrase(src, MasterPassphraseEnvVar)
	if err != nil {
		return "", err
	}
	defer crypto.WipeBytes(passphraseBytes)
	return string(passphraseBytes), nil
}

// requireExistingKeys refuses when the wrapped DEK is not where the config
// says. Service.Initialize generates a new salt and DEK when they are missing,
// which only `init` (and a server's first boot) may do: every other command
// works on an existing install's keys, and run from the wrong directory (key
// paths are resolved against it), with a wrong dek_path or an unmounted volume
// it would otherwise act on brand-new keys and report success (REVIEW-COVERAGE-2).
func requireExistingKeys(cfg *config.Config, service *encryption.Service, baseDir string) error {
	if service.WrappedDEKExists() {
		return nil
	}
	return missingKeysError(cfg, baseDir)
}

// missingKeysError is requireExistingKeys' refusal.
func missingKeysError(cfg *config.Config, baseDir string) error {
	if abs, err := filepath.Abs(baseDir); err == nil {
		baseDir = abs
	}
	dekPath := cfg.Storage.Encryption.DEKPath
	if !filepath.IsAbs(dekPath) {
		dekPath = filepath.Join(baseDir, dekPath)
	}
	return fmt.Errorf("no wrapped DEK at %s (storage.encryption.dek_path %q; relative key paths are resolved against the current directory %s): this command works on existing keys and does not create keys. Run it from the directory the server runs in, or fix dek_path; `admin encryption init` creates the keys of a new install",
		dekPath, cfg.Storage.Encryption.DEKPath, baseDir)
}

// InitLocalKeyOpService constructs and initializes the encryption.Service for
// a short-lived, LOCAL key-management operation that does not change the DEK
// or its wrapping — status/validate/fix-perms/rotate --dry-run/init — and has
// it participate in the same cross-process lock coordination the server (held
// for its whole lifetime) and the key writers (openKeyWriter, held for the
// duration of their write) already use (#92/#195/#196). These take the SHARED
// side of the lock: any number of them can run concurrently with each other,
// but every one is refused while a live server or an in-progress key writer
// holds the lock exclusively. Only init (createKeys) may generate missing key
// files, and it takes the lock exclusively before it does. Callers must
// `defer service.Shutdown()` on success to release the lock.
func InitLocalKeyOpService(cfg *config.Config, baseDir, passphrase string, createKeys bool) (*encryption.Service, error) {
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if createKeys {
		if err := service.AcquireExclusiveKeyLock(); err != nil {
			return nil, fmt.Errorf("%w — a live server or an in-progress key operation is using this key directory; stop it or wait for it to finish, then retry", err)
		}
	} else if err := requireExistingKeys(cfg, service, baseDir); err != nil {
		return nil, err
	}
	if err := service.Initialize(passphrase); err != nil {
		service.Shutdown()
		return nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}
	if err := service.AcquireSharedKeyLock(); err != nil {
		service.Shutdown()
		return nil, fmt.Errorf("%w — a live server or an in-progress rotation/migrate-provider is using this key directory; stop it or wait for it to finish, then retry", err)
	}
	return service, nil
}

// openKeyWriter prepares a Service for a command that writes key files or
// re-encrypts rows (rotate, upgrade-aad, rotate-kek, migrate-provider): the
// exclusive key lock first (refused while a server or another key operation
// runs), then DEK-rotation crash recovery from the database's redo marker, then
// Initialize on the existing keys.
//
// Recovery has to come first for every one of them, not only rotate: after a
// rotation killed between its sweep commit and the dek.key.pending -> dek.key
// rename, the pending file is the only copy of the DEK the rows are now under.
// upgrade-aad and rotate-kek used to delete it (a bare CleanPendingDEK) and
// migrate-provider to overwrite it, each making every swept row undecryptable
// (REVIEW-COVERAGE-2). The caller must Shutdown the service and close the DB.
func openKeyWriter(cfg *config.Config, baseDir, passphrase, what string) (*encryption.Service, *gorm.DB, error) {
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	// Hold the exclusive key lock across crash-recovery + the write (refuses if a
	// server is running — the #92 guard), so the recovery-promote below can never
	// race a live server. Shutdown() releases it.
	if err := service.AcquireExclusiveKeyLock(); err != nil {
		return nil, nil, fmt.Errorf("refusing to %s: %w — stop the running server before running it", what, err)
	}
	// OpenGormDB honors cfg.Storage.Type and keeps the driver selection inside the
	// storage package (ADR-049). Callers refuse remote storage before this.
	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		service.Shutdown()
		return nil, nil, fmt.Errorf("failed to open database to %s: %w", what, err)
	}
	// Heal an interrupted PRIOR rotation BEFORE Initialize, so Initialize loads the
	// correct (possibly just-promoted) active DEK: promote dek.key.pending when the
	// redo marker says the sweep committed, discard it otherwise.
	if err := service.RecoverInterruptedRotation(db); err != nil {
		closeGormDB(db)
		service.Shutdown()
		return nil, nil, fmt.Errorf("DEK-rotation crash recovery failed: %w", err)
	}
	if err := requireExistingKeys(cfg, service, baseDir); err != nil {
		closeGormDB(db)
		service.Shutdown()
		return nil, nil, err
	}
	if err := service.Initialize(passphrase); err != nil {
		closeGormDB(db)
		service.Shutdown()
		return nil, nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}
	return service, db, nil
}

// RotateWithConfig is the testable core of `encryption rotate`. Returns early
// (before any DB or encryption work) on the validation gates so tests don't
// need a real database or key files.
//
// Crash safety: the actual rotation runs inside Service.RotateDEKWithSweep,
// which re-encrypts every DEK-encrypted row in ONE database transaction,
// committed only if every row rotates cleanly (ADR-010) — a mid-sweep crash
// or kill leaves the sweep transaction rolled back and the OLD DEK still
// active and valid; nothing is lost. A crash AFTER the sweep transaction
// commits but BEFORE the new DEK file is promoted on disk is recovered by
// RecoverInterruptedRotation (called by this function before Initialize) via
// a redo marker written inside that same transaction — the next invocation
// (of this command, or a fresh `encryption rotate`/admin equivalent) promotes
// the already-committed new DEK rather than losing track of it or re-running
// the sweep. Either way, a kill at any point during a rotation leaves exactly
// one of the old or new DEK consistently active and every row decryptable
// under it — never a half-rotated database. See
// FuzzDEKSweepCrashConsistency (internal/encryption, exhaustive, every
// checkpoint) and TestRotateDEKWithSweep_KillAfterSweepCommitBeforePromote_RecoversCleanly
// (internal/encryption, deterministic, the single most dangerous checkpoint).
func RotateWithConfig(cfg *config.Config, confirm bool, dryRun bool, passSrc crypto.PassphraseSource) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}

	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("DEK rotation must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}

	if dryRun {
		return DryRunRotation(cfg, passSrc)
	}

	if !confirm {
		return fmt.Errorf("this is a write-locking operation. Re-run with --confirm")
	}

	fmt.Println("⚠️  Rotating DEK and re-encrypting all DEK-encrypted rows. This holds a write lock on the database — stop write traffic before continuing.")

	baseDir, _ := os.Getwd()
	passphrase, err := MasterPassphrase(cfg, passSrc)
	if err != nil {
		return err
	}

	// RotateDEKWithSweep needs a raw *gorm.DB so it can own the re-encryption
	// transaction (ADR-010), which the storage.Storage abstraction can't provide.
	service, db, err := openKeyWriter(cfg, baseDir, passphrase, "rotate")
	if err != nil {
		return err
	}
	defer service.Shutdown()
	defer closeGormDB(db)

	fmt.Println("🔄 Rotating DEK with full re-encryption sweep...")
	result, err := service.RotateDEKWithSweep(passphrase, db)
	if err != nil {
		return fmt.Errorf("DEK rotation failed: %w", err)
	}

	fmt.Println("✅ DEK rotated successfully")
	fmt.Printf("📋 New key version: %s\n", service.GetKeyVersion())
	printSweepResult(result)
	return nil
}

// DryRunRotation previews what a real "rotate" would touch — table names and row
// counts — WITHOUT making any changes to the database or the DEK, and without
// requiring --confirm. It uses the SAME shared-key-lock local operation pattern as
// status/validate/fix-perms/upgrade-aad (refused only while a live server or an
// in-progress rotation/migrate-provider holds the key directory exclusively), not
// the exclusive lock a real rotation takes — a dry run never writes the DEK, so it
// does not need to exclude a live server the way an actual rotation does.
func DryRunRotation(cfg *config.Config, passSrc crypto.PassphraseSource) error {
	baseDir, _ := os.Getwd()
	passphrase, err := MasterPassphrase(cfg, passSrc)
	if err != nil {
		return err
	}

	service, err := InitLocalKeyOpService(cfg, baseDir, passphrase, false)
	if err != nil {
		return err
	}
	defer service.Shutdown()

	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database for dry-run rotation preview: %w", err)
	}
	defer closeGormDB(db)

	fmt.Println("🔍 Dry run: previewing what a DEK rotation would re-encrypt — no changes will be made to the database or the DEK...")
	result, err := service.PreviewRotationSweep(db)
	if err != nil {
		return fmt.Errorf("dry-run rotation preview failed: %w", err)
	}

	fmt.Println("✅ Dry run complete — no changes were made")
	printSweepResult(result)
	return nil
}

// printSweepResult prints every field of a SweepResult — all 8 per-table "Swept"
// counts plus LegacyAADUpgraded — so an operator sees the FULL sweep outcome
// (real or previewed).
func printSweepResult(result *encryption.SweepResult) {
	fmt.Printf("📋 secret_versions: %d, api_tokens: %d, api_clients: %d, password_resets: %d, mfa_secrets: %d, dynamic_secret_configs: %d, dynamic_secret_leases: %d, notification_channels: %d (legacy AAD upgraded: %d)\n",
		result.SecretVersionsSwept, result.APITokensSwept, result.APIClientsSwept,
		result.AccountResetsSwept, result.MFASecretsSwept, result.DynamicSecretConfigsSwept, result.DynamicSecretLeasesSwept,
		result.NotificationChannelsSwept, result.LegacyAADUpgraded)
}

// UpgradeAADWithConfig is the testable core of `encryption upgrade-aad`.
// Returns early (before any DB or encryption work) when encryption is
// disabled or storage is remote, so tests don't need a real database or key
// files.
//
// Crash safety: unlike rotate, this does not change the DEK — a kill
// mid-sweep leaves whatever rows it already committed upgraded to per-row AAD
// and the rest still in their legacy (pre-AAD) form, both of which remain
// decryptable under the current DEK. Safe, and expected, to re-run: it only
// ever touches rows still in the legacy no-AAD form.
func UpgradeAADWithConfig(cfg *config.Config, passSrc crypto.PassphraseSource) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("AAD upgrade must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}

	baseDir, _ := os.Getwd()
	passphrase, err := MasterPassphrase(cfg, passSrc)
	if err != nil {
		return err
	}

	// A writer under the current DEK: exclusive, after crash recovery (an
	// interrupted rotation's pending DEK is promoted, never discarded).
	service, db, err := openKeyWriter(cfg, baseDir, passphrase, "upgrade AAD")
	if err != nil {
		return err
	}
	defer service.Shutdown()
	defer closeGormDB(db)

	fmt.Println("🔄 Upgrading legacy auth-secret rows to per-row AAD...")
	result, err := service.UpgradeAuthAAD(db)
	if err != nil {
		return fmt.Errorf("AAD upgrade failed: %w", err)
	}

	fmt.Println("✅ AAD upgrade complete")
	fmt.Printf("📋 mfa_secrets: %d, dynamic_secret_configs: %d, dynamic_secret_leases: %d (legacy rows upgraded: %d)\n",
		result.MFASecretsSwept, result.DynamicSecretConfigsSwept, result.DynamicSecretLeasesSwept, result.LegacyAADUpgraded)
	return nil
}

func closeGormDB(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// ValidateWithConfig is the testable core of `encryption validate`. Read-only:
// never modifies the database or key files.
func ValidateWithConfig(cfg *config.Config, passSrc crypto.PassphraseSource) error {
	if !cfg.Storage.Encryption.Enabled {
		fmt.Println("ℹ️  Encryption is disabled - nothing to validate")
		return nil
	}

	baseDir, _ := os.Getwd()

	fmt.Println("🔍 Validating encryption setup...")

	passphrase, err := MasterPassphrase(cfg, passSrc)
	if err != nil {
		return err
	}

	service, err := InitLocalKeyOpService(cfg, baseDir, passphrase, false)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return err
	}
	defer service.Shutdown()

	if err := service.ValidateKeyFiles(); err != nil {
		fmt.Printf("❌ Key file validation failed: %v\n", err)
		fmt.Println("💡 Run `encryption fix-perms` to fix permissions")
		return err
	}

	fmt.Println("✅ Encryption setup is valid")
	return nil
}

// InitWithConfig is the testable core of `encryption init`.
func InitWithConfig(cfg *config.Config, passSrc crypto.PassphraseSource) error {
	if !cfg.Storage.Encryption.Enabled {
		fmt.Println("❌ Encryption is disabled in configuration")
		return nil
	}

	baseDir, _ := os.Getwd()
	passphrase, err := MasterPassphrase(cfg, passSrc)
	if err != nil {
		return err
	}

	fmt.Println("🔐 Initializing encryption...")
	service, err := InitLocalKeyOpService(cfg, baseDir, passphrase, true)
	if err != nil {
		return err
	}
	defer service.Shutdown()

	fmt.Println("✅ Encryption initialized successfully")
	fmt.Printf("📋 Key version: %s\n", service.GetKeyVersion())
	return nil
}

// StatusWithConfig is the testable core of `encryption status`. Read-only:
// never modifies the database or key files. Unlike the other *WithConfig
// functions here, most failures are reported (printed) rather than returned —
// matching the original CLI behavior of always exiting 0 for a status check,
// since a status command reporting "not initialized" or "wrong passphrase" IS
// its successful, intended output, not a command failure.
func StatusWithConfig(cfg *config.Config, passSrc crypto.PassphraseSource) error {
	fmt.Println("🔐 Encryption Status")
	fmt.Println("==================")
	fmt.Printf("Enabled: %v\n", cfg.Storage.Encryption.Enabled)
	fmt.Printf("DEK Path: %s\n", cfg.Storage.Encryption.DEKPath)
	fmt.Printf("Salt Path: %s\n", cfg.Storage.Encryption.SaltPath)

	if !cfg.Storage.Encryption.Enabled {
		return nil
	}

	baseDir, _ := os.Getwd()
	passphrase, err := MasterPassphrase(cfg, passSrc)
	if err != nil {
		fmt.Printf("⚠️  %v\n", err)
		return nil
	}

	service, err := InitLocalKeyOpService(cfg, baseDir, passphrase, false)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return nil
	}
	defer service.Shutdown()

	fmt.Printf("Initialized: ✅\n")
	fmt.Printf("Key Version: %s\n", service.GetKeyVersion())
	PrintProviderStatus(cfg.Storage.Encryption.KeyProvider)

	return nil
}

func PrintProviderStatus(kp config.KeyProviderConfig) {
	provType := kp.Type
	if provType == "" {
		provType = "password"
	}
	fmt.Printf("Key Provider: %s\n", provType)
	switch provType {
	case "password":
		fmt.Println("  (passphrase-derived KEK; use `migrate-provider` to change)")
	case "file":
		fmt.Printf("  File: %s\n", kp.FilePath)
		if _, err := os.Stat(kp.FilePath); err == nil {
			fmt.Println("  Status: file accessible ✅")
		} else {
			fmt.Printf("  Status: file not accessible ❌ (%v)\n", err)
		}
	case "env":
		fmt.Printf("  Env var: %s\n", kp.EnvVar)
		if _, found, lerr := secretenv.LookupChecked(kp.EnvVar); lerr != nil { // as the env KEK provider reads it: a too-open file is misconfigured, not set
			fmt.Printf("  Status: env var misconfigured ❌ (%v)\n", lerr)
		} else if found {
			fmt.Println("  Status: env var set ✅")
		} else {
			fmt.Println("  Status: env var not set ❌")
		}
	case "exec":
		fmt.Printf("  Command: %v\n", kp.ExecCommand)
	case "shamir":
		fmt.Printf("  Share files: %d configured\n", len(kp.ShamirShareFiles))
	case "tpm":
		fmt.Printf("  TPM device: %s\n", kp.TPMDevice)
		fmt.Printf("  Wrapped key: %s\n", kp.WrappedKeyPath)
	case "aws-kms", "gcp-kms", "azure-kms":
		fmt.Printf("  KMS key: %s\n", kp.KMSKeyID)
		if kp.WrappedKeyPath != "" {
			fmt.Printf("  Wrapped key: %s\n", kp.WrappedKeyPath)
		}
		fmt.Println("  (connectivity not checked; verify credentials separately)")
	}
}

// FixPermsWithConfig is the testable core of `encryption fix-perms`.
func FixPermsWithConfig(cfg *config.Config, passSrc crypto.PassphraseSource) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}

	baseDir, _ := os.Getwd()
	passphrase, err := MasterPassphrase(cfg, passSrc)
	if err != nil {
		return err
	}

	service, err := InitLocalKeyOpService(cfg, baseDir, passphrase, false)
	if err != nil {
		return err
	}
	defer service.Shutdown()

	fmt.Println("🔧 Fixing key file permissions...")
	if err := service.FixKeyFilePermissions(); err != nil {
		return fmt.Errorf("failed to fix permissions: %w", err)
	}

	fmt.Println("✅ Key file permissions fixed")
	return nil
}
