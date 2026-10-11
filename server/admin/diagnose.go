package admin

import (
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// diagnose is NEW (not a port): it runs the checks the server's own boot
// path would run -- config parse, KEK/passphrase access, database open,
// migration state -- and reports exactly which one fails and why, without
// starting a listener. `admin validate` (internal/startup.ValidateStartup)
// checks that key FILES exist at the right size/mode; it does not attempt
// to actually decrypt with them, and it does not compare the database's
// schema epoch against this binary's. diagnose goes further on both, since
// "the server can't start" (ADR-108 §B1) is often exactly a passphrase that
// no longer decrypts the DEK, or a database migrated by a different binary
// version -- neither of which `validate` alone would catch.
var diagnosePassphraseSource crypto.PassphraseSource

var diagnoseCmd = &cobra.Command{
	Use:   "diagnose",
	Short: "Run the startup checks the server would run, and report which one fails",
	Long: `Runs, in order, the same checks server startup depends on: config parse,
encryption key (KEK/passphrase) access, database open, and migration state
-- reporting exactly which check fails and why, without starting a listener.

Exit codes: 0 if every check reports [ OK ] or [WARN], 1 if any check
reports [FAIL] (see the printed error message). A [WARN] (e.g. "not yet
migrated") does NOT fail the command -- only a [FAIL] does.`,
	RunE: runAdminDiagnose,
}

func init() {
	registerPassphraseFlags(diagnoseCmd, &diagnosePassphraseSource)
}

func runAdminDiagnose(cmd *cobra.Command, args []string) error { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	fmt.Println("Keyorix Server Admin: diagnose")
	fmt.Println("===============================")

	cfg, err := diagnoseConfigParse()
	if err != nil {
		fmt.Printf("[FAIL] config parse: %v\n", err)
		return fmt.Errorf("config parse: %w", err)
	}
	fmt.Println("[ OK ] config parse and schema validation")

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	if cfg.Storage.Encryption.Enabled {
		if err := diagnoseEncryption(cfg); err != nil {
			fmt.Printf("[FAIL] KEK/passphrase access: %v\n", err)
			return fmt.Errorf("KEK/passphrase access: %w", err)
		}
		fmt.Println("[ OK ] KEK/passphrase access (encryption key derived and verified)")
	} else {
		fmt.Println("[SKIP] KEK/passphrase access (storage.encryption.enabled is false)")
	}

	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		fmt.Printf("[FAIL] database open: %v\n", err)
		return fmt.Errorf("database open: %w", err)
	}
	defer closeGormDB(db)
	fmt.Println("[ OK ] database open")

	upToDate, detail, err := storage.InspectMigrationState(db)
	if err != nil {
		fmt.Printf("[FAIL] migration state: %v\n", err)
		return fmt.Errorf("migration state: %w", err)
	}
	if upToDate {
		fmt.Printf("[ OK ] migration state: %s\n", detail)
	} else {
		fmt.Printf("[WARN] migration state: %s\n", detail)
	}

	diagnoseRecoveryKey(db, cfg)

	fmt.Println("\nAll startup checks that can fail this server's boot passed.")
	if !upToDate {
		fmt.Println("The database schema is behind this binary; run `keyorix-server admin migrate` before starting.")
	}
	return nil
}

// diagnoseRecoveryKey reports, non-fatally, whether `recover-admin` is
// currently usable on this install (F6, recovery-key visibility). Skipped
// entirely in keyless mode -- recover-admin does not check a key there, so
// its absence is not a problem to warn about. Never fails the command: a
// missing recovery key does not stop the SERVER from starting, only
// `recover-admin` from working, so this is a [WARN] like migration state,
// not a [FAIL].
func diagnoseRecoveryKey(db *gorm.DB, cfg *config.Config) {
	if cfg.Security.RecoverAdmin.KeylessMode {
		fmt.Println("[SKIP] recovery key (security.recover_admin.insecure_keyless_admin_recovery is enabled)")
		return
	}
	var rec models.RecoveryKeyRecord
	err := db.Where("id = ?", 1).Take(&rec).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		fmt.Println("[WARN] recovery key not configured — recover-admin is unusable. " +
			"Run `keyorix-server admin recovery-key rotate` (see docs/SELF_HOSTING.md).")
	case err != nil:
		fmt.Printf("[WARN] recovery key: could not check (%v)\n", err)
	default:
		fmt.Printf("[ OK ] recovery key configured (generation %d)\n", rec.KeyVersion)
	}
}

func diagnoseConfigParse() (*config.Config, error) {
	cfg, err := config.Load(configPathFlag)
	if err != nil {
		return nil, err
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// diagnoseEncryption attempts a REAL KEK derivation (not just a file-exists
// check) under the same exclusive DEK lock the server itself acquires at
// startup, released immediately after. This is deliberately more thorough
// than `admin validate`'s validateEncryption, which only stats the salt/DEK
// files for existence and size.
func diagnoseEncryption(cfg *config.Config) error {
	providerType := cfg.Storage.Encryption.KeyProvider.Type
	var passphrase string
	if providerType == "" || providerType == "password" {
		passphraseBytes, err := crypto.ResolvePassphrase(diagnosePassphraseSource, "KEYORIX_MASTER_PASSWORD")
		if err != nil {
			return fmt.Errorf("no master passphrase available (%w); set KEYORIX_MASTER_PASSWORD, pass --passphrase-fd/--passphrase-file/--passphrase-stdin, or configure storage.encryption.key_provider (file/env/aws-kms)", err)
		}
		defer crypto.WipeBytes(passphraseBytes)
		passphrase = string(passphraseBytes)
	}

	svc := encryption.NewService(&cfg.Storage.Encryption, ".")
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return fmt.Errorf("failed to acquire the encryption key lock (another process — a live server, or a concurrent rotation — is using it): %w", err)
	}
	defer svc.Shutdown()

	if err := svc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to derive/verify the KEK: %w", err)
	}
	return nil
}
