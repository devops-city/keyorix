// migrate_provider.go — the testable core of `encryption migrate-provider`
// (and its `cleanup` subcommand).
//
// Re-wraps the DEK under a KEK from a different provider (ADR-041) so an existing
// install can move between KEK providers — most importantly password/file/env → a
// cloud KMS — without re-encrypting any data. Only the DEK's wrapping changes; the
// operation is fast and takes no database lock. After re-wrapping it verifies the
// target provider unwraps the DEK (round-tripping a probe value through a fresh
// service) and keeps a timestamped backup of the previous wrapped DEK, restoring it
// if verification fails.
package encryptionops

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"golang.org/x/sys/unix"
)

const (
	azureKMSProvider = "azure-kms"
)

// MigrateOpts is the target-provider description — mirrors the old CLI's
// --to-* flags so this core can be driven by any caller's own flag set
// without a cobra dependency.
type MigrateOpts struct {
	ToType                 string
	ToKMSKeyID             string
	ToWrappedKeyPath       string
	ToKMSEncryptionContext map[string]string
	ToFilePath             string
	ToEnvVar               string
	ToExecCommand          []string
	ToShareFiles           []string
	ToShareEnv             []string
	ToShareCommitment      string
	ToTPMDevice            string
	ToSaltPath             string
}

// TargetEncryptionConfig derives the target EncryptionConfig from the current one
// plus the --to-* options. The DEK path is preserved (the same dek.key is re-wrapped
// in place); only the key_provider (and, for password, optionally the salt path)
// changes.
func TargetEncryptionConfig(cur *config.EncryptionConfig, opts MigrateOpts) (config.EncryptionConfig, error) { // NOSONAR -- cognitive complexity 27, suppress go:S3776
	tgt := *cur
	kp := config.KeyProviderConfig{Type: opts.ToType}
	switch opts.ToType {
	case "password":
		if opts.ToSaltPath != "" {
			tgt.SaltPath = opts.ToSaltPath
		}
	case "file":
		if opts.ToFilePath == "" {
			return tgt, fmt.Errorf("--to-file-path is required for --to-type file")
		}
		kp.FilePath = opts.ToFilePath
	case "env":
		if opts.ToEnvVar == "" {
			return tgt, fmt.Errorf("--to-env-var is required for --to-type env")
		}
		kp.EnvVar = opts.ToEnvVar
	case "exec":
		if len(opts.ToExecCommand) == 0 {
			return tgt, fmt.Errorf("--to-exec-command is required for --to-type exec")
		}
		kp.ExecCommand = opts.ToExecCommand
	case "shamir":
		if len(opts.ToShareFiles)+len(opts.ToShareEnv) < 2 {
			return tgt, fmt.Errorf("--to-type shamir requires at least 2 shares via --to-shamir-share-files/--to-shamir-share-env (the threshold)")
		}
		kp.ShamirShareFiles = opts.ToShareFiles
		kp.ShamirShareEnv = opts.ToShareEnv
		kp.ShamirCommitment = opts.ToShareCommitment
	case "tpm":
		if opts.ToWrappedKeyPath == "" {
			return tgt, fmt.Errorf("--to-wrapped-key-path is required for --to-type tpm (where the sealed KEK blob lives)")
		}
		if opts.ToWrappedKeyPath == tgt.DEKPath {
			return tgt, fmt.Errorf("--to-wrapped-key-path must differ from the DEK path (%s)", tgt.DEKPath)
		}
		kp.TPMDevice = opts.ToTPMDevice
		kp.WrappedKeyPath = opts.ToWrappedKeyPath
	case "aws-kms", "gcp-kms", azureKMSProvider:
		if opts.ToKMSKeyID == "" {
			return tgt, fmt.Errorf("--to-kms-key-id is required for --to-type %s", opts.ToType)
		}
		if opts.ToWrappedKeyPath == "" {
			return tgt, fmt.Errorf("--to-wrapped-key-path is required for --to-type %s", opts.ToType)
		}
		if opts.ToWrappedKeyPath == tgt.DEKPath {
			return tgt, fmt.Errorf("--to-wrapped-key-path must differ from the DEK path (%s)", tgt.DEKPath)
		}
		// #123: azure-kms (RSA-OAEP wrap) has no AAD input — matches
		// NewKeyProviderFromConfig's hard rejection, checked here too so this fails
		// before any DEK backup/re-wrap work rather than after.
		if opts.ToType == azureKMSProvider && len(opts.ToKMSEncryptionContext) > 0 {
			return tgt, fmt.Errorf("--to-kms-encryption-context is not supported for --to-type azure-kms (RSA-OAEP key wrap has no AAD input)")
		}
		// KMSKeyProvider.KEK() only re-wraps (and so only applies a NEW encryption
		// context) when generating a FRESH KEK at a wrapped_key_path that doesn't yet
		// exist — pointing at an existing path takes the decrypt-the-existing-blob
		// path instead, which does not rebind it. Requiring a genuinely new path when
		// a context is supplied keeps this flag from silently no-op-ing.
		if len(opts.ToKMSEncryptionContext) > 0 && opts.ToType == cur.KeyProvider.Type && opts.ToWrappedKeyPath == cur.KeyProvider.WrappedKeyPath {
			return tgt, fmt.Errorf("--to-kms-encryption-context requires a NEW --to-wrapped-key-path (got the current one, %q): re-wrapping under a context only takes effect when a fresh KEK is generated", opts.ToWrappedKeyPath)
		}
		kp.KMSKeyID = opts.ToKMSKeyID
		kp.WrappedKeyPath = opts.ToWrappedKeyPath
		kp.KMSEncryptionContext = opts.ToKMSEncryptionContext
	default:
		return tgt, fmt.Errorf("unknown --to-type %q (supported: password, file, env, exec, shamir, tpm, aws-kms, gcp-kms, azure-kms)", opts.ToType)
	}
	tgt.KeyProvider = kp
	return tgt, nil
}

// TargetPassphrase resolves the passphrase for the TARGET provider. Only the
// password provider needs one (sourced per src's precedence, falling back to
// NewMasterPassphraseEnvVar); the others source the KEK from key material /
// KMS and return "".
func TargetPassphrase(providerType string, src crypto.PassphraseSource) (string, error) {
	if providerType != "" && providerType != "password" {
		return "", nil
	}
	passphraseBytes, err := crypto.ResolvePassphrase(src, NewMasterPassphraseEnvVar)
	if err != nil {
		return "", err
	}
	defer crypto.WipeBytes(passphraseBytes)
	return string(passphraseBytes), nil
}

// MigrateProviderWithConfig is the testable core of `encryption
// migrate-provider`. The validation gates (encryption enabled, local storage,
// target-config sanity, --confirm) all return before any key/DB work.
//
// Crash safety: the previous wrapped DEK is backed up (durably, fsynced)
// BEFORE the re-wrap, and the re-wrap itself only overwrites the active
// wrapped-DEK file after the new provider has been built successfully. A kill
// between the backup and the re-wrap leaves the OLD wrapped DEK untouched and
// a spare backup copy of it — re-running is safe. A kill DURING or
// immediately after RewrapDEKWithProvider but before this function's own
// verification step runs leaves the backup in place for a human to restore
// from manually (this function's own crash-free path restores it
// automatically on a verification FAILURE, but cannot run its own cleanup
// code if the process is killed); the DEK's plaintext value is unchanged
// either way, so no data is ever at risk of becoming undecryptable — at worst
// an operator must manually restore backupRel over the DEK path using the
// printed filename.
func MigrateProviderWithConfig(cfg *config.Config, opts MigrateOpts, confirm bool, oldSrc, newSrc crypto.PassphraseSource) error {
	enc := &cfg.Storage.Encryption
	if !enc.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("KEK-provider migration must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}
	if opts.ToType == "" {
		return fmt.Errorf("--to-type is required (password|file|env|exec|shamir|tpm|aws-kms|gcp-kms|azure-kms)")
	}
	tgtEnc, err := TargetEncryptionConfig(enc, opts)
	if err != nil {
		return err
	}
	if !confirm {
		return fmt.Errorf("this re-wraps the DEK and changes the KEK provider. Re-run with --confirm")
	}

	baseDir, _ := os.Getwd()

	oldPass, err := MasterPassphrase(cfg, oldSrc)
	if err != nil {
		return err
	}
	newPass, err := TargetPassphrase(tgtEnc.KeyProvider.Type, newSrc)
	if err != nil {
		return err
	}

	// 1. Open with the CURRENT provider — unwraps the DEK into memory — under the
	//    exclusive key lock and after DEK-rotation crash recovery: the re-wrap
	//    writes dek.key.pending, which after an interrupted rotation holds the
	//    only copy of the new DEK.
	oldSvc, db, err := openKeyWriter(cfg, baseDir, oldPass, "migrate the KEK provider")
	if err != nil {
		return err
	}
	defer oldSvc.Shutdown()
	closeGormDB(db)

	// 2. Encrypt a probe value under the current DEK — used after re-wrapping to
	//    verify the target provider yields the *same* DEK (data still decryptable).
	probe := []byte("keyorix-kek-provider-migration-probe")
	probeCT, _, err := oldSvc.EncryptSecret(probe)
	if err != nil {
		return fmt.Errorf("failed to encrypt verification probe: %w", err)
	}

	// 3. Back up the current wrapped DEK before overwriting it.
	backupRel := fmt.Sprintf("%s.migrate-backup.%d", enc.DEKPath, time.Now().Unix())
	if err := CopyFile(baseDir, enc.DEKPath, backupRel); err != nil {
		return fmt.Errorf("failed to back up current wrapped DEK: %w", err)
	}

	// 4. Build the TARGET provider and re-wrap the DEK under it.
	newProvider, err := encryption.NewKeyProviderFromConfig(&tgtEnc, baseDir, newPass)
	if err != nil {
		_ = os.Remove(filepath.Join(baseDir, backupRel))
		return fmt.Errorf("failed to build target provider: %w", err)
	}
	fmt.Printf("🔄 Re-wrapping DEK: %s → %s provider...\n", ProviderLabel(enc.KeyProvider.Type), opts.ToType)
	if err := oldSvc.RewrapDEKWithProvider(newProvider); err != nil {
		// RewrapDEK leaves the active DEK untouched on failure — drop the backup.
		_ = os.Remove(filepath.Join(baseDir, backupRel))
		return fmt.Errorf("re-wrap failed — no changes made to the active DEK: %w", err)
	}

	// 5. Verify a fresh service on the TARGET config unwraps the DEK and decrypts
	//    the probe. On any mismatch, restore the previous wrapped DEK and abort.
	verifySvc := encryption.NewService(&tgtEnc, baseDir)
	if err := verifySvc.Initialize(newPass); err != nil {
		RestoreBackup(baseDir, backupRel, enc.DEKPath)
		return fmt.Errorf("verification failed (target provider could not open) — restored previous DEK (its copy %s is kept; `migrate-provider cleanup` removes it): %w", backupRel, err)
	}
	defer verifySvc.Shutdown()
	got, err := verifySvc.DecryptSecret(probeCT)
	if err != nil || !bytes.Equal(got, probe) {
		RestoreBackup(baseDir, backupRel, enc.DEKPath)
		return fmt.Errorf("verification failed (probe did not round-trip under the target provider) — restored previous DEK (its copy %s is kept; `migrate-provider cleanup` removes it)", backupRel)
	}

	PrintMigrateSummary(tgtEnc, backupRel)
	return nil
}

// CopyFile copies baseDir/srcRel to baseDir/dstRel, both resolved and opened via
// securefiles' per-path-component O_NOFOLLOW walk (SecureOpenBeneath/SafeReadFile) so
// a symlink planted at any intermediate directory component (not just the leaf)
// between this tool starting and this copy running can't redirect the read or the
// write. The backup this produces is the rollback target if migration verification
// fails — a non-durable backup lost to a crash could leave neither a valid old nor
// new wrapped DEK on disk, so the write is fsynced (file and directory) before
// returning.
func CopyFile(baseDir, srcRel, dstRel string) error {
	data, err := securefiles.SafeReadFile(baseDir, srcRel)
	if err != nil {
		return err
	}
	f, err := securefiles.SecureOpenBeneath(baseDir, dstRel, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, 0600) // #nosec G304 -- baseDir/dstRel is operator-configured, walked via SecureOpenBeneath
	if err != nil {
		return err
	}
	// O_TRUNC keeps a pre-existing destination's mode untouched — the 0600 passed to
	// OpenFile above only applies when the file is freshly created. Without this
	// explicit Chmod, re-running migrate-provider (or RestoreBackup) against a dst
	// that already existed with a looser mode (e.g. a DEK/backup path left
	// world-readable by an older build, or created under a permissive umask) would
	// silently keep serving that looser mode to the re-wrapped/restored key material
	// (G68). Mirrors securefiles.SecureWriteFile/SecureWriteFileSync.
	if cerr := f.Chmod(0600); cerr != nil {
		_ = f.Close()
		return cerr
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return serr
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}
	return securefiles.SyncDir(filepath.Join(baseDir, filepath.Dir(dstRel)))
}

// RestoreBackup copies the backup back over the active DEK path. Best-effort: logs
// to stderr if the restore itself fails so the operator can recover manually.
func RestoreBackup(baseDir, backupRel, dekPath string) {
	if err := CopyFile(baseDir, backupRel, dekPath); err != nil {
		fmt.Fprintf(os.Stderr, "❌ CRITICAL: failed to restore DEK backup %s → %s: %v\n  Restore it manually before restarting.\n", backupRel, dekPath, err)
	}
}

func ProviderLabel(t string) string {
	if t == "" {
		return "password"
	}
	return t
}

func PrintMigrateSummary(tgt config.EncryptionConfig, backupRel string) {
	kp := tgt.KeyProvider
	fmt.Println("✅ DEK re-wrapped and verified under the new provider.")
	fmt.Printf("🗄️  Previous wrapped DEK backed up at %s.\n", backupRel)
	fmt.Println("   Its plaintext-after-unwrap is byte-identical to the DEK still in active use —")
	fmt.Println("   only the wrapping changed. Once you've confirmed the new provider works, run")
	fmt.Println("   `migrate-provider cleanup --confirm` to securely delete it")
	fmt.Println("   (and any other leftover migrate-backup files) rather than a plain rm.")
	fmt.Println()
	fmt.Println("⚠️  Update storage.encryption.key_provider in your config to match BEFORE the next restart:")
	fmt.Println()
	fmt.Println("    key_provider:")
	fmt.Printf("      type: %s\n", kp.Type)
	switch kp.Type {
	case "file":
		fmt.Printf("      file_path: %s\n", kp.FilePath)
	case "env":
		fmt.Printf("      env_var: %s\n", kp.EnvVar)
	case "exec":
		fmt.Printf("      exec_command: %v\n", kp.ExecCommand)
	case "shamir":
		if len(kp.ShamirShareFiles) > 0 {
			fmt.Printf("      shamir_share_files: %v\n", kp.ShamirShareFiles)
		}
		if len(kp.ShamirShareEnv) > 0 {
			fmt.Printf("      shamir_share_env: %v\n", kp.ShamirShareEnv)
		}
		if kp.ShamirCommitment != "" {
			fmt.Printf("      shamir_commitment: %s\n", kp.ShamirCommitment)
		} else {
			fmt.Println("      # shamir_commitment: not set — pass --to-shamir-commitment (the value")
			fmt.Println("      # printed by `shamir-split` for these shares) for real cryptographic")
			fmt.Println("      # verification of the reconstructed KEK (#429); without it, unseal falls")
			fmt.Println("      # back to a weaker, forgeable check and logs a loud warning at startup.")
		}
	case "tpm":
		if kp.TPMDevice != "" {
			fmt.Printf("      tpm_device: %s\n", kp.TPMDevice)
		}
		fmt.Printf("      wrapped_key_path: %s\n", kp.WrappedKeyPath)
	case "aws-kms", "gcp-kms", azureKMSProvider:
		fmt.Printf("      kms_key_id: %s\n", kp.KMSKeyID)
		fmt.Printf("      wrapped_key_path: %s\n", kp.WrappedKeyPath)
	case "password":
		fmt.Printf("      # salt_path: %s (set storage.encryption.salt_path)\n", tgt.SaltPath)
		fmt.Println("      # the master passphrase has changed — update your deployment's secret store")
	}
	fmt.Println()
	fmt.Println("⚠️  Unlike a `rotate`, this changes the KEK — and with it, the compliance-")
	fmt.Println("   evidence-pack signing key (#268). Any evidence pack signed BEFORE this")
	fmt.Println("   migration will report as \"superseded key version\" (not tampered) under")
	fmt.Println("   `compliance verify` from now on; a routine `encryption rotate`")
	fmt.Println("   does NOT have this effect. Run `compliance verify` on any outstanding")
	fmt.Println("   packs before this step if you need to confirm they're still valid.")
}

// MigrateProviderCleanupWithConfig is the testable core of `encryption
// migrate-provider cleanup`: no flag parsing, an explicit baseDir instead of
// os.Getwd().
func MigrateProviderCleanupWithConfig(cfg *config.Config, baseDir string, dryRun, confirm bool) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	matches, err := FindMigrateBackups(baseDir, cfg.Storage.Encryption.DEKPath)
	if err != nil {
		return fmt.Errorf("failed to scan for migrate-backup files: %w", err)
	}
	if len(matches) == 0 {
		fmt.Println("✅ No migrate-backup files found — nothing to clean up.")
		return nil
	}
	fmt.Printf("Found %d migrate-backup file(s):\n", len(matches))
	for _, m := range matches {
		fmt.Printf("  %s\n", m)
	}
	if dryRun {
		fmt.Println("\n(--dry-run: no files deleted)")
		return nil
	}
	if !confirm {
		return fmt.Errorf("this permanently and irreversibly shreds the listed backup file(s). Re-run with --confirm (or --dry-run to only list them)")
	}
	for _, m := range matches {
		if err := securefiles.SecureDeleteFile(filepath.Join(baseDir, m)); err != nil {
			return fmt.Errorf("failed to securely delete %s: %w", m, err)
		}
	}
	fmt.Printf("✅ Securely deleted %d migrate-backup file(s).\n", len(matches))
	return nil
}

// FindMigrateBackups lists filenames (relative to baseDir) matching
// "<base>.migrate-backup.*" for the given DEK path, sorted for stable output.
func FindMigrateBackups(baseDir, dekPath string) ([]string, error) {
	dir := filepath.Dir(filepath.Join(baseDir, dekPath))
	prefix := filepath.Base(dekPath) + ".migrate-backup."
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var matches []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		rel, rerr := filepath.Rel(baseDir, filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		matches = append(matches, rel)
	}
	sort.Strings(matches)
	return matches, nil
}
