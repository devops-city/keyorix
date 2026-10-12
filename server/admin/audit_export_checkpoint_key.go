// audit_export_checkpoint_key.go implements `keyorix-server admin audit
// export-checkpoint-key` (INSTALL-WALK-1 F12): the one documented way to produce
// the file `admin verify-audit --checkpoint-key-file` consumes. Before this
// command the flag's help said "extracted by the operator out of band" and no
// command did it, so an air-gapped drill could only ever see
// `external_anchor.authenticated == false`.
//
// The file holds the KEK-derived audit-checkpoint HMAC key (32 bytes, hex), never
// the KEK, the DEK or the passphrase. It is a shared secret: whoever holds it plus
// the database can forge a self-consistent checkpointed history, so the command
// writes it 0600 with O_EXCL, never prints it, and the runbook says where it may
// live. Like `admin backup` it derives the key under the exclusive key lock, so it
// needs the server stopped.
package admin

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/spf13/cobra"
)

var (
	exportCheckpointKeyOutput     string
	exportCheckpointKeyPassphrase crypto.PassphraseSource
)

var exportCheckpointKeyCmd = &cobra.Command{
	Use:   "export-checkpoint-key",
	Short: "Write the audit-checkpoint verification key to a file for verify-audit --checkpoint-key-file",
	Long: `Derives the audit-checkpoint signing key from the master passphrase and writes it,
hex-encoded, to --output (mode 0600; the file must not already exist). Pass that
file to 'verify-audit --checkpoint-key-file' so an exported checkpoint anchor is
cryptographically authenticated, not merely cross-checked.

The key is a shared secret: anyone holding it together with the database can
forge a validly-checkpointed history. Treat the file like the master passphrase
-- keep it off the host the audited database lives on (an offline auditor's
media), and delete it when the verification is done. The key itself is never
printed; only its public fingerprint (the key version a checkpoint records) is.

Like 'admin backup' this takes the exclusive key lock, so stop the server first.

Exit codes: 0 on success, 1 on any failure (see the printed error message).`,
	Args: cobra.NoArgs,
	RunE: runExportCheckpointKey,
}

func init() {
	exportCheckpointKeyCmd.Flags().StringVar(&exportCheckpointKeyOutput, "output", "", "Path to write the key file to (must not already exist; required)")
	registerPassphraseFlags(exportCheckpointKeyCmd, &exportCheckpointKeyPassphrase)
	auditCmd.AddCommand(exportCheckpointKeyCmd)
}

func runExportCheckpointKey(cmd *cobra.Command, args []string) error {
	if exportCheckpointKeyOutput == "" {
		return fmt.Errorf("--output is required")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("storage.encryption is not enabled, so no checkpoint signing key exists on this install")
	}

	// Refuse before deriving anything if the output path is taken, so a typo
	// never costs a passphrase prompt; O_EXCL below is the authoritative check.
	if _, statErr := os.Lstat(exportCheckpointKeyOutput); statErr == nil {
		return fmt.Errorf("--output %q already exists -- pick a new path", exportCheckpointKeyOutput)
	}

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	key, keyID, err := deriveCheckpointKey(cfg, exportCheckpointKeyPassphrase)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(key)

	encoded := []byte(hex.EncodeToString(key) + "\n")
	defer crypto.WipeBytes(encoded)

	f, err := os.OpenFile(exportCheckpointKeyOutput, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- operator-supplied output path, the whole point of this flag
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("--output %q already exists -- pick a new path", exportCheckpointKeyOutput)
		}
		return fmt.Errorf("create %q: %w", exportCheckpointKeyOutput, err)
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		_ = os.Remove(exportCheckpointKeyOutput)
		return fmt.Errorf("write %q: %w", exportCheckpointKeyOutput, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(exportCheckpointKeyOutput)
		return fmt.Errorf("close %q: %w", exportCheckpointKeyOutput, err)
	}

	fmt.Printf("Wrote the audit-checkpoint verification key (key version %s) to %s (mode 0600).\n", keyID, exportCheckpointKeyOutput)
	fmt.Println("This file is a shared secret: keep it off this host and delete it after verifying. Use it with:")
	fmt.Println("  keyorix-server admin verify-audit --anchor <checkpoint.json> --checkpoint-key-file " + exportCheckpointKeyOutput)

	recordAdminAction(cfg, "admin.audit_checkpoint_key_exported",
		fmt.Sprintf("exported the audit-checkpoint verification key (key version %s) to %s", keyID, exportCheckpointKeyOutput), true)
	return nil
}

// deriveCheckpointKey mirrors unwrapManifestKey: resolve the master passphrase
// (password provider only), take the exclusive key lock, derive the KEK and return
// a copy of the KEK-derived checkpoint key plus its public key version.
func deriveCheckpointKey(cfg *config.Config, src crypto.PassphraseSource) ([]byte, string, error) {
	var passphrase string
	if t := cfg.Storage.Encryption.KeyProvider.Type; t == "" || t == "password" {
		pb, err := crypto.ResolvePassphrase(src, "KEYORIX_MASTER_PASSWORD")
		if err != nil {
			return nil, "", fmt.Errorf("no master passphrase available (%w); set KEYORIX_MASTER_PASSWORD, pass "+
				"--passphrase-fd/--passphrase-file/--passphrase-stdin, or configure storage.encryption.key_provider "+
				"(file/env/aws-kms)", err)
		}
		defer crypto.WipeBytes(pb)
		passphrase = string(pb)
	}

	svc := encryption.NewService(&cfg.Storage.Encryption, ".")
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return nil, "", fmt.Errorf("failed to acquire the encryption key lock (stop the server first): %w", err)
	}
	defer svc.Shutdown()
	if err := svc.Initialize(passphrase); err != nil {
		return nil, "", fmt.Errorf("failed to derive/verify the KEK: %w", err)
	}
	key, keyID, ok := svc.AuditCheckpointKey()
	if !ok {
		return nil, "", fmt.Errorf("audit-checkpoint key unavailable (encryption not enabled?)")
	}
	return key, keyID, nil
}
