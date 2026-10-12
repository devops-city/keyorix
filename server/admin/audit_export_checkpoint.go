// audit_export_checkpoint.go implements `keyorix-server admin audit
// export-checkpoint` (docs/design-b4-offline-audit-verify.md): writes the
// database's most recently signed audit checkpoint to a file in exactly the
// JSON shape `keyorix-server admin verify-audit --anchor` already consumes
// (internal/auditverify.ExternalAnchorBundle) -- closing the loop for an
// air-gapped install, where an operator periodically exports the checkpoint
// to write-once media (a burned CD/DVD, a WORM-mode USB stick, a
// physically-locked S3 object-lock bucket) and later feeds that export back
// as --anchor during an offline verification, constraining even a host
// admin who holds the checkpoint signing key -- design §2's strongest leg
// -- without needing an always-on external notary/TSA.
//
// No new signing happens here: the Signature field is copied verbatim from
// the checkpoint row, already HMAC-signed by internal/core.signCheckpoint
// (the KEK-derived checkpoint key) at the moment the audit-checkpoint
// scheduler (or an explicit trigger) wrote it. This command only packages
// an already-signed fact for offline storage -- it never touches the
// signing key itself, matching every other admin command's storage-only
// footprint.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/spf13/cobra"
)

var exportCheckpointOutput string

var exportCheckpointCmd = &cobra.Command{
	Use:   "export-checkpoint",
	Short: "Export the latest signed audit checkpoint for offline/air-gapped anchor storage",
	Long: `Writes the database's most recently signed audit checkpoint to --output, in
exactly the JSON shape 'verify-audit --anchor' consumes. Intended to be run
periodically and the output copied to write-once media (write-once/read-
many optical media, a WORM-mode USB stick, an object-lock bucket) held
OUTSIDE this host -- an anchor genuinely held externally is the one check
that constrains a host admin who holds both this database and its
checkpoint signing key (design-b4-offline-audit-verify.md §2).

This does not create or sign a new checkpoint: it exports the most recent
one the audit-checkpoint scheduler already wrote. If none has been written
yet, this command fails rather than fabricating one.

--output must not already exist: each export is a distinct, timestamped
artifact -- overwriting a prior export on write-once media would defeat the
whole point.

Exit codes: 0 on success, 1 on any failure (see the printed error message).`,
	RunE: runExportCheckpoint,
}

func init() {
	exportCheckpointCmd.Flags().StringVar(&exportCheckpointOutput, "output", "", "Path to write the checkpoint export to (must not already exist; required)")
	auditCmd.AddCommand(exportCheckpointCmd)
}

func runExportCheckpoint(cmd *cobra.Command, args []string) error {
	if exportCheckpointOutput == "" {
		return fmt.Errorf("--output is required")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	var bundle *auditverify.ExternalAnchorBundle
	err = withUsableStorage(cfg, func(store corestorage.Storage) error {
		cp, err := store.LatestAuditCheckpoint(context.Background())
		if err != nil {
			return fmt.Errorf("read latest audit checkpoint: %w", err)
		}
		if cp == nil {
			return fmt.Errorf("no audit checkpoint has been written on this install yet -- " +
				"checkpoints are created by the audit-checkpoint scheduler (server startup log names its " +
				"interval); wait for the next cycle, or check that storage.encryption is enabled (checkpointing " +
				"requires a signing key)")
		}
		bundle = &auditverify.ExternalAnchorBundle{
			ChainedEvents:  cp.ChainedEvents,
			HeadID:         uint64(cp.HeadID),
			HeadHash:       cp.HeadHash,
			KeyVersion:     cp.KeyVersion,
			Signature:      cp.Signature,
			AnchorToken:    cp.AnchorToken,
			AnchorProvider: cp.AnchorProvider,
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("export-checkpoint: %w", err)
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("encode checkpoint export: %w", err)
	}
	// O_EXCL: each export is a distinct artifact; silently overwriting a
	// prior export on write-once media would defeat the whole point (and on
	// GENUINELY write-once media, the OS-level open would fail here anyway
	// -- this makes that refusal explicit and immediate rather than an
	// opaque I/O error).
	f, err := os.OpenFile(exportCheckpointOutput, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- operator-supplied output path, the whole point of this flag
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("--output %q already exists -- each export is a distinct artifact, pick a new path (e.g. include a timestamp)", exportCheckpointOutput)
		}
		return fmt.Errorf("create %q: %w", exportCheckpointOutput, err)
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %q: %w", exportCheckpointOutput, err)
	}

	fmt.Printf("Exported checkpoint (chained_events=%d, head_id=%d, key_version=%s) to %s\n",
		bundle.ChainedEvents, bundle.HeadID, bundle.KeyVersion, exportCheckpointOutput)
	fmt.Println("Copy this file to write-once/removable media held OUTSIDE this host, then verify with:")
	fmt.Printf("  keyorix-server admin verify-audit --anchor %s --checkpoint-key-file <key>\n"+
		"  (produce <key> with: keyorix-server admin audit export-checkpoint-key --output <key>)\n", exportCheckpointOutput)

	recordAdminAction(cfg, "admin.audit_checkpoint_exported",
		fmt.Sprintf("exported audit checkpoint (chained_events=%d, head_id=%d) to %s", bundle.ChainedEvents, bundle.HeadID, exportCheckpointOutput), true)

	return nil
}
