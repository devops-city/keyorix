// restore.go implements `keyorix-server admin restore` (ADR-108 §B3,
// design-b3-backup-v2.md): the other half of admin backup. Dispatches on
// the archive's own declared format_version: v2 (backupfmt, the only format
// `admin backup` writes now) is the normal path; v1 (physical, SQLite-only,
// #2099) is read-only-supported until Keyorix 1.0 (design §3.6 decision 3),
// implemented in backup_v1_legacy.go's readBackupArchive plus this file's
// runAdminRestoreV1.
//
// Refuses, rather than silently overwriting, an existing non-empty database
// or key file unless --overwrite-existing is given -- restoring into
// existing data is exactly the "trade loud failure for silent data loss"
// mistake this repo's engineering practices call out.
package admin

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// restoreFileMode is the mode every restored file (database and key files
// alike) is written with, regardless of what the archive's own manifest
// records -- a crafted manifest must never be able to make a restored
// key/DB file group- or world-readable. See writeRestoredFile.
const restoreFileMode = 0600

// defaultMaxRestoreEntryBytes/defaultMaxRestoreTotalBytes bound how much
// decompressed data restore will hold (per staged file, and in total) before
// refusing an archive -- an archive (gzip+tar) can decompress to far more
// bytes than it occupies on disk, and an operator restoring from
// removable/untrusted media has no independent way to know an archive is
// hostile before restore reads it. 1 GiB per file is generous headroom for
// a keyorix secrets database table or key-material file;
// --max-entry-bytes/--max-total-bytes raise it for a legitimately larger
// deployment.
const (
	defaultMaxRestoreEntryBytes = 1 << 30
	defaultMaxRestoreTotalBytes = 2 * defaultMaxRestoreEntryBytes
)

var (
	restoreInput             string
	restoreOverwriteExisting bool
	restoreAllowRollback     bool
	restoreMaxEntryBytes     int64
	restoreMaxTotalBytes     int64
	restorePassphraseSource  crypto.PassphraseSource
)

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore the database and encryption keys from a backup archive created by `admin backup`",
	Long: `Restores the database and every encryption key-material file from an archive
'admin backup' created, then applies any pending migration the same way
'admin migrate' does -- so an old backup restored under a newer binary ends
up ready to start, not merely restored to its old schema.

The archive's manifest is signature-verified (HMAC-SHA256, KEK-derived key,
design-b3-backup-v2.md §5) BEFORE any byte reaches the real target -- an
authenticity check a plain checksum cannot provide, since anyone who can
edit the archive can recompute a checksum to match. Restore also runs
'admin verify-audit' automatically against the restored database once
migrations are applied, and fails (non-zero exit) if it reports the audit
chain BROKEN.

Each restored file is written atomically (temp file + fsync + rename into
the target directory, which is itself fsynced afterward), so a failure or
crash partway through never leaves a target file truncated or half-written.

Refuses to overwrite an existing, non-empty database or key file unless
--overwrite-existing is given. Restore into a fresh/empty data dir with the
SAME config (same key-material paths) the backup was taken from. With
--overwrite-existing, an existing file is renamed aside to
<path>.pre-restore-<timestamp> rather than truncated or overwritten in
place, so an unrecoverable mistake during the restore still has a way back.

Rollback protection (design-b3-backup-v2.md §6): restoring an OLDER backup
than this host has already progressed past can silently resurrect access an
admin has since revoked (a suspended account, a deleted machine credential,
a rotated role grant) -- the restored database simply doesn't know the
revocation happened. Restore compares the archive's own certified audit
high-water mark against a host-local witness file
(<data-dir>/.audit-highwater-witness, sibling to the database, maintained by
every server this host has run) BEFORE writing anything to disk, and refuses
if the archive is behind. Pass --allow-rollback for a genuine disaster-
recovery restore of an intentionally older backup -- this writes an audit
event to the restored database recording exactly how far back the restore
went, once the chain is writable again.

An archive taken under the old (v1, pre-2026-09-28) physical/SQLite-only
format still restores, with a deprecation notice -- take a fresh backup
under the current format when convenient (a v1 archive can only be restored
into SQLite). The target may be SQLite or PostgreSQL, whichever backend the
config points at, regardless of the backend the v2 archive came from; for
PostgreSQL the target database must already exist and be empty.`,
	RunE: runAdminRestore,
}

func init() {
	restoreCmd.Flags().StringVar(&restoreInput, "input", "", "Path to the backup archive to restore from (required)")
	restoreCmd.Flags().BoolVar(&restoreOverwriteExisting, "overwrite-existing", false, "Overwrite an existing, non-empty database or key file (dangerous)")
	restoreCmd.Flags().BoolVar(&restoreAllowRollback, "allow-rollback", false, "Proceed even though this backup is behind this host's own audit trail (dangerous -- see the rollback-protection note above)")
	restoreCmd.Flags().Int64Var(&restoreMaxEntryBytes, "max-entry-bytes", defaultMaxRestoreEntryBytes,
		"Reject the archive if any single entry decompresses to more than this many bytes")
	restoreCmd.Flags().Int64Var(&restoreMaxTotalBytes, "max-total-bytes", defaultMaxRestoreTotalBytes,
		"Reject the archive if its total decompressed size across all entries exceeds this many bytes")
	registerPassphraseFlags(restoreCmd, &restorePassphraseSource)
	rootCmd.AddCommand(restoreCmd)
}

func runAdminRestore(cmd *cobra.Command, args []string) error {
	if restoreInput == "" {
		return fmt.Errorf("--input is required")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Storage.Type != "local" && cfg.Storage.Type != "sqlite" && !isPostgresStorage(cfg) {
		return fmt.Errorf("admin restore does not support storage type %q", cfg.Storage.Type)
	}

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	version, err := peekFormatVersion(restoreInput)
	if err != nil {
		return fmt.Errorf("read backup archive %q: %w", restoreInput, err)
	}
	switch version {
	case backupFormatVersion: // 1
		fmt.Println("NOTE: this archive uses the deprecated v1 (physical, pre-2026-09-28) backup format -- " +
			"it still restores, but take a fresh backup under the current format when convenient.")
		return runAdminRestoreV1(cfg)
	case backupfmt.FormatVersion: // 2
		return runAdminRestoreV2(cfg)
	default:
		return fmt.Errorf("backup archive format version %d is not supported by this binary (supports version %d or %d)",
			version, backupFormatVersion, backupfmt.FormatVersion)
	}
}

// peekFormatVersion reads just enough of the archive (its first tar entry,
// which must be MANIFEST.json in either format) to learn which format
// reader to dispatch to -- both backupManifest (v1) and backupfmt.Manifest
// (v2) declare format_version as their first JSON field, at the same
// top-level position, so this generic probe works against either without
// needing to know which one it's looking at yet.
func peekFormatVersion(path string) (int, error) {
	f, err := secretenv.OpenRegularNamed("backup archive", path) // operator-supplied input path; a FIFO is refused, not waited on
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck

	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("not a valid backup archive (gzip): %w", err)
	}
	defer gz.Close() //nolint:errcheck
	tr := tar.NewReader(gz)

	hdr, err := tr.Next()
	if err != nil {
		return 0, fmt.Errorf("read tar entry: %w", err)
	}
	if hdr.Name != "MANIFEST.json" {
		return 0, fmt.Errorf("archive's first entry is %q, expected MANIFEST.json -- not a keyorix-server admin backup", hdr.Name)
	}
	// A generous but bounded cap for the peek alone -- the real per-format
	// reader (readBackupArchive or ExtractArchive) re-applies the
	// operator-configured --max-entry-bytes immediately after this returns.
	data, err := io.ReadAll(io.LimitReader(tr, 64<<20))
	if err != nil {
		return 0, fmt.Errorf("read manifest: %w", err)
	}
	var probe struct {
		FormatVersion int `json:"format_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return 0, fmt.Errorf("parse manifest: %w", err)
	}
	return probe.FormatVersion, nil
}

// saturatingQuadruple returns n*4, clamped to math.MaxInt64 rather than
// silently overflowing into a negative int64 -- archiveInfo.Size() is a real
// file's size and realistically nowhere near this range on any filesystem
// today, but CheckFreeSpace's own fail-closed guarantee (internal/backupfmt/
// preflight.go) is only as good as what its caller hands it, and a negative
// requiredBytes here would otherwise reach CheckFreeSpace's own refusal for
// a different, confusing reason.
func saturatingQuadruple(n int64) int64 {
	if n < 0 || n > math.MaxInt64/4 {
		return math.MaxInt64
	}
	return n * 4
}

// runAdminRestoreV2 is the current (design-b3-backup-v2.md) restore path.
func runAdminRestoreV2(cfg *config.Config) error { // NOSONAR -- cognitive complexity, orchestrates §5.3's full stage-then-verify-then-commit sequence in one place deliberately
	isPG := isPostgresStorage(cfg)

	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}
	if isPG {
		if err := refuseNonEmptyPostgresTarget(cfg); err != nil {
			return err
		}
	} else if err := refuseNonEmptyExisting("database", dbPath); err != nil {
		return err
	}
	targetKeyPaths, err := expectedKeyFilePaths(cfg)
	if err != nil {
		return err
	}
	for _, p := range targetKeyPaths {
		if err := refuseNonEmptyExisting("key file", p); err != nil {
			return err
		}
	}

	archiveInfo, err := os.Stat(restoreInput)
	if err != nil {
		return fmt.Errorf("stat %q: %w", restoreInput, err)
	}
	// Staging needs roughly the uncompressed archive size again on top of
	// what's already on disk (the compressed archive itself); 4x the
	// compressed size is a deliberately generous, simple estimate (design
	// §7.4 doesn't mandate a precise compression-ratio calculation).
	if err := backupfmt.CheckFreeSpace(restoreInput, saturatingQuadruple(archiveInfo.Size())); err != nil {
		return fmt.Errorf("preflight free-space check (design §7.4): %w", err)
	}

	stagingDir, err := os.MkdirTemp("", "keyorix-admin-restore-*")
	if err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir) //nolint:errcheck

	archiveFile, err := secretenv.OpenRegularNamed("backup archive", restoreInput) // operator-supplied input path; a FIFO is refused, not waited on
	if err != nil {
		return fmt.Errorf("open %q: %w", restoreInput, err)
	}
	manifest, err := backupfmt.ExtractArchive(archiveFile, stagingDir, restoreMaxEntryBytes, restoreMaxTotalBytes)
	_ = archiveFile.Close()
	if err != nil {
		return fmt.Errorf("extract backup archive %q: %w", restoreInput, err)
	}

	if manifest.Backend != backupfmt.Backend {
		return fmt.Errorf("backup archive is format %q, this binary writes/expects %q -- restore refuses to mix formats",
			manifest.Backend, backupfmt.Backend)
	}
	if storage.SchemaEpochTooNew(manifest.SchemaEpoch) {
		return fmt.Errorf("backup archive's schema epoch %d is newer than this binary's schema epoch %d (ADR-097) -- "+
			"this backup was taken by a newer version of Keyorix; upgrade this binary before restoring it",
			manifest.SchemaEpoch, storage.CurrentSchemaEpoch())
	}
	if err := validateKeyFileSetV2(manifest.KeyFiles, targetKeyPaths); err != nil {
		return err
	}

	// design §5.3 step 2: unwrap the KEK from the archive's own STAGED
	// (still-wrapped) key files -- never the real target's, which has none
	// yet on a fresh restore. kekStagingDir is laid out with the SAME
	// relative paths cfg.Storage.Encryption expects, so the exact same
	// internal/encryption code path `admin diagnose`/`admin backup` use
	// works unmodified, just pointed elsewhere.
	stagedCfg, kekStagingDir, err := stageKeyFilesForKEKUnwrap(cfg, stagingDir, manifest.KeyFiles, targetKeyPaths)
	if err != nil {
		return err
	}
	manifestKey, err := unwrapManifestKey(stagedCfg, kekStagingDir, restorePassphraseSource, nil)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(manifestKey)

	if !backupfmt.VerifyManifestSignature(manifest, manifestKey) {
		return fmt.Errorf("backup archive's manifest signature is invalid -- the archive may be corrupted or " +
			"tampered with; restore refuses (design §5)")
	}

	// Rollback protection (§6.3) -- BEFORE any write to the real target,
	// reusing checkRollbackProtection UNCHANGED (the same function #2233
	// added and this restore path's v1 sibling still uses) by re-encoding
	// the v2 manifest's structured Checkpoint back into the same encoded
	// string shape ParseHighWater already knows. On Postgres, dbPath is
	// replaced by a synthesized identity path (postgresTargetIdentityPath)
	// used ONLY for its directory component (auditverify.WitnessPath) --
	// there is no single database file to open directly, so every count
	// below is read via the Postgres-specific helpers instead.
	identityPath := dbPath
	var destinationFloor, newerSubstantive int64
	highWaterEncoded := checkpointBundleToHighWaterString(manifest.Checkpoint)
	archiveRaw, err := archiveHeadFromStagedAuditEvents(stagingDir, manifest)
	if err != nil {
		return fmt.Errorf("read the archived database's audit event count: %w", err)
	}
	if isPG {
		identityPath, err = postgresTargetIdentityPath(cfg)
		if err != nil {
			return err
		}
		destinationFloor, err = postgresAuditEventCount(cfg)
		if err != nil {
			return fmt.Errorf("read existing destination database's audit event count: %w", err)
		}
		newerSubstantive, err = postgresAuditEventsNewerThan(cfg, archiveRaw)
		if err != nil {
			return fmt.Errorf("read existing destination database's newer audit events: %w", err)
		}
	} else {
		destinationFloor, err = readExistingDatabaseAuditEventCount(dbPath)
		if err != nil {
			return fmt.Errorf("read existing destination database's audit event count: %w", err)
		}
		newerSubstantive, err = destinationEventsNewerThan(dbPath, archiveRaw)
		if err != nil {
			return fmt.Errorf("read existing destination database's newer audit events: %w", err)
		}
	}
	rollbackCheck, err := checkRollbackProtection(highWaterEncoded, identityPath, destinationFloor, archiveRaw, newerSubstantive)
	if err != nil {
		return err
	}

	// Only past every check above: move staged key files into place, run
	// migrations against the fresh target, then load the data (design §3.4).
	restoreTS := time.Now().UTC().Format("20060102T150405Z")
	keyFileData := make([][]byte, len(manifest.KeyFiles))
	for i, entry := range manifest.KeyFiles {
		data, rerr := os.ReadFile(filepath.Join(stagingDir, entry.TarName)) // #nosec G304 -- our own staged file, already checksum-verified by ExtractArchive
		if rerr != nil {
			return fmt.Errorf("read staged key file %q: %w", entry.TarName, rerr)
		}
		keyFileData[i] = data
	}
	// A single atomic-set install, not a per-file loop: these key files form
	// one encryption configuration's required set (keyfiles.Registry), and a
	// host with only SOME of them present can never start -- see
	// writeRestoredFileSet's own doc comment.
	if err := writeRestoredFileSet(targetKeyPaths, keyFileData, restoreTS); err != nil {
		return fmt.Errorf("write key file set: %w", err)
	}
	if !isPG {
		// v2 loads rows into a freshly-migrated database rather than writing
		// a whole DB file (v1), so with --overwrite-existing the existing
		// database must be moved aside first -- migrating and loading into it
		// in place fails on the first colliding primary key.
		if err := moveAsideExistingSQLiteDB(dbPath, restoreTS); err != nil {
			return err
		}
		if err := removeStaleSQLiteSidecars(dbPath); err != nil {
			return fmt.Errorf("clear stale WAL sidecar files for %q: %w", dbPath, err)
		}
	}

	fmt.Println("Running migrations against the fresh target database...")
	if _, err := storage.NewStorageFactory().CreateStorage(cfg); err != nil {
		return fmt.Errorf("migrate restored database: %w", err)
	}

	targetDB, err := storage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("open freshly-migrated target database: %w", err)
	}
	defer closeGormDB(targetDB)

	fmt.Println("Loading data into the restored database (design §3.4)...")
	if loadErr := targetDB.Transaction(func(tx *gorm.DB) error {
		if err := backupfmt.LoadArchive(tx, manifest, stagingDir); err != nil {
			return err
		}
		return backfillOTPExpiryForOlderArchive(tx, manifest)
	}); loadErr != nil {
		return fmt.Errorf("load backup data: %w", loadErr)
	}

	if isPG {
		// Every row LoadArchive just inserted carries its ORIGINAL, explicit
		// primary-key value -- design's whole point, so cross-table
		// references keep resolving -- but Postgres never auto-advances a
		// SERIAL/BIGSERIAL column's sequence for an explicit-value INSERT
		// (only a value-omitted one calls nextval()). Left unresynced, the
		// very next auto-generated INSERT on any restored table collides
		// with an already-restored row's id -- found live as this exact
		// function's own upcoming recordAdminAction call failing with a
		// duplicate-key error on audit_events, and, worse, as the first real
		// login attempt against the freshly-restored server returning 401
		// (a Postgres connection left in an aborted-transaction state by
		// one of those failures poisons whichever request draws it next).
		// The same fixup pg_dump/pg_restore already do automatically.
		sqlDB, err := postgresOpenSQL(cfg)
		if err != nil {
			return fmt.Errorf("open target Postgres database to resync sequences: %w", err)
		}
		resyncErr := resyncPostgresSequences(sqlDB)
		_ = sqlDB.Close()
		if resyncErr != nil {
			return fmt.Errorf("resync Postgres sequences after restore: %w", resyncErr)
		}
	}

	var totalRows int64
	for _, te := range manifest.Tables {
		totalRows += te.RowCount
	}
	fmt.Printf("Restored %d table(s), %d row(s), %d key file(s) from %s (backup created %s)\n",
		len(manifest.Tables), totalRows, len(manifest.KeyFiles), restoreInput, manifest.CreatedAt.Format(time.RFC3339))
	fmt.Println("Run 'keyorix-server admin diagnose' to further confirm the restore.")

	recordAdminAction(cfg, "admin.restore_completed",
		fmt.Sprintf("restored from backup archive %s (created %s, format v2)", restoreInput, manifest.CreatedAt.Format(time.RFC3339)), true)

	if rollbackCheck.archiveEncoded != "" {
		if _, werr := auditverify.WriteWitnessIfHigher(auditverify.WitnessPath(identityPath), rollbackCheck.archiveEncoded); werr != nil {
			fmt.Printf("note: could not update the rollback-protection witness file: %v\n", werr)
		}
	}
	if rollbackCheck.overrodeRollback {
		recordAdminAction(cfg, "admin.restore_rollback_override",
			fmt.Sprintf("restored a backup that is %d audit event(s) behind this host's last known state "+
				"(--allow-rollback was used) -- any user/credential revocation recorded after that point is undone by this restore",
				rollbackCheck.gapEvents), true)
	}

	if isPG {
		return verifyRestoredAuditPostgres(cfg)
	}
	return verifyRestoredAudit(cfg, dbPath)
}

// validateKeyFileSetV2 is validateKeyFileSetV1 (backup_v1_legacy.go) for
// backupfmt.KeyFileEntry.
func validateKeyFileSetV2(archived []backupfmt.KeyFileEntry, target []string) error {
	if len(archived) != len(target) {
		return fmt.Errorf("backup archive has %d key file(s) but this config's encryption settings expect %d -- "+
			"restore refuses a partial/mismatched key-file set", len(archived), len(target))
	}
	for i, entry := range archived {
		if entry.OriginalPath != target[i] {
			return fmt.Errorf("backup archive's key file #%d is for path %q, this config expects %q -- "+
				"restore refuses a mismatched key-file set (restore into the same config the backup was taken from)",
				i, entry.OriginalPath, target[i])
		}
	}
	return nil
}

// stageKeyFilesForKEKUnwrap copies each archive key file's ALREADY-STAGED,
// checksum-verified bytes (in stagingDir/<TarName>, per ExtractArchive) into
// a fresh subdirectory mirroring the paths cfg.Storage.Encryption expects,
// and returns a copy of cfg whose key paths point at that mirror -- so
// unwrapManifestKey can point a real encryption.Service at it unmodified.
//
// #2604: every staged path must land INSIDE the staging directory. A
// relative key path already did; an ABSOLUTE one (the Docker image's
// /app/keys/... config) used to resolve, via keyfiles.Registry, to the real
// target path itself, so this "staging" step wrote the archive's key files
// straight into the target's key directory -- and commitRestoredFile's
// concurrent-creation guard then (correctly) refused to overwrite them,
// failing every restore onto a fresh, empty keys volume. stagedKeyPath/
// stagedEncryptionConfig (backup.go) re-root absolute paths under the
// staging directory instead; the guard itself is unchanged.
//
// targetKeyPaths is expectedKeyFilePaths(cfg), already validated 1:1 against
// keyFileEntries by validateKeyFileSetV2. Destinations are derived from it
// (config), never from the archive's own key-file metadata.
func stageKeyFilesForKEKUnwrap(cfg *config.Config, stagingDir string, keyFileEntries []backupfmt.KeyFileEntry, targetKeyPaths []string) (*config.Config, string, error) {
	kekDir := filepath.Join(stagingDir, "kek-material")
	if err := os.MkdirAll(kekDir, 0700); err != nil {
		return nil, "", fmt.Errorf("create KEK-unwrap staging directory: %w", err)
	}
	if len(targetKeyPaths) != len(keyFileEntries) {
		return nil, "", fmt.Errorf("internal error: %d expected key-file paths but %d archive key files", len(targetKeyPaths), len(keyFileEntries))
	}
	for i, entry := range keyFileEntries {
		data, err := os.ReadFile(filepath.Join(stagingDir, entry.TarName)) // #nosec G304 -- our own staged file, already checksum-verified by ExtractArchive
		if err != nil {
			return nil, "", fmt.Errorf("read staged key file %q: %w", entry.TarName, err)
		}
		// dest is computed from targetKeyPaths[i] (cfg.Storage.Encryption via
		// keyfiles.Registry) and kekDir only -- never from entry, the
		// archive-controlled metadata data was read from above. gosec's taint
		// analysis (G703) flags this write because data and dest both trace
		// back through the same loop iteration, but only the ARRAY INDEX
		// correlates with entry, not the path value.
		dest := stagedKeyPath(kekDir, targetKeyPaths[i])
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return nil, "", fmt.Errorf("create directory for staged key file %q: %w", dest, err)
		}
		if err := os.WriteFile(dest, data, 0600); err != nil { // #nosec G703 -- dest is config-derived (see above), not archive-controlled
			return nil, "", fmt.Errorf("stage key file at %q: %w", dest, err)
		}
	}
	stagedCfg := *cfg
	stagedCfg.Storage.Encryption = stagedEncryptionConfig(cfg.Storage.Encryption, kekDir)
	return &stagedCfg, kekDir, nil
}

// checkpointBundleToHighWaterString converts a v2 manifest's structured
// Checkpoint (design §5.4's ExternalAnchorBundle shape) back into the exact
// encoded string shape auditverify.ParseHighWater/EncodeHighWater use --
// letting checkRollbackProtection stay completely unchanged (and therefore
// exactly as tested) across both the v1 and v2 restore paths. nil (no
// checkpoint recorded -- a fresh/young source install) encodes to "".
func checkpointBundleToHighWaterString(b *auditverify.ExternalAnchorBundle) string {
	if b == nil {
		return ""
	}
	cp := &auditverify.Checkpoint{
		ChainedEvents: b.ChainedEvents,
		HeadID:        b.HeadID,
		HeadHash:      b.HeadHash,
		KeyVersion:    b.KeyVersion,
	}
	return auditverify.EncodeHighWater(cp, b.Signature)
}

// archiveHeadFromStagedAuditEvents returns the archived database's raw
// MAX(audit_events.id) -- the v2 equivalent of v1's
// auditEventCountFromDBBytes, computed by scanning the staged
// audit_events.ndjson file (rows are written in primary-key-ascending
// order, design §3.3, so the LAST successfully-parsed row's ID is the
// max) instead of querying a single-file SQLite image, since v2 has no
// such single file. 0 if the archive has no audit_events table entry at
// all (an install that never logged an event).
func archiveHeadFromStagedAuditEvents(stagingDir string, manifest backupfmt.Manifest) (int64, error) {
	var tarName string
	for _, te := range manifest.Tables {
		if te.Name == "audit_events" {
			tarName = te.TarName
			break
		}
	}
	if tarName == "" {
		return 0, nil
	}
	f, err := os.Open(filepath.Join(stagingDir, tarName)) // #nosec G304 -- our own staged file, already checksum-verified by ExtractArchive
	if err != nil {
		return 0, fmt.Errorf("open staged audit_events file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var maxID int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<30)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var row struct {
			ID uint
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return 0, fmt.Errorf("decode staged audit_events row: %w", err)
		}
		// #nosec G115 -- row.ID is an audit_events auto-increment primary key;
		// reaching math.MaxInt64 would require over 9.2 quintillion rows, not
		// a realistic overflow surface (the same reasoning this codebase's
		// preflight.go already applies to a filesystem block count/size
		// conversion).
		if int64(row.ID) > maxID {
			maxID = int64(row.ID)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read staged audit_events file: %w", err)
	}
	return maxID, nil
}

// runAdminRestoreV1 restores an archive written by the pre-2026-09-28
// physical (SQLite-only) format (#2099) -- unchanged from that format's
// original restore logic, kept until Keyorix 1.0 (design §3.6 decision 3).
func runAdminRestoreV1(cfg *config.Config) error {
	// v1 archives are always physical SQLite-file copies (#2099 never
	// supported any other backend) -- refuse a Postgres TARGET explicitly
	// here, rather than relying on manifest.Backend != "sqlite" below, which
	// only checks the ARCHIVE's own (always "sqlite") declared backend and
	// would otherwise silently pass regardless of cfg.Storage.Type, now that
	// runAdminRestore's outer gate admits Postgres configs too (H4).
	if isPostgresStorage(cfg) {
		return fmt.Errorf("this archive uses the deprecated v1 (physical, SQLite-only) backup format, which never " +
			"supported a Postgres target -- restore it into a SQLite-backed config, or take a fresh v2 backup " +
			"(design §3.6 decision 3)")
	}
	manifest, dbBytes, keyBlobs, err := readBackupArchive(restoreInput, restoreMaxEntryBytes, restoreMaxTotalBytes)
	if err != nil {
		return fmt.Errorf("read backup archive %q: %w", restoreInput, err)
	}
	if manifest.FormatVersion != backupFormatVersion {
		return fmt.Errorf("backup archive format version %d is not supported by this binary (supports version %d)",
			manifest.FormatVersion, backupFormatVersion)
	}
	if manifest.Backend != "sqlite" {
		return fmt.Errorf("backup archive is for backend %q, this config is sqlite -- restore refuses to mix backends", manifest.Backend)
	}

	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}
	if err := refuseNonEmptyExisting("database", dbPath); err != nil {
		return err
	}

	targetKeyPaths, err := expectedKeyFilePaths(cfg)
	if err != nil {
		return err
	}
	if err := validateKeyFileSetV1(manifest.KeyFiles, targetKeyPaths); err != nil {
		return err
	}

	if err := verifyChecksumV1(manifest.DBFile, dbBytes); err != nil {
		return err
	}
	for i, entry := range manifest.KeyFiles {
		if err := verifyChecksumV1(entry, keyBlobs[i]); err != nil {
			return err
		}
		if err := refuseNonEmptyExisting("key file", entry.OriginalPath); err != nil {
			return err
		}
	}

	destinationFloor, err := readExistingDatabaseAuditEventCount(dbPath)
	if err != nil {
		return fmt.Errorf("read existing destination database's audit event count: %w", err)
	}
	archiveRaw, err := auditEventCountFromDBBytes(dbBytes)
	if err != nil {
		return fmt.Errorf("read the archived database's audit event count: %w", err)
	}
	newerSubstantive, err := destinationEventsNewerThan(dbPath, archiveRaw)
	if err != nil {
		return fmt.Errorf("read existing destination database's newer audit events: %w", err)
	}
	rollbackCheck, err := checkRollbackProtection(manifest.AuditHighWater, dbPath, destinationFloor, archiveRaw, newerSubstantive)
	if err != nil {
		return err
	}

	restoreTS := time.Now().UTC().Format("20060102T150405Z")

	// A single atomic-set install, not a per-file loop -- see
	// writeRestoredFileSet's own doc comment (same gap as the v2 path's
	// key-file restore, fixed there for the same reason).
	keyFilePaths := make([]string, len(manifest.KeyFiles))
	for i, entry := range manifest.KeyFiles {
		keyFilePaths[i] = entry.OriginalPath
	}
	if err := writeRestoredFileSet(keyFilePaths, keyBlobs, restoreTS); err != nil {
		return fmt.Errorf("write key file set: %w", err)
	}
	if err := removeStaleSQLiteSidecars(dbPath); err != nil {
		return fmt.Errorf("clear stale WAL sidecar files for %q: %w", dbPath, err)
	}
	if err := writeRestoredFile(dbPath, dbBytes, restoreTS); err != nil {
		return fmt.Errorf("write database %q: %w", dbPath, err)
	}

	fmt.Println("Applying pending migrations to the restored database (idempotent)...")
	if _, err := storage.NewStorageFactory().CreateStorage(cfg); err != nil {
		return fmt.Errorf("migrate restored database: %w", err)
	}

	fmt.Printf("Restored database (%d bytes) and %d key file(s) from %s (backup created %s)\n",
		len(dbBytes), len(manifest.KeyFiles), restoreInput, manifest.CreatedAt.Format(time.RFC3339))
	fmt.Println("Run 'keyorix-server admin diagnose' to further confirm the restore.")

	recordAdminAction(cfg, "admin.restore_completed",
		fmt.Sprintf("restored from backup archive %s (created %s, format v1)", restoreInput, manifest.CreatedAt.Format(time.RFC3339)), true)

	if rollbackCheck.archiveEncoded != "" {
		if _, werr := auditverify.WriteWitnessIfHigher(auditverify.WitnessPath(dbPath), rollbackCheck.archiveEncoded); werr != nil {
			fmt.Printf("note: could not update the rollback-protection witness file: %v\n", werr)
		}
	}
	if rollbackCheck.overrodeRollback {
		recordAdminAction(cfg, "admin.restore_rollback_override",
			fmt.Sprintf("restored a backup that is %d audit event(s) behind this host's last known state "+
				"(--allow-rollback was used) -- any user/credential revocation recorded after that point is undone by this restore",
				rollbackCheck.gapEvents), true)
	}

	return verifyRestoredAudit(cfg, dbPath)
}

// rollbackCheckOutcome is checkRollbackProtection's result: whether the
// restore was allowed to proceed past a detected rollback, the size of that
// gap (for the audit event runAdminRestoreV1/V2 write once the restored
// chain is writable again), and the archive's own raw encoded high-water
// value (so the caller can advance the witness file to it after a
// successful restore, without re-parsing the manifest).
type rollbackCheckOutcome struct {
	overrodeRollback bool
	gapEvents        int64
	archiveEncoded   string
}

// checkRollbackProtection implements design-b3-backup-v2.md §6.3: compares
// the archive's own certified audit-trail progress (highWaterEncoded, empty
// if the source install had never written a checkpoint) against this host's
// witness file (sibling to dbPath, maintained by every server this host has
// run) BEFORE the caller writes anything to disk. Returns an error
// (refusing the restore) if the archive is behind and --allow-rollback was
// not given; any note worth printing is returned alongside a nil error
// otherwise. Shared unchanged by both the v1 and v2 restore paths --
// checkpointBundleToHighWaterString adapts v2's structured Checkpoint into
// this same encoded-string contract rather than this function changing.
//
// Reference = max(witness file, destinationFloor) -- destinationFloor (see
// readExistingDatabaseAuditEventCount) is the CURRENT destination database's
// own live raw audit-event count, read moments ago, right before this
// restore would overwrite it (0 when there is no pre-existing destination
// database). The witness file alone only advances on a checkpoint
// (scheduled, default every 24h, or on-demand) or a prior restore -- a
// change made to the destination since the last checkpoint would not have
// touched the witness at all. destinationFloor closes that gap: it has no
// checkpoint delay, because it is read directly, right now, from the exact
// database this restore is about to destroy.
//
// Three cases, per §6.3 (reference substituted for "witness" throughout):
//   - reference is 0 (no witness AND no pre-existing destination database):
//     nothing to compare against (a genuinely fresh host, or the first
//     restore ever run on this one) -- proceed. This is the legitimate
//     bootstrap case, not a gap to close.
//   - archive's high-water >= reference: this backup is at least as current
//     as anything this host has certified or the destination itself
//     contains -- proceed normally.
//   - archive's high-water < reference: refuse unless --allow-rollback.
//
// A malformed manifest.AuditHighWater (non-empty but unparseable -- a
// tampered or corrupted manifest) and a malformed witness file (exists but
// unparseable) are BOTH treated as hard errors, never silently downgraded to
// "absent" -- deleting or corrupting either one must not be a way to evade
// this check.
func checkRollbackProtection(highWaterEncoded, dbPath string, destinationFloor, archiveRaw, newerSubstantive int64) (rollbackCheckOutcome, error) {
	var archiveSigned int64
	if highWaterEncoded != "" {
		archiveCP, _, ok := auditverify.ParseHighWater(highWaterEncoded)
		if !ok {
			return rollbackCheckOutcome{}, fmt.Errorf(
				"backup archive's manifest carries an audit high-water value that does not parse -- " +
					"the manifest may be corrupted or tampered with; restore refuses rather than treat this as if the archive had no recorded history")
		}
		archiveSigned = archiveCP.ChainedEvents
	}

	witnessPath := auditverify.WitnessPath(dbPath)
	witnessCP, _, found, err := auditverify.ReadWitness(witnessPath)
	if err != nil {
		return rollbackCheckOutcome{}, fmt.Errorf(
			"could not read the rollback-protection witness file %q: %w -- investigate before proceeding "+
				"(a corrupted witness is not treated as absent)", witnessPath, err)
	}

	// Two independent comparisons, each between values of the same kind:
	//   - raw: the live destination database's MAX(audit_events.id) vs the
	//     archived database's own MAX(audit_events.id);
	//   - signed: the host witness's certified high-water vs the archive's
	//     certified high-water.
	// The archive is behind if EITHER says so; the reported gap is the larger.
	var gap, archiveEvents, reference int64
	// Raw: only events newer than the archive's own head that are NOT the
	// backup tool's own bookkeeping count (admin backup writes
	// admin.backup_created AFTER taking its snapshot, so the source database
	// is always one bookkeeping event ahead of its own freshest backup).
	if newerSubstantive > 0 {
		gap, archiveEvents, reference = newerSubstantive, archiveRaw, destinationFloor
	}
	if found && witnessCP.ChainedEvents > archiveSigned && witnessCP.ChainedEvents-archiveSigned > gap {
		gap, archiveEvents, reference = witnessCP.ChainedEvents-archiveSigned, archiveSigned, witnessCP.ChainedEvents
	}
	if gap == 0 {
		return rollbackCheckOutcome{archiveEncoded: highWaterEncoded}, nil
	}
	if !restoreAllowRollback {
		return rollbackCheckOutcome{}, fmt.Errorf(
			"refusing to restore: this backup's audit trail (%d event(s)) is %d event(s) BEHIND this host's own "+
				"last known state (%d event(s)) -- restoring it would silently un-revoke any user/credential access "+
				"revoked since this backup was taken. Pass --allow-rollback if this is a genuine disaster-recovery "+
				"restore of an intentionally older backup", archiveEvents, gap, reference)
	}
	fmt.Printf("WARNING: --allow-rollback is in effect. This backup's audit trail (%d event(s)) is %d event(s) "+
		"behind this host's own last known state (%d event(s)) -- proceeding will silently un-revoke any "+
		"user/credential access revoked since this backup was taken. Recording this override to the audit trail.\n",
		archiveEvents, gap, reference)
	return rollbackCheckOutcome{overrodeRollback: true, gapEvents: gap, archiveEncoded: highWaterEncoded}, nil
}

// readExistingDatabaseAuditEventCount opens dbPath (a SQLite file that may
// or may not exist yet) read-only and returns the raw, live MAX(id) from its
// audit_events table -- 0 when the file does not exist, is empty, or the
// table itself does not exist yet (a genuinely fresh/pre-migration database,
// not an error). This is deliberately a raw, unsigned count, not the signed
// checkpoint high-water: it needs to reflect changes made moments ago, with
// no checkpoint-interval delay, since it is read immediately before this
// exact database would be overwritten.
// rollbackBookkeepingEventTypes are audit events the admin tool itself writes
// around a backup; they never represent a revocation or any access change,
// so they do not make a destination "newer" than an archive.
var rollbackBookkeepingEventTypes = []string{"admin.backup_created"}

// destinationEventsNewerThan counts audit events in the existing destination
// database with id > archiveHead, excluding rollbackBookkeepingEventTypes.
// 0 when there is no destination database or no audit_events table.
func destinationEventsNewerThan(dbPath string, archiveHead int64) (int64, error) {
	info, statErr := os.Stat(dbPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return 0, nil
		}
		return 0, fmt.Errorf("stat %q: %w", dbPath, statErr)
	}
	if info.Size() == 0 {
		return 0, nil
	}
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return 0, fmt.Errorf("open %q read-only: %w", dbPath, err)
	}
	defer db.Close() //nolint:errcheck
	var n int64
	q := "SELECT COUNT(*) FROM audit_events WHERE id > ? AND event_type NOT IN (" +
		strings.TrimSuffix(strings.Repeat("?,", len(rollbackBookkeepingEventTypes)), ",") + ")"
	args := []any{archiveHead}
	for _, et := range rollbackBookkeepingEventTypes {
		args = append(args, et)
	}
	if err := db.QueryRow(q, args...).Scan(&n); err != nil { // nosemgrep: go.lang.security.audit.sqli.gosql-sqli.gosql-sqli -- q's dynamic part is only a "?,?,..." placeholder run sized off len(rollbackBookkeepingEventTypes) (a package-level literal slice); every actual value (archiveHead, et) is passed as a parameterized arg, never interpolated into q
		if strings.Contains(err.Error(), "no such table") {
			return 0, nil
		}
		return 0, fmt.Errorf("count newer audit events in %q: %w", dbPath, err)
	}
	return n, nil
}

func readExistingDatabaseAuditEventCount(dbPath string) (int64, error) {
	info, statErr := os.Stat(dbPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return 0, nil
		}
		return 0, fmt.Errorf("stat %q: %w", dbPath, statErr)
	}
	if info.Size() == 0 {
		return 0, nil
	}

	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return 0, fmt.Errorf("open %q read-only: %w", dbPath, err)
	}
	defer db.Close() //nolint:errcheck

	var count sql.NullInt64
	if err := db.QueryRow("SELECT MAX(id) FROM audit_events").Scan(&count); err != nil {
		// A missing audit_events table (a database created but never
		// migrated) is the fresh-database case, not a hard error -- every
		// other error (a genuinely corrupt or unreadable file) is.
		if strings.Contains(err.Error(), "no such table") {
			return 0, nil
		}
		return 0, fmt.Errorf("read audit_events count from %q: %w", dbPath, err)
	}
	return count.Int64, nil
}

// verifyRestoredAudit runs the same offline audit-chain re-walk
// `admin verify-audit` exposes as a standalone command, directly against the
// just-restored database file -- never through the config's normal
// server-guard-locked path, since this restore already holds that lock for
// its own duration (see acquireDatabaseLock above; a second acquisition
// attempt on the same config would just fail).
//
// A checksum (v1) or a manifest signature (v2) only prove the archive was
// not corrupted/tampered IN TRANSIT -- this is the step in restore that can
// detect the RESTORED DATABASE was tampered with (or the source itself was,
// before backup ever ran), by re-walking its ADR-029 audit hash chain -- run
// automatically so an operator doesn't have to remember to do it by hand.
// Only a BROKEN verdict fails restore (non-zero exit); VALID and
// INDETERMINATE are both reported but do not, matching verify-audit's own
// documented semantics.
func verifyRestoredAudit(cfg *config.Config, dbPath string) error {
	db, err := auditverify.OpenSQLiteReadOnly(dbPath)
	if err != nil {
		return fmt.Errorf("open restored database for automatic verify-audit: %w", err)
	}
	defer db.Close() //nolint:errcheck
	return runVerifyRestoredAudit(cfg, db)
}

// runVerifyRestoredAudit is verifyRestoredAudit's backend-neutral core,
// shared with verifyRestoredAuditPostgres (restore_postgres.go) -- takes an
// already-opened auditverify.DB (either dialect; that package's own
// independence requirement means every query past this point is identical
// regardless of which one it is).
func runVerifyRestoredAudit(cfg *config.Config, db *auditverify.DB) error {
	var opts auditverify.Options
	if cfg.Audit.OfflineAnchorPath != "" {
		data, err := secretenv.ReadRegularFile("audit anchor", cfg.Audit.OfflineAnchorPath) // operator-configured path (audit.offline_anchor_path); a FIFO is refused, not waited on
		if err != nil {
			return fmt.Errorf("automatic verify-audit: read configured offline anchor %q: %w", cfg.Audit.OfflineAnchorPath, err)
		}
		bundle, err := auditverify.ParseExternalAnchorBundle(data)
		if err != nil {
			return fmt.Errorf("automatic verify-audit: parse configured offline anchor %q: %w", cfg.Audit.OfflineAnchorPath, err)
		}
		opts.ExternalAnchor = bundle
	}

	// The restored key files are in place by now: derive the same KEK-derived
	// checkpoint key `admin audit export-checkpoint-key` would write, so a retention
	// gap left by a sanctioned purge authenticates (without it every database that was
	// ever purged restored as INDETERMINATE, while `admin verify-audit
	// --checkpoint-key-file` on the same data said VALID). A failure to derive it is
	// not fatal: verification still runs, and says why it could not authenticate.
	if key, _, kerr := deriveCheckpointKey(cfg, restorePassphraseSource); kerr == nil {
		defer crypto.WipeBytes(key)
		opts.CheckpointKey = key
	} else {
		fmt.Printf("note: could not derive the audit-checkpoint key for the automatic verify-audit: %v\n", kerr)
	}

	result, err := auditverify.Verify(context.Background(), db, opts)
	if err != nil {
		return fmt.Errorf("automatic verify-audit failed to run: %w", err)
	}

	fmt.Printf("verify-audit on the restored database: %s", result.Verdict)
	if result.Reason != "" {
		fmt.Printf(" (%s)", result.Reason)
	}
	fmt.Println()

	if result.Verdict == auditverify.VerdictBroken {
		return newExitCodeError(1, fmt.Errorf(
			"the restored database failed automatic audit-chain verification (%s) -- do not trust this restore; "+
				"run 'keyorix-server admin verify-audit' directly for the full report", result.Verdict))
	}
	return nil
}

// expectedKeyFilePaths re-derives the CURRENT (restore-target) config's
// key-material paths via the same registry `admin audit`/`admin backup` use.
// keyfiles.Registry's required entries (salt, DEK, provider wrapped-key,
// shamir shares) are included unconditionally regardless of whether the file
// currently exists on disk -- exactly what a fresh/empty data dir needs.
func expectedKeyFilePaths(cfg *config.Config) ([]string, error) {
	specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
	if err != nil {
		return nil, fmt.Errorf("build key-file registry: %w", err)
	}
	paths := make([]string, len(specs))
	for i, s := range specs {
		paths[i] = s.Path
	}
	return paths, nil
}

// removeStaleSQLiteSidecars removes dbPath's WAL-mode sidecar files
// (-wal, -shm) if present. Best-effort existence-based removal: absent is
// the common/expected case (a genuinely fresh data dir), not an error.
// moveAsideExistingSQLiteDB renames an existing, non-empty SQLite database
// (and its -wal/-shm sidecars, which hold committed-but-uncheckpointed pages
// of that same database) to "<path>.pre-restore-<restoreTS>", the same
// never-truncate convention writeRestoredFile uses for key files. Only acts
// under --overwrite-existing; without it refuseNonEmptyExisting has already
// refused a non-empty target, and a 0-byte placeholder is migrated in place.
func moveAsideExistingSQLiteDB(dbPath, restoreTS string) error {
	if !restoreOverwriteExisting {
		return nil
	}
	info, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat existing database %q: %w", dbPath, err)
	}
	if info.Size() == 0 {
		return nil
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := dbPath + suffix
		aside := fmt.Sprintf("%s.pre-restore-%s%s", dbPath, restoreTS, suffix)
		if err := os.Rename(src, aside); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("move existing %q aside to %q: %w", src, aside, err)
		}
	}
	return fsyncDir(filepath.Dir(dbPath))
}

func removeStaleSQLiteSidecars(dbPath string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// refuseNonEmptyExisting is the "don't trade loud failure for silent data
// loss" guard: a missing or genuinely-empty (0-byte, e.g. `admin init
// --database` on a fresh dir) target is fine to write, but anything with
// actual content requires an explicit --overwrite-existing.
func refuseNonEmptyExisting(label, path string) error {
	if restoreOverwriteExisting {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil // does not exist (or another error writeRestoredFile will surface) -- fine to write
	}
	if info.Size() > 0 {
		return fmt.Errorf("%s %q already exists and is not empty -- restore refuses to overwrite it "+
			"(pass --overwrite-existing if you are certain, e.g. this is a genuine disaster-recovery restore; "+
			"the normal flow is restoring into a fresh/empty data dir)", label, path)
	}
	return nil
}

// writeRestoredFile atomically writes data to path -- see prepareRestoredFile
// and commitRestoredFile, which this just runs back-to-back for a single
// file. A multi-file SET (the key-material files restored together) should
// use writeRestoredFileSet instead, which runs every file's prepare phase to
// completion before committing any of them -- see that function's own doc
// comment for why.
func writeRestoredFile(path string, data []byte, restoreTS string) error {
	tmpPath, err := prepareRestoredFile(path, data)
	if err != nil {
		return err
	}
	return commitRestoredFile(path, tmpPath, restoreTS)
}

// writeRestoredFileSet installs a SET of restored files -- the key-material
// files a single encryption configuration needs together (KEK salt, wrapped
// DEK, provider-specific files) -- as a tight group rather than one at a
// time. restore.go's per-file guarantee (temp + fsync + rename/link) makes
// EACH file crash-safe on its own, but says nothing about the SET: the
// previous code called writeRestoredFile for each key file in a simple loop,
// so a crash between file i and file i+1 left the target with a partial key
// set (e.g. the KEK salt restored, the wrapped DEK not) -- a host that can
// never start (keyfiles.Registry requires every entry), with no automatic
// recovery. Worse, without --overwrite-existing, a retry doesn't help: the
// already-written file(s) are now non-empty, so refuseNonEmptyExisting's
// preflight check (which ran once, before ANY file in this restore was
// written) fails on the very next attempt -- an operator would need to
// manually find and delete the partially-restored file(s) first, something
// this restore command gives no guidance about.
//
// This narrows that window rather than claiming to close it (true atomicity
// across independently-pathed files isn't achievable without a filesystem
// transaction): every file's prepare phase (write + fsync a temp copy) runs
// to completion FIRST, for the whole set, with every target path still
// completely untouched -- a failure here leaves nothing installed, so a
// retry sees the exact same preflight state as the first attempt. Only once
// every file in the set is durably staged does the commit phase begin,
// installing each one in turn. The unsafe window shrinks from "any of N full
// write+fsync+rename cycles, with whatever else runs between them" down to
// "N fast rename/link syscalls run back-to-back with nothing else
// interleaved" -- still not zero, but as tight as this per-path (not
// per-directory) file set allows.
func writeRestoredFileSet(paths []string, data [][]byte, restoreTS string) error {
	if len(paths) != len(data) {
		return fmt.Errorf("internal error: %d paths but %d data buffer(s) for a restored file set", len(paths), len(data))
	}

	type staged struct {
		path, tmpPath string
	}
	var prepared []staged
	for i, path := range paths {
		tmpPath, err := prepareRestoredFile(path, data[i])
		if err != nil {
			for _, s := range prepared {
				_ = os.Remove(s.tmpPath)
			}
			return err
		}
		prepared = append(prepared, staged{path: path, tmpPath: tmpPath})
	}

	for _, s := range prepared {
		if err := commitRestoredFile(s.path, s.tmpPath, restoreTS); err != nil {
			return fmt.Errorf("install %q: %w", s.path, err)
		}
	}
	return nil
}

// prepareRestoredFile writes data to a temp file in path's directory and
// fsyncs it, without touching path itself -- the half of writeRestoredFile
// that can be run for an entire file SET before any of them commit (see
// writeRestoredFileSet). On any error the temp file is removed and "" is
// returned; on success, the caller owns cleanup of the returned temp path
// (commitRestoredFile removes it as part of installing, or the caller must
// os.Remove it directly if abandoning the prepare).
func prepareRestoredFile(path string, data []byte) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("create directory: %w", err)
	}

	// #nosec G304 -- path is either this config's own database path or one
	// returned by keyfiles.Registry (already SafePath-sanitized) and, for key
	// files, already matched 1:1 against the archive manifest by
	// validateKeyFileSetV1/V2 -- never an attacker-controlled path from the archive.
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".restoring-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, restoreFileMode); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("set file mode: %w", err)
	}
	return tmpPath, nil
}

// commitRestoredFile installs tmpPath (an already-written-and-fsynced temp
// file from prepareRestoredFile, in the same directory as path) at path --
// renamed (or, without --overwrite-existing, hard-linked -- see below) into
// place, then fsyncs the directory. Always writes restoreFileMode (0600),
// never whatever mode the archive's manifest recorded -- a crafted manifest
// must never be able to make a restored key/DB file group- or
// world-readable.
//
// With --overwrite-existing, an existing file at path is renamed aside to
// "<path>.pre-restore-<restoreTS>" (never truncated or overwritten in
// place) before the new file is renamed in, so an unrecoverable mistake
// during an --overwrite-existing restore still has a way back. Without it,
// the new file is hard-linked into place instead of renamed: os.Link fails
// atomically with EEXIST if path already exists, closing the window between
// refuseNonEmptyExisting's earlier check and this write during which
// another process could have created path (os.Rename has no portable
// no-clobber option and would silently replace it).
func commitRestoredFile(path, tmpPath, restoreTS string) error {
	dir := filepath.Dir(path)
	// No-op once renamed/linked into place below.
	defer os.Remove(tmpPath) //nolint:errcheck

	if restoreOverwriteExisting {
		if _, err := os.Stat(path); err == nil {
			aside := fmt.Sprintf("%s.pre-restore-%s", path, restoreTS)
			if err := os.Rename(path, aside); err != nil {
				return fmt.Errorf("move existing %q aside to %q: %w", path, aside, err)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %q: %w", path, err)
		}
		if err := os.Rename(tmpPath, path); err != nil {
			return fmt.Errorf("rename into place: %w", err)
		}
	} else {
		// Re-check immediately before linking (refuseNonEmptyExisting's own
		// check happened earlier, before any file in this restore was
		// written) -- a non-empty file here means something else created it
		// concurrently during this restore, not the archive being restored.
		if info, err := os.Stat(path); err == nil {
			if info.Size() > 0 {
				return fmt.Errorf("%q was created concurrently during restore and is not empty -- refusing to overwrite it", path)
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove empty placeholder %q: %w", path, err)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %q: %w", path, err)
		}
		if err := os.Link(tmpPath, path); err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("%q was created concurrently during restore -- refusing to overwrite it", path)
			}
			return fmt.Errorf("link into place: %w", err)
		}
	}

	if err := fsyncDir(dir); err != nil {
		return fmt.Errorf("fsync directory %q: %w", dir, err)
	}
	return nil
}

// fsyncDir fsyncs a directory's own inode/entry list after a create, link,
// or rename within it -- otherwise the new directory entry pointing at the
// just-written, already-fsynced file can itself be lost on a crash, even
// though the file's own contents were durably synced.
func fsyncDir(dir string) error {
	// #nosec G304 -- dir is filepath.Dir() of writeRestoredFile's own path
	// argument, never attacker-controlled archive content (see that
	// function's own #nosec comment).
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck
	return d.Sync()
}
