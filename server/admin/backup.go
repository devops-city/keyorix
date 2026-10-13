// backup.go implements `keyorix-server admin backup` (ADR-108 §B3,
// design-b3-backup-v2.md): a consistent, offline, backend-neutral logical
// snapshot of the database and every encryption key-material file. On
// SQLite, always taken while this admin command holds the database
// exclusively (acquireDatabaseLock) -- the same "operations that need the
// database to themselves" guarantee every other admin command relies on. On
// Postgres, consistency instead comes from a single REPEATABLE READ
// snapshot transaction by default (design §4) -- the exclusive lock is an
// explicit --exclusive opt-in there, since holding it would block an
// ADR-039 HA deployment's other replicas from (re)starting for the whole
// backup, the exact availability cost those deployments choose Postgres to
// avoid.
//
// A complete backup is TWO things -- the database and the keys -- matching
// docs/SELF_HOSTING.md §5's existing manual guidance for the Docker/Postgres
// deployment shape. Every backup now writes the v2 logical format
// (internal/backupfmt) unconditionally -- design §3.6's explicit decision:
// no --format=physical escape hatch, no conditional/opt-in physical mode.
// `admin restore` still reads an old v1-physical-format archive (backup_v1_
// legacy.go) until Keyorix 1.0; this command never produces one again.
package admin

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// auditHighWaterMetadataKey is the system_metadata key internal/core's
// advanceAuditHighWater (audit_checkpoint.go) writes under -- must stay
// byte-for-byte identical to that unexported constant and to
// internal/auditverify's own copy (verify.go), since all three read/write
// the exact same row. Duplicated rather than imported: server/admin cannot
// reach internal/core's unexported constant, and this package already has
// its own direct-SQL access pattern to the raw DB.
const auditHighWaterMetadataKey = "audit_checkpoint_highwater" // #nosec G101 -- metadata key name, not a credential

// backupLiveAfterReadHook, when non-nil, runs on the live-server path after
// every key-file and database read and before the key set is re-verified.
// Test-only: it lets a test change a key file at exactly that point. Always
// nil in production.
var backupLiveAfterReadHook func()

var (
	backupOutput           string
	backupPassphraseSource crypto.PassphraseSource
	backupExclusive        bool
)

// isPostgresStorage reports whether cfg is configured for Postgres storage
// -- the same two spellings storage/factory.go's own createPostgresStorage
// dispatch accepts.
func isPostgresStorage(cfg *config.Config) bool {
	return cfg.Storage.Type == "postgres" || cfg.Storage.Type == "postgresql"
}

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a consistent offline backup of the database and encryption keys",
	Long: `Writes a single archive (--output) containing a consistent, backend-neutral
logical snapshot of the configured database AND every encryption
key-material file (internal/keyfiles.Registry -- the same enumeration
'admin audit' checks). Neither alone is a usable backup: the database
without the keys is unreadable ciphertext, the keys without the database
are useless.

The archive's per-table manifest is signed (HMAC-SHA256, KEK-derived key,
design-b3-backup-v2.md §5) so tampering is caught by 'admin restore' before
any byte reaches the target -- not only by a post-hoc 'admin verify-audit'.

On SQLite, consistency is guaranteed by the same exclusive database lock
every admin command takes: no server (or other admin command) can be
writing while this runs -- so on SQLite, STOP THE SERVER FIRST; a backup
beside a live SQLite server is refused. On Postgres, backup instead reads
through a single REPEATABLE READ snapshot transaction by default (design §4)
and works beside a LIVE server (e.g. 'docker compose exec backend ...'): the
key files are read while holding the key-rotation read lock, so no key
rotation can change them or re-encrypt rows until every read is done, and
they are re-checked afterwards -- if a rotation is in progress, or the key
files changed during the backup, it fails and leaves no archive. Pass
--exclusive for the stronger (but availability-costing) guarantee of also
holding the exclusive lock, e.g. before a major upgrade; that needs the
server stopped.

--output must not already exist: each backup is a distinct, timestamped
artifact. Store it OFF this host -- a backup that never leaves the machine
it was taken on protects against nothing.

Restore with: keyorix-server admin restore --input <archive>`,
	RunE: runAdminBackup,
}

func init() {
	backupCmd.Flags().StringVar(&backupOutput, "output", "", "Path to write the backup archive to (must not already exist; required)")
	backupCmd.Flags().BoolVar(&backupExclusive, "exclusive", false,
		"Postgres only: hold this database's exclusive advisory lock for the whole backup, on top of the default "+
			"REPEATABLE READ snapshot -- v1's stronger (but HA-availability-costing) guarantee, for e.g. a maintenance-"+
			"window backup before a major upgrade (design §4). No effect on SQLite, which already always holds this lock.")
	registerPassphraseFlags(backupCmd, &backupPassphraseSource)
	rootCmd.AddCommand(backupCmd)
}

func runAdminBackup(cmd *cobra.Command, args []string) error {
	if backupOutput == "" {
		return fmt.Errorf("--output is required")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Storage.Type != "local" && cfg.Storage.Type != "sqlite" && !isPostgresStorage(cfg) {
		return fmt.Errorf("admin backup does not support storage type %q", cfg.Storage.Type)
	}

	// design §4: SQLite always holds the exclusive lock (VACUUM INTO's own
	// precedent, and its only consistency mechanism); Postgres holds it only
	// with --exclusive -- by default, Postgres backups run under a
	// REPEATABLE READ snapshot instead, specifically so an ADR-039 HA
	// deployment's other replicas are never blocked from (re)starting for
	// the backup's duration, the whole reason those deployments choose
	// Postgres over SQLite in the first place.
	if !isPostgresStorage(cfg) || backupExclusive {
		lock, err := acquireDatabaseLock(cfg)
		if err != nil {
			if isPostgresStorage(cfg) {
				return fmt.Errorf("--exclusive needs the database to itself: stop the server first, or drop "+
					"--exclusive for the default live (REPEATABLE READ snapshot) backup: %w", err)
			}
			return fmt.Errorf("on SQLite, admin backup needs the database to itself -- stop the server first "+
				"(a live backup without downtime needs Postgres): %w", err)
		}
		defer lock.Release() //nolint:errcheck
	}

	if err := preflightBackupFreeSpace(cfg); err != nil {
		return fmt.Errorf("preflight free-space check (design §7.4): %w", err)
	}

	// readKeyFilesForBackup runs INSIDE unwrapManifestKey's onLocked callback
	// (SESSION-AT AT1 area 3/4) -- while the exclusive key lock from the KEK
	// derivation above is still held, not after it releases. See
	// unwrapManifestKey's own doc comment for the race this closes.
	var keyEntries []backupfmt.KeyFileEntry
	var keyBlobs [][]byte
	manifestKey, err := unwrapManifestKey(cfg, ".", backupPassphraseSource, func() error {
		var kerr error
		keyEntries, keyBlobs, kerr = readKeyFilesForBackup(cfg)
		return kerr
	})
	// #2602: a live server holds dek.lock exclusively for its whole lifetime,
	// so on Postgres -- where the database side needs no lock (the REPEATABLE
	// READ snapshot below) -- the key side switches to the live path instead
	// of refusing. --exclusive and SQLite never reach here live: both already
	// hold (or were refused) the database lock above.
	liveServer := false
	if err != nil && isPostgresStorage(cfg) && !backupExclusive && errors.Is(err, syscall.EWOULDBLOCK) {
		release, lerr := encryption.NewService(&cfg.Storage.Encryption, ".").AcquireKeyFileReadLock()
		if lerr != nil {
			return fmt.Errorf("a key rotation or provider migration is in progress -- retry the backup after it "+
				"completes: %w", lerr)
		}
		// Held until every read below -- the key files AND the database
		// snapshot -- is done; see liveKeyMaterial's doc comment.
		defer release()
		keyEntries, keyBlobs, manifestKey, err = liveKeyMaterial(cfg, backupPassphraseSource)
		liveServer = err == nil
	}
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(manifestKey)
	if liveServer {
		fmt.Println("A live server holds the encryption key lock: taking a live backup (keys read under the " +
			"key-rotation read lock, database through one REPEATABLE READ snapshot).")
	}

	gdb, err := storage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("open source database: %w", err)
	}
	defer closeGormDB(gdb)

	// design §4: the ENTIRE backup -- every table -- reads through ONE
	// REPEATABLE READ transaction/connection on Postgres, never one
	// transaction per table (closes the ordering hazard #2101 raised: no
	// window exists in which a concurrent write becomes visible to one
	// table's read but not another's, since every table sees the identical
	// snapshot taken at BEGIN). SQLite has no equivalent step here -- its
	// consistency already comes from the exclusive lock acquired above.
	readDB := gdb
	var pgSnapshotTx *gorm.DB
	if isPostgresStorage(cfg) {
		tx := gdb.Begin(&sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if tx.Error != nil {
			return fmt.Errorf("begin REPEATABLE READ snapshot transaction: %w", tx.Error)
		}
		pgSnapshotTx = tx
		readDB = tx
	}
	// Release the snapshot transaction/connection the moment reading is
	// done, not deferred to function exit: recordAdminAction below opens a
	// SEPARATE storage connection (via withUsableStorage) which, on
	// Postgres, runs migration DDL that takes an ACCESS EXCLUSIVE lock --
	// that blocks behind ANY still-open transaction holding even a read
	// lock on the same table, including this one's own. Found live via
	// TestAdminBackupRestore_Postgres_RoundTrip: with the transaction held
	// open until function exit (defer tx.Rollback()), the backup itself
	// completed but recordAdminAction's internal migration attempt deadlocked
	// against this process's own still-open REPEATABLE READ transaction and
	// hung for the full 10-minute test timeout.
	releaseSnapshotTx := func() {
		if pgSnapshotTx != nil {
			pgSnapshotTx.Rollback() //nolint:errcheck // read-only snapshot; rollback (not commit) is always correct to release it
			pgSnapshotTx = nil
		}
	}
	defer releaseSnapshotTx()

	highWater, err := readAuditHighWater(readDB)
	if err != nil {
		return fmt.Errorf("read audit high-water mark: %w", err)
	}

	f, err := os.OpenFile(backupOutput, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- operator-supplied output path, the whole point of this flag
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("--output %q already exists -- each backup is a distinct artifact, pick a new path (e.g. include a timestamp)", backupOutput)
		}
		return fmt.Errorf("create %q: %w", backupOutput, err)
	}

	manifest, werr := backupfmt.WriteBackup(readDB, storage.CurrentSchemaEpoch(), highWater, manifestKey, keyEntries, keyBlobs, f)
	releaseSnapshotTx() // all reads are done -- release before anything below opens another connection
	if werr == nil && liveServer {
		// Belt and braces for any key-file writer that does NOT take the
		// rewrite lock (first-boot key generation, an `admin restore`
		// installing keys): never archive a key set that changed under us.
		if backupLiveAfterReadHook != nil {
			backupLiveAfterReadHook()
		}
		werr = verifyKeyFilesUnchanged(cfg, keyEntries)
	}
	if werr != nil {
		_ = f.Close()
		_ = os.Remove(backupOutput)
		return fmt.Errorf("write backup archive: %w", werr)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(backupOutput)
		return fmt.Errorf("close %q: %w", backupOutput, err)
	}

	if len(manifest.DanglingReferences) > 0 {
		fmt.Printf("WARNING: this backup's source database has %d pre-existing dangling reference(s) "+
			"(design §3.4) -- see the archive's MANIFEST.json for details. This backup itself succeeded; "+
			"a restore from it will refuse to load until these are fixed at the source.\n", len(manifest.DanglingReferences))
	}

	var totalRows int64
	for _, te := range manifest.Tables {
		totalRows += te.RowCount
	}
	fmt.Printf("Backup written to %s (%d table(s), %d row(s) total, %d key file(s))\n",
		backupOutput, len(manifest.Tables), totalRows, len(keyEntries))
	fmt.Println("Store this archive OFF this host. Restore with:")
	fmt.Printf("  keyorix-server admin restore --input %s\n", backupOutput)

	recordAdminAction(cfg, "admin.backup_created",
		fmt.Sprintf("created backup archive %s (%d table(s), %d row(s), %d key file(s))",
			backupOutput, len(manifest.Tables), totalRows, len(keyEntries)), true)
	return nil
}

// unwrapManifestKey performs the same "KEK/passphrase access" step `admin
// diagnose`'s diagnoseEncryption already does (real KEK derivation, under
// the exclusive DEK lock, released via Shutdown), then returns the
// KEK-derived backup-manifest signing key (design §5.2) -- the raw KEK
// itself never leaves internal/encryption. baseDir is where the encryption
// service looks for key-material files relative to cfg.Storage.Encryption's
// configured paths: "." for `admin backup` (the real, current key files);
// a staging directory laid out to match those same relative paths for
// `admin restore` (design §5.3: unwrap from the archive's own STAGED, still
// -wrapped key files, never the real target's, since a fresh restore target
// has none yet).
//
// onLocked, when non-nil, runs AFTER BackupManifestKey succeeds but BEFORE
// the exclusive key lock releases (Shutdown runs via defer, after onLocked
// returns) -- SESSION-AT AT1 area 3/4: `admin backup` passes
// readKeyFilesForBackup here so the live key-file set it archives is read
// while STILL holding the same exclusive lock that protects the KEK
// derivation above, not after releasing it. Before this, the lock was
// released the moment unwrapManifestKey returned, and readKeyFilesForBackup
// ran its own, separately-timed, completely unlocked os.ReadFile loop over
// MULTIPLE files (salt, wrapped-DEK, provider-specific) -- a concurrent
// `admin encryption rotate-kek`/rotate-provider, which takes this SAME
// exclusive lock for exactly this reason (AcquireExclusiveKeyLock's own doc
// comment: serializes against "an in-progress rotation/migrate-provider"),
// could acquire it, rewrite some but not all of those files, and release,
// landing entirely inside that unlocked window -- archiving a key-material
// set that is individually well-formed per file but mutually inconsistent
// as a set, unusable by a later restore. `admin restore`'s own call passes
// nil: it unwraps from the archive's own staged (already-extracted, static)
// key files, never the live target's, so no concurrent-rotation race
// applies there.
func unwrapManifestKey(cfg *config.Config, baseDir string, passphraseSource crypto.PassphraseSource, onLocked func() error) ([]byte, error) {
	providerType := cfg.Storage.Encryption.KeyProvider.Type
	var passphrase string
	if providerType == "" || providerType == "password" {
		passphraseBytes, err := crypto.ResolvePassphrase(passphraseSource, "KEYORIX_MASTER_PASSWORD")
		if err != nil {
			return nil, fmt.Errorf("no master passphrase available (%w); set KEYORIX_MASTER_PASSWORD, pass "+
				"--passphrase-fd/--passphrase-file/--passphrase-stdin, or configure storage.encryption.key_provider "+
				"(file/env/aws-kms)", err)
		}
		defer crypto.WipeBytes(passphraseBytes)
		passphrase = string(passphraseBytes)
	}

	svc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return nil, fmt.Errorf("failed to acquire the encryption key lock (another process is using it): %w", err)
	}
	defer svc.Shutdown()

	if err := svc.Initialize(passphrase); err != nil {
		return nil, fmt.Errorf("failed to derive/verify the KEK: %w", err)
	}
	key, _, ok := svc.BackupManifestKey()
	if !ok {
		return nil, fmt.Errorf("backup-manifest signing key unavailable (encryption not enabled?)")
	}
	if onLocked != nil {
		if err := onLocked(); err != nil {
			return nil, err
		}
	}
	return key, nil
}

// preflightBackupFreeSpace implements design §7.4 for `admin backup`: refuse
// up front if --output's filesystem doesn't have enough free space, using
// the source database's current on-disk size as the estimate. SQLite has an
// actual file to stat; Postgres has no single file, so its estimate comes
// from pg_database_size(current_database()) instead -- both feed the same
// backupfmt.CheckFreeSpace check.
func preflightBackupFreeSpace(cfg *config.Config) error {
	if isPostgresStorage(cfg) {
		size, err := postgresDatabaseSize(cfg)
		if err != nil {
			return fmt.Errorf("estimate source database size: %w", err)
		}
		return backupfmt.CheckFreeSpace(backupOutput, size)
	}
	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}
	info, statErr := os.Stat(dbPath)
	if statErr != nil {
		return nil // a not-yet-existing source database has nothing to estimate from; migrateDatabase will fail loudly on its own if that's wrong
	}
	return backupfmt.CheckFreeSpace(backupOutput, info.Size())
}

// postgresDatabaseSize queries pg_database_size(current_database()) via a
// short-lived connection -- just for the preflight estimate, independent of
// the REPEATABLE READ snapshot transaction the real backup reads through.
func postgresDatabaseSize(cfg *config.Config) (int64, error) {
	gdb, err := storage.OpenGormDB(cfg)
	if err != nil {
		return 0, err
	}
	defer closeGormDB(gdb)
	var size int64
	if err := gdb.Raw("SELECT pg_database_size(current_database())").Scan(&size).Error; err != nil {
		return 0, err
	}
	return size, nil
}

// readKeyFile reads one key file through secretenv.OpenRegular, so a FIFO planted
// at a key-file path fails the backup instead of hanging it in open(2).
func readKeyFile(path string) ([]byte, error) {
	f, _, err := secretenv.OpenRegular(path, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// readKeyFilesForBackup reads every file internal/keyfiles.Registry
// enumerates and computes its checksum -- unchanged from v1 (design §1: no
// new subcommands or UX for key-material handling).
func readKeyFilesForBackup(cfg *config.Config) ([]backupfmt.KeyFileEntry, [][]byte, error) {
	specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
	if err != nil {
		return nil, nil, fmt.Errorf("build key-file registry: %w", err)
	}
	entries := make([]backupfmt.KeyFileEntry, len(specs))
	blobs := make([][]byte, len(specs))
	for i, spec := range specs {
		data, rerr := readKeyFile(spec.Path)
		if rerr != nil {
			return nil, nil, fmt.Errorf("read key file %q: %w", spec.Path, rerr)
		}
		sum := sha256.Sum256(data)
		entries[i] = backupfmt.KeyFileEntry{
			OriginalPath: spec.Path,
			TarName:      fmt.Sprintf("keyfiles/%d", i),
			Mode:         uint32(spec.Mode),
			SHA256:       hex.EncodeToString(sum[:]),
			Size:         int64(len(data)),
		}
		blobs[i] = data
	}
	return entries, blobs, nil
}

// readAuditHighWater reads the raw "audit_checkpoint_highwater"
// system_metadata value from the SAME connection backupfmt.WriteBackup will
// read table data from, under the SAME exclusive lock, so it reflects
// exactly the state being backed up -- empty if no checkpoint has ever been
// written on this install (a fresh/young install, not an error).
func readAuditHighWater(gdb *gorm.DB) (string, error) {
	var meta models.SystemMetadata
	err := gdb.Where("key = ?", auditHighWaterMetadataKey).Take(&meta).Error
	switch {
	case err == nil:
		return meta.Value, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return "", nil
	default:
		return "", err
	}
}

// liveKeyMaterial is `admin backup`'s key side when a live server holds
// dek.lock (#2602): it reads the live key-file set and derives the
// backup-manifest signing key from a STAGED copy of exactly those bytes,
// never by initializing an encryption Service against the live key
// directory (INV-ENCRYPTION-01: nothing may Initialize there without
// dek.lock, which the live server holds). The staged copy gets its own,
// uncontended dek.lock, so unwrapManifestKey runs unchanged against it.
//
// The caller must hold the key-file rewrite lock in shared mode
// (Service.AcquireKeyFileReadLock) across this call AND the database
// snapshot read, so no rotation can rewrite these files -- or commit a
// re-encryption sweep -- in between. A live server itself never rewrites
// key files after startup; verifyKeyFilesUnchanged re-checks the set after
// the database read for any writer that does not take that lock.
func liveKeyMaterial(cfg *config.Config, src crypto.PassphraseSource) ([]backupfmt.KeyFileEntry, [][]byte, []byte, error) {
	entries, blobs, err := readKeyFilesForBackup(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	stagingDir, err := os.MkdirTemp("", "keyorix-admin-backup-keys-*")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create key staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir) //nolint:errcheck
	stagedCfg := *cfg
	stagedCfg.Storage.Encryption = stagedEncryptionConfig(cfg.Storage.Encryption, stagingDir)
	for i, e := range entries {
		dest := stagedKeyPath(stagingDir, e.OriginalPath)
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return nil, nil, nil, fmt.Errorf("stage key file %q: %w", e.OriginalPath, err)
		}
		if err := os.WriteFile(dest, blobs[i], 0o600); err != nil {
			return nil, nil, nil, fmt.Errorf("stage key file %q: %w", e.OriginalPath, err)
		}
	}
	key, err := unwrapManifestKey(&stagedCfg, stagingDir, src, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return entries, blobs, key, nil
}

// stagedKeyPath mirrors a live key-file path under stagingDir: a relative
// path keeps its shape (the staged Service's baseDir is stagingDir), an
// absolute one is re-rooted beneath it.
func stagedKeyPath(stagingDir, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Join(stagingDir, p)
	}
	return filepath.Join(stagingDir, filepath.Clean(p))
}

// stagedEncryptionConfig rewrites every key-file path keyfiles.Registry
// enumerates (salt, DEK, write-capable providers' wrapped KEK, Shamir share
// files -- across the primary provider and its fallbacks) to its staged
// mirror. Relative paths already resolve under the staged baseDir and are
// left as-is; absolute ones are re-rooted, matching stagedKeyPath. Any other
// provider input (an env var, a KEK file, a KMS key ID) is only ever READ by
// KEK derivation and is left pointing where it is.
func stagedEncryptionConfig(enc config.EncryptionConfig, stagingDir string) config.EncryptionConfig {
	reroot := func(p string) string {
		if p != "" && filepath.IsAbs(p) {
			return stagedKeyPath(stagingDir, p)
		}
		return p
	}
	var stageProvider func(kp config.KeyProviderConfig) config.KeyProviderConfig
	stageProvider = func(kp config.KeyProviderConfig) config.KeyProviderConfig {
		kp.WrappedKeyPath = reroot(kp.WrappedKeyPath)
		if kp.ShamirShareFiles != nil {
			shares := make([]string, len(kp.ShamirShareFiles))
			for i, sh := range kp.ShamirShareFiles {
				shares[i] = reroot(sh)
			}
			kp.ShamirShareFiles = shares
		}
		if kp.Fallbacks != nil {
			fbs := make([]config.KeyProviderConfig, len(kp.Fallbacks))
			for i, fb := range kp.Fallbacks {
				fbs[i] = stageProvider(fb)
			}
			kp.Fallbacks = fbs
		}
		return kp
	}
	enc.SaltPath = reroot(enc.SaltPath)
	enc.DEKPath = reroot(enc.DEKPath)
	enc.KeyProvider = stageProvider(enc.KeyProvider)
	return enc
}

// verifyKeyFilesUnchanged re-reads the live key-file set after a live
// backup's database read and refuses the backup if any file was added,
// removed or rewritten since it was archived.
func verifyKeyFilesUnchanged(cfg *config.Config, archived []backupfmt.KeyFileEntry) error {
	now, _, err := readKeyFilesForBackup(cfg)
	if err != nil {
		return fmt.Errorf("re-read key files after the database snapshot: %w", err)
	}
	if len(now) != len(archived) {
		return fmt.Errorf("the encryption key files changed during the backup (%d file(s) before, %d after) -- "+
			"refusing to write an archive whose keys may not match its data; retry the backup", len(archived), len(now))
	}
	for i := range now {
		if now[i].OriginalPath != archived[i].OriginalPath || now[i].SHA256 != archived[i].SHA256 {
			return fmt.Errorf("the encryption key file %q changed during the backup -- refusing to write an archive "+
				"whose keys may not match its data; retry the backup", archived[i].OriginalPath)
		}
	}
	return nil
}
