// backup_v1_legacy.go holds the v1 (physical, SQLite-only) archive format's
// READ side only -- design-b3-backup-v2.md §3.6 decision 3: "admin restore
// accepts v1-physical-format archives until Keyorix 1.0, then drops it; new
// backups always write v2 (logical) once v2 ships." admin backup no longer
// writes this format at all (backup.go is v2-only); this file exists purely
// so a v1 archive taken under #2099, before v2 shipped, still restores.
package admin

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// backupFormatVersion is v1's format_version value -- restore's format
// dispatch (restore.go's peekFormatVersion) routes exactly this value to
// the v1 reader below, and refuses anything else it doesn't also recognize
// as v2 (backupfmt.FormatVersion).
const backupFormatVersion = 1

// backupManifest is v1's MANIFEST.json shape -- unchanged from #2099, kept
// only so an old archive still parses. See backupfmt.Manifest for the
// current (v2) shape.
type backupManifest struct {
	FormatVersion  int               `json:"format_version"`
	CreatedAt      time.Time         `json:"created_at"`
	Backend        string            `json:"backend"`
	DBFile         backupFileEntry   `json:"db_file"`
	KeyFiles       []backupFileEntry `json:"key_files"`
	AuditHighWater string            `json:"audit_high_water,omitempty"`
}

// backupFileEntry is v1's per-file manifest entry shape -- unchanged from
// #2099. See backupfmt.KeyFileEntry for the current (v2) shape (structurally
// identical; kept as a separate type since this one belongs to the frozen
// v1 format, not the evolving v2 one).
type backupFileEntry struct {
	OriginalPath string `json:"original_path"`
	TarName      string `json:"tar_name"`
	Mode         uint32 `json:"mode"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}

// readBackupArchive parses a gzipped tar written by v1's (now-removed)
// writeBackupArchive, requiring the manifest and every entry it references
// to be present before returning anything -- restore must never proceed on
// a partially-readable archive. maxEntryBytes/maxTotalBytes (0 means "use
// the package default") bound how much decompressed data this will ever
// hold in memory, since the archive is operator-supplied input that may
// come from untrusted or removable media (a gzip+tar decompression bomb):
// every read is through io.LimitReader, never a bare io.ReadAll(tr).
//
// The first entry must be MANIFEST.json -- every other entry's declared
// size in that already-parsed manifest becomes ITS per-entry cap, and any
// entry whose name the manifest does not reference is rejected as soon as
// its header is seen, before its body is read at all. Every entry must be a
// regular file (rejecting symlinks/hardlinks/devices), and duplicate entry
// names are rejected.
func readBackupArchive(path string, maxEntryBytes, maxTotalBytes int64) (backupManifest, []byte, [][]byte, error) {
	if maxEntryBytes <= 0 {
		maxEntryBytes = defaultMaxRestoreEntryBytes
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = defaultMaxRestoreTotalBytes
	}

	f, err := secretenv.OpenRegularNamed("backup archive", path) // operator-supplied input path; a FIFO is refused, not waited on
	if err != nil {
		return backupManifest{}, nil, nil, err
	}
	defer f.Close() //nolint:errcheck

	gz, err := gzip.NewReader(f)
	if err != nil {
		return backupManifest{}, nil, nil, fmt.Errorf("not a valid backup archive (gzip): %w", err)
	}
	defer gz.Close() //nolint:errcheck
	tr := tar.NewReader(gz)

	var manifest backupManifest
	manifestRead := false
	var dbBytes []byte
	keyBlobsByName := make(map[string][]byte)
	seenNames := make(map[string]bool)
	var totalRead int64
	first := true

	readCapped := func(name string, limit int64) ([]byte, error) {
		remaining := maxTotalBytes - totalRead
		if remaining < 0 {
			remaining = 0
		}
		effLimit := limit
		if remaining < effLimit {
			effLimit = remaining
		}
		data, err := io.ReadAll(io.LimitReader(tr, effLimit+1))
		if err != nil {
			return nil, fmt.Errorf("read tar entry %q: %w", name, err)
		}
		if int64(len(data)) > effLimit {
			if effLimit < limit {
				return nil, fmt.Errorf("archive exceeds the %d-byte total decompressed size limit (--max-total-bytes)", maxTotalBytes)
			}
			return nil, fmt.Errorf("archive entry %q exceeds the %d-byte per-entry size limit (--max-entry-bytes)", name, limit)
		}
		totalRead += int64(len(data))
		return data, nil
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return backupManifest{}, nil, nil, fmt.Errorf("read tar entry: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			return backupManifest{}, nil, nil, fmt.Errorf(
				"archive entry %q is not a regular file (tar type %q) -- restore refuses non-regular entries",
				hdr.Name, string(hdr.Typeflag))
		}
		if seenNames[hdr.Name] {
			return backupManifest{}, nil, nil, fmt.Errorf("archive contains a duplicate entry %q", hdr.Name)
		}
		seenNames[hdr.Name] = true

		if first {
			first = false
			if hdr.Name != "MANIFEST.json" {
				return backupManifest{}, nil, nil, fmt.Errorf(
					"archive's first entry is %q, expected MANIFEST.json -- not a keyorix-server admin backup", hdr.Name)
			}
			data, err := readCapped(hdr.Name, maxEntryBytes)
			if err != nil {
				return backupManifest{}, nil, nil, err
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return backupManifest{}, nil, nil, fmt.Errorf("parse manifest: %w", err)
			}
			manifestRead = true
			continue
		}

		entry, ok := manifestEntryFor(manifest, hdr.Name)
		if !ok {
			return backupManifest{}, nil, nil, fmt.Errorf(
				"archive contains entry %q, which is not referenced by its own MANIFEST.json -- restore refuses unlisted entries", hdr.Name)
		}
		if entry.Size < 0 || entry.Size > maxEntryBytes {
			return backupManifest{}, nil, nil, fmt.Errorf(
				"archive manifest declares %q at %d bytes, exceeding the %d-byte per-entry limit (--max-entry-bytes)",
				hdr.Name, entry.Size, maxEntryBytes)
		}
		data, err := readCapped(hdr.Name, entry.Size)
		if err != nil {
			return backupManifest{}, nil, nil, err
		}
		if hdr.Name == manifest.DBFile.TarName {
			dbBytes = data
		} else {
			keyBlobsByName[hdr.Name] = data
		}
	}

	if !manifestRead {
		return backupManifest{}, nil, nil, fmt.Errorf("archive has no MANIFEST.json -- not a keyorix-server admin backup")
	}
	if dbBytes == nil {
		return backupManifest{}, nil, nil, fmt.Errorf("archive has no %s entry", manifest.DBFile.TarName)
	}
	keyBlobs := make([][]byte, len(manifest.KeyFiles))
	for i, entry := range manifest.KeyFiles {
		blob, ok := keyBlobsByName[entry.TarName]
		if !ok {
			return backupManifest{}, nil, nil, fmt.Errorf("archive manifest references %q but the archive has no such entry", entry.TarName)
		}
		keyBlobs[i] = blob
	}
	return manifest, dbBytes, keyBlobs, nil
}

// manifestEntryFor looks up the backupFileEntry a tar entry name corresponds
// to (the database file, or one of the key files) in an already-parsed
// manifest -- used both for each entry's declared (and therefore capped)
// size, and to reject any tar entry the manifest does not reference.
func manifestEntryFor(manifest backupManifest, tarName string) (backupFileEntry, bool) {
	if tarName == manifest.DBFile.TarName {
		return manifest.DBFile, true
	}
	for _, kf := range manifest.KeyFiles {
		if tarName == kf.TarName {
			return kf, true
		}
	}
	return backupFileEntry{}, false
}

// auditEventCountFromDBBytes returns MAX(audit_events.id) of an archived
// (v1-format) SQLite database image, read from a private temp copy (0 when
// the table is absent, e.g. an archive from an install that never logged an
// event). v2's equivalent is archiveHeadFromStagedAuditEvents (restore.go),
// since a v2 archive has no single whole-database file to copy.
func auditEventCountFromDBBytes(data []byte) (int64, error) {
	dir, err := os.MkdirTemp("", "keyorix-restore-audit-*")
	if err != nil {
		return 0, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck
	p := filepath.Join(dir, "archive.db")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return 0, fmt.Errorf("write temp copy: %w", err)
	}
	return readExistingDatabaseAuditEventCount(p)
}

// validateKeyFileSetV1 is validateKeyFileSet (restore.go) for v1's
// backupFileEntry shape -- refuses a partial or mismatched key-file restore
// instead of silently dropping or misplacing a file.
func validateKeyFileSetV1(archived []backupFileEntry, target []string) error {
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

// verifyChecksumV1 is verifyChecksum (restore.go) for v1's backupFileEntry
// shape.
func verifyChecksumV1(entry backupFileEntry, data []byte) error {
	if int64(len(data)) != entry.Size {
		return fmt.Errorf("archive entry %q failed integrity check (size mismatch: got %d, want %d) -- "+
			"the backup file may be corrupted or tampered with", entry.TarName, len(data), entry.Size)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
		return fmt.Errorf("archive entry %q failed integrity check (checksum mismatch) -- "+
			"the backup file may be corrupted or tampered with", entry.TarName)
	}
	return nil
}
