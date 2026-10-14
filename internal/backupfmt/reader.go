package backupfmt

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
)

// defaultMaxEntryBytes/defaultMaxTotalBytes mirror v1's own archive-size
// caps (server/admin's identical consts) -- an archive is operator-supplied
// input that may come from untrusted or removable media (a gzip+tar
// decompression bomb), so every read here is bounded regardless of what the
// stream claims to contain.
const (
	defaultMaxEntryBytes = 1 << 30
	defaultMaxTotalBytes = 2 * defaultMaxEntryBytes
)

// ExtractArchive streams a v2 logical-format archive (gzip+tar) from r into
// stagingDir (design §5.3 step 1): MANIFEST.json must be the first entry;
// every OTHER entry must be referenced by the parsed manifest (a key file or
// a table's NDJSON), with its declared size honored as a hard per-entry
// cap and its declared SHA-256 verified as it's written -- an entry
// mismatching its own declared checksum, an entry the manifest doesn't
// reference, a duplicate entry name, or a non-regular-file entry (symlink,
// hardlink, device) all refuse the whole extraction. maxEntryBytes/
// maxTotalBytes of 0 use the package defaults.
//
// Returns the parsed (NOT YET signature-verified -- that needs the KEK,
// unwrapped from the now-staged key files, which is the caller's next step
// per §5.3) manifest. stagingDir must already exist (mode 0700, caller's
// responsibility -- this function does not create or clean it up, matching
// v1's own os.MkdirTemp-then-defer-RemoveAll pattern at the call site).
func ExtractArchive(r io.Reader, stagingDir string, maxEntryBytes, maxTotalBytes int64) (Manifest, error) {
	if maxEntryBytes <= 0 {
		maxEntryBytes = defaultMaxEntryBytes
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = defaultMaxTotalBytes
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return Manifest{}, fmt.Errorf("not a valid backup archive (gzip): %w", err)
	}
	defer gz.Close() //nolint:errcheck
	tr := tar.NewReader(gz)

	var manifest Manifest
	manifestRead := false
	seenNames := make(map[string]bool)
	var totalRead int64
	first := true

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("read tar entry: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			return Manifest{}, fmt.Errorf(
				"archive entry %q is not a regular file (tar type %q) -- restore refuses non-regular entries",
				hdr.Name, string(hdr.Typeflag))
		}
		// hdr.Name (and the manifest TarName it is matched against below) is
		// attacker-controlled here: the manifest is not signature-verified
		// until after extraction. Refuse absolute paths and any ".." escape
		// before anything is written (tar-slip; Session P, 2026-09-29).
		if !filepath.IsLocal(hdr.Name) {
			return Manifest{}, fmt.Errorf(
				"archive entry %q is not a safe relative path (absolute path or path traversal) -- restore refuses it", hdr.Name)
		}
		if seenNames[hdr.Name] {
			return Manifest{}, fmt.Errorf("archive contains a duplicate entry %q", hdr.Name)
		}
		seenNames[hdr.Name] = true

		if first {
			first = false
			if hdr.Name != "MANIFEST.json" {
				return Manifest{}, fmt.Errorf(
					"archive's first entry is %q, expected MANIFEST.json -- not a keyorix-server admin backup", hdr.Name)
			}
			data, err := readCapped(tr, maxEntryBytes, maxTotalBytes, &totalRead, "MANIFEST.json")
			if err != nil {
				return Manifest{}, err
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return Manifest{}, fmt.Errorf("parse manifest: %w", err)
			}
			manifestRead = true
			if err := stageFile(stagingDir, "MANIFEST.json", data); err != nil {
				return Manifest{}, err
			}
			continue
		}
		if !manifestRead {
			return Manifest{}, fmt.Errorf("internal error: reading entries before the manifest was parsed")
		}

		declaredSize, declaredSHA256, ok := manifestEntryFor(manifest, hdr.Name)
		if !ok {
			return Manifest{}, fmt.Errorf(
				"archive contains entry %q, which is not referenced by its own MANIFEST.json -- restore refuses unlisted entries", hdr.Name)
		}
		if declaredSize < 0 || declaredSize > maxEntryBytes {
			return Manifest{}, fmt.Errorf(
				"archive manifest declares %q at %d bytes, exceeding the %d-byte per-entry limit", hdr.Name, declaredSize, maxEntryBytes)
		}
		data, err := readCapped(tr, declaredSize, maxTotalBytes, &totalRead, hdr.Name)
		if err != nil {
			return Manifest{}, err
		}
		if int64(len(data)) != declaredSize {
			return Manifest{}, fmt.Errorf("archive entry %q failed integrity check (size mismatch: got %d, want %d) -- "+
				"the backup file may be corrupted or tampered with", hdr.Name, len(data), declaredSize)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != declaredSHA256 {
			return Manifest{}, fmt.Errorf("archive entry %q failed integrity check (checksum mismatch) -- "+
				"the backup file may be corrupted or tampered with", hdr.Name)
		}
		if err := stageFile(stagingDir, hdr.Name, data); err != nil {
			return Manifest{}, err
		}
	}

	if !manifestRead {
		return Manifest{}, fmt.Errorf("archive has no MANIFEST.json -- not a keyorix-server admin backup")
	}
	for _, kf := range manifest.KeyFiles {
		if !seenNames[kf.TarName] {
			return Manifest{}, fmt.Errorf("archive manifest references key file %q but the archive has no such entry", kf.TarName)
		}
	}
	for _, te := range manifest.Tables {
		if !seenNames[te.TarName] {
			return Manifest{}, fmt.Errorf("archive manifest references table %q but the archive has no such entry (%s)", te.Name, te.TarName)
		}
	}
	return manifest, nil
}

// manifestEntryFor looks up a tar entry name's declared size/checksum in an
// already-parsed manifest -- the MANIFEST.json entry itself, a key file, or
// a table's NDJSON file.
func manifestEntryFor(manifest Manifest, tarName string) (size int64, sha256 string, ok bool) {
	for _, kf := range manifest.KeyFiles {
		if tarName == kf.TarName {
			return kf.Size, kf.SHA256, true
		}
	}
	for _, te := range manifest.Tables {
		if tarName == te.TarName {
			return te.UncompressedSize, te.SHA256, true
		}
	}
	return 0, "", false
}

// readCapped reads at most limit bytes of the current tar entry (never more,
// regardless of what the entry claims to decompress to), and never lets the
// running total across the whole archive (tracked in *totalRead) exceed
// maxTotalBytes.
func readCapped(tr *tar.Reader, limit, maxTotalBytes int64, totalRead *int64, name string) ([]byte, error) {
	remaining := max(maxTotalBytes-*totalRead, 0)
	effLimit := min(remaining, limit)
	data, err := io.ReadAll(io.LimitReader(tr, effLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read tar entry %q: %w", name, err)
	}
	if int64(len(data)) > effLimit {
		if effLimit < limit {
			return nil, fmt.Errorf("archive exceeds the %d-byte total decompressed size limit", maxTotalBytes)
		}
		return nil, fmt.Errorf("archive entry %q exceeds the %d-byte per-entry size limit", name, limit)
	}
	*totalRead += int64(len(data))
	return data, nil
}

// stageFile writes data to stagingDir/name, creating any intermediate
// directories the tar entry's own name implies (e.g. "tables/", "keyfiles/").
// name comes from an archive entry's tar header, which is attacker-controlled
// at this point in restore (the manifest's own TarName values are not yet
// signature-verified). ExtractArchive already refuses a non-local name; the
// check is repeated here so stageFile stays safe for any future caller.
func stageFile(stagingDir, name string, data []byte) error {
	if !filepath.IsLocal(name) {
		return fmt.Errorf("refusing to stage %q: not a safe relative path", name)
	}
	dest := filepath.Join(stagingDir, name)
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return fmt.Errorf("create staging subdirectory for %q: %w", name, err)
	}
	if err := os.WriteFile(dest, data, 0600); err != nil {
		return fmt.Errorf("stage %q: %w", name, err)
	}
	return nil
}
