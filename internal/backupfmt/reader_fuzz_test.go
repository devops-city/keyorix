package backupfmt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// fuzzExtractCapEntry/fuzzExtractCapTotal are deliberately tiny -- far below
// defaultMaxEntryBytes/defaultMaxTotalBytes -- so a cap that were silently
// bypassed (a decompression bomb, or a declared-vs-actual size mismatch that
// slips through) shows up as THIS fuzz run writing more bytes than the cap
// allows, not merely as a slow run that happens to finish within whatever
// timeout the harness gives it.
const (
	fuzzExtractCapEntry = 1 << 12 // 4 KiB
	fuzzExtractCapTotal = 1 << 14 // 16 KiB
)

// FuzzExtractArchive is SESSION-BV target 2's bounded-work and
// manifest-coverage half: arbitrary archive bytes must never panic, must
// never cause more than fuzzExtractCapTotal bytes to land on disk under
// stagingDir regardless of what the stream claims to decompress to, and --
// when accepted -- every staged file's bytes must independently re-hash to
// exactly what the archive's own (now-staged) MANIFEST.json declared for it.
// That last check doesn't just call ExtractArchive's internal verification
// again: it re-derives the hash from the bytes actually sitting on disk
// after the fact, so a bug that verified the wrong buffer (e.g. checked the
// compressed bytes, or checked before truncating to the declared size) would
// still be caught here.
func FuzzExtractArchive(f *testing.F) {
	seedRealArchive(f)
	f.Add([]byte{})
	f.Add([]byte("not a gzip archive at all"))
	f.Add([]byte{0x1f, 0x8b}) // gzip magic, nothing else
	f.Add(craftArchive(f, "MANIFEST.json", nil))
	f.Add(craftArchive(f, "tables/x.ndjson", bytes.Repeat([]byte{'a'}, 1<<20))) // declared-size bomb attempt: 1MB payload, tiny caps below
	f.Add(craftArchive(f, "../escaped.txt", []byte("attacker-controlled")))
	f.Add(craftArchive(f, "tables/../../escaped.txt", []byte("attacker-controlled")))
	f.Add(craftManyEntriesUnderPerEntryCapOverTotalCap(f))

	f.Fuzz(func(t *testing.T, data []byte) {
		stagingDir := t.TempDir()
		manifest, err := ExtractArchive(bytes.NewReader(data), stagingDir, fuzzExtractCapEntry, fuzzExtractCapTotal)

		var totalOnDisk int64
		walkErr := filepath.WalkDir(stagingDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			info, statErr := d.Info()
			if statErr != nil {
				return statErr
			}
			totalOnDisk += info.Size()
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk staging dir: %v", walkErr)
		}
		if totalOnDisk > fuzzExtractCapTotal {
			t.Fatalf("ExtractArchive wrote %d bytes under staging, exceeding its own %d-byte total cap "+
				"(err=%v) -- bounded-work guarantee violated", totalOnDisk, fuzzExtractCapTotal, err)
		}

		if err != nil {
			return // rejected -- bounded-work already confirmed above, nothing else to check
		}

		for _, kf := range manifest.KeyFiles {
			assertStagedHashMatches(t, stagingDir, kf.TarName, kf.SHA256, kf.Size)
		}
		for _, te := range manifest.Tables {
			assertStagedHashMatches(t, stagingDir, te.TarName, te.SHA256, te.UncompressedSize)
		}
	})
}

func assertStagedHashMatches(t *testing.T, stagingDir, tarName, declaredSHA256 string, declaredSize int64) {
	t.Helper()
	full := filepath.Join(stagingDir, tarName) // #nosec G304 -- tarName comes from a manifest ExtractArchive itself already matched/staged under stagingDir
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("manifest declares accepted entry %q but it is not readable from staging: %v", tarName, err)
	}
	if int64(len(data)) != declaredSize {
		t.Fatalf("staged entry %q is %d bytes, manifest declares %d -- ExtractArchive accepted a size mismatch",
			tarName, len(data), declaredSize)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != declaredSHA256 {
		t.Fatalf("staged entry %q re-hashes to %q, manifest declares %q -- ExtractArchive accepted a checksum mismatch",
			tarName, got, declaredSHA256)
	}
}

// craftManyEntriesUnderPerEntryCapOverTotalCap builds an archive with several
// key-file entries, each individually under fuzzExtractCapEntry but summing
// to well over fuzzExtractCapTotal -- the one shape a single-entry
// craftArchive call structurally cannot produce, and the specific case a
// total-bytes cap (as opposed to a mere per-entry cap) exists to catch: no
// single entry ever looks like a bomb on its own.
func craftManyEntriesUnderPerEntryCapOverTotalCap(t testing.TB) []byte {
	t.Helper()
	const (
		perEntry   = fuzzExtractCapEntry - 100            // comfortably under the per-entry cap
		numEntries = (fuzzExtractCapTotal / perEntry) + 3 // comfortably over the total cap once summed
	)
	var keyFiles []KeyFileEntry
	var blobs [][]byte
	for i := range numEntries {
		blob := bytes.Repeat([]byte{byte('a' + i%26)}, perEntry)
		sum := sha256.Sum256(blob)
		keyFiles = append(keyFiles, KeyFileEntry{
			OriginalPath: "k", TarName: fmt.Sprintf("keyfiles/%d", i),
			Size: int64(len(blob)), SHA256: hex.EncodeToString(sum[:]),
		})
		blobs = append(blobs, blob)
	}
	m := Manifest{KeyFiles: keyFiles}
	mj, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write("MANIFEST.json", mj)
	for i, kf := range keyFiles {
		write(kf.TarName, blobs[i])
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// seedRealArchive adds a real, fully valid v2 archive (produced by
// writeBackupModels, the same path a genuine `admin backup` takes) as a
// corpus seed -- the one input shape that must always be ACCEPTED, giving
// the fuzzer a structurally-valid starting point to mutate from rather than
// only ever bouncing off the gzip/tar header wall.
func seedRealArchive(f *testing.F) {
	f.Helper()
	db := openTestDB(f)
	var buf bytes.Buffer
	if _, err := writeBackupModels(db, testSeedModels(), 1, "", testManifestKey(), nil, nil, &buf); err != nil {
		f.Fatalf("build seed archive: %v", err)
	}
	f.Add(buf.Bytes())
}
