// seed_v2_corpus_all_v2_test.go keeps legacy seeds out of the
// FuzzStorageFaultOperations corpus (PERF-FIX-4 follow-up, STORAGE-HARDEN-1).
//
// FUZZ-SEEDS-1 (#3219) re-encoded every committed seed as v2 and
// TestSeedV2_AppendingToInterfaceOrCatalogDoesNotChangeDecoding proves a v2
// seed does not move when a storage method or an op is added. That guard only
// looks at v2 seeds: a legacy (index-addressed) seed committed afterwards, for
// example a fuzzer finding copied straight from testdata, is skipped by it and
// starts drifting with the next storage method. This test refuses one.
package faultops

import (
	"encoding/hex"
	"path/filepath"
	"testing"
)

// TestCommittedSeeds_AreAllV2: every committed seed is a well-formed v2 seed
// that resolves against the current op catalog and storage method list.
func TestCommittedSeeds_AreAllV2(t *testing.T) {
	files := committedSeedFiles(t)
	if len(files) == 0 {
		t.Fatal("no committed seeds found: this guard would pass vacuously")
	}
	for _, f := range files {
		data := readFuzzCorpusFile(t, f)
		if len(data) == seedV2Len && data[0] == seedV2Magic {
			if _, ok := decodeFuzzOpV2(data); ok {
				continue
			}
		}
		t.Errorf("%s is not a resolving v2 seed (bytes %s). Legacy seeds address the op and storage method by list "+
			"index and re-point whenever either list grows. Replay it (REPLAY_HEX=%s go test ./server/faultops/ "+
			"-run TestReplayStorageFaultInput -v) to see the op, method, nth and kind it targets today, and commit "+
			"encodeFuzzOpV2(opKey, method, nth, kindIndex) instead", filepath.Base(f), hex.EncodeToString(data), hex.EncodeToString(data))
	}
}
