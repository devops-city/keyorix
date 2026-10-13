// opcatalog_corpus_pin_test.go pins the exact opKey that specific named,
// long-lived fuzz corpus files (testdata/fuzz/FuzzStorageFaultOperations/<hash>)
// must decode to.
//
// decodeFuzzOp (fuzz_storage_fault_operations_test.go) picks the exercised
// operation via `int(data[0]) % len(opCatalog)` -- a raw modulo on opCatalog's
// CURRENT length. opCatalog is a plain ordered slice, so removing OR adding an
// entry anywhere in it (not just near the end) silently reindexes every OTHER
// corpus file's op selection too: a corpus file that used to reproduce one
// specific closed finding can end up "passing" against an entirely different,
// unrelated operation, with no visible signal -- decodeFuzzOp always returns
// SOME valid, in-bounds index, so nothing errors and the subtest still goes
// green.
//
// This bit for real, already, once: ADR-108 Phase 6 step 14c (PR #2171/#2172,
// deleting the 7 /system-proxy-only ops from opCatalog) silently retargeted
// all 4 corpus files pinned below -- confirmed empirically by decoding each
// file's raw bytes against both the pre-14c and post-14c opCatalog and
// finding a DIFFERENT opKey each time (see reports/CLI-RELEASE.md for the
// full before/after trace). Each of these 4 files is cited in
// docs/security-closures.tsv as the "permanent regression" proving a specific
// CLOSED finding stays fixed; a silently-retargeted corpus file is no longer
// proving that finding at all, even though `go test` reports PASS.
//
// WHAT THIS CATCHES: any opCatalog length/order change that causes one of
// these 4 SPECIFIC, already-named corpus files to decode to a DIFFERENT opKey
// than the one pinned here. That is a hard failure requiring the corpus
// file's raw bytes to be regenerated -- see this file's own
// regenerateCorpusOpIndex doc comment for the technique.
//
// WHAT THIS DOES NOT CATCH (name it, per this repo's "name mechanisms for
// what they verify" rule):
//   - Any OTHER seed corpus file under testdata/fuzz/FuzzStorageFaultOperations/
//     that is not one of the 4 enumerated below -- e.g. one found by fuzzing
//     but not yet promoted to a named security-closures.tsv claim. A catalog
//     change can still silently retarget those with no failure here.
//   - A change to storageInterfaceMethodNames() (the SEPARATE modulo that
//     picks the faulted storage method, decoded from data[1:3]) -- this test
//     only pins opCatalog's own opKey selection (data[0]), not the method,
//     NthCall, or fault-kind fields.
//   - A change that happens to leave data[0]%len(opCatalog) landing on the
//     SAME opKey by coincidence -- that is not a bug, so there is nothing for
//     this test to catch in that case (it only fails when the decoded opKey
//     actually differs from the pin).
package faultops

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// pinnedCorpusOps is intentionally small and hand-curated (not derived from
// scanning testdata/fuzz/ wholesale) -- see the package doc comment above for
// why: it only covers the corpus files docs/security-closures.tsv already
// names as a specific closed finding's permanent regression.
var pinnedCorpusOps = []struct {
	corpusFile string // basename under testdata/fuzz/FuzzStorageFaultOperations/
	claimID    string // docs/security-closures.tsv claim_id this corpus file proves
	wantOpKey  string // opCatalog[i].Key this file's raw bytes must decode to
}{
	{"637f47f4387c3138", "role-permissions-postcommit-read-atomicity-004", "REST POST /api/v1/rotation-policies/"},
	{"ad8a1c49b476fc19", "createproject-environment-seed-panic-003", "REST POST /api/v1/projects"},
	{"7c0a2492ee5d1dfa", "breakglass-revoke-half-commit-001", "REST POST /api/v1/roles/"},
	{"c3012b444731c557", "breakglass-revoke-cache-evict-panic-001", "REST POST /api/v1/groups/{id}/members"},
}

// readFuzzCorpusFile parses a Go native fuzz corpus file's on-disk format
// (`go test fuzz v1\n[]byte("...")\n`) and returns the single []byte argument
// it encodes. Every corpus file under testdata/fuzz/FuzzStorageFaultOperations/
// has exactly this shape (FuzzStorageFaultOperations declares one []byte
// parameter) -- this does not attempt to handle any other fuzz signature.
func readFuzzCorpusFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading corpus file %s: %v", path, err)
	}
	lines := strings.SplitN(string(raw), "\n", 2)
	if len(lines) != 2 || strings.TrimSpace(lines[0]) != "go test fuzz v1" {
		t.Fatalf("corpus file %s: unexpected header %q, want \"go test fuzz v1\"", path, lines[0])
	}
	valueLine := strings.TrimSpace(lines[1])
	const prefix, suffix = "[]byte(", ")"
	if !strings.HasPrefix(valueLine, prefix) || !strings.HasSuffix(valueLine, suffix) {
		t.Fatalf("corpus file %s: value line %q is not a single []byte(...) literal", path, valueLine)
	}
	quoted := strings.TrimSuffix(strings.TrimPrefix(valueLine, prefix), suffix)
	data, err := strconv.Unquote(quoted)
	if err != nil {
		t.Fatalf("corpus file %s: unquoting %q: %v", path, quoted, err)
	}
	return []byte(data)
}

func TestOpcatalogCorpusFilesTargetPinnedOps(t *testing.T) {
	for _, p := range pinnedCorpusOps {
		t.Run(p.claimID, func(t *testing.T) {
			path := filepath.Join("testdata", "fuzz", "FuzzStorageFaultOperations", p.corpusFile)
			data := readFuzzCorpusFile(t, path)
			decoded, ok := decodeFuzzOpAny(data)
			if !ok {
				t.Fatalf("decodeFuzzOp could not decode %s -- opCatalog or storageInterfaceMethodNames() is empty", path)
			}
			gotKey := opCatalog[decoded.opIndex].Key
			if gotKey != p.wantOpKey {
				t.Fatalf("corpus file %s (proving test for docs/security-closures.tsv claim %q) now decodes to "+
					"op %q, want %q -- opCatalog's length or order changed and silently retargeted this corpus "+
					"file's raw bytes onto a DIFFERENT operation (it still passes, but is no longer testing what "+
					"the claim says it tests). Regenerate: find %q's new index in the CURRENT opCatalog, re-encode "+
					"this file's byte[0] to that index (leave bytes[1:] unchanged -- they encode the fault method/"+
					"NthCall/kind, independent of opCatalog), confirm it decodes back to %q, then update this file "+
					"and this test's pin together if the intended op has genuinely changed on purpose.",
					path, p.claimID, gotKey, p.wantOpKey, p.wantOpKey, p.wantOpKey)
			}
		})
	}
}
