// seed_v2_migration_test.go: FUZZ-SEEDS-1. Proves the v1 -> v2 corpus migration
// kept every seed on the (op, storage method, nth, kind) it was written for, and
// guards the property v2 exists for: appending to the storage interface or the
// op catalog must not change how a committed v2 seed decodes.
//
// testdata/seed_v1_history/ holds, per seed, the legacy (index-addressed) bytes
// it had before migration and the (op, method, nth, kind) it targeted WHEN IT
// WAS WRITTEN. That target was recovered by checking out the commit that last
// set the seed's bytes and decoding them with that commit's own opCatalog and
// storage.Storage method list; those two lists are frozen next to the table as
// <snapshot>.ops / <snapshot>.methods (13 distinct snapshots cover all seeds).
package faultops

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

const seedV1HistoryDir = "testdata/seed_v1_history"

type seedV1Row struct {
	seed     string
	snapshot string
	commit   string
	op       string
	method   string
	nth      int
	kind     faultstorage.FaultKind
	legacy   []byte
}

func loadSeedV1History(t *testing.T) map[string]seedV1Row {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(seedV1HistoryDir, "golden.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]seedV1Row{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 8 {
			t.Fatalf("malformed history row %q", line)
		}
		nth, err := strconv.Atoi(f[5])
		if err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(f[7])
		if err != nil {
			t.Fatal(err)
		}
		var kind faultstorage.FaultKind
		found := false
		for _, k := range faultKinds {
			if k.String() == f[6] {
				kind, found = k, true
			}
		}
		if !found {
			t.Fatalf("history row %q: unknown fault kind %q", f[0], f[6])
		}
		rows[f[0]] = seedV1Row{f[0], f[1], f[2], f[3], f[4], nth, kind, b}
	}
	return rows
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// decodeLegacyWith is decodeFuzzOp's arithmetic over explicit lists.
func decodeLegacyWith(data []byte, opKeys, methods []string) (op, method string, nth int, kind faultstorage.FaultKind) {
	b := func(i int) byte {
		if i < len(data) {
			return data[i]
		}
		return 0
	}
	op = opKeys[int(b(0))%len(opKeys)]
	method = methods[(int(b(1))<<8|int(b(2)))%len(methods)]
	return op, method, 1 + int(b(3))%5, faultKinds[int(b(4))%len(faultKinds)]
}

// documentedRetargets are seeds whose v2 target (their seedIntent entry) is
// deliberately NOT what the legacy bytes decode to under the lists of the commit
// that last set them. Each needs a reason; nothing else may differ.
var documentedRetargets = map[string]string{
	// PERF-FIX-6: Authorize's bypass read (RoleSetBypassesPermissionChecks, 4th
	// call) is now part of ResolveUserPermissionAt, the same call site; the old
	// method is no longer called on this op.
	"bulk-approve-rolesetbypass-audit-2549": "PERF-FIX-6 folded the 4th Authorize bypass read into ResolveUserPermissionAt",
	// Already drifted in the commit that added them (the op and/or method their
	// bytes pointed at are not in today's lists); intent recovered from:
	"31fd1db68a395324": "finding 2026-10-02-FINDING-mfa-login-getmfasecret-...: input=c688c2 -> REST POST /auth/mfa/verify, GetMFASecret#1, error",
	"bdbfad52d4cc7bae": "finding 2026-09-21-FINDING-role-update-permission-replace-...: F3b, UpdateRole's RemovePermissionFromRole panic (REST PUT /api/v1/roles/{id})",
	"fc345daad612100a": "#1969 commit message: first-call ambiguous commit in the already-covered CreateSecret op (REST POST /api/v1/secrets/); op inferred, method/nth/kind from the bytes",
}

// TestSeedMigration_V2TargetsSameOperationAsLegacyUnderOriginalLists: for every
// committed seed, decoding its ORIGINAL v1 bytes under the op catalog / method
// list that existed when it was written must give the same operation as
// decoding the committed v2 seed under today's lists.
func TestSeedMigration_V2TargetsSameOperationAsLegacyUnderOriginalLists(t *testing.T) {
	history := loadSeedV1History(t)
	files := committedSeedFiles(t)
	if len(history) != len(files) {
		t.Errorf("%d committed seeds but %d history rows: every seed needs exactly one row (new seeds must be written as v2, with a row only if they were ever legacy)", len(files), len(history))
	}
	for _, f := range files {
		name := filepath.Base(f)
		h, ok := history[name]
		if !ok {
			t.Errorf("%s has no row in %s/golden.tsv", name, seedV1HistoryDir)
			continue
		}
		// 1. the recorded target really is what the legacy bytes meant under the original lists.
		ops := readLines(t, filepath.Join(seedV1HistoryDir, h.snapshot+".ops"))
		methods := readLines(t, filepath.Join(seedV1HistoryDir, h.snapshot+".methods"))
		op, method, nth, kind := decodeLegacyWith(h.legacy, ops, methods)
		if op != h.op || method != h.method || nth != h.nth || kind != h.kind {
			t.Errorf("%s: legacy bytes %x under snapshot %s decode to (%q,%s,%d,%s), history row says (%q,%s,%d,%s)",
				name, h.legacy, h.snapshot, op, method, nth, kind, h.op, h.method, h.nth, h.kind)
			continue
		}
		// 2. the committed v2 seed decodes to the same operation under today's lists.
		d, ok := decodeFuzzOpV2(readFuzzCorpusFile(t, f))
		if !ok {
			t.Errorf("%s is not a resolvable v2 seed", name)
			continue
		}
		gotOp := opCatalog[d.opIndex].Key
		if reason, retarget := documentedRetargets[name]; retarget {
			in, ok := seedIntent[name]
			if !ok {
				t.Errorf("%s is a documented retarget (%s) but has no seedIntent entry", name, reason)
				continue
			}
			if gotOp != in.op || d.methodName != in.method {
				t.Errorf("%s: v2 decodes to (%q,%s), want its seedIntent (%q,%s) (%s)", name, gotOp, d.methodName, in.op, in.method, reason)
			}
			if gotOp == op && d.methodName == method {
				t.Errorf("%s is listed as a retarget but its v2 target equals the legacy one; drop it from documentedRetargets", name)
			}
			if d.nthCall != nth || d.kind != kind {
				t.Errorf("%s retarget changed nth/kind: (%d,%s) vs (%d,%s)", name, d.nthCall, d.kind, nth, kind)
			}
			continue
		}
		if gotOp != op || d.methodName != method || d.nthCall != nth || d.kind != kind {
			t.Errorf("%s: v2 seed decodes to (%q,%s,%d,%s) but it was written for (%q,%s,%d,%s)",
				name, gotOp, d.methodName, d.nthCall, d.kind, op, method, nth, kind)
		}
	}
}

// TestSeedMigration_LegacyDecodeIsWhatDrifted documents why the migration was
// needed (and keeps the table honest): decoding the original bytes under
// TODAY's lists differs for at least the seeds known to have drifted, while the
// v2 seeds do not.
func TestSeedMigration_LegacyDecodeIsWhatDrifted(t *testing.T) {
	opKeys := make([]string, len(opCatalog))
	for i, o := range opCatalog {
		opKeys[i] = o.Key
	}
	methods := storageInterfaceMethodNames()
	drifted := 0
	for _, h := range loadSeedV1History(t) {
		op, method, _, _ := decodeLegacyWith(h.legacy, opKeys, methods)
		if op != h.op || method != h.method {
			drifted++
		}
	}
	if drifted == 0 {
		t.Fatal("no legacy seed drifts under today's lists: either the table is wrong or the snapshots are stale")
	}
	t.Logf("%d of %d legacy seeds would decode to a different (op, method) under today's lists", drifted, len(loadSeedV1History(t)))
}

// TestSeedV2_AppendingToInterfaceOrCatalogDoesNotChangeDecoding is the guard
// the legacy encoding lacked: it simulates a storage method (and an op) being
// appended -- including ones that sort FIRST, which is what shifted legacy
// indices -- and requires every committed v2 seed to decode identically.
func TestSeedV2_AppendingToInterfaceOrCatalogDoesNotChangeDecoding(t *testing.T) {
	opKeys := make([]string, len(opCatalog))
	for i, o := range opCatalog {
		opKeys[i] = o.Key
	}
	methods := storageInterfaceMethodNames()

	grownMethods := [][]string{
		append(append([]string{}, methods...), "ZZZAppendedMethod"),
		append([]string{"AAAPrependedMethod"}, methods...),
		append(append(append([]string{}, methods[:len(methods)/2]...), "MMMInsertedMethod"), methods[len(methods)/2:]...),
	}
	grownOps := [][]string{
		append(append([]string{}, opKeys...), "REST POST /api/v1/appended-op"),
		append([]string{"REST GET /api/v1/prepended-op"}, opKeys...),
	}

	// the added names must not collide, or the simulation would prove nothing.
	for _, m := range []string{"ZZZAppendedMethod", "AAAPrependedMethod", "MMMInsertedMethod"} {
		for _, e := range methods {
			if nameHash4(m) == nameHash4(e) {
				t.Fatalf("simulated method %q collides with %q", m, e)
			}
		}
	}

	v2seeds := 0
	legacyShifted := 0
	for _, f := range committedSeedFiles(t) {
		data := readFuzzCorpusFile(t, f)
		if len(data) == 0 || data[0] != seedV2Magic {
			continue
		}
		v2seeds++
		base, ok := decodeFuzzOpV2With(data, opKeys, methods)
		if !ok {
			t.Errorf("%s does not resolve", f)
			continue
		}
		for _, gm := range grownMethods {
			got, ok := decodeFuzzOpV2With(data, opKeys, gm)
			if !ok || got != base {
				t.Errorf("%s: appending a storage method changed its decoding: %+v -> %+v (ok=%v)", f, base, got, ok)
			}
		}
		for _, go2 := range grownOps {
			got, ok := decodeFuzzOpV2With(data, go2, methods)
			// opIndex legitimately moves when an op is inserted before it; the KEY must not.
			if !ok || go2[got.opIndex] != opKeys[base.opIndex] || got.methodName != base.methodName ||
				got.nthCall != base.nthCall || got.kind != base.kind {
				t.Errorf("%s: appending an op changed its decoding: %+v -> %+v (ok=%v)", f, base, got, ok)
			}
		}
	}
	if v2seeds == 0 {
		t.Fatal("no committed v2 seeds: this guard would pass vacuously")
	}

	// Counter-check: the SAME growth does move the legacy decode, so the test is
	// capable of failing.
	for _, h := range loadSeedV1History(t) {
		o1, m1, _, _ := decodeLegacyWith(h.legacy, opKeys, methods)
		o2, m2, _, _ := decodeLegacyWith(h.legacy, opKeys, grownMethods[1])
		if o1 != o2 || m1 != m2 {
			legacyShifted++
		}
	}
	if legacyShifted == 0 {
		t.Fatal("prepending a method moved no legacy decode: the guard's simulation is not exercising index drift")
	}
}
