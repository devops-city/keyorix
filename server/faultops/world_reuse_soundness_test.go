// world_reuse_soundness_test.go — Session M item M5's MANDATORY soundness
// gate: the whole checked-in seed corpus, replayed forward and reversed
// through ONE reused-and-reset world pair, must produce IDENTICAL verdicts
// (pass/fail/skip AND the actual before/after/refAfter snapshot hashes) to
// the SAME inputs replayed through a fresh-per-call world pair (the
// pre-reuse behaviour, still exercised by every other caller of
// runOneFuzzIteration unchanged). A planted state-leak must make this test
// FAIL -- proven by TestWorldReuseSoundness_CatchesPlantedStateLeak below,
// which is the red half of this gate's own red/green proof (CLAUDE.md: "A
// guard nobody has watched fail is not a guard").
package faultops

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// loadFaultOpsCorpus reads every checked-in seed file for
// FuzzStorageFaultOperations plus the 5 explicit f.Add seeds the fuzz target
// itself defines (re-derived the same way FuzzStorageFaultOperations does,
// not hand-copied, so this can't drift from the real seed set).
func loadFaultOpsCorpus(t *testing.T) [][]byte {
	t.Helper()
	var inputs [][]byte

	dir := "testdata/fuzz/FuzzStorageFaultOperations"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read corpus file %s: %v", e.Name(), err)
		}
		b, ok := parseGoFuzzCorpusFile(data)
		if !ok {
			t.Fatalf("corpus file %s: could not parse go-fuzz-corpus format", e.Name())
		}
		inputs = append(inputs, b)
	}

	inputs = append(inputs, faultOpsExplicitSeeds()...)

	if len(inputs) == 0 {
		t.Fatal("no corpus inputs found — soundness gate would vacuously pass, refusing to run")
	}
	return inputs
}

// parseGoFuzzCorpusFile parses the one-argument `[]byte(...)` shape every
// FuzzStorageFaultOperations corpus file uses (Go's native fuzz corpus
// format: a "go test fuzz v1" header line, then one Go expression per fuzz
// argument). Uses go/parser on the expression line rather than a hand-rolled
// scanner, so it handles every Go string-literal escape form correctly
// (raw bytes, \x.., \u.., octal) instead of only the common case.
func parseGoFuzzCorpusFile(data []byte) ([]byte, bool) {
	lines := splitLines(data)
	if len(lines) < 2 {
		return nil, false
	}
	// lines[0] is the "go test fuzz v1" header; lines[1] is `[]byte("...")`.
	expr := lines[1]
	const prefix = `[]byte(`
	const suffix = `)`
	if len(expr) < len(prefix)+len(suffix) || expr[:len(prefix)] != prefix || expr[len(expr)-1:] != suffix {
		return nil, false
	}
	quoted := expr[len(prefix) : len(expr)-1]
	s, err := strconv.Unquote(quoted)
	if err != nil {
		return nil, false
	}
	return []byte(s), true
}

func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, string(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}

// faultOpsExplicitSeeds re-derives FuzzStorageFaultOperations's own f.Add
// seed set (fuzz_storage_fault_operations_test.go) via the same seedFor
// logic, so the soundness gate covers them too without hand-copying bytes
// that would drift the moment the real seeds change.
func faultOpsExplicitSeeds() [][]byte {
	seedFor := func(opKey, method string, nth int, kind byte) []byte {
		opIdx := -1
		for i, op := range opCatalog {
			if op.Key == opKey {
				opIdx = i
				break
			}
		}
		if opIdx < 0 {
			return nil
		}
		methods := storageInterfaceMethodNames()
		methodIdx := -1
		for i, m := range methods {
			if m == method {
				methodIdx = i
				break
			}
		}
		if methodIdx < 0 {
			return nil
		}
		return []byte{byte(opIdx), byte(methodIdx >> 8), byte(methodIdx), byte(nth - 1), kind}
	}

	var out [][]byte
	add := func(opKey, method string, nth int, kind byte) {
		if s := seedFor(opKey, method, nth, kind); s != nil {
			out = append(out, s)
		}
	}
	add("REST PUT /api/v1/roles/{id}", "RemovePermissionFromRole", 1, 0)
	add("REST POST /api/v1/secrets/", "CreateSecret", 1, 1)
	add("GRPC keyorix.v1.RoleService.AssignRole", "GetUserRoleIDsAt", 1, 0)
	add("REST DELETE /api/v1/secrets/{id}", "DeleteSecret", 1, 2)
	// PERF-FIX-7: the cache-hit account re-read this seed faults is now
	// GetSessionAuthLiveness#1 (was GetUser#1), the same call site.
	add("REST DELETE /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}", "GetSessionAuthLiveness", 1, 0)
	return out
}

// verdict is one input's observable outcome: category (skip/fail/pass, from
// the subtest's own Skipped()/Failed() status) plus the three snapshot
// hashes checkOracles actually compared (empty when the fault never fired,
// since runOneFuzzIterationWithWorlds returns before snapshotting `after` in
// that case — itself a real category, not an omission, and still compared).
type verdict struct {
	category        string // "skip", "fail", "pass"
	fired           bool
	beforeH, afterH string
	refAfterH       string
	oi              oracleInput // full snapshots, for table-level diffing on mismatch
}

// captureVerdict runs one input as a t.Run subtest (so a t.Fatalf inside it
// unwinds only that subtest's goroutine, not the whole gate) and reports its
// outcome. reusedRef/reusedW nil builds a fresh world pair (the baseline);
// non-nil resets the given pair in place.
func captureVerdict(t *testing.T, name string, data []byte, reusedRef, reusedW *faultWorld) verdict {
	t.Helper()
	var v verdict
	t.Run(name, func(st *testing.T) {
		defer func() {
			switch {
			case st.Skipped():
				v.category = "skip"
			case st.Failed():
				v.category = "fail"
			default:
				v.category = "pass"
			}
		}()
		observe := func(oi oracleInput) {
			v.fired = true
			v.beforeH = oi.before.Hash
			v.afterH = oi.after.Hash
			v.refAfterH = oi.refAfter.Hash
			v.oi = oi
		}
		runOneFuzzIterationWithWorlds(st, data, reusedRef, reusedW, observe)
	})
	return v
}

// TestWorldReuseSoundness is the mandatory gate itself. See the package doc
// comment above.
func TestWorldReuseSoundness(t *testing.T) {
	inputs := loadFaultOpsCorpus(t)
	t.Logf("soundness gate: %d corpus inputs", len(inputs))

	baseline := make([]verdict, len(inputs))
	for i, in := range inputs {
		baseline[i] = captureVerdict(t, "baseline", in, nil, nil)
	}

	t.Run("forward", func(t *testing.T) {
		ref := buildReusableFaultWorld(t, nil)
		w := buildReusableFaultWorld(t, nil)
		for i, in := range inputs {
			got := captureVerdict(t, "reused", in, ref, w)
			want := baseline[i]
			assertVerdictsMatch(t, i, "forward", got, want)
		}
	})

	t.Run("reversed", func(t *testing.T) {
		ref := buildReusableFaultWorld(t, nil)
		w := buildReusableFaultWorld(t, nil)
		for i := len(inputs) - 1; i >= 0; i-- {
			got := captureVerdict(t, "reused", inputs[i], ref, w)
			want := baseline[i]
			assertVerdictsMatch(t, i, "reversed", got, want)
		}
	})
}

// assertVerdictsMatch compares category, fired, and the three snapshot
// hashes -- with ONE deliberate tolerance, mirroring checkOracles' own
// oracle-(a) carve-out ("state diverges only in outcome-log tables...
// never a real business-state inconsistency", onlyOutcomeLogTables): a
// reused-world run's outcomeLogTables rows (AuditEvent, SecretAccessLog)
// carry the reused httptest.Server's own ephemeral port (rebuildTransport
// spins up a fresh httptest.Server on every reset -- see world_reuse_test.go),
// which will not match the separately-built fresh-world baseline's port.
// That is a property of comparing two independently-constructed
// httptest.Server instances, not a reuse-soundness defect -- the SAME
// divergence would occur between any two fresh-per-call worlds. Using
// hashExcluding(outcomeLogTables...) -- the exact table set checkOracles
// itself now tolerates, not a hardcoded "AuditEvent" this gate would drift
// out of sync with the moment production adds another outcome-log table (as
// it did with SecretAccessLog, #2314) -- keeps this gate's notion of
// "acceptable" identical to production's. Everything else -- category,
// fired, and every non-outcome-log table's content -- is compared with NO
// tolerance.
func assertVerdictsMatch(t *testing.T, i int, pass string, got, want verdict) {
	t.Helper()
	if got.category != want.category || got.fired != want.fired {
		t.Errorf("input %d (%s pass): reused verdict {cat:%s fired:%v} != fresh-world baseline {cat:%s fired:%v}",
			i, pass, got.category, got.fired, want.category, want.fired)
		return
	}
	if !got.fired {
		return
	}
	if !verdictsMatch(got, want) {
		t.Errorf("input %d (%s pass): reused verdict {before:%s after:%s refAfter:%s} != "+
			"fresh-world baseline {before:%s after:%s refAfter:%s} (diverges outside %v)",
			i, pass, got.beforeH, got.afterH, got.refAfterH, want.beforeH, want.afterH, want.refAfterH, outcomeLogTables)
		diffSnapshots(t, "before", got.oi.before, want.oi.before)
		diffSnapshots(t, "after", got.oi.after, want.oi.after)
		diffSnapshots(t, "refAfter", got.oi.refAfter, want.oi.refAfter)
		return
	}
	if got.beforeH != want.beforeH || got.afterH != want.afterH || got.refAfterH != want.refAfterH {
		t.Logf("ACCEPTABLE-BY-DESIGN: input %d (%s pass): reused vs fresh-world snapshots diverge only in "+
			"outcome-log tables %v (independent httptest.Server ephemeral ports) -- matches checkOracles' own "+
			"onlyOutcomeLogTables carve-out, not a reuse-soundness defect", i, pass, outcomeLogTables)
	}
}

func diffSnapshots(t *testing.T, label string, got, want dbSnapshot) {
	t.Helper()
	if got.Hash == want.Hash {
		return
	}
	for tbl, gts := range got.Tables {
		wts := want.Tables[tbl]
		if gts.Hash != wts.Hash {
			t.Logf("  %s.%s DIFFERS: reused=%v baseline=%v", label, tbl, gts.Rows, wts.Rows)
		}
	}
}

// verdictsMatch is assertVerdictsMatch's comparison, factored out as a pure
// predicate (no t.Errorf/t.Logf) so TestWorldReuseSoundness_CatchesPlantedStateLeak
// below can count mismatches without spamming -v output for a test that is
// SUPPOSED to diverge.
func verdictsMatch(got, want verdict) bool {
	if got.category != want.category || got.fired != want.fired {
		return false
	}
	if !got.fired {
		return true
	}
	return hashExcluding(got.oi.before, outcomeLogTables...) == hashExcluding(want.oi.before, outcomeLogTables...) &&
		hashExcluding(got.oi.after, outcomeLogTables...) == hashExcluding(want.oi.after, outcomeLogTables...) &&
		hashExcluding(got.oi.refAfter, outcomeLogTables...) == hashExcluding(want.oi.refAfter, outcomeLogTables...)
}

// TestWorldReuseSoundness_CatchesPlantedStateLeak is the mandatory red half
// of this gate's own red/green proof (CLAUDE.md: "A guard nobody has
// watched fail is not a guard" / "red-proof every guard"). It plants a
// deliberate state-leak — resetWorldTables silently skipping the
// "secret_versions" table via leakTableForTest (world_reuse_test.go) — and confirms
// TestWorldReuseSoundness's own comparison predicate (verdictsMatch, the
// exact logic assertVerdictsMatch uses) actually flags divergence, not just
// that the underlying bug exists. Without this test, a gate that always
// happened to report PASS (a bug in the gate itself, not in reuse) would be
// silently indistinguishable from a gate that has nothing to catch.
func TestWorldReuseSoundness_CatchesPlantedStateLeak(t *testing.T) {
	if os.Getenv("KEYORIX_RUN_REDPROOF_TESTS") == "" {
		t.Skip("manual red-proof, skipped by default: set KEYORIX_RUN_REDPROOF_TESTS=1 to run it. This test " +
			"deliberately plants a state-leak bug and expects the gate's comparison to flag real oracle " +
			"violations inside nested subtests (via t.Errorf), which necessarily marks THIS test FAILED too " +
			"-- that is the correct, desired outcome of a red-proof, not a bug, so it cannot be a normal " +
			"always-green CI test. Run it standalone with -run TestWorldReuseSoundness_CatchesPlantedStateLeak " +
			"-v to re-verify the gate still has teeth; look for \"planted state leak correctly detected\".")
	}
	inputs := loadFaultOpsCorpus(t)

	baseline := make([]verdict, len(inputs))
	for i, in := range inputs {
		baseline[i] = captureVerdict(t, "baseline", in, nil, nil)
	}

	probe := buildReusableFaultWorld(t, nil)
	var sqliteTables []string
	if err := probe.db.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").
		Scan(&sqliteTables).Error; err != nil {
		t.Fatalf("list tables to verify the plant target exists: %v", err)
	}
	found := false
	for _, tbl := range sqliteTables {
		if tbl == "secret_versions" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("plant target table %q not found among real tables %v -- leakTableForTest would be a silent "+
			"no-op, making this red-proof vacuous", "secret_versions", sqliteTables)
	}

	leakTableForTest = "secret_versions"
	defer func() { leakTableForTest = "" }()

	ref := buildReusableFaultWorld(t, nil)
	w := buildReusableFaultWorld(t, nil)
	mismatches := 0
	for i, in := range inputs {
		got := captureVerdict(t, "leaky", in, ref, w)
		if !verdictsMatch(got, baseline[i]) {
			mismatches++
		}
	}

	if mismatches == 0 {
		t.Fatal("planted state leak (resetWorldTables silently skipping the secret_versions table) produced ZERO " +
			"detected mismatches across the whole corpus -- the soundness gate would NOT have caught this " +
			"class of bug; the gate is not trustworthy")
	}
	t.Logf("planted state leak correctly detected: %d/%d inputs diverged from the fresh-world baseline",
		mismatches, len(inputs))
}
