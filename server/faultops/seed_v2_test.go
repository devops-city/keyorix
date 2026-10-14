// seed_v2_test.go adds a key-addressed (v2) seed format for
// FuzzStorageFaultOperations, decoded alongside the legacy index-addressed one
// (C-MERGE-FRICTION).
//
// The legacy layout, decoded by decodeFuzzOp
// (fuzz_storage_fault_operations_test.go), is
//
//	[opIndex, methodIdxHi, methodIdxLo, nth, kind]
//
// with opIndex taken `% len(opCatalog)` and the method index `% len(methods)`,
// where methods is storage.Storage's method set in reflect order — which is
// ALPHABETICAL. So a committed seed silently re-points:
//   - its OP whenever opCatalog is reordered, an op is inserted before it, or
//     the catalog grows past opIndex's residue (#2396's SAML op shifted the
//     WebAuthn ops; seed webauthn-loginfinish-…-2603 replayed the wrong op);
//   - its FAULTED METHOD whenever any storage method is added whose name sorts
//     before it — i.e. on almost every storage-layer PR.
//
// Nothing errors: the decode always lands on SOME valid op/method, and the
// seed still passes, testing something other than what its name says. On
// main at the time of writing, 12 named regression seeds had drifted this way
// (see seedIntent below).
//
// The v2 layout addresses both by a stable key instead:
//
//	[0xFE, opKeyHash(4), methodNameHash(4), nth, kind]
//
// where *Hash is the first 4 bytes of sha256(name). decodeFuzzOpAny reads v2
// when byte 0 is 0xFE AND both hashes resolve, and falls back to the legacy
// decode otherwise (so a fuzzer mutation of a v2 seed still decodes to
// something, exactly like any other legacy input).
//
// Wiring (FUZZ-SEEDS-1): the fuzz loop, REPLAY_HEX tracer and corpus pin test
// decode with decodeFuzzOpAny, the whole corpus is v2, and
// TestCommittedV2Seeds_RequireV2Decoder fails if a v2 seed is ever committed
// while one of those call sites reverts to the legacy decodeFuzzOp. The
// migration is proven by seed_v2_migration_test.go.
package faultops

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

const seedV2Magic = 0xFE

// seedV2Len is the exact length encodeFuzzOpV2 produces.
const seedV2Len = 11

func nameHash4(name string) uint32 {
	sum := sha256.Sum256([]byte(name))
	return binary.BigEndian.Uint32(sum[:4])
}

var faultKinds = []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}

// encodeFuzzOpV2 builds a v2 seed. nth is 1..5 (as decoded); kind is an
// index into faultKinds.
func encodeFuzzOpV2(opKey, method string, nth int, kind byte) []byte {
	out := make([]byte, seedV2Len)
	out[0] = seedV2Magic
	binary.BigEndian.PutUint32(out[1:5], nameHash4(opKey))
	binary.BigEndian.PutUint32(out[5:9], nameHash4(method))
	out[9] = byte(nth - 1)
	out[10] = kind
	return out
}

// decodeFuzzOpV2 decodes a v2 seed; ok is false when data is not a v2 seed
// or either hash names no current op / storage method.
func decodeFuzzOpV2(data []byte) (decodedFuzzOp, bool) {
	opKeys := make([]string, len(opCatalog))
	for i, op := range opCatalog {
		opKeys[i] = op.Key
	}
	return decodeFuzzOpV2With(data, opKeys, storageInterfaceMethodNames())
}

// decodeFuzzOpV2With is decodeFuzzOpV2 against explicit op-key and method
// lists, so a test can decode under a list that differs from the live one
// (an appended method, a frozen historical list).
func decodeFuzzOpV2With(data []byte, opKeys, methods []string) (decodedFuzzOp, bool) {
	if len(data) < seedV2Len || data[0] != seedV2Magic {
		return decodedFuzzOp{}, false
	}
	opH := binary.BigEndian.Uint32(data[1:5])
	mH := binary.BigEndian.Uint32(data[5:9])
	opIdx := -1
	for i, k := range opKeys {
		if nameHash4(k) == opH {
			opIdx = i
			break
		}
	}
	method := ""
	for _, m := range methods {
		if nameHash4(m) == mH {
			method = m
			break
		}
	}
	if opIdx < 0 || method == "" {
		return decodedFuzzOp{}, false
	}
	return decodedFuzzOp{
		opIndex:    opIdx,
		methodName: method,
		nthCall:    1 + int(data[9])%5,
		kind:       faultKinds[int(data[10])%len(faultKinds)],
	}, true
}

// decodeFuzzOpAny is the decoder every replay path should use: v2 when the
// input is a resolvable v2 seed, the legacy index decode otherwise.
func decodeFuzzOpAny(data []byte) (decodedFuzzOp, bool) {
	if d, ok := decodeFuzzOpV2(data); ok {
		return d, true
	}
	return decodeFuzzOp(data)
}

// seedIntent records what each drifted named regression seed is FOR, derived
// from its file name (op and/or faulted method) and confirmed by replaying
// the corrected encoding through TestReplayStorageFaultInput (all pass).
// scripts/fuzzing/reencode-seeds.go encodes these from this table, not from
// whatever their legacy bytes decode to at re-encode time.
var seedIntent = map[string]struct{ op, method string }{
	"2413_migrateusertomachine_withnamedlock_error":          {"REST POST /api/v1/projects/{id}/machine-identities/migrate-from-user", "WithNamedLock"},
	"2428_restoregroup_getgroup_error":                       {"GRPC keyorix.v1.GroupService.RestoreGroup", "GetGroup"},
	"2565_finishwebauthnlogin_consumemfachallenge_error":     {"REST POST /auth/webauthn/login/finish", "ConsumeMFAChallenge"},
	"2565_finishwebauthnlogin_consumewebauthnsession_error":  {"REST POST /auth/webauthn/login/finish", "ConsumeWebAuthnSession"},
	"2565_finishwebauthnlogin_listwebauthncredentials_error": {"REST POST /auth/webauthn/login/finish", "ListWebAuthnCredentials"},
	"5900200031": {"GRPC keyorix.v1.UserService.CreateUser", "CountProjectMembershipsByUsers"},
	"mfa-verify-enforcesessionlimit-panic-2416":      {"REST POST /auth/mfa/verify", "EnforceSessionLimit"},
	"bulk_delete_getsecret_partial_success_reported": {"REST POST /api/v1/projects/{id}/secrets/bulk-delete", "GetSecret"},
	// PERF-FIX-6: the 4th Authorize's bypass read (this seed's nth is 4) is now
	// part of ResolveUserPermissionAt#4, the same call site; see
	// TestOracleAErrorBranch_BulkAccessRequestAuditDiffIsAcceptedWithoutATolerance.
	"bulk-approve-rolesetbypass-audit-2549":            {"REST POST /api/v1/access-requests/bulk-approve", "ResolveUserPermissionAt"},
	"classification-createsecretaccesslog-panic-2554":  {"REST PATCH /api/v1/secrets/{id}/classification", "CreateSecretAccessLog"},
	"invitations-countsetuptokenssince-audit-2599":     {"REST POST /api/v1/invitations", "CountSetupTokensSince"},
	"mfa-disable-deletesessionsforuserexcept-accepted": {"REST POST /api/v1/auth/mfa/disable", "DeleteSessionsForUserExcept"},
	"mfa-verify-createsession-steplost-2567":           {"REST POST /auth/mfa/verify", "CreateSession"},
	"webauthn-loginfinish-listcredentials-2565":        {"REST POST /auth/webauthn/login/finish", "ListWebAuthnCredentials"},
	// FUZZ-RULES-2: committed already legacy-encoded; TestByDesignSeeds_AcceptedOnlyThroughTheirRule.
	"3091_webauthn_loginfinish_getuserpermissions_effect_then_error":   {"REST POST /auth/webauthn/login/finish", "GetUserPermissions"},
	"3106_webauthn_loginfinish_getuserroles_effect_then_error":         {"REST POST /auth/webauthn/login/finish", "GetUserRoles"},
	"3093_grpc_createuser_getuserrolescopes_error":                     {"GRPC keyorix.v1.UserService.CreateUser", "GetUserRoleScopes"},
	"3093_grpc_updateuser_getuserrolescopes_nth2_error":                {"GRPC keyorix.v1.UserService.UpdateUser", "GetUserRoleScopes"},
	"3094_recoverycodes_regenerate_marktotpstepused_effect_then_error": {"REST POST /api/v1/auth/mfa/recovery-codes/regenerate", "MarkTOTPStepUsed"},
	"3101_mfa_verify_getuserpermissions_error":                         {"REST POST /auth/mfa/verify", "GetUserPermissions"},
	// FUZZ-SEEDS-1: these three were already drifted in the commit that added
	// them (their op and/or method no longer exist), so seedV1History's
	// "written-at-commit" decode is itself wrong. Intent recovered from the
	// finding/commit that introduced each; see documentedRetargets.
	"31fd1db68a395324": {"REST POST /auth/mfa/verify", "GetMFASecret"},
	"bdbfad52d4cc7bae": {"REST PUT /api/v1/roles/{id}", "RemovePermissionFromRole"},
	"fc345daad612100a": {"REST POST /api/v1/secrets/", "CreateSecret"},
}

const fuzzCorpusDir = "testdata/fuzz/FuzzStorageFaultOperations"

func committedSeedFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(fuzzCorpusDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Fatalf("no committed seeds under %s — this test would pass vacuously", fuzzCorpusDir)
	}
	return files
}

func TestSeedV2_RoundTripAndUniqueHashes(t *testing.T) {
	seen := map[uint32]string{}
	for _, op := range opCatalog {
		h := nameHash4(op.Key)
		if prev, ok := seen[h]; ok && prev != op.Key {
			t.Fatalf("op key hash collision: %q and %q — widen the v2 hash", prev, op.Key)
		}
		seen[h] = op.Key
	}
	mseen := map[uint32]string{}
	methods := storageInterfaceMethodNames()
	for _, m := range methods {
		if prev, ok := mseen[nameHash4(m)]; ok {
			t.Fatalf("storage method hash collision: %q and %q — widen the v2 hash", prev, m)
		}
		mseen[nameHash4(m)] = m
	}
	for i, op := range opCatalog {
		m := methods[i%len(methods)]
		for nth := 1; nth <= 5; nth++ {
			for kind := range byte(3) {
				d, ok := decodeFuzzOpAny(encodeFuzzOpV2(op.Key, m, nth, kind))
				if !ok || opCatalog[d.opIndex].Key != op.Key || d.methodName != m || d.nthCall != nth || d.kind != faultKinds[kind] {
					t.Fatalf("v2 round trip of (%q,%q,%d,%d) decoded to %+v ok=%v", op.Key, m, nth, kind, d, ok)
				}
			}
		}
	}
	// A legacy input (byte 0 != 0xFE) still takes the legacy path unchanged.
	legacy := []byte{3, 0, 7, 1, 2}
	a, _ := decodeFuzzOp(legacy)
	b, _ := decodeFuzzOpAny(legacy)
	if a != b {
		t.Fatalf("decodeFuzzOpAny changed a legacy decode: %+v vs %+v", a, b)
	}
	// 0xFE with unresolvable hashes falls back to legacy (fuzzer mutations).
	junk := []byte{seedV2Magic, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1}
	a, _ = decodeFuzzOp(junk)
	b, _ = decodeFuzzOpAny(junk)
	if a != b {
		t.Fatalf("an unresolvable 0xFE input must fall back to the legacy decode: %+v vs %+v", a, b)
	}
}

// TestCommittedV2Seeds_Resolve: every committed seed that starts with the v2
// magic byte must be a well-formed v2 seed whose op key AND method name
// resolve against the current catalog — a v2 seed whose op was renamed or
// deleted would otherwise silently fall back to a legacy decode of its hash
// bytes. Equivalently: no LEGACY seed may start with 0xFE (it would be
// ambiguous), so a fuzzer-found 0xFE input must be re-encoded before commit.
func TestCommittedV2Seeds_Resolve(t *testing.T) {
	n := 0
	for _, f := range committedSeedFiles(t) {
		data := readFuzzCorpusFile(t, f)
		if len(data) == 0 || data[0] != seedV2Magic {
			continue
		}
		n++
		if len(data) != seedV2Len {
			t.Errorf("%s starts with the v2 magic byte 0x%X but is %d bytes, not %d — either a malformed v2 seed or a "+
				"legacy seed that happens to start with 0x%X (ambiguous: re-encode it with encodeFuzzOpV2)",
				f, seedV2Magic, len(data), seedV2Len, seedV2Magic)
			continue
		}
		if _, ok := decodeFuzzOpV2(data); !ok {
			t.Errorf("%s is a v2 seed whose op-key hash %x or method hash %x matches no current opCatalog key / "+
				"storage.Storage method — the op or method was renamed or removed; re-target the seed", f, data[1:5], data[5:9])
		}
	}
	t.Logf("%d committed seed(s) carry the v2 magic byte; any that failed to resolve are reported above", n)
}

// TestCommittedV2Seeds_RequireV2Decoder guards the condition v2 seeds depend
// on: the fuzz loop itself must decode v2. If any v2 seed is committed while
// runOneFuzzIterationWithWorlds still calls the legacy decodeFuzzOp, the
// seed would replay as legacy garbage (0xFE % len(opCatalog)) and still pass.
func TestCommittedV2Seeds_RequireV2Decoder(t *testing.T) {
	var v2 []string
	for _, f := range committedSeedFiles(t) {
		data := readFuzzCorpusFile(t, f)
		if len(data) > 0 && data[0] == seedV2Magic {
			v2 = append(v2, filepath.Base(f))
		}
	}
	if len(v2) == 0 {
		t.Log("no v2 seeds committed; the fuzz loop's decoder is not yet required to understand v2")
		return
	}
	// Every path that turns a seed into an op must understand v2: the fuzz
	// loop itself, the REPLAY_HEX tracer, and the corpus pin test.
	for _, file := range v2DecoderCallSites {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "decoded, ok := decodeFuzzOpAny(data)") {
			t.Errorf("%d v2 seed(s) are committed (%v) but %s still decodes with the legacy decodeFuzzOp — they "+
				"would replay as legacy-decoded garbage and pass. Run `go run scripts/fuzzing/reencode-seeds.go`, which "+
				"switches every call site and re-encodes the corpus together.", len(v2), v2, file)
		}
	}
}

// v2DecoderCallSites are the files whose `decoded, ok := decodeFuzzOp(data)`
// line scripts/fuzzing/reencode-seeds.go switches to decodeFuzzOpAny.
var v2DecoderCallSites = []string{
	"fuzz_storage_fault_operations_test.go", // runOneFuzzIterationWithWorlds
	"replay_test.go",                        // traceFuzzOp
	"opcatalog_corpus_pin_test.go",          // TestOpcatalogCorpusFilesTargetPinnedOps
}

// TestSeedIntent_TableResolves: every seedIntent entry names a committed
// seed, a current op (when set) and a current storage method — so the table
// the re-encoder relies on cannot silently rot.
func TestSeedIntent_TableResolves(t *testing.T) {
	ops := map[string]bool{}
	for _, op := range opCatalog {
		ops[op.Key] = true
	}
	methods := map[string]bool{}
	for _, m := range storageInterfaceMethodNames() {
		methods[m] = true
	}
	for file, in := range seedIntent {
		if _, err := os.Stat(filepath.Join(fuzzCorpusDir, file)); err != nil {
			t.Errorf("seedIntent names %q, which is not a committed seed: %v", file, err)
		}
		if !ops[in.op] {
			t.Errorf("seedIntent[%q] names op %q, which is not in opCatalog", file, in.op)
		}
		if !methods[in.method] {
			t.Errorf("seedIntent[%q] names method %q, which is not a storage.Storage method", file, in.method)
		}
	}
}

// TestReportSeedIntentDrift is a REPORT, not a gate: it logs every seedIntent
// seed whose legacy bytes currently decode to something other than its
// intended op/method. Method drift recurs on every storage-method addition
// that sorts earlier (reflect order is alphabetical) until the corpus is
// re-encoded as v2, and failing on it would turn unrelated storage PRs red in
// the merge queue — the friction this change exists to remove. The intent is
// still enforced where it matters: the re-encoder encodes from seedIntent.
func TestReportSeedIntentDrift(t *testing.T) {
	drifted := 0
	for file, in := range seedIntent {
		data := readFuzzCorpusFile(t, filepath.Join(fuzzCorpusDir, file))
		d, ok := decodeFuzzOpAny(data)
		if !ok {
			continue
		}
		gotOp := opCatalog[d.opIndex].Key
		if gotOp != in.op || d.methodName != in.method {
			drifted++
			t.Logf("DRIFTED %s: decodes to (%q, %s), intent (%q, %s)", file, gotOp, d.methodName, in.op, in.method)
		}
	}
	t.Logf("%d of %d intent-tracked seed(s) currently drifted", drifted, len(seedIntent))
}

// --- re-encoder (run by scripts/fuzzing/reencode-seeds.go, never by plain go test) ---

// TestReencodeLegacySeedsToV2 rewrites every legacy seed under fuzzCorpusDir
// as v2, IN PLACE, when REENCODE_SEEDS_V2=1. Target per seed: seedIntent when
// listed, otherwise what the seed was written for (testdata/seed_v1_history,
// see seed_v2_migration_test.go) -- NOT what its bytes decode to right now,
// which is already drifted for 83 of 88 seeds. nth/kind come from the same row. Idempotent: v2 seeds are skipped.
func TestReencodeLegacySeedsToV2(t *testing.T) {
	if os.Getenv("REENCODE_SEEDS_V2") != "1" {
		t.Skip("set REENCODE_SEEDS_V2=1 (via scripts/fuzzing/reencode-seeds.go) to rewrite the corpus")
	}
	rewritten := 0
	for _, f := range committedSeedFiles(t) {
		data := readFuzzCorpusFile(t, f)
		if _, ok := decodeFuzzOpV2(data); ok {
			continue
		}
		// The target is what the seed was WRITTEN for (seedV1History, recovered
		// from the commit that last set its bytes), never what its bytes decode
		// to now: 20+ seeds had already drifted, and re-encoding the live decode
		// would have frozen the drift in. A seed with no history row cannot be
		// migrated safely.
		g, ok := loadSeedV1History(t)[filepath.Base(f)]
		if !ok {
			t.Fatalf("%s: no row in %s -- cannot tell what it was written for", f, seedV1HistoryDir)
		}
		op, method := g.op, g.method
		if in, ok := seedIntent[filepath.Base(f)]; ok {
			op, method = in.op, in.method
		}
		kind := byte(0)
		for i, k := range faultKinds {
			if k == g.kind {
				kind = byte(i)
			}
		}
		d := decodedFuzzOp{nthCall: g.nth, kind: g.kind}
		out := encodeFuzzOpV2(op, method, d.nthCall, kind)
		body := fmt.Sprintf("go test fuzz v1\n[]byte(%s)\n", strconv.Quote(string(out)))
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		rewritten++
		t.Logf("v2 %s -> (%q, %s, nth=%d, kind=%s)", strings.TrimPrefix(f, fuzzCorpusDir+"/"), op, method, d.nthCall, d.kind)
	}
	t.Logf("re-encoded %d legacy seed(s) as v2", rewritten)
}
