// canary_leak_fault_fuzz_test.go — ADR-112 "Secrets and audit": a secret
// value must never appear in server logs, error messages/HTTP or gRPC error
// bodies, URLs/redirects, audit event descriptions, or metrics, enforced by
// a test oracle rather than by review alone. See docs/secret-canary-leak-harness.md
// for exactly what this covers and what it structurally cannot (client-side
// logs, anything outside this process).
//
// Two passes, one shared scanner:
//
//  1. TestFreshCanarySecretLifecycleUnderFault mints its own unique,
//     high-entropy canary values (crypto/rand, never one of opCatalog's own
//     fixed "fuzz-value"-family literals) and drives create -> update ->
//     delete directly against the real HTTP transport — the exact calls
//     opCatalog's own secret entries make (opcatalog_test.go:688,700,716),
//     just with a canary this harness fully controls instead of a hardcoded
//     fixture — faulting the underlying CreateSecret/UpdateSecret/DeleteSecret
//     storage call (error, then panic) at each step. Error paths are where a
//     leak is most likely to hide: a wrapped storage error that echoes back
//     the value it was trying to write.
//  2. TestCanaryLeakAcrossSecretOperations is the broad sweep: every
//     opCatalog operation whose key names a secret-shaped resource (secrets,
//     ACLs, shares, dynamic secrets, secret templates) — read-only reuse of
//     opCatalog, exactly like FuzzAuditCompleteness in
//     audit_completeness_fuzz_test.go, no changes to opcatalog_test.go — run
//     with no fault, then faulted at the first and last distinct
//     storage.Storage method its own unfaulted dry run actually calls
//     (discovered via FaultyStorage.Calls(), not a hand-maintained per-op
//     table that would drift the moment a new wiring batch lands), both as a
//     returned error and as a panic. Needles are knownSecretValueLiterals
//     (below) — the complete, grep-verified set of secret-value literals
//     opcatalog_test.go embeds — so a leak of the catalog's own fixture
//     value is caught across every op, not only the two literals the
//     existing narrow oracle (e) in fuzz_storage_fault_operations_test.go
//     checks (canaryFragments, scoped to result.Detail only).
//
// Every captured channel is scanned after every run: the HTTP/gRPC response
// body (opResult.Detail), the stdlib `log` package output emitted during the
// call (the sole logger in this codebase — server/middleware/logger.go
// hardcodes log.Default()), every AuditEvent row written since the call
// started (Description and Diff columns), and the /metrics endpoint.
//
// FuzzCanaryLeakUnderFault (bottom of this file) is a SEPARATE Fuzz
// entrypoint over the same secret-touching op set — deliberately NOT wired
// into FuzzStorageFaultOperations' checkOracles: fuzz_storage_fault_operations_test.go
// is a declared conflict hotspot (opScopedBestEffortTables/knownOpenTolerances,
// almost every fuzzer PR touches the same lists). A standalone entrypoint
// gets the same fault-injected fuzzing coverage with zero edits to that file.
package faultops

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// knownSecretValueLiterals is every literal string opcatalog_test.go
// assigns to a Secret's Value field, derived 2026-10-02 by grepping every
// `"value": "fuzz...`, `Value: "fuzz...` and `new_value...: "fuzz...`
// occurrence in that file and cross-checking each hit against the field it's
// assigned to — NOT every "fuzz-*" string there; most of those are
// names/usernames, never a secret's own value. Extend this list, don't
// replace it, if a future opCatalog entry introduces a new secret-value
// literal.
var knownSecretValueLiterals = []string{
	"fuzz-value",                   // REST POST /api/v1/secrets/ (create), GRPC CreateSecret
	"fuzz-value-updated",           // REST PUT /api/v1/secrets/{id}
	"fuzz-b10-secret-grpc-updated", // GRPC UpdateSecret
	"fuzz-rotated-value",           // REST POST /api/v1/secrets/{id}/rotate
	"fuzz-rollback-setup-rotated",  // REST POST /api/v1/secrets/{id}/rollback (setup)
}

// canaryNeedles derives the raw/hex/base64(std)/base64(url) encodings of a
// secret value to scan for — mirrors server/http/canary_secret_leakage_fuzz_test.go's
// deriveCanary reasoning: no legitimate channel in this codebase ever hex/
// base64-encodes a secret value, so a match on the ENCODED form alone is
// already sufficient evidence of a leak; no offset-aware decode-back is
// needed. Every literal's own charset (lowercase letters, digits, hyphens)
// needs no URL-escaping, so the "URL-encoded variant" is identical to the
// raw form — covered by construction, not a separate pass.
func canaryNeedles(value string) []string {
	if value == "" {
		return nil
	}
	return []string{
		value,
		hex.EncodeToString([]byte(value)),
		base64.StdEncoding.EncodeToString([]byte(value)),
		base64.URLEncoding.EncodeToString([]byte(value)),
	}
}

// newHighEntropyCanary mints a value no legitimate code path could already
// contain: a fixed prefix (for readable failure messages) plus 20 bytes of
// crypto/rand. tag distinguishes canaries minted within the same test run.
func newHighEntropyCanary(tag string) string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not a condition this harness should quietly
		// tolerate — a canary this harness can't trust the uniqueness of
		// defeats its own purpose.
		panic("canary_leak_fault_fuzz_test.go: crypto/rand failed: " + err.Error())
	}
	return fmt.Sprintf("kxleak-%s-%s", tag, hex.EncodeToString(b))
}

// lockedLogBuffer and redirectLog mirror server/http/canary_secret_leakage_fuzz_test.go's
// lockedBuffer/log.SetOutput discipline: log.SetOutput is GLOBAL process
// state (stdlib `log` has no per-world instance), so it is redirected ONCE
// for the whole test/fuzz run and restored via Cleanup — never per-world,
// which would race concurrent goSafe writers from other worlds.
type lockedLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedLogBuffer) since(offset int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.buf.String()
	if offset > len(s) {
		return ""
	}
	return s[offset:]
}

func (b *lockedLogBuffer) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// cleanupHelper is the common subset of *testing.T and *testing.F redirectLog
// needs, so the same log redirect works for both the deterministic sweep and
// the Fuzz entrypoint.
type cleanupHelper interface {
	Helper()
	Cleanup(func())
}

func redirectLog(th cleanupHelper) *lockedLogBuffer {
	th.Helper()
	lb := &lockedLogBuffer{}
	prev := log.Writer()
	log.SetOutput(lb)
	th.Cleanup(func() { log.SetOutput(prev) })
	return lb
}

// auditTextSince returns the Description and Diff columns of every
// AuditEvent row written after sinceMaxID — the free-text fields a leak
// would have to land in, since every other column is a typed ID/bool/time.
func auditTextSince(w *faultWorld, sinceMaxID uint) []string {
	var rows []struct {
		Description string
		Diff        string
	}
	w.db.Table("audit_events").Where("id > ?", sinceMaxID).Order("id asc").Find(&rows)
	out := make([]string, 0, len(rows)*2)
	for _, r := range rows {
		out = append(out, r.Description, r.Diff)
	}
	return out
}

// scrapeMetrics fetches /metrics exactly as server/http/canary_secret_leakage_fuzz_test.go
// does (unauthenticated — router.go's pathMetrics has no auth middleware);
// the extra bearer header httpJSON always attaches is harmless, the route
// never inspects it.
func scrapeMetrics(ctx context.Context, w *faultWorld) (string, error) {
	st, body, err := httpJSON(ctx, w, http.MethodGet, "/metrics", nil)
	if err != nil {
		return "", err
	}
	if st != http.StatusOK {
		return "", fmt.Errorf("GET /metrics: HTTP %d: %s", st, body)
	}
	return string(body), nil
}

// scanLeakChannels is this oracle's single check, applied identically by
// both passes: body/log/audit/metrics must not contain ANY needle derived
// from ANY canary the caller cares about this run. Mirrors checkOracles'
// convention (fuzz_storage_fault_operations_test.go) of calling t.Errorf
// directly with enough context to reproduce.
func scanLeakChannels(t *testing.T, label string, needles []string, httpOrGRPCDetail, logSlice, metricsSnapshot string, auditTexts []string) {
	t.Helper()
	check := func(channel, haystack string) {
		if haystack == "" {
			return
		}
		for _, n := range needles {
			if n != "" && strings.Contains(haystack, n) {
				t.Errorf("CANARY-LEAK VIOLATION — %s: secret value leaked into %s (matched %q)", label, channel, n)
				return // one violation per channel is enough to fail loudly; don't spam the same leak four times
			}
		}
	}
	check("http/grpc response", httpOrGRPCDetail)
	check("server log output", logSlice)
	check("metrics output", metricsSnapshot)
	for i, a := range auditTexts {
		check(fmt.Sprintf("audit_events row #%d", i), a)
	}
}

// mustExecuteRecoveringPanics runs fn, converting an escaped panic into a
// t.Errorf (the real Recovery middleware/RecoveryInterceptor should already
// have turned any application panic into a 500/codes.Internal response
// before it ever reaches here — the same expectation fuzz_storage_fault_operations_test.go's
// runOneFuzzIterationWithWorlds enforces).
func mustExecuteRecoveringPanics(t *testing.T, fn func() (opResult, error)) opResult {
	t.Helper()
	var result opResult
	var execErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic escaped the transport layer entirely: %v", r)
			}
		}()
		result, execErr = fn()
	}()
	if execErr != nil {
		t.Skipf("transport error (not an application error): %v", execErr)
	}
	return result
}

// --- Pass 1: a fresh, high-entropy canary driven through create/update/delete ---

type faultVariant struct {
	name  string
	fault *faultstorage.FaultSpec
}

func faultVariants(method string) []faultVariant {
	return []faultVariant{
		{"no-fault", nil},
		{"error", &faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: errFuzzInjected}},
		{"panic", &faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindPanic, Err: errFuzzInjected}},
	}
}

func createCanarySecret(ctx context.Context, w *faultWorld, name, value string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secrets/", map[string]any{
		"name": name, "value": value, "project_id": 1, "environment_id": 1, "type": "generic",
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("creating prerequisite canary secret: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding create-secret response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

func assertNoFreshCanaryLeak(t *testing.T, label string, w *faultWorld, logBuf *lockedLogBuffer, logOffset int, beforeMaxID uint, result opResult, canaryValues ...string) {
	t.Helper()
	needles := make([]string, 0, len(canaryValues)*4)
	for _, v := range canaryValues {
		needles = append(needles, canaryNeedles(v)...)
	}
	metrics, mErr := scrapeMetrics(context.Background(), w)
	if mErr != nil {
		t.Logf("scraping /metrics: %v (not itself a leak finding)", mErr)
	}
	scanLeakChannels(t, label, needles, result.Detail, logBuf.since(logOffset), metrics, auditTextSince(w, beforeMaxID))
}

func TestFreshCanarySecretLifecycleUnderFault(t *testing.T) {
	logBuf := redirectLog(t)

	t.Run("create", func(t *testing.T) {
		for _, tc := range faultVariants("CreateSecret") {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				w := newFaultWorld(t, nil)
				canaryVal := newHighEntropyCanary("create-" + tc.name)
				logOffset := logBuf.len()
				beforeMaxID := maxAuditEventID(w)
				if tc.fault != nil {
					w.faulty.Arm(tc.fault)
				}
				result := mustExecuteRecoveringPanics(t, func() (opResult, error) {
					st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secrets/", map[string]any{
						"name": "canary-create-" + tc.name, "value": canaryVal, "project_id": 1, "environment_id": 1, "type": "generic",
					})
					if err != nil {
						return opResult{}, err
					}
					return httpResult(st, body), nil
				})
				drainAllBackgroundGoroutines()
				assertNoFreshCanaryLeak(t, "fresh-canary create/"+tc.name, w, logBuf, logOffset, beforeMaxID, result, canaryVal)
			})
		}
	})

	t.Run("update", func(t *testing.T) {
		for _, tc := range faultVariants("UpdateSecret") {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				w := newFaultWorld(t, nil)
				setupVal := newHighEntropyCanary("update-setup-" + tc.name)
				id, err := createCanarySecret(ctx, w, "canary-update-"+tc.name, setupVal)
				if err != nil {
					t.Fatalf("setup: creating prerequisite secret: %v", err)
				}
				drainAllBackgroundGoroutines()
				updateVal := newHighEntropyCanary("update-new-" + tc.name)
				logOffset := logBuf.len()
				beforeMaxID := maxAuditEventID(w)
				if tc.fault != nil {
					w.faulty.Arm(tc.fault)
				}
				result := mustExecuteRecoveringPanics(t, func() (opResult, error) {
					st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), map[string]any{"value": updateVal})
					if err != nil {
						return opResult{}, err
					}
					return httpResult(st, body), nil
				})
				drainAllBackgroundGoroutines()
				assertNoFreshCanaryLeak(t, "fresh-canary update/"+tc.name, w, logBuf, logOffset, beforeMaxID, result, setupVal, updateVal)
			})
		}
	})

	t.Run("delete", func(t *testing.T) {
		for _, tc := range faultVariants("DeleteSecret") {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				w := newFaultWorld(t, nil)
				setupVal := newHighEntropyCanary("delete-setup-" + tc.name)
				id, err := createCanarySecret(ctx, w, "canary-delete-"+tc.name, setupVal)
				if err != nil {
					t.Fatalf("setup: creating prerequisite secret: %v", err)
				}
				drainAllBackgroundGoroutines()
				logOffset := logBuf.len()
				beforeMaxID := maxAuditEventID(w)
				if tc.fault != nil {
					w.faulty.Arm(tc.fault)
				}
				result := mustExecuteRecoveringPanics(t, func() (opResult, error) {
					st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), nil)
					if err != nil {
						return opResult{}, err
					}
					return httpResult(st, body), nil
				})
				drainAllBackgroundGoroutines()
				assertNoFreshCanaryLeak(t, "fresh-canary delete/"+tc.name, w, logBuf, logOffset, beforeMaxID, result, setupVal)
			})
		}
	})
}

// --- Pass 2: the broad opCatalog sweep ---

// secretTouchingOps is every opCatalog entry whose key names a secret-shaped
// resource — a case-insensitive substring match on "secret" rather than a
// hand-maintained list, so a future opCatalog entry automatically joins this
// sweep without anyone remembering to add it here (the "enumeration only as
// complete as the idioms it knows about" failure class CLAUDE.md warns
// about). Confirmed against the full catalog (2026-10-02): matches every
// REST /api/v1/secrets/... entry, every GRPC ...SecretService.../ShareService.ShareSecret
// entry, secret-templates, and dynamic-secrets/DynamicSecretService entries.
func secretTouchingOps() []operation {
	var out []operation
	for _, op := range opCatalog {
		if strings.Contains(strings.ToLower(op.Key), "secret") {
			out = append(out, op)
		}
	}
	return out
}

// distinctCallMethods runs op once (Setup, then an unfaulted Execute) and
// returns the distinct storage.Storage method names Execute itself invoked,
// in first-seen order — how this harness picks which method to fault for a
// given op, instead of a per-op table that would silently drift the moment
// a new wiring batch changes an op's call shape underneath it.
func distinctCallMethods(t *testing.T, op operation) []string {
	t.Helper()
	ctx := context.Background()
	w := newFaultWorld(t, nil)
	var state any
	var err error
	if op.Setup != nil {
		state, err = op.Setup(ctx, w)
		if err != nil {
			return nil
		}
	}
	before := len(w.faulty.Calls())
	if _, err := op.Execute(ctx, w, state); err != nil {
		return nil
	}
	calls := w.faulty.Calls()[before:]
	seen := make(map[string]bool, len(calls))
	var out []string
	for _, c := range calls {
		if !seen[c.Method] {
			seen[c.Method] = true
			out = append(out, c.Method)
		}
	}
	return out
}

// runCanaryLeakCheck builds one fresh world, runs op's Setup unfaulted, arms
// fault (nil for the baseline run), executes, and scans every channel for
// every knownSecretValueLiterals needle (plus any extraNeedles the caller
// folds in).
func runCanaryLeakCheck(t *testing.T, op operation, fault *faultstorage.FaultSpec, logBuf *lockedLogBuffer, extraNeedles ...string) {
	t.Helper()
	ctx := context.Background()
	w := newFaultWorld(t, nil)

	var state any
	var err error
	if op.Setup != nil {
		state, err = op.Setup(ctx, w)
		if err != nil {
			t.Skipf("op setup itself errored — not a leak finding: %v", err)
		}
	}
	drainAllBackgroundGoroutines()
	beforeMaxID := maxAuditEventID(w)
	logOffset := logBuf.len()

	if fault != nil {
		w.faulty.Arm(fault)
	}

	result := mustExecuteRecoveringPanics(t, func() (opResult, error) {
		return op.Execute(ctx, w, state)
	})
	drainAllBackgroundGoroutines()

	needles := make([]string, 0, (len(knownSecretValueLiterals)+len(extraNeedles))*4)
	for _, lit := range knownSecretValueLiterals {
		needles = append(needles, canaryNeedles(lit)...)
	}
	for _, v := range extraNeedles {
		needles = append(needles, canaryNeedles(v)...)
	}

	metrics, mErr := scrapeMetrics(ctx, w)
	if mErr != nil {
		t.Logf("scraping /metrics for %q: %v (not itself a leak finding)", op.Key, mErr)
	}

	label := fmt.Sprintf("op=%s", op.Key)
	if fault != nil {
		label = fmt.Sprintf("%s fault=%s#%d/%s", label, fault.Method, fault.NthCall, fault.Kind)
	}
	scanLeakChannels(t, label, needles, result.Detail, logBuf.since(logOffset), metrics, auditTextSince(w, beforeMaxID))
}

func TestCanaryLeakAcrossSecretOperations(t *testing.T) {
	ops := secretTouchingOps()
	if len(ops) == 0 {
		t.Fatal("no secret-touching operations found in opCatalog — has the catalog's naming convention changed?")
	}
	logBuf := redirectLog(t)

	for _, op := range ops {
		t.Run(strings.ReplaceAll(op.Key, " ", "_"), func(t *testing.T) {
			t.Run("no-fault", func(t *testing.T) {
				runCanaryLeakCheck(t, op, nil, logBuf)
			})

			methods := distinctCallMethods(t, op)
			if len(methods) == 0 {
				t.Skip("no storage.Storage calls observed on an unfaulted dry run — nothing to fault")
			}
			targets := []string{methods[0]}
			if last := methods[len(methods)-1]; last != targets[0] {
				targets = append(targets, last)
			}
			for _, method := range targets {
				for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
					method, kind := method, kind
					t.Run(fmt.Sprintf("%s_%s", method, kind), func(t *testing.T) {
						runCanaryLeakCheck(t, op, &faultstorage.FaultSpec{
							Method: method, NthCall: 1, Kind: kind, Err: errFuzzInjected,
						}, logBuf)
					})
				}
			}
		})
	}
}

// FuzzCanaryLeakUnderFault is item (b): fault-injected fuzzing over the same
// secret-touching op set as TestCanaryLeakAcrossSecretOperations, as a
// standalone Fuzz entrypoint — see the package doc comment above for why
// this is deliberately not wired into FuzzStorageFaultOperations instead.
func FuzzCanaryLeakUnderFault(f *testing.F) {
	ops := secretTouchingOps()
	if len(ops) == 0 {
		f.Skip("no secret-touching operations in opCatalog")
	}
	methods := storageInterfaceMethodNames()
	if len(methods) == 0 {
		f.Skip("no storage.Storage methods found via reflection")
	}
	for i := range ops {
		f.Add(uint8(i), uint8(0), uint8(0), uint8(faultstorage.KindError))
	}
	logBuf := redirectLog(f)

	kinds := []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}
	f.Fuzz(func(t *testing.T, opSel, methodHi, methodLo, kindSel uint8) {
		op := ops[int(opSel)%len(ops)]
		methodIdx := (int(methodHi)<<8 | int(methodLo)) % len(methods)
		kind := kinds[int(kindSel)%len(kinds)]
		runCanaryLeakCheck(t, op, &faultstorage.FaultSpec{
			Method: methods[methodIdx], NthCall: 1, Kind: kind, Err: errFuzzInjected,
		}, logBuf)
	})
}
