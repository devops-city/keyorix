// replay_test.go: a saved failing input must be triage-able standalone, per
// RULES ("the harness prints the decoded operation list, principals and fault
// schedule as readable lines... Add a -run replay test that takes a saved
// input and prints that trace").
//
// Go's native fuzz corpus files under testdata/fuzz/FuzzStorageFaultOperations/
// already replay automatically on a plain `go test ./server/faultops/...`
// (Go's fuzzing runtime treats every corpus entry as a regular subtest, no
// -fuzz flag needed) — so reproducibility itself doesn't need new machinery.
// What's missing is a READABLE trace of what a given input decodes to; this
// file adds that, plus a standalone replay entrypoint for a specific saved
// input independent of the full seed/corpus run.
//
// No delta-minimizer beyond Go's own built-in byte-level corpus minimizer
// (`go test -fuzz=FuzzStorageFaultOperations -fuzzminimizetime=...`): this
// harness's fuzz input is a single (op, method, NthCall, kind) tuple, not a
// multi-op sequence — there is no "drop one operation and keep the shortest
// failing list" to do at this input shape. RULES' minimizer requirement
// targets a multi-op sequence; if/when this harness grows to fuzz sequences
// of operations (STEP 0's documented follow-up), a real operation-dropping
// minimizer belongs here.
package faultops

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// traceFuzzOp renders data's decoded meaning as a readable, single-line trace:
// which operation, which storage method/call-count/fault-kind, exactly what
// RULES asks the harness to print on every run so a saved failure is
// self-describing without re-deriving the decode logic by hand.
func traceFuzzOp(data []byte) string {
	decoded, ok := decodeFuzzOpAny(data)
	if !ok {
		return fmt.Sprintf("input=%x -> undecodable (empty catalog/method list)", data)
	}
	op := opCatalog[decoded.opIndex]
	return fmt.Sprintf("input=%x -> op=%q fault=(method=%s, NthCall=%d, kind=%s) principal=admin (bootstrapped)",
		data, op.Key, decoded.methodName, decoded.nthCall, decoded.kind)
}

// TestReplayStorageFaultInput replays ONE saved input, given as a hex string
// in REPLAY_HEX, with full readable tracing — for triaging a specific
// corpus/crasher file in isolation without running the whole seed/corpus set.
// Usage: REPLAY_HEX=0001020304 go test ./server/faultops/... -run TestReplayStorageFaultInput -v
func TestReplayStorageFaultInput(t *testing.T) {
	hexInput := os.Getenv("REPLAY_HEX")
	if hexInput == "" {
		t.Skip("set REPLAY_HEX=<hex-encoded fuzz input bytes> to replay a specific saved input")
	}
	data, err := hex.DecodeString(hexInput)
	if err != nil {
		t.Fatalf("REPLAY_HEX is not valid hex: %v", err)
	}
	t.Log(traceFuzzOp(data))
	t.Run("fresh", func(t *testing.T) { runOneFuzzIteration(t, data) })
	// The fuzz loop runs inputs through reused worlds (world_reuse_test.go).
	// resetForReuse rebuilds the core and wipes the DB, so the two paths should
	// agree; replaying both makes a disagreement visible during triage.
	t.Run("reused", func(t *testing.T) {
		ref := buildReusableFaultWorld(t, nil)
		w := buildReusableFaultWorld(t, nil)
		runOneFuzzIterationWithWorlds(t, data, ref, w, nil)
	})
}
