// owed_audit_oracle_fuzz_test.go -- FuzzOwedAuditRevocations: FuzzStorageFaultOperations
// restricted to the owed-audit rule's scope (owed_audit_oracle_test.go): the SSO
// callback, the plain secret suspend and every op in auditTx3RevocationOps, under a fault
// on LogAuditEvent, ClaimPendingAuditEvent, CreatePendingAuditEvent or WithTransaction
// (the audit-path methods and the owing / settle transactions), call
// ordinal 1-3, any fault kind. It runs the SAME iteration and the SAME oracle as the
// main target (runOneFuzzIterationReporting -> checkOraclesReporting); only the input
// space is narrowed so a short burst spends all of its time on the revocations.
//
// Run: go test ./server/faultops -run '^$' -fuzz '^FuzzOwedAuditRevocations$' -fuzztime 90s
//
// Registered in scripts/fuzzing/targets.d at 30m (the fuzz-targets drift guard requires
// every real FuzzXxx to be declared). The space is small (42 ops x 4 methods x 3 ordinals x 3 kinds)
// and TestOwedAuditOracle_SweepEveryScopedOp (KEYORIX_OWED_SWEEP_WIDE=1) covers it
// exhaustively; this target is for bursts and for finding what the sweep's fixed
// ordinals miss after a change to the audit path.
package faultops

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func FuzzOwedAuditRevocations(f *testing.F) {
	ops := owedAuditScopedOps()
	methods := []string{"LogAuditEvent", "ClaimPendingAuditEvent", "CreatePendingAuditEvent", "WithTransaction"}
	kinds := []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError}
	for i := range ops {
		f.Add([]byte{byte(i), 0, 0, 0})
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			t.Skip("need op, method, ordinal and kind bytes")
		}
		op := ops[int(data[0])%len(ops)]
		method := methods[int(data[1])%len(methods)]
		nth := int(data[2])%3 + 1
		kind := kinds[int(data[3])%len(kinds)]

		opIdx := -1
		for i := range opCatalog {
			if opCatalog[i].Key == op {
				opIdx = i
				break
			}
		}
		methodIdx := -1
		for i, m := range storageInterfaceMethodNames() {
			if m == method {
				methodIdx = i
				break
			}
		}
		if opIdx < 0 || methodIdx < 0 {
			t.Fatalf("op %q (catalog index %d) or method %q (index %d) is not in the harness", op, opIdx, method, methodIdx)
		}
		// The harness's own input encoding (driveFaultCase builds the same bytes).
		runOneFuzzIterationReporting(t, t, []byte{byte(opIdx), byte(methodIdx >> 8), byte(methodIdx), byte(nth - 1), fuzzKindSelector(kind)}, nil, nil, nil)
	})
}
