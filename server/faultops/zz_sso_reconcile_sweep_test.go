package faultops

import (
	"fmt"
	"os"
	"testing"
)

// TestSSOReconcileFaultSweep (#2910) is FuzzStorageFaultOperations' own
// iteration body and oracles, run EXHAUSTIVELY over the two SSO login ops:
// every storage method × NthCall 1..5 × every fault kind. It does not sample.
// The fuzzer's byte layout picks the op as data[0] % len(opCatalog), so with
// about 300 ops a random run reaches these two rarely, and reaches them with a
// method their reconcile actually calls more rarely still. A sweep makes "the
// fuzzer ran over SSO reconcile" a statement about every input, not a sample.
//
// Opt-in (KEYORIX_FAULTOPS_SSO_SWEEP=1): it runs every input of 418 methods ×
// 5 × 3 per op, a few minutes in total. Inputs whose fault never fires return
// right after Execute, exactly as in the fuzzer.
//
//	KEYORIX_FAULTOPS_SSO_SWEEP=1 go test ./server/faultops/ -run TestSSOReconcileFaultSweep -timeout 60m
//
// Each input is a subtest named by its REPLAY_HEX, so a violation replays with
// TestReplayStorageFaultInput.
func TestSSOReconcileFaultSweep(t *testing.T) {
	if os.Getenv("KEYORIX_FAULTOPS_SSO_SWEEP") != "1" {
		t.Skip("set KEYORIX_FAULTOPS_SSO_SWEEP=1 to sweep every storage fault over the SSO login ops")
	}
	ops := []string{"REST POST /auth/saml/{provider}/acs", "REST GET /auth/sso/{provider}/callback"}
	methods := storageInterfaceMethodNames()
	ref := buildReusableFaultWorld(t, nil)
	w := buildReusableFaultWorld(t, nil)
	for _, key := range ops {
		opIdx := -1
		for i, op := range opCatalog {
			if op.Key == key {
				opIdx = i
			}
		}
		if opIdx < 0 || opIdx > 255 {
			t.Fatalf("op %q not addressable by one fuzz byte (index %d)", key, opIdx)
		}
		fired := 0
		for mi := range methods {
			for nth := 1; nth <= 5; nth++ {
				for kind := range 3 {
					data := []byte{byte(opIdx), byte(mi >> 8), byte(mi), byte(nth - 1), byte(kind)}
					t.Run(fmt.Sprintf("%x", data), func(t *testing.T) {
						runOneFuzzIterationWithWorlds(t, data, ref, w, func(oracleInput) { fired++ })
					})
				}
			}
		}
		t.Logf("SWEEP %s: %d of %d inputs fired a fault and were checked by the oracles", key, fired, len(methods)*5*3)
	}
}
