package faultops

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestOpFaultSweep is TestSSOReconcileFaultSweep for any ops: the fuzzer's own
// iteration body and oracles, run EXHAUSTIVELY (every storage method × NthCall
// 1..5 × every fault kind) over the opCatalog keys named in
// KEYORIX_FAULTOPS_SWEEP_OPS, separated by ";". The fuzzer picks the op from
// one byte of ~300, so a change to one op's write path is reached by a random
// run rarely; a sweep checks every input. Opt-in, a few minutes per op:
//
//	KEYORIX_FAULTOPS_SWEEP_OPS='REST POST /api/v1/auth/change-password' \
//	  go test ./server/faultops/ -run TestOpFaultSweep -timeout 60m
//
// Each input is a subtest named by its REPLAY_HEX, so a violation replays with
// TestReplayStorageFaultInput. Used for AUTH-2 (change-password, profile, setup
// consume).
func TestOpFaultSweep(t *testing.T) {
	spec := os.Getenv("KEYORIX_FAULTOPS_SWEEP_OPS")
	if spec == "" {
		t.Skip("set KEYORIX_FAULTOPS_SWEEP_OPS to the opCatalog keys to sweep (separated by ';')")
	}
	methods := storageInterfaceMethodNames()
	ref := buildReusableFaultWorld(t, nil)
	w := buildReusableFaultWorld(t, nil)
	for key := range strings.SplitSeq(spec, ";") {
		key = strings.TrimSpace(key)
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
