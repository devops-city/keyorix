// One file per entry; never append to a shared list. See registry_entries_test.go.
package guards

func init() {
	registerMFAStepUpPurposeAllow("internal/faultstorage/faulty_storage_generated.go:(*FaultyStorage).GetActiveMFAStepUpGrant:w.real.GetActiveMFAStepUpGrant", mfaStepUpAllowEntry{
		expectedPurpose: "",
		reason: "generated, mechanical pass-through (w.real.GetActiveMFAStepUpGrant(...)) inside the same " +
			"test/fuzz-harness-only wrapper — see the (*FaultyStorage).ConsumeMFAStepUpGrant entry's " +
			"reasoning; this is the read-only sibling call, same forwarding shape.",
	})
}
