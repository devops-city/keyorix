// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerMFAStepUpPurposeAllow("internal/faultstorage/faulty_storage_generated.go:(*FaultyStorage).ConsumeMFAStepUpGrant:w.real.ConsumeMFAStepUpGrant", mfaStepUpAllowEntry{
		expectedPurpose: "",
		reason: "generated, mechanical pass-through (w.real.ConsumeMFAStepUpGrant(...)) inside a " +
			"test/fuzz-harness-only storage.Storage wrapper (server/faultops's FuzzStorageFaultOperations) " +
			"— forwards whatever purpose argument the real caller already hardcoded, unmodified. The real " +
			"call site making the authorization decision is whatever separately-guarded internal/core " +
			"function invoked it; this line is one hop further down, at the storage interface, and never " +
			"itself chooses or inspects the purpose value.",
	})
}
