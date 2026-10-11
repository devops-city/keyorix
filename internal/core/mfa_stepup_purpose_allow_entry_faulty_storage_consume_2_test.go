// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerMFAStepUpPurposeAllow("internal/faultstorage/faulty_storage_generated.go:(*FaultyStorage).ConsumeMFAStepUpGrant:w.real.ConsumeMFAStepUpGrant#2", mfaStepUpAllowEntry{
		expectedPurpose: "",
		reason:          "see the (*FaultyStorage).ConsumeMFAStepUpGrant entry above — the second (KindEffectThenError) call to the real ConsumeMFAStepUpGrant inside the same generated wrapper method, same pass-through reasoning.",
	})
}
