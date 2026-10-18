// One file per entry; never append to a shared list. See registry_entries_test.go.
package guards

func init() {
	registerMFAStepUpPurposeAllow("internal/faultstorage/faulty_storage_generated.go:(*FaultyStorage).GetActiveMFAStepUpGrant:w.real.GetActiveMFAStepUpGrant#2", mfaStepUpAllowEntry{
		expectedPurpose: "",
		reason:          "see the (*FaultyStorage).GetActiveMFAStepUpGrant entry above — the second (KindEffectThenError) call to the real GetActiveMFAStepUpGrant inside the same generated wrapper method, same pass-through reasoning.",
	})
}
