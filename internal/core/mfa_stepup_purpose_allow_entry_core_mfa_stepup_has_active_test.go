// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerMFAStepUpPurposeAllow("internal/core/mfa_stepup.go:(*KeyorixCore).HasActiveMFAStepUp:c.storage.GetActiveMFAStepUpGrant", mfaStepUpAllowEntry{
		expectedPurpose: "",
		reason: "HasActiveMFAStepUp's own implementation: forwards the `purpose` PARAMETER it was called " +
			"with straight through to storage.GetActiveMFAStepUpGrant. This is the shared primitive, not a " +
			"consumer -- it has no fixed purpose of its own to hardcode. Enforcement responsibility sits " +
			"with HasActiveMFAStepUp's own callers, which this same allowlist enumerates separately " +
			"(currently none outside this function).",
	})
}
