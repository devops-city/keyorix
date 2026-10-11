// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerMFAStepUpPurposeAllow("internal/core/classification_gate.go:(*KeyorixCore).checkRestrictedMFAGate:c.storage.GetActiveMFAStepUpGrant", mfaStepUpAllowEntry{
		expectedPurpose: "MFAStepUpPurposeRestrictedSecretRead",
		reason: "checkRestrictedMFAGate, the classification_restricted_requires_mfa_stepup gate for " +
			"reading a ClassificationRestricted secret's value. Must reject a MFAStepUpPurposeReauth grant " +
			"(minted only for account-security changes) -- the two purposes must never satisfy each other.",
	})
}
