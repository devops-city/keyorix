// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerMFAStepUpPurposeAllow("internal/core/mfa_stepup.go:(*KeyorixCore).revokeUndeliveredStepUpGrant:c.storage.ConsumeMFAStepUpGrant", mfaStepUpAllowEntry{
		expectedPurpose: "MFAStepUpPurposeRestrictedSecretRead",
		reason:          "not an authorization decision: it ends the grant a failed step-up write created, so a refused step-up leaves no elevation behind (#3277 follow-up). Pinned to MFAStepUpPurposeRestrictedSecretRead: consuming a reauth grant here would end an unrelated, delivered re-authentication.",
	})
}
