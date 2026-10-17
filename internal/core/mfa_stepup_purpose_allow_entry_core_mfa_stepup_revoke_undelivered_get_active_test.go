// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerMFAStepUpPurposeAllow("internal/core/mfa_stepup.go:(*KeyorixCore).revokeUndeliveredStepUpGrant:c.storage.GetActiveMFAStepUpGrant", mfaStepUpAllowEntry{
		expectedPurpose: "MFAStepUpPurposeRestrictedSecretRead",
		reason:          "not an authorization decision: it looks up whether the grant a failed step-up write created landed, so it can be revoked (#3277 follow-up). Pinned to the one purpose VerifyMFAStepUp writes, so it can never see a reauth grant.",
	})
}
