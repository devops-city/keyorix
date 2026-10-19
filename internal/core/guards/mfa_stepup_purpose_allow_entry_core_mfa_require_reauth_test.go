// One file per entry; never append to a shared list. See registry_entries_test.go.
package guards

func init() {
	registerMFAStepUpPurposeAllow("internal/core/mfa.go:(*KeyorixCore).requireReauth:c.storage.ConsumeMFAStepUpGrant", mfaStepUpAllowEntry{
		expectedPurpose: "MFAStepUpPurposeReauth",
		reason: "requireReauth's account-security-factor-change gate (DisableMFA, " +
			"RegenerateMFARecoveryCodes, ActivateMFA, WebAuthn credential register/delete, email change). " +
			"Must reject the ambient MFAStepUpPurposeRestrictedSecretRead grant a plain login mints -- " +
			"accepting it here is the exact confused-deputy shape this fix closed (a leaked bearer token " +
			"plus the password would otherwise ride the account owner's own earlier login into an " +
			"account takeover). Now calls the atomic-consume ConsumeMFAStepUpGrant instead of the " +
			"read-only HasActiveMFAStepUp (single-use reauth grant fix, follow-up to #1775) -- accepting " +
			"the grant here also invalidates it, so it cannot go on to authorize a second, different " +
			"sensitive action within the same window.",
	})
}
