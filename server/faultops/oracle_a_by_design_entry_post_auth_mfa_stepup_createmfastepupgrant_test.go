// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	registerOracleAByDesign("post_auth_mfa_stepup_createmfastepupgrant", oracleAByDesignError{
		op:     "REST POST /api/v1/auth/mfa/stepup",
		method: "CreateMFAStepUpGrant",
		kind:   faultstorage.KindError,
		nth:    1,
		tables: []string{"MFASecret"},
		// #2894 review: the post-verdict denial is now audited mfa.error (it used
		// to go unaudited), the same outcome log the login rows below carry.
		outcomeLogs: []string{"AuditEvent"},
		designComment: "internal/core/mfa_stepup.go: VerifyMFAStepUp consumes the TOTP step " +
			"(advancing MFASecret's replay window) BEFORE minting the step-up grant, and fails " +
			"closed if the grant write fails",
		provingTest: "internal/core/TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed",
		why: "The consume is not a side effect of the grant — it is the single-use enforcement. " +
			"Rolling it back when CreateMFAStepUpGrant fails would hand the caller a code that is " +
			"still valid, so a caller who can induce a storage failure could replay one TOTP code " +
			"indefinitely. The reported ERROR is correct (no grant was issued, so no elevated " +
			"action is authorized), and MFASecret's advance is the security property, not a " +
			"partial commit. Previously carried as a knownOpenTolerance citing #2549, which " +
			"mis-labelled intended behaviour as a filed-but-unfixed bug and so guaranteed " +
			"perpetual re-filing at each expiry.",
	})
}
