// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	// REAL VIOLATION, allowlisted only because the fix is in a login/MFA handler
	// owned by FIX-3277 (INVARIANT-GUARDS-1 brief: do not touch those). Reported
	// under "Needs coordinator" in SESSION-INVARIANT-GUARDS-1.md. Remove this row
	// in the commit that wraps the call in besteffort.Run (as sso.go does).
	registerBestEffortCallAllow("internal/core/mfa_stepup.go:(*KeyorixCore).VerifyMFAStepUp:clearLoginFailures", bestEffortCallAllowEntry{
		reason: "VerifyMFAStepUp calls clearLoginFailures bare AFTER createStepUpGrant committed; sso.go wraps the same call in besteffort.Run: a panic there escapes with a live step-up grant the caller was told failed (the undelivered-grant shape INV-CORE-stepup-grant-delivered-or-absent exists to close). Fix: besteffort.Run(ctx, \"<handler>.clearLoginFailures\", func() error { c.clearLoginFailures(ctx, user); return nil }).",
	})
}
