// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// ORPHAN-2 (#2844 triage class D). FinishWebAuthnLogin's ambient
	// MFAStepUpGrant is written AFTER the session, under besteffort.Run, and is
	// best-effort by design: docs/atomicity-exempt.tsv's
	// (*KeyorixCore).FinishWebAuthnLogin row ("trailing
	// UpsertMFAStepupToken/CreateMFAStepUpGrant are best-effort UX convenience
	// post-mint"), internal/core/webauthn.go's own comment ("Best-effort.
	// ... Panic-safe as well as error-tolerant", #2844). When that write errors
	// or panics, the login is still delivered, and the run differs from the
	// fault-free reference ONLY by the missing grant row. Losing it costs the
	// user a later step-up prompt for a restricted secret, never access.
	// requireLogSubstring ties the exemption to besteffort.Run having actually
	// absorbed THIS step (both its error and its panic log lines contain it).
	registerOpScopedBestEffort("post_auth_webauthn_login_finish_createmfastepupgrant", opScopedBestEffortTable{
		op: "REST POST /auth/webauthn/login/finish", method: "CreateMFAStepUpGrant", tables: []string{"MFAStepUpGrant"},
		requireLogSubstring: `best-effort step "webauthn.FinishWebAuthnLogin.CreateMFAStepUpGrant"`,
		pinnedKinds:         []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic},
	})
}
