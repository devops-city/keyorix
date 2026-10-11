// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// ReleaseLoginAttempt (#2936): a request that delivers a session returns its
	// reserved per-IP login-budget slot (server/http/handlers/auth.go
	// returnLoginSlot) through core.ReleaseLoginAttempt, which is explicitly
	// best-effort (besteffort.Run: an error OR a panic is logged, counted and
	// swallowed). The login itself has already succeeded; a failed release only
	// leaves that one LoginAttempt row counted -- the stricter side of the
	// budget, never a looser one. So when the faulted method is the release
	// itself, the run differs from the fault-free reference by exactly that
	// row and nothing else. Method-scoped: a LoginAttempt divergence caused by
	// any OTHER faulted method is not covered here. A method-only entry is
	// sound because the method is best-effort at EVERY call site: the only
	// storage.ReleaseLoginAttempt caller is core.ReleaseLoginAttempt
	// (rate_limit.go), and every handler release (auth.go returnLoginSlot,
	// mfa.go, webauthn.go -- including the pre-verdict CR3/#2565 releases)
	// goes through it.
	registerBestEffortTable("ReleaseLoginAttempt", []string{"LoginAttempt"})
}
