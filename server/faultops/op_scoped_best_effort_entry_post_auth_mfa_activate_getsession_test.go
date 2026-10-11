// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// REST POST /api/v1/auth/mfa/activate, /mfa/disable, /change-password, GetSession:
	// ActivateMFA, DisableMFA, and ChangePassword each resolve the caller's own
	// session (via keepSessionToken) so their post-change session purge can spare
	// it. #2835: when that lookup fails, the purge deliberately still widens to
	// include the caller's own session (the correct fail-closed fallback — we
	// cannot prove which session is the caller's, so revoking all of them is
	// safer than guessing; see resolveKeepSession's doc comment, account.go) —
	// unchanged by this fix. What changed is that the widening now writes
	// EventKeepSessionLookupFailed instead of vanishing silently, so AuditEvent
	// joins the pre-existing Session-only diff. requireLogSubstring ties this to
	// evidence the reviewed fallback actually fired, not to the diff shape alone
	// (same discipline as the WithTransaction entry below).
	registerOpScopedBestEffort("post_auth_mfa_activate_getsession", opScopedBestEffortTable{
		op: "REST POST /api/v1/auth/mfa/activate", method: "GetSession", tables: []string{"Session", "AuditEvent"},
		requireLogSubstring: "could not resolve the caller's own session",
	})
}
