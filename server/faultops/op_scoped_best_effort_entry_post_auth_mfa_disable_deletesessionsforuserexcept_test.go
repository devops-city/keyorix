// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// REST POST /api/v1/auth/mfa/disable, DeleteSessionsForUserExcept:
	// DisableMFA's own comment ("Best-effort: disable must not fail on a
	// cleanup error.") explicitly discards deleteSessionsForUserAndEvict's
	// error after MFA is already flipped off and the secret/recovery codes
	// already deleted (internal/core/mfa.go, `_ =
	// c.deleteSessionsForUserAndEvict(ctx, userID, 0, "")`) — the security
	// downgrade purging sessions is the control; a purge failure here must
	// not report an already-successful MFA disable as failed. Found live by
	// FuzzStorageFaultOperations (this PR's own newly-wired op). Scoped to
	// this op, not a blanket bestEffortTables entry keyed by method name,
	// since DeleteSessionsForUserExcept IS load-bearing at other call sites
	// (RevokeUserSessions propagates its error as "failed to revoke
	// sessions").
	//
	// #2835: AuditEvent joined this entry's tables, and requireLogSubstring was
	// added, when the purge failure stopped being silent. A plain (non-panic)
	// error from DeleteSessionsForUserExcept now writes EventSessionRevocationFailed
	// (account.go's deleteSessionsForUserAndEvict, the ONE choke point all 8
	// call sites share) instead of vanishing the instant this op's own `_ =
	// c.deleteSessionsForUserAndEvict(...)` discards it. The purge failure
	// itself is still correctly non-fatal to the MFA disable; only its
	// silence was the defect.
	registerOpScopedBestEffort("post_auth_mfa_disable_deletesessionsforuserexcept", opScopedBestEffortTable{
		op: "REST POST /api/v1/auth/mfa/disable", method: "DeleteSessionsForUserExcept", tables: []string{"Session", "AuditEvent"},
		requireLogSubstring: "deleteSessionsForUserAndEvict failed to purge sessions for user",
	})
}
