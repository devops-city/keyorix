// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// REST POST /api/v1/auth/webauthn/register/finish, DeleteSessionsForUserExcept:
	// the "Related" finding from the same #2835 sweep — the purge itself
	// failing (not the keep-session lookup widening scope) at a DIFFERENT op
	// reaching the identical deleteSessionsForUserAndEvict choke point
	// (webauthn.go's own post-registration session purge). Same tradeoff,
	// same fix, different op string — scoped per-op like its mfa/disable
	// sibling above, not a blanket bestEffortTables entry, for the same
	// reason (DeleteSessionsForUserExcept is load-bearing elsewhere).
	registerOpScopedBestEffort("post_auth_webauthn_register_finish_deletesessionsforuserexcept", opScopedBestEffortTable{
		op: "REST POST /api/v1/auth/webauthn/register/finish", method: "DeleteSessionsForUserExcept", tables: []string{"Session", "AuditEvent"},
		requireLogSubstring: "deleteSessionsForUserAndEvict failed to purge sessions for user",
	})
}
