// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerOpScopedBestEffort("post_auth_mfa_disable_getsession", opScopedBestEffortTable{
		op: "REST POST /api/v1/auth/mfa/disable", method: "GetSession", tables: []string{"Session", "AuditEvent"},
		requireLogSubstring: "could not resolve the caller's own session",
	})
}
