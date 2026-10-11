// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// LogAuditEvent: internal/core/service.go's emitAudit (the SINGLE choke
	// point every c.Log*/writeAuditEvent* helper funnels through) calls
	// c.storage.LogAuditEvent and, on failure, its own comment says so
	// explicitly: "Surface it loudly instead of swallowing" — loudly means a
	// log.Printf("SECURITY: failed to persist audit event ...") line, NOT an
	// error return; every c.Log* audit helper (LogRoleUpdated,
	// LogPermissionAssigned, etc.) has a bare `error`-less signature, so this
	// is a repo-wide, architectural guarantee that an audit-write failure
	// never fails the primary operation it's recording — not something
	// specific to UpdateRole or any other single caller. FLAG FOR REVIEW: the
	// comment itself already names the accepted gap ("A failed chain-write is
	// an audit gap that VerifyAuditChain cannot detect") — a SEPARATE,
	// already-existing subsystem's job, not something this task should
	// re-litigate.
	registerBestEffortTable("LogAuditEvent", []string{"AuditEvent"})
}
