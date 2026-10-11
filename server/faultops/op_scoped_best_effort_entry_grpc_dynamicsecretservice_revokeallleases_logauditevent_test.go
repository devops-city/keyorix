// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerOpScopedBestEffort("grpc_dynamicsecretservice_revokeallleases_logauditevent", opScopedBestEffortTable{op: "GRPC keyorix.v1.DynamicSecretService.RevokeAllLeases", method: "LogAuditEvent", tables: []string{"DynamicSecretLease", "AuditEvent"}})
}
