// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerOpScopedBestEffort("post_dynamic_secrets_leases_leaseid_revoke_logauditevent", opScopedBestEffortTable{op: "REST POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke", method: "LogAuditEvent", tables: []string{"DynamicSecretLease", "AuditEvent"}})
}
