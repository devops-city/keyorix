// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerOpScopedBestEffort("post_dynamic_secrets_configs_id_revoke_all_logauditevent", opScopedBestEffortTable{op: "REST POST /api/v1/dynamic-secrets/configs/{id}/revoke-all", method: "LogAuditEvent", tables: []string{"DynamicSecretLease", "AuditEvent"}})
}
