// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerEffectThenErrorExclusion("post_dynamic_secrets_leases_leaseid_revoke_logauditevent", effectThenErrorExclusion{op: "REST POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke", method: "LogAuditEvent", columns: map[string][]string{"DynamicSecretLease": {"RevokeError"}}})
}
