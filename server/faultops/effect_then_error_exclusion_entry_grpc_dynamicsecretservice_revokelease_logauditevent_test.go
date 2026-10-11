// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerEffectThenErrorExclusion("grpc_dynamicsecretservice_revokelease_logauditevent", effectThenErrorExclusion{op: "GRPC keyorix.v1.DynamicSecretService.RevokeLease", method: "LogAuditEvent", columns: map[string][]string{"DynamicSecretLease": {"RevokeError"}}})
}
