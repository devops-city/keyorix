// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerSecretNodesRawSQLAllow("internal/storage/store/local_secrets.go:deleteProjectCascade", secretNodesRawSQLAllowEntry{
		reason: "Delete cascade: the `secret_id IN (SELECT id FROM secret_nodes WHERE project_id = ?)` subqueries that revoke the project's SecretACL grants (#2798) and close approved secret-scoped access requests (#2797) must reach the nodes this same cascade just soft-deleted, the same as the ShareRecord revoke beside them. A deleted_at IS NULL predicate would match none of them and leave the grants live for a later RestoreProject.",
	})
}
