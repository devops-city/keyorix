// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerSecretNodesRawSQLAllow("internal/storage/store/local_secrets.go:RestoreProject", secretNodesRawSQLAllowEntry{
		reason: "Restore path: `UPDATE secret_nodes SET purge_at = NULL ... AND secret_nodes.deleted_at >= ?` selects exactly the soft-deleted children of this project's delete cascade (deleted_at at or after the cascade timestamp), clearing their frozen purge date before the Unscoped un-delete. A deleted_at IS NULL predicate would match nothing.",
	})
}
