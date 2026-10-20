// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerSecretNodesRawSQLAllow("internal/storage/store/local_purge_secret_refs.go:<package-level>", secretNodesRawSQLAllowEntry{
		reason: "PurgeParentSecretNode is a label naming which purged id a cascaded column holds (secret_nodes.id), not a query. Purge hard-deletes secret_nodes rows that are ALREADY soft-deleted (PurgeDeletedSecretsBefore selects on deleted_at), so reaching them is the point. Covers every package-level literal in this file.",
	})
}
