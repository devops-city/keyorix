// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerSecretNodesRawSQLAllow("internal/storage/store/secret_node_cache_epoch.go:<package-level>", secretNodesRawSQLAllowEntry{
		reason: "DDL, not row access: sqliteCacheEpochTriggerSQL is the exact text of the cache_epoch trigger (its body UPDATEs the row by id after any update). The trigger must fire for every row, soft-deleted or not, so the generation signal stays monotonic. Covers every package-level literal in this file.",
	})
}
