// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	registerSecretNodesRawSQLAllow("internal/storage/store/secret_suspend_marker_trigger.go:EnsureSecretSuspendMarkerTrigger", secretNodesRawSQLAllowEntry{
		reason: "Postgres trigger DDL plus a one-time maintenance UPDATE, not a row reader: the UPDATE clears suspend_clear_synced_copies on every row that is not suspended, soft-deleted or not, so a stale marker cannot survive a later restore and make a resume clear synced copies it should not (HA-READY-1, #3362). It must see soft-deleted rows, which the predicate deleted_at IS NULL would hide.",
	})
}
