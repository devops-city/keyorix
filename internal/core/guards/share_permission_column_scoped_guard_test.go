package guards

import "testing"

// TestUpdateSharePermission_IsColumnScoped pins the #2648 fix structurally:
// UpdateSharePermission persists through LocalStorage.UpdateShareRecord, which
// must issue a conditional, column-scoped UPDATE (permission, expires_at,
// updated_at, scoped to deleted_at IS NULL) and never GORM Save — whose upsert
// fallback resurrected a concurrently revoked share. The Postgres race test
// (TestCTAReview_UpdateSharePermission_vs_RevokeShare_CrossReplicaPostgres)
// proves the behaviour where a DSN exists; this runs everywhere.
//
// Hops checked: UpdateSharePermission -> tx.UpdateShareRecord (the transaction
// that also carries its audit row, AUDIT-TX-2) -> its LocalStorage body.
func TestUpdateSharePermission_IsColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../../storage/store/local_sharing.go", "UpdateShareRecord")
	assertCoreWritesOnlyVia(t, "../sharing.go", "UpdateSharePermission", "tx", "UpdateShareRecord", "Save", "CreateShareRecord")
}
