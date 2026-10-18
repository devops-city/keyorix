package core

import "testing"

// TestUpdateSharePermission_ClassifiesFromALockedRead pins SHARE-CAS-1
// structurally, on every backend: inside its transaction UpdateSharePermission
// reads the share it classifies through tx.LockShareRecordForUpdate (FOR UPDATE
// on PostgreSQL), before tx.UpdateShareRecord, and never through an unlocked
// tx.GetShareRecord. A plain in-transaction read locks nothing under READ
// COMMITTED, so a concurrent narrowing could commit between the classification
// and the write. The receiver must be tx: the same call on c.storage runs
// outside the transaction and its lock ends with the statement.
//
// What it does not check: that the lock is taken by the storage (that is
// TestLockShareRecordForUpdate_DialectMatchedLocking in internal/storage/store)
// or that it serializes two replicas (the pg-gated
// TestCTAReview_UpdateSharePermission_*VsConcurrent*_CrossReplicaPostgres).
func TestUpdateSharePermission_ClassifiesFromALockedRead(t *testing.T) {
	lockAt, updateAt := -1, -1
	for i, c := range columnScopedFuncCalls(t, "sharing.go", "KeyorixCore", "UpdateSharePermission") {
		switch {
		case c.Recv == "tx" && c.Name == "GetShareRecord":
			t.Errorf("UpdateSharePermission reads the share with tx.GetShareRecord: an unlocked read cannot hold its classification until the write")
		case c.Recv == "tx" && c.Name == "LockShareRecordForUpdate" && lockAt < 0:
			lockAt = i
		case c.Recv == "tx" && c.Name == "UpdateShareRecord" && updateAt < 0:
			updateAt = i
		}
	}
	if lockAt < 0 {
		t.Fatalf("UpdateSharePermission no longer calls tx.LockShareRecordForUpdate: its classification read is not locked")
	}
	if updateAt < 0 {
		t.Fatalf("UpdateSharePermission no longer calls tx.UpdateShareRecord: update this guard with the new write")
	}
	if lockAt > updateAt {
		t.Errorf("tx.LockShareRecordForUpdate runs after tx.UpdateShareRecord: the classification read must come first")
	}
}
