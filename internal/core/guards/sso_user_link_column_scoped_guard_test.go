package guards

import "testing"

// TestResolveSSOUser_ClaimIsColumnScopedAndReReads pins both halves of the
// #2699 fix structurally, so they hold in a DSN-less run too
// (TestCTAReview_ResolveSSOUser_vs_DeleteUser_CrossReplicaPostgres is the
// behavioural proof, and it needs real Postgres).
//
//	(1) the claim writes external_id alone, through a conditional UPDATE, and
//	    resolveSSOUser never reaches UpdateUser (the full-row Save whose upsert
//	    fallback resurrected a deleted account) or a bare Save again;
//	(2) resolveSSOUser re-reads the user through storage.GetUser.
//
// (2) is asserted separately on purpose: it is the half that stops a session
// being minted. Without the re-read, resolveSSOUser hands CompleteSSO's login
// gate the pre-claim snapshot — which still says is_active/active — so a
// deleted or suspended account logs in even once the row itself is correctly
// left alone. A guard on the write shape alone would certify half a fix.
//
// Hops checked: resolveSSOUser -> c.storage.ClaimUserExternalIDIfUnset -> its
// LocalStorage body; resolveSSOUser -> c.storage.GetUser.
func TestResolveSSOUser_ClaimIsColumnScopedAndReReads(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../../storage/store/local_users.go", "ClaimUserExternalIDIfUnset")
	assertCoreWritesOnlyVia(t, "../sso.go", "resolveSSOUser", "storage", "ClaimUserExternalIDIfUnset", "Save", "UpdateUser")
	assertCoreWritesOnlyVia(t, "../sso.go", "resolveSSOUser", "storage", "GetUser", "Save", "UpdateUser")
}
