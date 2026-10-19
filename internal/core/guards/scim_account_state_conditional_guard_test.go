package guards

import "testing"

// TestSCIMAccountStateWrites_AreConditional pins C-RACE-FIX-B2 structurally:
// the two SCIM lifecycle writers derive their new account_state from the one
// they read, so they must persist it through the conditional
// SetAccountStateIfMatches (WHERE account_state = <pre-read value>), never the
// blind SetAccountState, which would revert a SuspendUser that committed after
// their read. The pg-gated
// TestCTAReview_SCIM_vs_SuspendUser_WithoutRowLock_CrossReplicaPostgres proves
// the behaviour; this runs everywhere.
//
// Hops checked: scimUpdateUserTx (UpdateSCIMUser's transaction body) and
// DeprovisionSCIMUser, each a single function body. It does not check any other
// SetAccountState caller (setAccountState, account.go, recover_admin): those
// set a state that does not depend on the one they read.
func TestSCIMAccountStateWrites_AreConditional(t *testing.T) {
	for _, fn := range []string{"scimUpdateUserTx", "DeprovisionSCIMUser"} {
		assertCoreWritesOnlyVia(t, "../scim.go", fn, "tx", "SetAccountStateIfMatches", "SetAccountState", "UpdateUser", "Save")
	}
}
