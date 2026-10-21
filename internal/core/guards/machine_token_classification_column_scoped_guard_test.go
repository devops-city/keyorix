package guards

import "testing"

// TestClassifyMachineToken_IsColumnScoped pins the #2696 fix structurally, the
// way TestUpdateSharePermission_IsColumnScoped pins #2648's: both classify
// entry points must persist through
// LocalStorage.SetMachineIdentityCredentialClassification, a conditional
// column-scoped UPDATE, and neither may reach a full-row writer again. The
// Postgres race test
// (TestCTAReview_ClassifyMachineToken_vs_RevokeMachineToken_CrossReplicaPostgres)
// proves the behaviour where a DSN exists; this runs everywhere, including the
// DSN-less default CI leg.
//
// `UpdateMachineIdentityCredential` is listed as forbidden even though the
// method no longer exists on storage.Storage — so that re-adding it (the most
// likely way this regresses, since it is what the deleted primitive was called)
// turns this red rather than merely failing to compile somewhere else.
//
// Hops checked: ClassifyMachineToken / ClassifyMachineTokenByID ->
// c.storage.SetMachineIdentityCredentialClassification -> its LocalStorage body.
func TestClassifyMachineToken_IsColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../../storage/store/local_machine_credentials.go", "SetMachineIdentityCredentialClassification")
	// AUDIT-TX-3: ClassifyMachineToken writes through its audited transaction's handle.
	for fn, recv := range map[string]string{"ClassifyMachineToken": "tx", "ClassifyMachineTokenByID": "storage"} {
		assertCoreWritesOnlyVia(t, "../machine_token.go", fn, recv,
			"SetMachineIdentityCredentialClassification", "Save", "UpdateMachineIdentityCredential")
	}
}
