package guards

import "testing"

// TestSetSecretAutoRotate_IsColumnScoped pins the #2650 fix structurally:
// SetSecretAutoRotate must persist through
// LocalStorage.UpdateSecretRotationConfig — a conditional UPDATE of only the
// rotation columns, re-asserting the live row, its project and its pre-read
// rotation backend — and never UpdateSecret's full-row Save, whose upsert
// fallback undeleted a concurrently deleted secret and reverted concurrent
// binding/ownership changes. The Postgres race test
// (TestCTAReview_SetSecretAutoRotate_vs_DeleteSecret_CrossReplicaPostgres)
// proves the behaviour where a DSN exists; this runs everywhere.
//
// Hops checked: SetSecretAutoRotate -> c.storage.UpdateSecretRotationConfig ->
// its LocalStorage body.
func TestSetSecretAutoRotate_IsColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../../storage/store/local_secrets.go", "UpdateSecretRotationConfig")
	assertCoreWritesOnlyVia(t, "../rotation_executor.go", "SetSecretAutoRotate", "storage", "UpdateSecretRotationConfig", "UpdateSecret", "Save", "TransitionSecretStatus")
}
