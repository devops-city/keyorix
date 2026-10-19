package guards

import "testing"

// TestUserProfileWrites_AreColumnScoped pins the #2653/#2654 fix structurally:
// UpdateUser (admin edit) and UpdateOwnProfile (self-service edit) must persist
// only the profile columns they own, through
// LocalStorage.UpdateUserIfActiveStateMatches's column-scoped conditional
// UPDATE — never the full pre-read row, which reverted a concurrent
// SuspendUser / ChangePassword / MFA / lockout write. The Postgres race tests
// (TestCTAReview_UpdateUser_vs_SuspendUser_CrossReplicaPostgres,
// TestCTAReview_UpdateOwnProfile_vs_ChangePassword_CrossReplicaPostgres) prove
// the behaviour where a DSN exists; this runs everywhere.
//
// Hops checked: UpdateOwnProfile -> c.UpdateUser (core) ->
// storage/tx.UpdateUserIfActiveStateMatches -> its LocalStorage body. It does
// not check SCIM's callers of the same storage method (they get the same
// column scoping from the storage body, which is what this asserts).
func TestUserProfileWrites_AreColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../../storage/store/local_users.go", "UpdateUserIfActiveStateMatches")
	assertCoreWritesOnlyVia(t, "../users.go", "UpdateUser", "tx", "UpdateUserIfActiveStateMatches", "UpdateUser", "Save")
	assertCoreWritesOnlyVia(t, "../account.go", "UpdateOwnProfile", "c", "UpdateUser", "UpdateUser", "Save", "UpdateUserIfActiveStateMatches")
}
