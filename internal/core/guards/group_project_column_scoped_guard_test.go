package guards

import "testing"

// TestUpdateGroupAndProject_AreColumnScoped pins the #2697 fix structurally, so
// it holds in a DSN-less run too (the three
// TestCTAReview_Update{Group,Project}_vs_* Postgres tests are the behavioural
// proof, and they need real Postgres).
//
// All four entry points are covered, not just the two the issue's title names:
// core.UpdateGroup and both SCIM rename paths reach the same primitive, and the
// SCIM pair is the likelier trigger in practice (an IdP DELETE followed closely
// by a PUT/PATCH), so leaving them unguarded would guard the less exposed half.
//
// The deleted primitives (UpdateGroup / UpdateProject on storage.Storage) are
// named as forbidden even though they no longer exist, so re-adding one — the
// most likely regression, since that is what they were called — turns this red
// rather than merely failing to compile somewhere else.
//
// Hops checked: {core.UpdateGroup, ReplaceSCIMGroup, PatchSCIMGroup} ->
// c.storage.UpdateGroupFields -> its LocalStorage body; core.UpdateProject ->
// c.storage.UpdateProjectFields -> its LocalStorage body.
func TestUpdateGroupAndProject_AreColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../../storage/store/local_users.go", "UpdateGroupFields")
	assertColumnScopedStorageWrite(t, "../../storage/store/local_secrets.go", "UpdateProjectFields")

	assertCoreWritesOnlyVia(t, "../groups.go", "UpdateGroup", "storage", "UpdateGroupFields", "Save", "UpdateGroup")
	for _, fn := range []string{"ReplaceSCIMGroup", "PatchSCIMGroup"} {
		assertCoreWritesOnlyVia(t, "../scim_groups.go", fn, "storage", "UpdateGroupFields", "Save", "UpdateGroup")
	}
	assertCoreWritesOnlyVia(t, "../catalog.go", "UpdateProject", "storage", "UpdateProjectFields", "Save", "UpdateProject")
}
