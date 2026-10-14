// concurrency_child_under_deleted_project_postgres_test.go — #2702, #2710,
// #2711, #2712.
//
// Four writers created or revived a child of a project while serializing only
// against a concurrent DeleteENVIRONMENT — via the EnvironmentSecretGuardLockKey
// named lock and an in-lock environment-existence check — and never against a
// concurrent DeletePROJECT, whose cascade takes no such named lock. It row-locks
// the project and sweeps the project's secrets and environments directly. So the
// entirely legitimate order
//
//	B's cascade locks the project, sweeps the children that exist (A's is not
//	inserted yet), commits
//	A inserts (or un-deletes) its child anyway
//
// left a LIVE child under a deleted project. Same end state as #2656, which was
// fixed for RestoreEnvironment only; this closes the four create/restore
// siblings using the same lockLiveParent write-then-check, now reachable from
// internal/core through the Storage.LockLiveProject method this change adds.
//
// Each test asserts the EFFECT — the count of live children under the deleted
// project — rather than A's returned error, because A is legitimately allowed
// either to fail or to be swept; what it may not do is leave a live child
// behind. That end state is reachable, not merely untidy: GetSecret and
// AuthorizeSecret do not check project liveness, so a global-scope role or an
// ACL grant still reaches the value, and the purge only ever collects
// soft-deleted rows, so the orphan outlives the project purge.
//
// What these DO NOT cover: the opposite interleaving, where A's FOR SHARE lands
// first and B's cascade blocks on it. lockLiveParent's doc comment argues that
// order is safe (the cascade's later statements take a fresh READ COMMITTED
// snapshot and see A's committed child), and the beforeA hook used here can only
// produce the order that actually caused the bug. Stated rather than left to be
// assumed covered.
//
// Reuses the two-replica fixture in
// concurrency_check_then_act_exempt_review_postgres_test.go (same package); see
// that file's header for what the GORM-callback interleaving technique does and
// does not prove.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// liveChildrenOfDeletedProject counts LIVE rows of model whose project_id is the
// fixture project, for use after replica B deleted that project: every one of
// them is an orphan.
//
// The `deleted_at IS NULL` is explicit because ctaReview.countLive queries
// Unscoped() — despite its name it does not filter soft-deleted rows, each
// caller supplies its own liveness predicate. Omitting it here counted the rows
// B's cascade had correctly swept, which made two of these tests fail against a
// working fix (environments: 4 swept rows counted as orphans; the restore test:
// the still-deleted secret counted as live). Written down because the next
// helper built on countLive will hit the same thing.
func (f *ctaReview) liveChildrenOfDeletedProject(model any) int64 {
	f.t.Helper()
	return f.countLive(model, "project_id = ? AND deleted_at IS NULL", f.projectID)
}

// requireProjectDeleted asserts B's cascade really did commit, so a zero
// orphan count cannot be the vacuous consequence of the delete having failed.
func (f *ctaReview) requireProjectDeleted(deleteErr error) {
	f.t.Helper()
	require.NoError(f.t, deleteErr, "replica B's DeleteProject must report success; the whole point is that it did")
	var live int64
	require.NoError(f.t, f.setupDB.Model(&models.Project{}).
		Where("id = ? AND deleted_at IS NULL", f.projectID).Count(&live).Error)
	require.Zero(f.t, live, "fixture precondition: the project must actually be soft-deleted")
}

func TestCTAReview_CreateSecret_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	var delErr error
	fired := f.beforeA("create", "secret_nodes", func() {
		delErr = f.coreB.DeleteProject(f.ctx, f.projectID, true)
	})

	_, createErr := f.coreA.CreateSecret(f.ctx, &CreateSecretRequest{
		Name: "s2702", Value: []byte("v"), ProjectID: f.projectID, EnvironmentID: f.envID,
		Type: "password", CreatedBy: "cta", OwnerID: f.adminID,
	})

	require.True(t, fired(), "replica A never reached its secret INSERT — the interleaving under test never happened")
	f.requireProjectDeleted(delErr)

	assert.Zero(t, f.liveChildrenOfDeletedProject(&models.SecretNode{}),
		"no live secret may remain under a deleted project: GetSecret and AuthorizeSecret do not check project "+
			"liveness, so a global-scope role or an ACL still reaches its value, and the purge only collects "+
			"soft-deleted rows so it is never cleaned up (create err: %v)", createErr)
	// And no orphan version 1 either: the version is written in the same
	// transaction, so a rolled-back secret must take its version with it.
	assert.Zero(t, f.countLive(&models.SecretVersion{}, "secret_node_id IN (SELECT id FROM secret_nodes WHERE project_id = ?)", f.projectID),
		"a rolled-back secret create must not leave version 1 behind (create err: %v)", createErr)
}

func TestCTAReview_CreateFolder_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	var delErr error
	fired := f.beforeA("create", "secret_nodes", func() {
		delErr = f.coreB.DeleteProject(f.ctx, f.projectID, true)
	})

	_, createErr := f.coreA.CreateFolder(f.ctx, f.adminID, "f2711", f.projectID, f.envID, nil)

	require.True(t, fired(), "replica A never reached its folder INSERT — the interleaving under test never happened")
	f.requireProjectDeleted(delErr)

	assert.Zero(t, f.liveChildrenOfDeletedProject(&models.SecretNode{}),
		"a folder is a secret_nodes row and counts toward DeleteEnvironment's active-secret guard exactly like "+
			"a secret, so it must not survive a deleted project either (create err: %v)", createErr)
}

func TestCTAReview_CreateEnvironment_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	var delErr error
	fired := f.beforeA("create", "environments", func() {
		delErr = f.coreB.DeleteProject(f.ctx, f.projectID, true)
	})

	_, createErr := f.coreA.CreateEnvironment(f.ctx, f.projectID, "env2710")

	require.True(t, fired(), "replica A never reached its environment INSERT — the interleaving under test never happened")
	f.requireProjectDeleted(delErr)

	// One live environment is seeded by the fixture and swept by B's cascade, so
	// the expected count here is zero, not "one fewer than before".
	assert.Zero(t, f.liveChildrenOfDeletedProject(&models.Environment{}),
		"a live environment under a deleted project is never purged (PurgeDeletedEnvironmentsBefore takes only "+
			"deleted rows), so it outlives the project purge — and core.CreateSecret checks only that the "+
			"environment is live, so a global-scope principal can then create secrets in it (create err: %v)",
		createErr)
}

func TestCTAReview_RestoreSecret_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	// A secret deleted BEFORE the project, so the project cascade leaves it alone
	// (GORM scopes the sweep to deleted_at IS NULL) and its earlier deleted_at is
	// what RestoreProject would use to tell the two apart. This is the row A tries
	// to revive.
	s := f.secret("s2712", f.adminID)
	require.NoError(t, f.setupDB.Delete(&models.SecretNode{}, s.ID).Error)

	var delErr error
	fired := f.beforeA("update", "secret_nodes", func() {
		delErr = f.coreB.DeleteProject(f.ctx, f.projectID, true)
	})

	restoreErr := f.coreA.RestoreSecret(f.ctx, f.adminID, s.ID)

	require.True(t, fired(), "replica A never reached its restore UPDATE — the interleaving under test never happened")
	f.requireProjectDeleted(delErr)

	assert.Zero(t, f.liveChildrenOfDeletedProject(&models.SecretNode{}),
		"RestoreSecret's own error message promises it refuses when the parent project is deleted; its "+
			"requireLiveProject check ran before the transaction, so the cascade could commit in between and "+
			"the restore cleared deleted_at anyway (restore err: %v)", restoreErr)
}
