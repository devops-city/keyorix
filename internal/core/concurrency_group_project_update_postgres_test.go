// concurrency_group_project_update_postgres_test.go — #2697.
//
// LocalStorage.UpdateGroup and LocalStorage.UpdateProject were bare GORM
// Save(...) calls on a struct the caller had read earlier, unlocked. Save
// writes every column, and on a soft-delete model its 0-rows fallback is
// `INSERT ... ON CONFLICT (id) DO UPDATE SET <every column>`, which includes
// `deleted_at = NULL`. Three distinct consequences, one subtest each:
//
//  1. a rename that lands after DeleteGroup brings the group BACK — and
//     DeleteGroup deliberately keeps its GroupRole/UserGroup rows so a restore
//     can work, so the group returns with every role grant and membership live,
//     with no restore audit event and without going through RestoreGroup. An
//     IdP DELETE closely followed by a PUT is enough (ReplaceSCIMGroup and
//     PatchSCIMGroup rename through the same primitive);
//  2. a rename whose read predates an admin setting require_mfa=true writes
//     `false` back over it — ADR-037's per-project MFA control silently
//     disabled, by a caller that needs no roles.assign and produces no audit
//     event (core.UpdateProject only audits when ITS OWN requireMFA argument
//     changes the value it read);
//  3. a rename that lands after DeleteProject resurrects the project row alone
//     — its secrets and environments stay deleted — after which
//     requireLiveProject and the RestoreSecret/RestoreEnvironment liveness
//     checks pass again for holders of project-scoped grants.
//
// Reuses the two-replica fixture in
// concurrency_check_then_act_exempt_review_postgres_test.go (same package);
// see that file's header for what the GORM-callback interleaving technique
// does and does not prove.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestCTAReview_UpdateGroup_vs_DeleteGroup_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	g, err := f.setup.CreateGroup(f.ctx, f.adminID, &CreateGroupRequest{Name: "grp-2697", Description: "d"})
	require.NoError(t, err)
	// A role grant on the group, so the resurrection's real consequence — live
	// grants coming back with it — is observable rather than inferred.
	role, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setupDB.Create(&models.GroupRole{GroupID: g.ID, RoleID: role.ID, ProjectID: f.projectID}).Error)

	var delErr error
	fired := f.beforeA("update", "groups", func() {
		delErr = f.coreB.DeleteGroup(f.ctx, f.adminID, g.ID)
	})

	_, upErr := f.coreA.UpdateGroup(f.ctx, f.adminID, &UpdateGroupRequest{ID: g.ID, Name: "grp-2697-renamed"})

	require.True(t, fired(), "replica A never reached its groups UPDATE — the interleaving under test never happened")
	require.NoError(t, delErr, "replica B's delete must report success; the whole point is that it did")

	assert.Equal(t, int64(1), f.countLive(&models.Group{}, "id = ? AND deleted_at IS NOT NULL", g.ID),
		"a delete that returned success must stay deleted: UpdateGroup must not resurrect the row (update err: %v)", upErr)
	// The grant row survives a delete by design (so RestoreGroup can work); what
	// must NOT happen is it becoming live again via a resurrected group.
	assert.Equal(t, int64(0), f.countLive(&models.Group{}, "id = ? AND deleted_at IS NULL", g.ID),
		"no live group row may carry the deleted group's still-present role grants")
}

func TestCTAReview_UpdateProject_vs_SetRequireMFA_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	proj, err := f.setup.CreateProject(f.ctx, "proj-2697-mfa", "d")
	require.NoError(t, err)
	require.False(t, proj.RequireMFA)

	// Replica B turns the ADR-037 per-project MFA requirement ON between A's
	// unlocked GetProject and A's own UPDATE.
	var mfaErr error
	fired := f.beforeA("update", "projects", func() {
		on := true
		_, mfaErr = f.coreB.UpdateProject(f.ctx, proj.ID, "proj-2697-mfa", "d", &on)
	})

	// A does a plain rename: requireMFA is nil, so A is not asking to change the
	// flag at all. It must therefore not change.
	_, upErr := f.coreA.UpdateProject(f.ctx, proj.ID, "proj-2697-renamed", "d", nil)

	require.True(t, fired(), "replica A never reached its projects UPDATE — the interleaving under test never happened")
	require.NoError(t, mfaErr, "replica B's require_mfa change must report success")

	var persisted models.Project
	require.NoError(t, f.setupDB.First(&persisted, proj.ID).Error)
	assert.True(t, persisted.RequireMFA,
		"a rename that passed requireMFA=nil must not revert a concurrently-enabled per-project MFA requirement (update err: %v)", upErr)
}

func TestCTAReview_UpdateProject_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	proj, err := f.setup.CreateProject(f.ctx, "proj-2697-del", "d")
	require.NoError(t, err)

	var delErr error
	fired := f.beforeA("update", "projects", func() {
		delErr = f.coreB.DeleteProject(f.ctx, 0, proj.ID, true)
	})

	_, upErr := f.coreA.UpdateProject(f.ctx, proj.ID, "proj-2697-del-renamed", "d", nil)

	require.True(t, fired(), "replica A never reached its projects UPDATE — the interleaving under test never happened")
	require.NoError(t, delErr, "replica B's delete must report success; the whole point is that it did")

	assert.Equal(t, int64(1), f.countLive(&models.Project{}, "id = ? AND deleted_at IS NOT NULL", proj.ID),
		"a delete that returned success must stay deleted: UpdateProject must not resurrect the project row (update err: %v)", upErr)
}
