// local_lifecycle_cascade_test.go — LIFECYCLE-CASCADE-1: soft-delete cascades must revoke
// every authorization that a later restore would otherwise silently revive.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedProjectWithSecret creates project -> environment -> one secret on a store built by
// newRestoreTestStore and returns their IDs.
func seedProjectWithSecret(t *testing.T, ls *LocalStorage) (projectID, secretID uint) {
	t.Helper()
	ctx := context.Background()
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "casc", Description: "d"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: proj.ID, EnvironmentID: env.ID, Name: "db-pw", IsSecret: true, Type: "text", Status: "active",
	})
	require.NoError(t, err)
	return proj.ID, sec.ID
}

// newCascadeAccessStore is newRestoreTestStore plus the access-request tables.
func newCascadeAccessStore(t *testing.T) *LocalStorage {
	t.Helper()
	ls := newRestoreTestStore(t)
	require.NoError(t, ls.db.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}))
	return ls
}

// approveSecretRequest persists an approved secret-scoped request, the row
// core.hasApprovedSecretAccessRequest reads to open the restricted-read approval gate.
func approveSecretRequest(t *testing.T, ls *LocalStorage, projectID, secretID, userID uint) uint {
	t.Helper()
	sid := secretID
	req, err := ls.CreateAccessRequest(context.Background(), &models.AccessRequest{
		ProjectID: projectID, UserID: userID, SecretID: &sid, State: "approved",
	})
	require.NoError(t, err)
	return req.ID
}

func requireSecretRequestNotApproved(t *testing.T, ls *LocalStorage, requestID uint) *models.AccessRequest {
	t.Helper()
	got, err := ls.GetAccessRequest(context.Background(), requestID)
	require.NoError(t, err)
	assert.NotEqual(t, "approved", got.State, "the approval must not survive delete + restore")
	assert.Equal(t, "expired", got.State)
	require.NotNil(t, got.ResolvedAt, "a closed request carries resolved_at so retention can purge it")
	return got
}

// #2797: DeleteSecret did not close approved secret-scoped AccessRequests, so the
// restricted-read approval revived on RestoreSecret.
func TestDeleteSecret_ClosesApprovedSecretAccessRequests_NotRevivedByRestoreSecret(t *testing.T) {
	ctx := context.Background()
	ls := newCascadeAccessStore(t)
	projectID, secretID := seedProjectWithSecret(t, ls)
	reqID := approveSecretRequest(t, ls, projectID, secretID, 10)
	// A project-scoped (non-secret) approved request must be left alone.
	projReq, err := ls.CreateAccessRequest(ctx, &models.AccessRequest{ProjectID: projectID, UserID: 11, State: "approved"})
	require.NoError(t, err)

	require.NoError(t, ls.DeleteSecret(ctx, secretID))
	require.NoError(t, ls.RestoreSecret(ctx, secretID))

	requireSecretRequestNotApproved(t, ls, reqID)
	still, err := ls.GetAccessRequest(ctx, projReq.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", still.State, "project-scoped requests are unrelated to the secret's lifecycle")
}

// Same proof through the project cascade.
func TestDeleteProjectCascade_ClosesApprovedSecretAccessRequests_NotRevivedByRestoreProject(t *testing.T) {
	ctx := context.Background()
	ls := newCascadeAccessStore(t)
	projectID, secretID := seedProjectWithSecret(t, ls)
	reqID := approveSecretRequest(t, ls, projectID, secretID, 10)

	require.NoError(t, ls.DeleteProject(ctx, projectID))
	_, _, err := ls.RestoreProject(ctx, projectID)
	require.NoError(t, err)

	requireSecretRequestNotApproved(t, ls, reqID)
}

// Retention: a request closed by the delete sweep is a normal terminal row, purged by
// DeleteResolvedAccessRequestsBefore once past the cutoff, and not before.
func TestDeleteSecret_ClosedAccessRequestFollowsResolvedRetention(t *testing.T) {
	ctx := context.Background()
	ls := newCascadeAccessStore(t)
	projectID, secretID := seedProjectWithSecret(t, ls)
	reqID := approveSecretRequest(t, ls, projectID, secretID, 10)
	require.NoError(t, ls.DeleteSecret(ctx, secretID))

	n, _, err := ls.DeleteResolvedAccessRequestsBefore(ctx, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Zero(t, n, "a request closed just now is inside the retention window")
	_, err = ls.GetAccessRequest(ctx, reqID)
	require.NoError(t, err)

	n, _, err = ls.DeleteResolvedAccessRequestsBefore(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	_, err = ls.GetAccessRequest(ctx, reqID)
	require.Error(t, err)
}

// #2798: deleteProjectCascade revoked ShareRecord rows but not SecretACL rows, unlike
// DeleteSecret (CWE-284), so an ACL grant came back live on RestoreProject with zero
// re-authorization.
func TestDeleteProjectCascade_RevokesSecretACLs_NotRevivedByRestoreProject(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)
	projectID, secretID := seedProjectWithSecret(t, ls)

	require.NoError(t, ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: secretID, UserID: 10, Permissions: `["secrets.read"]`, GrantedBy: 1,
	}))

	require.NoError(t, ls.DeleteProject(ctx, projectID))
	_, _, err := ls.RestoreProject(ctx, projectID)
	require.NoError(t, err)

	_, err = ls.GetSecretACL(ctx, secretID, 10)
	require.Error(t, err, "the grantee's ACL must not survive delete + RestoreProject")
	acls, err := ls.ListSecretACLs(ctx, secretID)
	require.NoError(t, err)
	assert.Empty(t, acls)
}

// #2795: PurgeDeletedProjectsBefore hard-deleted the project but left its
// machine_identity_roles rows behind, and GetMachineRoleIDsAt's LEFT JOIN on projects
// then read the missing project (NULL deleted_at) as live, so the machine kept a role at
// a project that no longer exists.
func TestPurgeDeletedProjectsBefore_RemovesMachineIdentityRoles(t *testing.T) {
	ctx := context.Background()
	ls := newPurgeTestStore(t)
	old := time.Now().AddDate(0, 0, -40)
	cutoff := time.Now().AddDate(0, 0, -30)

	require.NoError(t, ls.db.Create(&models.Project{ID: 1, Name: "doomed"}).Error)
	require.NoError(t, ls.db.Unscoped().Model(&models.Project{}).Where("id = ?", 1).Update("deleted_at", old).Error)
	require.NoError(t, ls.db.Create(&models.Project{ID: 2, Name: "live"}).Error)
	require.NoError(t, ls.db.Create(&models.MachineIdentityRole{MachineIdentityID: 7, RoleID: 3, ProjectID: 1}).Error)
	require.NoError(t, ls.db.Create(&models.MachineIdentityRole{MachineIdentityID: 7, RoleID: 4, ProjectID: 2}).Error)

	n, err := ls.PurgeDeletedProjectsBefore(ctx, cutoff)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	ids, err := ls.GetMachineRoleIDsAt(ctx, 7, storage.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.Empty(t, ids, "the machine must hold no role at a purged project")

	var rows int64
	require.NoError(t, ls.db.Model(&models.MachineIdentityRole{}).Where("project_id = ?", 1).Count(&rows).Error)
	assert.Zero(t, rows, "the purged project's machine_identity_roles rows must be deleted")

	ids, err = ls.GetMachineRoleIDsAt(ctx, 7, storage.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.Equal(t, []uint{4}, ids, "a live project's machine grant must survive the purge")
}
