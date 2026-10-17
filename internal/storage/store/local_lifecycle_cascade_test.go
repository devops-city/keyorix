// local_lifecycle_cascade_test.go — LIFECYCLE-CASCADE-1: soft-delete cascades must revoke
// every authorization that a later restore would otherwise silently revive.
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
