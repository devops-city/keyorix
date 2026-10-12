package core

// PERF-FIX-5: AuthorizeSecretAction reuses the caller's resolution of the secret only
// when it names the secret being decided. Any other resolution (another secret's row,
// more than one, nil) is ignored and the secret is fetched, so a caller cannot get a
// decision about one secret judged against another secret's scope.

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeSecretAction_ReusesOnlyTheSameSecretsResolution(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c, db, secretID := shareTermRig(t) // secret 1 in project 1; user 2 holds a no-permission role there
	ctx := context.Background()

	// Secret 2 lives in project 7, where user 2 holds secrets.read.
	require.NoError(t, db.Create(&models.Permission{ID: 70, Name: permSecretsRead, Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 51, Name: "reader-p7"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 51, PermissionID: 70}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 51, ProjectID: 7}).Error)
	other := &models.SecretNode{ID: 2, Name: "other", IsSecret: true, ProjectID: 7, EnvironmentID: 70, OwnerID: 9}
	require.NoError(t, db.Create(other).Error)

	decide := func(id uint, resolved ...*models.SecretNode) bool {
		d, err := c.AuthorizeSecretAction(ctx, 2, id, permSecretsRead, "", resolved...)
		require.NoError(t, err)
		return d.Allowed
	}
	require.True(t, decide(other.ID), "control: user 2 may read secret 2")
	require.True(t, decide(other.ID, other), "control: secret 2's own resolution is reused")
	require.False(t, decide(secretID), "control: user 2 may not read secret 1")

	// Secret 1 decided with a resolution that is not secret 1's: fetched, still denied.
	assert.False(t, decide(secretID, other), "another secret's row must not be used to decide this one")
	relabelled := *other
	relabelled.ID = 3
	assert.False(t, decide(secretID, &relabelled), "a row naming a third secret is ignored")
	assert.False(t, decide(secretID, nil), "a nil resolution is ignored")
	assert.False(t, decide(secretID, other, other), "more than one resolution is ignored")
}
