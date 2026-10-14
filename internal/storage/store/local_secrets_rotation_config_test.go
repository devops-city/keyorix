// local_secrets_rotation_config_test.go — SQLite integration test for
// LocalStorage.UpdateSecretRotationConfig (#2650): the conditional,
// column-scoped write core.SetSecretAutoRotate persists through. Each case
// models one concurrent change landing between the caller's GetSecret and
// this write, and asserts the write fails closed (matched=false) and leaves
// the row exactly as the concurrent writer left it.
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func rotationConfigFixture(t *testing.T) (*LocalStorage, *models.SecretNode) {
	t.Helper()
	ls := newTransitionSecretStatusStore(t)
	node := &models.SecretNode{ID: 1, Name: "db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 7}
	require.NoError(t, ls.db.Create(node).Error)
	// The caller's stale snapshot, already mutated in memory to the new spec.
	snap := *node
	snap.AutoRotate = true
	snap.RotationLength = 32
	return ls, &snap
}

func TestUpdateSecretRotationConfig_WritesOnlyRotationColumns(t *testing.T) {
	ls, snap := rotationConfigFixture(t)
	ctx := context.Background()
	// A concurrent ownership clear lands after the snapshot was read.
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where("id = ?", 1).Update("owner_id", 0).Error)

	matched, err := ls.UpdateSecretRotationConfig(ctx, snap, "")
	require.NoError(t, err)
	require.True(t, matched)

	var got models.SecretNode
	require.NoError(t, ls.db.First(&got, 1).Error)
	assert.True(t, got.AutoRotate)
	assert.Equal(t, 32, got.RotationLength)
	assert.Zero(t, got.OwnerID, "the stale snapshot's owner_id must not be written back")
}

func TestUpdateSecretRotationConfig_DeletedSecretFailsClosed(t *testing.T) {
	ls, snap := rotationConfigFixture(t)
	require.NoError(t, ls.db.Delete(&models.SecretNode{}, 1).Error)

	matched, err := ls.UpdateSecretRotationConfig(context.Background(), snap, "")
	require.NoError(t, err)
	assert.False(t, matched, "a concurrently deleted secret must not be written (or undeleted)")

	var live int64
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where("id = ?", 1).Count(&live).Error)
	assert.Zero(t, live, "the secret must stay soft-deleted")
}

func TestUpdateSecretRotationConfig_RebindFailsClosed(t *testing.T) {
	ls, snap := rotationConfigFixture(t)
	// A concurrent admin binds a backend after the snapshot (backend "") was read.
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where("id = ?", 1).
		Updates(map[string]any{"rotation_backend": "aws", "rotation_ref": "iam/user"}).Error)

	matched, err := ls.UpdateSecretRotationConfig(context.Background(), snap, "")
	require.NoError(t, err)
	assert.False(t, matched, "the admin gate was decided on backend \"\"; the row is now bound to \"aws\"")

	var got models.SecretNode
	require.NoError(t, ls.db.First(&got, 1).Error)
	assert.Equal(t, "aws", got.RotationBackend, "the admin's binding must survive")
}

func TestUpdateSecretRotationConfig_MovedProjectFailsClosed(t *testing.T) {
	ls, snap := rotationConfigFixture(t)
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where("id = ?", 1).Update("project_id", 2).Error)

	matched, err := ls.UpdateSecretRotationConfig(context.Background(), snap, "")
	require.NoError(t, err)
	assert.False(t, matched, "the authorization was decided in project 1; the secret is now in project 2")
}
