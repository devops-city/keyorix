package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// C-RACE-FIX-B2: the SCIM lifecycle paths change account_state, and
// UpdateUserIfActiveStateMatches no longer writes that column (#2653/#2654,
// column-scoped to the profile columns). These assert the PERSISTED row, read
// back from the database — not the in-memory struct UpdateSCIMUser returns,
// which carries the new state whether or not anything wrote it.

func TestUpdateSCIMUser_DeactivatePersistsDeprovisionedAccountState(t *testing.T) {
	t.Parallel()
	c, db := newSCIMStateCore(t)
	no := false

	_, err := c.UpdateSCIMUser(context.Background(), 2, 1, nil, nil, &no)
	require.NoError(t, err)

	var got models.User
	require.NoError(t, db.First(&got, 1).Error)
	assert.Equal(t, AccountDeprovisioned, got.AccountState, "SCIM deactivation must persist account_state=deprovisioned")
	assert.False(t, got.IsActive)
}

func TestUpdateSCIMUser_ReactivatePersistsActiveAccountState(t *testing.T) {
	t.Parallel()
	c, db := newSCIMStateCore(t)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).
		Updates(map[string]any{"account_state": AccountDeprovisioned, "is_active": false}).Error)
	yes := true

	_, err := c.UpdateSCIMUser(context.Background(), 2, 1, nil, nil, &yes)
	require.NoError(t, err)

	var got models.User
	require.NoError(t, db.First(&got, 1).Error)
	assert.Equal(t, AccountActive, got.AccountState, "SCIM reactivation must persist account_state=active")
	assert.True(t, got.IsActive)
}

func TestDeprovisionSCIMUser_PersistsDeprovisionedAccountState(t *testing.T) {
	t.Parallel()
	c, db := newSCIMStateCore(t)
	require.NoError(t, db.AutoMigrate(&models.Role{}, &models.PersonalAccessToken{}))

	require.NoError(t, c.DeprovisionSCIMUser(context.Background(), 2, 1))

	var got models.User
	require.NoError(t, db.Unscoped().First(&got, 1).Error)
	assert.True(t, got.DeletedAt.Valid, "SCIM DELETE soft-deletes the user")
	assert.Equal(t, AccountDeprovisioned, got.AccountState, "SCIM DELETE must persist account_state=deprovisioned on the recoverable record")
	assert.False(t, got.IsActive)
}
