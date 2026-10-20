package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3419: the PAT revocation is part of the SCIM deactivation's transaction. If it
// fails, the deactivation must roll back with it: never an inactive account whose
// PAT rows are still unrevoked (an IdP re-enable would hand them back). Write-gated
// SQLite always, Postgres when KEYORIX_TEST_PG_DSN is set.
func TestUpdateSCIMUser_PATRevokeFailureRollsBackDeactivation(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		u := &models.User{Username: "frank", UsernameFolded: "frank", Email: "frank@example.com",
			IsActive: true, AccountState: AccountActive, ExternalID: "okta|frank"}
		require.NoError(t, w.db.Create(u).Error)
		require.NoError(t, w.db.Create(&models.PersonalAccessToken{UserID: u.ID, Name: "ci", TokenHash: "pat-frank"}).Error)
		w.fs.Arm(&faultstorage.FaultSpec{
			Method: "RevokeAllPersonalAccessTokensForUser", NthCall: 1, Kind: faultstorage.KindError,
			Err: errors.New("simulated PAT revoke failure"),
		})

		off := false
		var err error
		runWithDeadline(t, 30*time.Second, func() {
			_, err = w.c.UpdateSCIMUser(context.Background(), 0, u.ID, nil, nil, &off)
		})
		require.Error(t, err, "a failed PAT revocation must fail the SCIM deactivation")
		require.True(t, w.fs.Fired(), "the armed fault must have fired, or this test proves nothing")

		var after models.User
		require.NoError(t, w.db.First(&after, u.ID).Error)
		assert.True(t, after.IsActive, "the deactivation must roll back with the failed revocation")
		assert.Equal(t, AccountActive, NormalizeAccountState(after.AccountState))
		var unrevoked int64
		require.NoError(t, w.db.Model(&models.PersonalAccessToken{}).
			Where("user_id = ? AND revoked = ?", u.ID, false).Count(&unrevoked).Error)
		assert.Equal(t, int64(1), unrevoked)
	})
}
