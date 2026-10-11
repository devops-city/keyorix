package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// OTP-EXPIRY-1: one_time_password_expires_at is written by SetOneTimePasswordExpiry,
// persisted by CreateUser, and cleared by SetPasswordHash.
func TestUser_OneTimePasswordExpiry(t *testing.T) {
	ctx := context.Background()
	ls := newUsersFullStore(t)
	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	u, err := ls.CreateUser(ctx, &models.User{
		Username: "otp-u", UsernameFolded: "otp-u", Email: "otp@example.com", EmailFolded: "otp@example.com",
		OneTimePasswordExpiresAt: &exp,
	})
	require.NoError(t, err)
	// A fresh struct per read: GORM leaves a pointer field alone when the column is NULL.
	reload := func() models.User {
		var r models.User
		require.NoError(t, ls.db.First(&r, u.ID).Error)
		return r
	}

	r := reload()
	require.NotNil(t, r.OneTimePasswordExpiresAt, "CreateUser persists the expiry with the row")
	assert.True(t, r.OneTimePasswordExpiresAt.Equal(exp))

	// A new password supersedes the one-time password and its expiry.
	require.NoError(t, ls.SetPasswordHash(ctx, u.ID, "$2a$bcrypt", time.Now()))
	assert.Nil(t, reload().OneTimePasswordExpiresAt, "SetPasswordHash must clear the expiry")

	// SetOneTimePasswordExpiry sets, then clears, touching nothing else.
	require.NoError(t, ls.SetOneTimePasswordExpiry(ctx, u.ID, &exp, time.Now()))
	r = reload()
	require.NotNil(t, r.OneTimePasswordExpiresAt)
	assert.True(t, r.OneTimePasswordExpiresAt.Equal(exp))
	assert.Equal(t, "$2a$bcrypt", r.PasswordHash)
	require.NoError(t, ls.SetOneTimePasswordExpiry(ctx, u.ID, nil, time.Now()))
	assert.Nil(t, reload().OneTimePasswordExpiresAt)

	require.Error(t, ls.SetOneTimePasswordExpiry(ctx, 99999, &exp, time.Now()), "unknown user")
}
