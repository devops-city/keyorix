package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const acctTestUser = "alice"

func TestUpdateOwnProfile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("updates display name and email with the correct current password", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		hash, _ := bcrypt.GenerateFromPassword([]byte("Current#Passw0rd!"), int(bcryptCost.Load()))
		existing := &models.User{ID: 1, Username: acctTestUser, Email: "alice@old.com", DisplayName: "Alice", PasswordHash: string(hash)}

		ms.On("GetUser", ctx, uint(1)).Return(existing, nil)
		ms.On("GetUserByEmail", ctx, "alice@new.com").Return(nil, nil)
		ms.On("UpdateUserIfActiveStateMatches", ctx, mock.AnythingOfType("*models.User"), false).Return(true, nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil) // AUDIT-TX-3: the update commits with its audit row

		_, err := c.UpdateOwnProfile(ctx, 1, "Alice New", "alice@new.com", "Current#Passw0rd!")
		require.NoError(t, err)
		assert.Equal(t, "alice@new.com", existing.Email)
		assert.Equal(t, "Alice New", existing.DisplayName)
		// Username is never touched by a self-service profile update.
		assert.Equal(t, "alice", existing.Username)
	})

	t.Run("rejects an email change without the current password", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		hash, _ := bcrypt.GenerateFromPassword([]byte("Current#Passw0rd!"), int(bcryptCost.Load()))
		existing := &models.User{ID: 1, Username: acctTestUser, Email: "alice@old.com", PasswordHash: string(hash)}

		ms.On("GetUser", ctx, uint(1)).Return(existing, nil)

		_, err := c.UpdateOwnProfile(ctx, 1, "", "alice@new.com", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "incorrect")
		assert.Equal(t, "alice@old.com", existing.Email, "email must not change on a rejected request")
		ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})

	t.Run("rejects an email change with an incorrect current password", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		hash, _ := bcrypt.GenerateFromPassword([]byte("Current#Passw0rd!"), int(bcryptCost.Load()))
		existing := &models.User{ID: 1, Username: acctTestUser, Email: "alice@old.com", PasswordHash: string(hash)}

		ms.On("GetUser", ctx, uint(1)).Return(existing, nil)

		_, err := c.UpdateOwnProfile(ctx, 1, "", "alice@new.com", "wrong-password")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "incorrect")
		assert.Equal(t, "alice@old.com", existing.Email)
		ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})

	t.Run("display-name-only change needs no password", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		hash, _ := bcrypt.GenerateFromPassword([]byte("Current#Passw0rd!"), int(bcryptCost.Load()))
		existing := &models.User{ID: 1, Username: acctTestUser, Email: "alice@old.com", DisplayName: "Alice", PasswordHash: string(hash)}

		ms.On("GetUser", ctx, uint(1)).Return(existing, nil)
		ms.On("UpdateUserIfActiveStateMatches", ctx, mock.AnythingOfType("*models.User"), false).Return(true, nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil) // AUDIT-TX-3: the update commits with its audit row

		_, err := c.UpdateOwnProfile(ctx, 1, "Alice New", "", "")
		require.NoError(t, err)
		assert.Equal(t, "Alice New", existing.DisplayName)
		assert.Equal(t, "alice@old.com", existing.Email)
	})

	t.Run("re-submitting the same email needs no password", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		hash, _ := bcrypt.GenerateFromPassword([]byte("Current#Passw0rd!"), int(bcryptCost.Load()))
		existing := &models.User{ID: 1, Username: acctTestUser, Email: "alice@old.com", PasswordHash: string(hash)}

		ms.On("GetUser", ctx, uint(1)).Return(existing, nil)
		ms.On("UpdateUserIfActiveStateMatches", ctx, mock.AnythingOfType("*models.User"), false).Return(true, nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil) // AUDIT-TX-3: the update commits with its audit row

		_, err := c.UpdateOwnProfile(ctx, 1, "", "alice@old.com", "")
		require.NoError(t, err)
	})

	t.Run("rejects an email already used by another user", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		hash, _ := bcrypt.GenerateFromPassword([]byte("Current#Passw0rd!"), int(bcryptCost.Load()))
		existing := &models.User{ID: 1, Username: acctTestUser, Email: "alice@old.com", PasswordHash: string(hash)}
		other := &models.User{ID: 2, Email: "taken@x.com"}

		ms.On("GetUser", ctx, uint(1)).Return(existing, nil)
		ms.On("GetUserByEmail", ctx, "taken@x.com").Return(other, nil)

		_, err := c.UpdateOwnProfile(ctx, 1, "", "taken@x.com", "Current#Passw0rd!")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})
}

func TestChangePassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	oldHash, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), int(bcryptCost.Load()))

	t.Run("changes password and drops other sessions", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		user := &models.User{ID: 1, Username: acctTestUser, PasswordHash: string(oldHash)}

		ms.On("GetUser", ctx, uint(1)).Return(user, nil)
		ms.On("SetPasswordHash", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("GetSession", ctx, "current-token").Return(&models.Session{ID: 7, UserID: 1}, nil)
		ms.On("ListSessionTokenHashesForUser", ctx, uint(1)).Return([]string{}, nil)
		ms.On("DeleteSessionsForUserExcept", ctx, uint(1), uint(7)).Return(nil)
		ms.On("RevokeAllPersonalAccessTokensForUser", mock.Anything, mock.Anything).Return(nil, nil)
		// History rule (default HistoryCount=5): no prior hashes, then record + prune.
		ms.On("RecentPasswordHashes", ctx, uint(1), 5).Return([]string{}, nil)
		ms.On("AddPasswordHistory", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("PrunePasswordHistory", ctx, uint(1), 5).Return(nil)

		const newPw = "Brandnew#Passw0rd!" // policy-compliant: 16+, upper/lower/digit/special
		err := c.ChangePassword(ctx, 1, "oldpassword", newPw, "current-token")
		require.NoError(t, err)
		// The new password verifies against the freshly stored hash.
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(newPw)))
		ms.AssertCalled(t, "DeleteSessionsForUserExcept", ctx, uint(1), uint(7))
		ms.AssertCalled(t, "AddPasswordHistory", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything)
	})

	t.Run("revokes the user's PATs and evicts them from the auth cache", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		var evicted []string
		c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })
		user := &models.User{ID: 1, Username: acctTestUser, PasswordHash: string(oldHash)}

		ms.On("GetUser", ctx, uint(1)).Return(user, nil)
		ms.On("SetPasswordHash", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("GetSession", ctx, "current-token").Return(&models.Session{ID: 7, UserID: 1}, nil)
		ms.On("ListSessionTokenHashesForUser", ctx, uint(1)).Return([]string{}, nil)
		ms.On("DeleteSessionsForUserExcept", ctx, uint(1), uint(7)).Return(nil)
		// Two active PATs are revoked and their hashes returned for cache eviction.
		ms.On("RevokeAllPersonalAccessTokensForUser", ctx, uint(1)).Return([]string{"hash-a", "hash-b"}, nil)
		ms.On("RecentPasswordHashes", ctx, uint(1), 5).Return([]string{}, nil)
		ms.On("AddPasswordHistory", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("PrunePasswordHistory", ctx, uint(1), 5).Return(nil)

		require.NoError(t, c.ChangePassword(ctx, 1, "oldpassword", "Brandnew#Passw0rd!", "current-token"))
		ms.AssertCalled(t, "RevokeAllPersonalAccessTokensForUser", ctx, uint(1))
		assert.ElementsMatch(t, []string{"hash-a", "hash-b"}, evicted, "revoked PAT hashes are evicted from the auth cache")
	})

	// Red-proof for Session O's O2 item 2: applyNewPassword's PAT-revoke failure used
	// to be `_ =` -- the password change succeeded (correctly, it must not roll back
	// just because cleanup failed) but nothing signaled that an old PAT, possibly
	// minted from the exact compromised session that forced this reset, was still
	// live. Before the fix this test's EventPasswordChangePATRevokeFailed assertion
	// could never pass (no second audit event was ever written).
	t.Run("PAT revoke failure is audited loudly, password change still succeeds", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		user := &models.User{ID: 1, Username: acctTestUser, PasswordHash: string(oldHash)}

		ms.On("GetUser", ctx, uint(1)).Return(user, nil)
		ms.On("SetPasswordHash", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("GetSession", ctx, "current-token").Return(&models.Session{ID: 7, UserID: 1}, nil)
		ms.On("ListSessionTokenHashesForUser", ctx, uint(1)).Return([]string{}, nil)
		ms.On("DeleteSessionsForUserExcept", ctx, uint(1), uint(7)).Return(nil)
		ms.On("RevokeAllPersonalAccessTokensForUser", ctx, uint(1)).Return(nil, assert.AnError)
		ms.On("RecentPasswordHashes", ctx, uint(1), 5).Return([]string{}, nil)
		ms.On("AddPasswordHistory", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("PrunePasswordHistory", ctx, uint(1), 5).Return(nil)
		var loggedTypes []string
		ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
			Run(func(args mock.Arguments) {
				loggedTypes = append(loggedTypes, args.Get(1).(*models.AuditEvent).EventType)
			}).
			Return(nil)

		err := c.ChangePassword(ctx, 1, "oldpassword", "Brandnew#Passw0rd!", "current-token")
		require.NoError(t, err, "a failed PAT revoke must not roll back an already-succeeded password change")
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte("Brandnew#Passw0rd!")))
		assert.Contains(t, loggedTypes, EventPasswordChangePATRevokeFailed,
			"a failed PAT revoke after a password change must be audited distinctly, not silently swallowed")
	})

	t.Run("rejects reuse of a recent password", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		// The new password is a former one whose hash is in history.
		const reused = "Recycled#Passw0rd!"
		reusedHash, _ := bcrypt.GenerateFromPassword([]byte(reused), int(bcryptCost.Load()))
		user := &models.User{ID: 1, Username: acctTestUser, PasswordHash: string(oldHash)}
		ms.On("GetUser", ctx, uint(1)).Return(user, nil)
		ms.On("RecentPasswordHashes", ctx, uint(1), 5).Return([]string{string(reusedHash)}, nil)

		err := c.ChangePassword(ctx, 1, "oldpassword", reused, "current-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reuse a recent password")
		ms.AssertNotCalled(t, "SetPasswordHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects reuse of the current password", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		// A policy-compliant current password that the user tries to "change" to itself.
		const cur = "Current#Passw0rd!"
		curHash, _ := bcrypt.GenerateFromPassword([]byte(cur), int(bcryptCost.Load()))
		user := &models.User{ID: 1, Username: acctTestUser, PasswordHash: string(curHash)}
		ms.On("GetUser", ctx, uint(1)).Return(user, nil)

		err := c.ChangePassword(ctx, 1, cur, cur, "current-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reuse a recent password")
		ms.AssertNotCalled(t, "SetPasswordHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects an incorrect current password without writing", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		user := &models.User{ID: 1, PasswordHash: string(oldHash)}
		ms.On("GetUser", ctx, uint(1)).Return(user, nil)

		err := c.ChangePassword(ctx, 1, "wrongpassword", "Brandnew#Passw0rd!", "current-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "incorrect")
		ms.AssertNotCalled(t, "SetPasswordHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects a new password that violates the policy", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		user := &models.User{ID: 1, Username: acctTestUser, PasswordHash: string(oldHash)}
		ms.On("GetUser", ctx, uint(1)).Return(user, nil)

		// Current password is correct, but the new one is too short / not complex.
		// Policy is checked after the current-password check, so the new password
		// is rejected and nothing is written.
		err := c.ChangePassword(ctx, 1, "oldpassword", "short", "current-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password must")
		ms.AssertNotCalled(t, "SetPasswordHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestPasswordExpired(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	fixed := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }

	t.Run("disabled when MaxAgeDays is zero", func(t *testing.T) {
		c.passwordPolicy = PasswordPolicy{MaxAgeDays: 0}
		old := fixed.Add(-365 * 24 * time.Hour)
		assert.False(t, c.PasswordExpired(&models.User{PasswordChangedAt: &old}))
	})

	t.Run("expired past max age", func(t *testing.T) {
		c.passwordPolicy = PasswordPolicy{MaxAgeDays: 90}
		set := fixed.Add(-100 * 24 * time.Hour)
		assert.True(t, c.PasswordExpired(&models.User{PasswordChangedAt: &set}))
	})

	t.Run("not expired within max age", func(t *testing.T) {
		c.passwordPolicy = PasswordPolicy{MaxAgeDays: 90}
		set := fixed.Add(-30 * 24 * time.Hour)
		assert.False(t, c.PasswordExpired(&models.User{PasswordChangedAt: &set}))
	})

	t.Run("legacy nil falls back to created_at", func(t *testing.T) {
		c.passwordPolicy = PasswordPolicy{MaxAgeDays: 90}
		created := fixed.Add(-200 * 24 * time.Hour)
		assert.True(t, c.PasswordExpired(&models.User{CreatedAt: created}))
	})
}

func TestRevokeOwnSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("revokes a session the caller owns", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSessionByID", ctx, uint(5)).Return(&models.Session{ID: 5, UserID: 1}, nil)
		ms.On("DeleteSession", ctx, uint(5)).Return(nil)

		require.NoError(t, c.RevokeOwnSession(ctx, 1, 5))
		ms.AssertCalled(t, "DeleteSession", ctx, uint(5))
	})

	t.Run("will not revoke another user's session", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSessionByID", ctx, uint(5)).Return(&models.Session{ID: 5, UserID: 2}, nil)

		err := c.RevokeOwnSession(ctx, 1, 5)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		ms.AssertNotCalled(t, "DeleteSession", mock.Anything, mock.Anything)
	})
}

func TestListOwnSessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	want := []*models.Session{{ID: 1, UserID: 1}, {ID: 2, UserID: 1}}
	ms.On("ListSessionsByUser", ctx, uint(1)).Return(want, nil)

	got, err := c.ListOwnSessions(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}
