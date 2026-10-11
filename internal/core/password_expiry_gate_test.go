package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func newExpiryCore(ms *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	c := NewKeyorixCore(ms)
	c.now = func() time.Time { return fixed }
	c.passwordPolicy = PasswordPolicy{MaxAgeDays: 90}
	return c
}

var (
	expiryFixed   = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	expiryExpired = expiryFixed.Add(-100 * 24 * time.Hour)
	expiryRecent  = expiryFixed.Add(-30 * 24 * time.Hour)
)

func TestEnforcePasswordExpiryGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("no-op when MaxAgeDays is zero (feature disabled)", func(t *testing.T) {
		ms := new(MockStorage)
		c := newExpiryCore(ms)
		c.passwordPolicy = PasswordPolicy{MaxAgeDays: 0}
		user := &models.User{ID: 1, AccountState: AccountActive, PasswordChangedAt: &expiryExpired}
		require.NoError(t, c.enforcePasswordExpiryGate(ctx, user))
		assert.Equal(t, AccountActive, user.AccountState)
		ms.AssertNotCalled(t, "SetAccountState", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("no-op when password is not yet expired", func(t *testing.T) {
		ms := new(MockStorage)
		c := newExpiryCore(ms)
		user := &models.User{ID: 1, AccountState: AccountActive, PasswordChangedAt: &expiryRecent}
		require.NoError(t, c.enforcePasswordExpiryGate(ctx, user))
		assert.Equal(t, AccountActive, user.AccountState)
		ms.AssertNotCalled(t, "SetAccountState", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("no-op when already password_reset_required", func(t *testing.T) {
		ms := new(MockStorage)
		c := newExpiryCore(ms)
		user := &models.User{ID: 1, AccountState: AccountPasswordResetRequired, PasswordChangedAt: &expiryExpired}
		require.NoError(t, c.enforcePasswordExpiryGate(ctx, user))
		assert.Equal(t, AccountPasswordResetRequired, user.AccountState)
		ms.AssertNotCalled(t, "SetAccountState", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("no-op when suspended", func(t *testing.T) {
		ms := new(MockStorage)
		c := newExpiryCore(ms)
		user := &models.User{ID: 1, AccountState: AccountSuspended, PasswordChangedAt: &expiryExpired}
		require.NoError(t, c.enforcePasswordExpiryGate(ctx, user))
		assert.Equal(t, AccountSuspended, user.AccountState)
		ms.AssertNotCalled(t, "SetAccountState", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("no-op when pending_first_login", func(t *testing.T) {
		ms := new(MockStorage)
		c := newExpiryCore(ms)
		user := &models.User{ID: 1, AccountState: AccountPendingFirstLogin, PasswordChangedAt: &expiryExpired}
		require.NoError(t, c.enforcePasswordExpiryGate(ctx, user))
		assert.Equal(t, AccountPendingFirstLogin, user.AccountState)
		ms.AssertNotCalled(t, "SetAccountState", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("transitions active user to password_reset_required on expiry", func(t *testing.T) {
		ms := new(MockStorage)
		c := newExpiryCore(ms)
		user := &models.User{ID: 7, AccountState: AccountActive, PasswordChangedAt: &expiryExpired}
		ms.On("SetAccountState", ctx, uint(7), AccountPasswordResetRequired, expiryFixed).Return(nil)
		require.NoError(t, c.enforcePasswordExpiryGate(ctx, user))
		assert.Equal(t, AccountPasswordResetRequired, user.AccountState)
		assert.Equal(t, expiryFixed, user.UpdatedAt)
		ms.AssertCalled(t, "SetAccountState", ctx, uint(7), AccountPasswordResetRequired, expiryFixed)
	})

	t.Run("propagates storage error and does not mutate user state", func(t *testing.T) {
		ms := new(MockStorage)
		c := newExpiryCore(ms)
		user := &models.User{ID: 7, AccountState: AccountActive, PasswordChangedAt: &expiryExpired}
		storageErr := errors.New("db unreachable")
		ms.On("SetAccountState", ctx, uint(7), AccountPasswordResetRequired, expiryFixed).Return(storageErr)
		err := c.enforcePasswordExpiryGate(ctx, user)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to enforce password expiry")
		assert.Equal(t, AccountActive, user.AccountState, "state must not be mutated on storage error")
	})
}

// TestLogin_ExpiredPassword verifies that Login transitions an active user to
// password_reset_required when the password max-age policy has elapsed (ADR-025
// hard gate), so EnforceAccountSetup blocks API access on subsequent requests.
func TestLogin_ExpiredPassword(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ctx := context.Background()

	hash, err := bcrypt.GenerateFromPassword([]byte("Secret#Passw0rd!"), bcrypt.MinCost)
	require.NoError(t, err)
	user := &models.User{
		ID:                7,
		Username:          "expireduser",
		PasswordHash:      string(hash),
		IsActive:          true,
		AccountState:      AccountActive,
		PasswordChangedAt: &expiryExpired,
	}

	ms.On("GetUserByUsername", ctx, "expireduser").Return(user, nil)
	ms.On("SetAccountState", ctx, uint(7), AccountPasswordResetRequired, expiryFixed).Return(nil)
	sessionRow := &models.Session{ID: 1, UserID: 7, SessionToken: "tok"}
	ms.On("CreateSession", ctx, mock.AnythingOfType("*models.Session")).Return(sessionRow, nil)

	c := NewKeyorixCore(ms)
	c.now = func() time.Time { return expiryFixed }
	c.SetPasswordPolicy(PasswordPolicy{MaxAgeDays: 90})

	session, returnedUser, loginErr := c.Login(ctx, &LoginRequest{Username: "expireduser", Password: "Secret#Passw0rd!"})
	require.NoError(t, loginErr)
	assert.NotNil(t, session)
	assert.Equal(t, AccountPasswordResetRequired, returnedUser.AccountState,
		"Login must gate the returned user to password_reset_required when password is expired")
	ms.AssertCalled(t, "SetAccountState", ctx, uint(7), AccountPasswordResetRequired, expiryFixed)
}

// TestLogin_ExpiredPassword_StorageError verifies that Login fails closed when the
// account-state update for an expired password cannot be persisted.
func TestLogin_ExpiredPassword_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ctx := context.Background()

	hash, _ := bcrypt.GenerateFromPassword([]byte("Secret#Passw0rd!"), bcrypt.MinCost)
	user := &models.User{
		ID:                7,
		Username:          "expireduser",
		PasswordHash:      string(hash),
		IsActive:          true,
		AccountState:      AccountActive,
		PasswordChangedAt: &expiryExpired,
	}
	ms.On("GetUserByUsername", ctx, "expireduser").Return(user, nil)
	ms.On("SetAccountState", ctx, uint(7), AccountPasswordResetRequired, expiryFixed).Return(errors.New("db down"))

	c := NewKeyorixCore(ms)
	c.now = func() time.Time { return expiryFixed }
	c.SetPasswordPolicy(PasswordPolicy{MaxAgeDays: 90})

	_, _, loginErr := c.Login(ctx, &LoginRequest{Username: "expireduser", Password: "Secret#Passw0rd!"})
	require.Error(t, loginErr, "Login must fail when the expiry gate state update cannot be persisted")
	ms.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// TestLogin_NotExpired_NoStateChange verifies that a user whose password is within
// the max-age window logs in normally with no account-state side effect.
func TestLogin_NotExpired_NoStateChange(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ctx := context.Background()

	hash, _ := bcrypt.GenerateFromPassword([]byte("Secret#Passw0rd!"), bcrypt.MinCost)
	user := &models.User{
		ID:                8,
		Username:          "freshuser",
		PasswordHash:      string(hash),
		IsActive:          true,
		AccountState:      AccountActive,
		PasswordChangedAt: &expiryRecent,
	}
	ms.On("GetUserByUsername", ctx, "freshuser").Return(user, nil)
	sessionRow := &models.Session{ID: 2, UserID: 8, SessionToken: "tok2"}
	ms.On("CreateSession", ctx, mock.AnythingOfType("*models.Session")).Return(sessionRow, nil)

	c := NewKeyorixCore(ms)
	c.now = func() time.Time { return expiryFixed }
	c.SetPasswordPolicy(PasswordPolicy{MaxAgeDays: 90})

	_, returnedUser, loginErr := c.Login(ctx, &LoginRequest{Username: "freshuser", Password: "Secret#Passw0rd!"})
	require.NoError(t, loginErr)
	assert.Equal(t, AccountActive, returnedUser.AccountState)
	ms.AssertNotCalled(t, "SetAccountState", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
