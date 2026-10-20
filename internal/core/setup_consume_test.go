package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// strongPw passes DefaultPasswordPolicy (>=16 chars, upper/lower/digit/special).
const strongPw = "Str0ng!Passw0rd-2026"

func TestDescribeSetupToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := setupPrefix + "describe1"
	hash := sha256Hex(raw)

	t.Run("returns purpose, email, and display name for an active token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		uid := uint(3)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(&models.SetupToken{
			ID: 1, State: SetupTokenActive, Purpose: SetupPurposeAccountSetup,
			SubjectEmail: "new@acme.io", SubjectUserID: &uid, ExpiresAt: c.now().Add(time.Hour),
		}, nil)
		ms.On("GetUser", ctx, uid).Return(&models.User{ID: uid, DisplayName: "Dana"}, nil)

		info, err := c.DescribeSetupToken(ctx, raw)
		require.NoError(t, err)
		assert.Equal(t, SetupPurposeAccountSetup, info.Purpose)
		assert.Equal(t, "new@acme.io", info.Email)
		assert.Equal(t, "Dana", info.DisplayName)
	})

	t.Run("does not consume the token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(&models.SetupToken{
			ID: 1, State: SetupTokenActive, Purpose: SetupPurposePasswordResetLink,
			SubjectEmail: "x@y.io", ExpiresAt: c.now().Add(time.Hour),
		}, nil)
		_, err := c.DescribeSetupToken(ctx, raw)
		require.NoError(t, err)
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects a dead token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(&models.SetupToken{
			ID: 1, State: SetupTokenConsumed, Purpose: SetupPurposeAccountSetup, ExpiresAt: c.now().Add(time.Hour),
		}, nil)
		_, err := c.DescribeSetupToken(ctx, raw)
		require.Error(t, err)
	})
}

func TestCompleteSetup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := setupPrefix + "consume1"
	hash := sha256Hex(raw)
	uid := uint(4)

	activeAccountSetup := func(c *KeyorixCore) *models.SetupToken {
		return &models.SetupToken{
			ID: 2, State: SetupTokenActive, Purpose: SetupPurposeAccountSetup,
			SubjectEmail: "new@acme.io", SubjectUserID: &uid, ExpiresAt: c.now().Add(time.Hour),
		}
	}

	t.Run("sets the password, activates the account, and mints a session (auto-login)", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		user := &models.User{ID: uid, Username: "dana", AccountState: AccountPendingFirstLogin}
		ms.On("GetSetupTokenByHash", ctx, hash).Return(activeAccountSetup(c), nil)
		ms.On("GetUser", ctx, uid).Return(user, nil)
		ms.On("RecentPasswordHashes", ctx, uid, 5).Return([]string{}, nil)
		ms.On("MarkSetupTokenConsumed", ctx, uint(2), mock.AnythingOfType("time.Time")).Return(true, nil)
		ms.On("SetPasswordHash", ctx, uid, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("SetAccountState", ctx, uid, AccountActive, mock.Anything).Return(nil)
		ms.On("AddPasswordHistory", ctx, uid, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("PrunePasswordHistory", ctx, uid, 5).Return(nil)
		// AUTH-2 item 1: the response identity is resolved before the transaction.
		ms.On("GetUserRoles", ctx, uid).Return([]*models.Role{{Name: "viewer"}}, nil)
		ms.On("GetUserPermissions", ctx, uid).Return([]*storage.Permission{}, nil)
		ms.On("EnforceSessionLimit", mock.Anything, uid, mock.Anything).Return(nil)
		ms.On("CreateSession", ctx, mock.AnythingOfType("*models.Session")).
			Return(&models.Session{ID: 1, UserID: uid, SessionToken: "sess-abc"}, nil)
		// Completing setup must evict the subject's other sessions (keeping the new
		// one) so a stolen session can't survive a self-service password reset.
		ms.On("ListSessionTokenHashesForUser", ctx, uid).Return([]string{}, nil)
		ms.On("DeleteSessionsForUserExcept", ctx, uid, uint(1)).Return(nil)
		ms.On("RevokeAllPersonalAccessTokensForUser", mock.Anything, mock.Anything).Return(nil, nil)

		res, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.NoError(t, err)
		assert.Equal(t, "sess-abc", res.Session.SessionToken)
		assert.Equal(t, []string{"viewer"}, res.Identity.Roles, "the identity comes back with the session")
		assert.Equal(t, AccountActive, user.AccountState, "restricted account cleared to active")
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(strongPw)))
		ms.AssertCalled(t, "MarkSetupTokenConsumed", ctx, uint(2), mock.AnythingOfType("time.Time"))
		ms.AssertCalled(t, "CreateSession", ctx, mock.AnythingOfType("*models.Session"))
		ms.AssertCalled(t, "DeleteSessionsForUserExcept", ctx, uid, uint(1))
	})

	t.Run("an account with MFA enabled does NOT get an auto-login session (must complete the second factor)", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		user := &models.User{ID: uid, Username: "dana", AccountState: AccountPendingFirstLogin, MFAEnabled: true}
		ms.On("GetSetupTokenByHash", ctx, hash).Return(activeAccountSetup(c), nil)
		ms.On("GetUser", ctx, uid).Return(user, nil)
		ms.On("RecentPasswordHashes", ctx, uid, 5).Return([]string{}, nil)
		ms.On("MarkSetupTokenConsumed", ctx, uint(2), mock.AnythingOfType("time.Time")).Return(true, nil)
		ms.On("SetPasswordHash", ctx, uid, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("SetAccountState", ctx, uid, AccountActive, mock.Anything).Return(nil)
		ms.On("AddPasswordHistory", ctx, uid, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("PrunePasswordHistory", ctx, uid, 5).Return(nil)
		ms.On("RevokeAllPersonalAccessTokensForUser", mock.Anything, mock.Anything).Return(nil, nil)
		// The reset must still lock out any stolen session (keepID=0: keep none), even
		// though no new session is minted.
		ms.On("ListSessionTokenHashesForUser", ctx, uid).Return([]string{}, nil)
		ms.On("DeleteSessionsForUserExcept", ctx, uid, uint(0)).Return(nil)

		res, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.ErrorIs(t, err, ErrMFARequired)
		require.NotNil(t, res, "the user must be returned so the HTTP layer can start an MFA challenge")
		assert.Nil(t, res.Session, "no session may be minted until the second factor is completed")
		assert.Equal(t, uid, res.User.ID)
		// The password itself was still accepted and the token still consumed — only
		// the session mint is withheld.
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(strongPw)))
		ms.AssertCalled(t, "MarkSetupTokenConsumed", ctx, uint(2), mock.AnythingOfType("time.Time"))
		ms.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
		ms.AssertCalled(t, "DeleteSessionsForUserExcept", ctx, uid, uint(0))
	})

	t.Run("an account with a passkey (WebAuthn) enrolled also skips auto-login", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		user := &models.User{ID: uid, Username: "dana", AccountState: AccountPendingFirstLogin, WebAuthnEnabled: true}
		ms.On("GetSetupTokenByHash", ctx, hash).Return(activeAccountSetup(c), nil)
		ms.On("GetUser", ctx, uid).Return(user, nil)
		ms.On("RecentPasswordHashes", ctx, uid, 5).Return([]string{}, nil)
		ms.On("MarkSetupTokenConsumed", ctx, uint(2), mock.AnythingOfType("time.Time")).Return(true, nil)
		ms.On("SetPasswordHash", ctx, uid, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("SetAccountState", ctx, uid, AccountActive, mock.Anything).Return(nil)
		ms.On("AddPasswordHistory", ctx, uid, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		ms.On("PrunePasswordHistory", ctx, uid, 5).Return(nil)
		ms.On("RevokeAllPersonalAccessTokensForUser", mock.Anything, mock.Anything).Return(nil, nil)
		ms.On("ListSessionTokenHashesForUser", ctx, uid).Return([]string{}, nil)
		ms.On("DeleteSessionsForUserExcept", ctx, uid, uint(0)).Return(nil)

		res, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.ErrorIs(t, err, ErrMFARequired)
		require.NotNil(t, res)
		assert.Nil(t, res.Session)
		ms.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
	})

	t.Run("an externally-managed (SSO/SCIM) account is refused a local password", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		user := &models.User{ID: uid, Username: "dana", AccountState: AccountActive, ExternalID: "okta|123"}
		ms.On("GetSetupTokenByHash", ctx, hash).Return(activeAccountSetup(c), nil)
		ms.On("GetUser", ctx, uid).Return(user, nil)

		_, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "external identity provider")
		// The token must NOT be consumed and no session minted.
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
		ms.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
	})

	t.Run("a weak password is rejected WITHOUT consuming the token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		user := &models.User{ID: uid, Username: "dana", AccountState: AccountPendingFirstLogin}
		ms.On("GetSetupTokenByHash", ctx, hash).Return(activeAccountSetup(c), nil)
		ms.On("GetUser", ctx, uid).Return(user, nil)
		ms.On("RecentPasswordHashes", ctx, uid, 5).Return([]string{}, nil)

		_, err := c.CompleteSetup(ctx, raw, "short", "ua", "1.2.3.4")
		require.Error(t, err)
		// The link must remain usable: the token was never consumed, no session minted.
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
		ms.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
		ms.AssertNotCalled(t, "SetPasswordHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects an invitation_accept token (handled by the invitation producer)", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(&models.SetupToken{
			ID: 2, State: SetupTokenActive, Purpose: SetupPurposeInvitationAccept,
			SubjectEmail: "new@acme.io", ExpiresAt: c.now().Add(time.Hour),
		}, nil)
		_, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.Error(t, err)
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects a suspended account", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(activeAccountSetup(c), nil)
		ms.On("GetUser", ctx, uid).Return(&models.User{ID: uid, AccountState: AccountSuspended}, nil)
		_, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "suspended")
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects an expired token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(&models.SetupToken{
			ID: 2, State: SetupTokenActive, Purpose: SetupPurposeAccountSetup,
			SubjectEmail: "new@acme.io", SubjectUserID: &uid, ExpiresAt: c.now().Add(-time.Hour),
		}, nil)
		ms.On("MarkSetupTokenExpired", ctx, uint(2)).Return(nil)
		_, err := c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
		require.Error(t, err)
	})
}
