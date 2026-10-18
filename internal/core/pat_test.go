package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateOwnPAT(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("returns plaintext once and stores only the hash", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		var captured *models.PersonalAccessToken
		ms.On("CreatePersonalAccessToken", ctx, mock.AnythingOfType("*models.PersonalAccessToken")).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.PersonalAccessToken) }).
			Return(&models.PersonalAccessToken{ID: 1}, nil)
		// The token commits with its pat.created row (AUDIT-TX-2).
		ms.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

		res, err := c.CreateOwnPAT(ctx, 1, "ci-token", nil, nil, 0, 0, nil)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(res.PlainToken, patPrefix), "raw token carries the kx_pat_ prefix")
		require.NotNil(t, captured)
		assert.Equal(t, sha256Hex(res.PlainToken), captured.TokenHash, "stored value is the hash of the plaintext")
		assert.NotEqual(t, res.PlainToken, captured.TokenHash, "plaintext is never stored")
		assert.True(t, strings.HasPrefix(captured.TokenPrefix, patPrefix))
		assert.Empty(t, captured.Scopes, "an unscoped token stores no allowlist (inherits owner)")
		assert.Zero(t, captured.ProjectScope)
	})

	t.Run("persists a least-privilege scope restriction (ADR-042)", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		var captured *models.PersonalAccessToken
		ms.On("CreatePersonalAccessToken", ctx, mock.AnythingOfType("*models.PersonalAccessToken")).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.PersonalAccessToken) }).
			Return(&models.PersonalAccessToken{ID: 1}, nil)
		// The token commits with its pat.created row (AUDIT-TX-2).
		ms.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

		_, err := c.CreateOwnPAT(ctx, 1, "ci-read-only", nil, []string{"secrets.read", "  ", "secrets.read"}, 7, 0, nil)
		require.NoError(t, err)
		require.NotNil(t, captured)
		// Blanks dropped, duplicates removed, encoded as JSON.
		assert.Equal(t, `["secrets.read"]`, captured.Scopes)
		assert.Equal(t, uint(7), captured.ProjectScope)
		// Round-trips back into a restriction.
		r := patRestrictionFrom(captured)
		require.NotNil(t, r)
		assert.Equal(t, []string{"secrets.read"}, r.Permissions)
		assert.Equal(t, uint(7), r.ProjectID)
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		_, err := c.CreateOwnPAT(ctx, 1, "   ", nil, nil, 0, 0, nil)
		require.Error(t, err)
		ms.AssertNotCalled(t, "CreatePersonalAccessToken", mock.Anything, mock.Anything)
	})
}

func TestValidatePATToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := patPrefix + "abc123def456"
	hash := sha256Hex(raw)

	t.Run("resolves a valid token to its user and roles", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1}, nil)
		ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: acctTestUser, IsActive: true, AccountState: AccountActive}, nil)
		role := "system_viewer"
		ms.On("GetUserRoles", ctx, uint(1)).Return([]*models.Role{{Name: role}}, nil)

		user, roles, restriction, patID, err := c.ValidatePATToken(ctx, raw)
		require.NoError(t, err)
		assert.Equal(t, uint(1), user.ID)
		assert.Equal(t, []string{role}, roles)
		assert.Nil(t, restriction, "an unscoped token resolves to no restriction (full inheritance)")
		assert.Equal(t, uint(9), patID, "the PAT's row id is surfaced so the caller can touch last_used_at itself")
	})

	t.Run("surfaces the least-privilege restriction for a scoped token (ADR-042)", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{
			ID: 9, UserID: 1, Scopes: `["secrets.read"]`, ProjectScope: 4,
		}, nil)
		ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: acctTestUser, IsActive: true, AccountState: AccountActive}, nil)
		ms.On("GetUserRoles", ctx, uint(1)).Return([]*models.Role{{Name: "system_viewer"}}, nil)

		_, _, restriction, _, err := c.ValidatePATToken(ctx, raw)
		require.NoError(t, err)
		require.NotNil(t, restriction)
		assert.Equal(t, []string{"secrets.read"}, restriction.Permissions)
		assert.Equal(t, uint(4), restriction.ProjectID)
	})

	t.Run("rejects a revoked token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1, Revoked: true}, nil)
		_, _, _, _, err := c.ValidatePATToken(ctx, raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("rejects an expired token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		past := time.Now().Add(-time.Hour)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1, Name: "old-ci", ExpiresAt: &past}, nil)
		// emitPATExpiredNotification is called best-effort before the error is returned.
		// It dedups against any existing unread notification for this token first.
		ms.On("ListNotifications", ctx, uint(1), true, 200).Return([]*models.Notification{}, nil)
		ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(&models.Notification{ID: 1}, nil)
		_, _, _, _, err := c.ValidatePATToken(ctx, raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("rejects a token for an inactive user", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1}, nil)
		ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, IsActive: false}, nil)
		_, _, _, _, err := c.ValidatePATToken(ctx, raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "inactive")
	})

	t.Run("rejects a token for a suspended user (is_active still true)", func(t *testing.T) {
		// SuspendUser sets account_state=suspended but leaves is_active untouched, so the
		// is_active check alone would let a suspended user keep using their PAT. The
		// account-state gate must reject it — mirroring ValidateSessionToken.
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1}, nil)
		ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, IsActive: true, AccountState: AccountSuspended}, nil)
		_, _, _, _, err := c.ValidatePATToken(ctx, raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not active")
		// Must reject before stamping last-used — a blocked token is not "used".
		ms.AssertNotCalled(t, "TouchPersonalAccessToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects an unknown token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(nil, assert.AnError)
		_, _, _, _, err := c.ValidatePATToken(ctx, raw)
		require.Error(t, err)
	})

	t.Run("rejects a non-PAT token before any storage lookup", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		_, _, _, _, err := c.ValidatePATToken(ctx, "some-session-token")
		require.Error(t, err)
		ms.AssertNotCalled(t, "GetPersonalAccessTokenByHash", mock.Anything, mock.Anything)
	})
}

func TestRevokeOwnPAT(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("revokes a token the caller owns", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByID", ctx, uint(3)).Return(&models.PersonalAccessToken{ID: 3, UserID: 1, TokenHash: "hash-3"}, nil)
		ms.On("RevokePersonalAccessToken", ctx, uint(3)).Return(nil)
		hash, rerr := c.RevokeOwnPAT(ctx, 1, 3)
		require.NoError(t, rerr)
		assert.Equal(t, "hash-3", hash, "revoke returns the token hash for cache eviction")
		ms.AssertCalled(t, "RevokePersonalAccessToken", ctx, uint(3))
	})

	t.Run("will not revoke another user's token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByID", ctx, uint(3)).Return(&models.PersonalAccessToken{ID: 3, UserID: 2}, nil)
		_, err := c.RevokeOwnPAT(ctx, 1, 3)
		require.Error(t, err)
		ms.AssertNotCalled(t, "RevokePersonalAccessToken", mock.Anything, mock.Anything)
	})
}

// TestDecodePATScopes covers the three branches: empty → nil (unrestricted),
// valid JSON → parsed list, and corrupted JSON → patScopeCorrupted sentinel
// (fail-closed, #r124-M).
func TestDecodePATScopes(t *testing.T) {
	t.Parallel()
	t.Run("empty string returns nil (unrestricted)", func(t *testing.T) {
		assert.Nil(t, DecodePATScopes(""))
	})
	t.Run("whitespace-only treated as empty", func(t *testing.T) {
		assert.Nil(t, DecodePATScopes("   "))
	})
	t.Run("valid JSON array returns scopes", func(t *testing.T) {
		scopes := DecodePATScopes(`["secrets.read","secrets.write"]`)
		assert.Equal(t, []string{"secrets.read", "secrets.write"}, scopes)
	})
	t.Run("corrupted JSON returns sentinel not nil (fail-closed)", func(t *testing.T) {
		got := DecodePATScopes(`{bad json}`)
		assert.Equal(t, patScopeCorrupted, got,
			"a corrupted scope column must fail CLOSED (sentinel), not return nil (unrestricted)")
	})
	t.Run("sentinel is never matched by any real permission string", func(t *testing.T) {
		sentinel := patScopeCorrupted
		for _, real := range []string{"secrets.read", "secrets.write", "secrets.delete", "system.read", "system.write"} {
			found := false
			for _, s := range sentinel {
				if s == real {
					found = true
				}
			}
			assert.False(t, found, "sentinel must not overlap any real permission: %q", real)
		}
	})
}
