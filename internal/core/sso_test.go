package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func ssoTestCore(t *testing.T) (*KeyorixCore, *MockStorage, *rsa.PrivateKey, *SSOProvider) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	store := new(MockStorage)
	p := &SSOProvider{
		Name: "okta", Issuer: "https://idp.test", ClientID: "client-1",
		OAuth: &oauth2.Config{
			ClientID:    "client-1",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test/authorize", TokenURL: "https://idp.test/token"},
			RedirectURL: "https://keyorix.test/auth/sso/okta/callback",
			Scopes:      []string{"openid", "email"},
		},
		CompleteURL: "https://keyorix.test/auth/sso/complete",
	}
	c := &KeyorixCore{
		storage:      store,
		now:          time.Now,
		ssoJWKS:      staticResolver{kid: "kid-1", key: &key.PublicKey},
		ssoProviders: map[string]*SSOProvider{"okta": p},
	}
	return c, store, key, p
}

func TestVerifyIDToken(t *testing.T) {
	t.Parallel()
	c, _, key, p := ssoTestCore(t)
	ctx := context.Background()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "https://idp.test", "aud": "client-1", "sub": "okta|123",
			"email": "ada@x.io", "nonce": "N1", "exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	b := base()
	b["name"] = "Ada Lovelace"
	sub, email, name, _, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", b))
	require.NoError(t, err)
	assert.Equal(t, "okta|123", sub)
	assert.Equal(t, "ada@x.io", email)
	assert.Equal(t, "Ada Lovelace", name)

	// Wrong audience → rejected.
	bad := base()
	bad["aud"] = "someone-else"
	_, _, _, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", bad))
	require.Error(t, err)

	// Nonce mismatch → rejected (replay / mix-up protection).
	_, _, _, _, err = c.verifyIDToken(ctx, p, "WRONG", signToken(t, key, "kid-1", base()))
	require.Error(t, err)

	// Expired → rejected.
	exp := base()
	exp["exp"] = time.Now().Add(-time.Hour).Unix()
	_, _, _, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", exp))
	require.Error(t, err)

	// Wrong issuer → rejected (keyfn refuses it).
	iss := base()
	iss["iss"] = "https://evil.test"
	_, _, _, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", iss))
	require.Error(t, err)
}

func TestVerifyIDToken_EmailVerified(t *testing.T) {
	t.Parallel()
	c, _, key, p := ssoTestCore(t)
	ctx := context.Background()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "https://idp.test", "aud": "client-1", "sub": "okta|123",
			"email": "ada@x.io", "nonce": "N1", "exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	// email_verified absent → email is trusted (OIDC-optional; Entra omits it).
	_, email, _, _, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", base()))
	require.NoError(t, err)
	assert.Equal(t, "ada@x.io", email)

	// email_verified: true → email trusted.
	ok := base()
	ok["email_verified"] = true
	_, email, _, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", ok))
	require.NoError(t, err)
	assert.Equal(t, "ada@x.io", email)

	// email_verified: false → email DROPPED (untrusted), but the token still verifies
	// and the subject is unaffected.
	no := base()
	no["email_verified"] = false
	sub, email, _, _, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", no))
	require.NoError(t, err)
	assert.Equal(t, "okta|123", sub)
	assert.Empty(t, email)

	// email_verified sent as the string "false" → also dropped (no parse failure).
	noStr := base()
	noStr["email_verified"] = "false"
	_, email, _, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", noStr))
	require.NoError(t, err)
	assert.Empty(t, email)

	// email_verified sent as the string "true" → trusted.
	okStr := base()
	okStr["email_verified"] = "true"
	_, email, _, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", okStr))
	require.NoError(t, err)
	assert.Equal(t, "ada@x.io", email)
}

// TestVerifyIDToken_Azp covers the multi-audience azp (authorized party) check that
// mirrors OIDCVerifier.Verify in oidc.go: a single-audience token needs no azp, but a
// multi-audience token MUST carry an azp equal to this provider's client_id, or a token
// legitimately issued to a different (also-trusted) party could be replayed here.
func TestVerifyIDToken_Azp(t *testing.T) {
	t.Parallel()
	c, _, key, p := ssoTestCore(t)
	ctx := context.Background()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "https://idp.test", "aud": []string{"client-1"}, "sub": "okta|123",
			"email": "ada@x.io", "nonce": "N1", "exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	t.Run("single audience, no azp: accepted", func(t *testing.T) {
		sub, _, _, _, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", base()))
		require.NoError(t, err)
		assert.Equal(t, "okta|123", sub)
	})

	t.Run("multiple audiences, no azp: rejected", func(t *testing.T) {
		claims := base()
		claims["aud"] = []string{"client-1", "some-other-trusted-client"}
		_, _, _, _, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", claims))
		require.Error(t, err)
		assert.ErrorContains(t, err, "azp")
	})

	t.Run("multiple audiences, azp for a different client: rejected", func(t *testing.T) {
		claims := base()
		claims["aud"] = []string{"client-1", "some-other-trusted-client"}
		claims["azp"] = "some-other-trusted-client" // matches an audience, but not this provider's client_id
		_, _, _, _, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", claims))
		require.Error(t, err)
		assert.ErrorContains(t, err, "azp")
	})

	t.Run("multiple audiences, azp matches this client: accepted", func(t *testing.T) {
		claims := base()
		claims["aud"] = []string{"client-1", "some-other-trusted-client"}
		claims["azp"] = "client-1"
		sub, _, _, _, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", claims))
		require.NoError(t, err)
		assert.Equal(t, "okta|123", sub)
	})
}

func TestResolveSSOUser(t *testing.T) {
	t.Parallel()
	// Mirrors the real storage "not found" error (wrapping the typed
	// storage.ErrUserNotFound sentinel, #504), so the mock matches the real path.
	notFound := func() error {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
	}

	t.Run("externalId match wins", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		// The subject is looked up under this provider's scoped external_id.
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return(&models.User{ID: 7}, nil)
		u, err := c.resolveSSOUser(context.Background(), "okta", "okta|123", "ada@x.io", true)
		require.NoError(t, err)
		assert.Equal(t, uint(7), u.ID)
		store.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything)
	})

	t.Run("verified email links a never-federated account and claims it", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return(&models.User{ID: 9, ExternalID: ""}, nil)
		// First link claims the account for this provider+subject (so a later provider
		// can't re-link it).
		// #2699: the claim is a column-scoped conditional write of external_id
		// alone, and the caller then re-reads so its login gate acts on the
		// COMMITTED row rather than the snapshot read above.
		store.On("ClaimUserExternalIDIfUnset", mock.Anything, uint(9), "sso:okta:okta|123", mock.Anything).Return(true, nil)
		store.On("GetUser", mock.Anything, uint(9)).Return(&models.User{ID: 9, ExternalID: "sso:okta:okta|123", IsActive: true, AccountState: AccountActive}, nil)
		u, err := c.resolveSSOUser(context.Background(), "okta", "okta|123", "ada@x.io", true)
		require.NoError(t, err)
		assert.Equal(t, uint(9), u.ID)
		assert.Equal(t, "sso:okta:okta|123", u.ExternalID, "the re-read row, not the pre-claim snapshot, is what comes back")
		store.AssertCalled(t, "ClaimUserExternalIDIfUnset", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		store.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})

	t.Run("unverified email does NOT match an existing account (no takeover)", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return((*models.User)(nil), notFound())
		// emailVerified=false: the email fallback is skipped entirely — an IdP that merely
		// asserts (or omits email_verified for) an address can't claim an existing account.
		u, err := c.resolveSSOUser(context.Background(), "okta", "okta|123", "ada@x.io", false)
		require.NoError(t, err)
		assert.Nil(t, u)
		store.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything)
	})

	t.Run("email fallback refuses an account bound to a different provider", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return((*models.User)(nil), notFound())
		// This email belongs to an account already bound to IdP "azure". The "okta"
		// assertion must NOT be able to claim it — that is the takeover this guards.
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").
			Return(&models.User{ID: 99, ExternalID: "sso:azure:abc"}, nil)
		u, err := c.resolveSSOUser(context.Background(), "okta", "okta|123", "ada@x.io", true)
		require.Error(t, err)
		assert.ErrorContains(t, err, "different SSO provider")
		assert.Nil(t, u)
	})

	t.Run("email fallback allows an account bound to the SAME provider", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").
			Return(&models.User{ID: 11, ExternalID: "sso:okta:other-sub"}, nil)
		u, err := c.resolveSSOUser(context.Background(), "okta", "okta|123", "ada@x.io", true)
		require.NoError(t, err)
		assert.Equal(t, uint(11), u.ID)
	})

	t.Run("no match returns nil (caller decides)", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return((*models.User)(nil), notFound())
		u, err := c.resolveSSOUser(context.Background(), "okta", "okta|123", "ada@x.io", true)
		require.NoError(t, err)
		assert.Nil(t, u)
	})

	// No-subject regression: a SAML assertion can carry an email with no Subject (see
	// CompleteSAML). The claim protection must still bind the account to THIS provider
	// so a later, different provider can't take it over by asserting the same email —
	// silently skipping the claim step just because sub=="" would defeat it.
	t.Run("verified email with NO subject still claims the account for this provider", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		// sub=="" so the externalId fast-path lookup must not even run.
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return(&models.User{ID: 9, ExternalID: ""}, nil)
		store.On("ClaimUserExternalIDIfUnset", mock.Anything, uint(9), "sso:okta:", mock.Anything).Return(true, nil)
		store.On("GetUser", mock.Anything, uint(9)).Return(&models.User{ID: 9, ExternalID: "sso:okta:", IsActive: true, AccountState: AccountActive}, nil)
		u, err := c.resolveSSOUser(context.Background(), "okta", "", "ada@x.io", true)
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.Equal(t, uint(9), u.ID)
		store.AssertCalled(t, "ClaimUserExternalIDIfUnset", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		store.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
		store.AssertNotCalled(t, "GetUserByExternalID", mock.Anything, mock.Anything)
	})

	// Once claimed via a no-subject assertion, a DIFFERENT provider asserting the same
	// email must still be refused — that is the whole point of the claim.
	t.Run("account claimed via a no-subject assertion still blocks a different provider", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "sso:azure:azure|1").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").
			Return(&models.User{ID: 9, ExternalID: "sso:okta:"}, nil)
		u, err := c.resolveSSOUser(context.Background(), "azure", "azure|1", "ada@x.io", true)
		require.Error(t, err)
		assert.ErrorContains(t, err, "different SSO provider")
		assert.Nil(t, u)
	})
}

func TestProvisionSSOUser(t *testing.T) {
	t.Parallel()
	notFound := func() error {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
	}

	t.Run("JIT-creates an active passwordless user with the default role", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		// No existing match (gated resolve re-check), unique username derivation.
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return((*models.User)(nil), notFound())
		store.On("GetUserByUsername", mock.Anything, "ada").Return((*models.User)(nil), notFound())
		var created *models.User
		store.On("CreateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			created = u
			return true
		})).Return(&models.User{ID: 42}, nil)
		store.On("GetRoleByName", mock.Anything, "system_viewer").Return(&models.Role{ID: 3}, nil)
		store.On("AssignRole", mock.Anything, uint(42), uint(3), mock.Anything).Return(nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		u, err := c.provisionSSOUser(context.Background(), p, "okta|123", "ada@x.io", true, "Ada Lovelace")
		require.NoError(t, err)
		assert.Equal(t, uint(42), u.ID)
		// Active (not pending_first_login — an SSO user must not be trapped in a
		// restricted password-change-only session), externalId pinned, real display name.
		assert.Equal(t, AccountActive, created.AccountState)
		assert.True(t, created.IsActive)
		assert.Equal(t, "sso:okta:okta|123", created.ExternalID, "JIT account is bound to the asserting provider")
		assert.Equal(t, "ada@x.io", created.Email)
		assert.Equal(t, "Ada Lovelace", created.DisplayName)
		assert.NotEmpty(t, created.PasswordHash) // unusable random hash, not blank
	})

	t.Run("refuses when the IdP returned no email", func(t *testing.T) {
		c, _, _, p := ssoTestCore(t)
		_, err := c.provisionSSOUser(context.Background(), p, "okta|123", "", true, "Ada")
		require.Error(t, err)
	})

	// ADR-022's domain allowlist previously only gated the email-based
	// InviteToProject/InviteGlobal flow — an SSO login from an unapproved
	// domain (e.g. a misconfigured/multi-tenant IdP) could still silently
	// JIT-provision an account. Verify it's now enforced here too.
	t.Run("refuses a disallowed email domain", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		c.SetMembershipDomainAllowlist([]string{"allowed.com"})

		_, err := c.provisionSSOUser(context.Background(), p, "okta|999", "mallory@evil.com", true, "Mallory")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not on the allowlist")
		store.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})

	// CRITICAL regression: the JIT path must NOT reuse an existing account matched by an
	// UNVERIFIED email — that was an account-takeover (an IdP omitting email_verified could
	// assert a victim's email and be logged in as the victim). With emailVerified=false the
	// dedup goes through resolveSSOUser, which skips the email branch, so the existing
	// victim account is NOT returned; a fresh account is created instead.
	t.Run("does NOT reuse an existing account on an unverified email", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		// sub does not match; an existing victim account DOES match the email.
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:evil|999").Return((*models.User)(nil), notFound())
		victim := &models.User{ID: 7, Username: "victim", Email: "victim@corp.com", ExternalID: "sso:okta:legit"}
		store.On("GetUserByEmail", mock.Anything, "victim@corp.com").Return(victim, nil)
		// A fresh account is provisioned instead of reusing the victim.
		store.On("GetUserByUsername", mock.Anything, "victim").Return((*models.User)(nil), notFound())
		var created *models.User
		store.On("CreateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool { created = u; return true })).
			Return(&models.User{ID: 99}, nil)
		store.On("GetRoleByName", mock.Anything, mock.Anything).Return(&models.Role{ID: 3}, nil)
		store.On("AssignRole", mock.Anything, uint(99), uint(3), mock.Anything).Return(nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		u, err := c.provisionSSOUser(context.Background(), p, "evil|999", "victim@corp.com", false /* email NOT verified */, "Mallory")
		require.NoError(t, err)
		assert.Equal(t, uint(99), u.ID, "must be the fresh account, not the victim (id 7)")
		require.NotNil(t, created)
		assert.Equal(t, "sso:okta:evil|999", created.ExternalID, "fresh account bound to the asserting provider+subject, not the victim")
		store.AssertNotCalled(t, "ClaimUserExternalIDIfUnset", mock.Anything, mock.Anything, mock.Anything, mock.Anything) // victim not claimed/reused
		store.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})

	t.Run("reuses an existing user instead of duplicating", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return(&models.User{ID: 5}, nil)
		u, err := c.provisionSSOUser(context.Background(), p, "okta|123", "ada@x.io", true, "Ada")
		require.NoError(t, err)
		assert.Equal(t, uint(5), u.ID)
		store.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})

	t.Run("honours a configured default_role", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		p.DefaultRole = "project_admin"
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return((*models.User)(nil), notFound())
		store.On("GetUserByUsername", mock.Anything, "ada").Return((*models.User)(nil), notFound())
		store.On("CreateUser", mock.Anything, mock.Anything).Return(&models.User{ID: 7}, nil)
		store.On("GetRoleByName", mock.Anything, "project_admin").Return(&models.Role{ID: 9}, nil)
		store.On("AssignRole", mock.Anything, uint(7), uint(9), mock.Anything).Return(nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		_, err := c.provisionSSOUser(context.Background(), p, "okta|123", "ada@x.io", true, "Ada")
		require.NoError(t, err)
		store.AssertCalled(t, "GetRoleByName", mock.Anything, "project_admin")
	})

	// Session O atomicity fix: the user row and its default-role grant now run in
	// one transaction (the same bootstrap shape #2295 fixed for first-boot) --
	// an unknown/misconfigured default_role must refuse the whole provision, not
	// silently mint a user with zero roles that an admin would only discover much
	// later. Was "an unknown default_role grants nothing but still provisions"
	// before this fix.
	t.Run("an unknown default_role refuses the whole provision, no orphaned user", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		p.DefaultRole = "does_not_exist"
		store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return((*models.User)(nil), notFound())
		store.On("GetUserByUsername", mock.Anything, "ada").Return((*models.User)(nil), notFound())
		store.On("CreateUser", mock.Anything, mock.Anything).Return(&models.User{ID: 8}, nil)
		store.On("GetRoleByName", mock.Anything, "does_not_exist").Return((*models.Role)(nil), notFound())

		_, err := c.provisionSSOUser(context.Background(), p, "okta|123", "ada@x.io", true, "Ada")
		require.Error(t, err)
		store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	})
}

func TestExtractTokenStringList(t *testing.T) {
	t.Parallel()
	_, _, key, _ := ssoTestCore(t)
	tok := func(claims jwt.MapClaims) string { return signToken(t, key, "kid-1", claims) }

	t.Run("string array", func(t *testing.T) {
		vals, present := extractTokenStringList(tok(jwt.MapClaims{"groups": []string{"admins", "devs"}}), "groups")
		assert.True(t, present)
		assert.Equal(t, []string{"admins", "devs"}, vals)
	})

	t.Run("absent claim → not present", func(t *testing.T) {
		_, present := extractTokenStringList(tok(jwt.MapClaims{"sub": "x"}), "groups")
		assert.False(t, present, "an absent claim must be distinguishable from an empty list")
	})

	t.Run("empty array → present and empty", func(t *testing.T) {
		vals, present := extractTokenStringList(tok(jwt.MapClaims{"groups": []string{}}), "groups")
		assert.True(t, present)
		assert.Empty(t, vals)
	})

	t.Run("single string coerced to a list", func(t *testing.T) {
		vals, present := extractTokenStringList(tok(jwt.MapClaims{"groups": "admins"}), "groups")
		assert.True(t, present)
		assert.Equal(t, []string{"admins"}, vals)
	})

	t.Run("configurable claim name", func(t *testing.T) {
		vals, present := extractTokenStringList(tok(jwt.MapClaims{"roles": []string{"ops"}}), "roles")
		assert.True(t, present)
		assert.Equal(t, []string{"ops"}, vals)
	})

	t.Run("malformed token → not present", func(t *testing.T) {
		_, present := extractTokenStringList("not-a-jwt", "groups")
		assert.False(t, present)
	})
}

func TestSyncSSOGroups(t *testing.T) {
	t.Parallel()
	t.Run("authoritative: adds asserted, removes non-asserted native groups", func(t *testing.T) {
		c, store, key, p := ssoTestCore(t)
		p.GroupSync = true
		raw := signToken(t, key, "kid-1", jwt.MapClaims{"groups": []string{"admins", "devs"}})
		// Native groups: admins(1), devs(2), ops(3). User currently in devs(2), ops(3).
		store.On("ListGroups", mock.Anything).Return([]*models.Group{{ID: 1, Name: "admins"}, {ID: 2, Name: "devs"}, {ID: 3, Name: "ops"}}, nil)
		store.On("GetUserGroups", mock.Anything, uint(7)).Return([]*models.Group{{ID: 2, Name: "devs"}, {ID: 3, Name: "ops"}}, nil)
		store.On("AddUserToGroup", mock.Anything, uint(7), uint(1), uint(0)).Return(nil)      // admins: asserted, not current → add (global)
		store.On("RemoveUserFromGroup", mock.Anything, uint(7), uint(3), uint(0)).Return(nil) // ops: current, not asserted → remove (global)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		// FIX-2: removals now route through the guarded RemoveUserFromGroupGlobal
		// (guardLastGlobalAdminMembership, guardLastProjectAdminGroupMembership)
		// instead of calling storage.RemoveUserFromGroup directly — both guards
		// short-circuit cleanly (no admin-tier role anywhere in this fixture), but
		// still need these lookups stubbed.
		store.On("GetRoleByName", mock.Anything, "super_admin").Return(nil, assert.AnError)
		store.On("GetRoleByName", mock.Anything, "admin").Return(nil, assert.AnError)
		store.On("GetRoleByName", mock.Anything, "system_admin").Return(nil, assert.AnError)
		store.On("ListGroupRoleAssignments", mock.Anything, uint(3)).Return(nil, nil)
		// The membership audit events now name the user and group (audit_refs.go);
		// an unreadable name degrades to the bare id, which is all this test needs.
		store.On("GetUser", mock.Anything, mock.Anything).Return(nil, assert.AnError).Maybe()
		store.On("GetGroup", mock.Anything, mock.Anything).Return(nil, assert.AnError).Maybe()

		require.NoError(t, c.syncSSOGroups(context.Background(), p, 7, raw))

		store.AssertCalled(t, "AddUserToGroup", mock.Anything, uint(7), uint(1), uint(0))
		store.AssertCalled(t, "RemoveUserFromGroup", mock.Anything, uint(7), uint(3), uint(0))
		// devs(2) already a member and still asserted → untouched.
		store.AssertNotCalled(t, "AddUserToGroup", mock.Anything, uint(7), uint(2), uint(0))
		store.AssertNotCalled(t, "RemoveUserFromGroup", mock.Anything, uint(7), uint(2), uint(0))
	})

	t.Run("ignores asserted groups with no native counterpart", func(t *testing.T) {
		c, store, key, p := ssoTestCore(t)
		p.GroupSync = true
		raw := signToken(t, key, "kid-1", jwt.MapClaims{"groups": []string{"nonexistent"}})
		store.On("ListGroups", mock.Anything).Return([]*models.Group{{ID: 1, Name: "admins"}}, nil)
		store.On("GetUserGroups", mock.Anything, uint(7)).Return([]*models.Group{}, nil)

		require.NoError(t, c.syncSSOGroups(context.Background(), p, 7, raw))
		store.AssertNotCalled(t, "AddUserToGroup", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("absent groups claim → no-op (never touches memberships)", func(t *testing.T) {
		c, store, key, p := ssoTestCore(t)
		p.GroupSync = true
		raw := signToken(t, key, "kid-1", jwt.MapClaims{"sub": "okta|123"}) // no groups claim

		require.NoError(t, c.syncSSOGroups(context.Background(), p, 7, raw))
		// Returns before listing groups — so an IdP that omits groups in the id_token
		// can't strip a user's memberships.
		store.AssertNotCalled(t, "ListGroups", mock.Anything)
		store.AssertNotCalled(t, "RemoveUserFromGroup", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

}

// An IdP group assertion must NOT add the user to an admin-conferring native group (the
// SCIM admin-group guard applied to the SSO path), while a non-admin group still syncs.
// Uses real storage so the GetGroupRoles → roleSetContainsAdmin predicate is exercised.
func TestReconcileSSOGroups_RefusesAdminGroupEscalation(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Group{}, &models.UserGroup{},
		&models.GroupRole{}, &models.Role{}, &models.AuditEvent{}, &models.Permission{}, &models.RolePermission{}))
	ls := store.NewLocalStorage(db)
	c := NewKeyorixCore(ls)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 7, Username: "alice"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "admin", BypassesPermissionChecks: true}).Error) // an admin-bypass role
	require.NoError(t, db.Create(&models.Role{ID: 9, Name: "viewer"}).Error)                                // non-admin
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "keyorix-admins"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 2, Name: "engineers"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 2}).Error) // group 1 confers admin
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 2, RoleID: 9}).Error) // group 2 is benign

	// The IdP asserts BOTH group names. The reconcile must SUCCEED: the admin
	// group is refused by the escalation guard, which is a counted "blocked", not
	// an error -- the privilege simply is not granted, which is the fail-closed
	// direction (#2839 item 1 made real failures an error; a blocked escalation
	// deliberately is not one, or an install whose GroupRoleMap names an admin
	// group could never log that user in).
	require.NoError(t, c.reconcileSSOGroups(ctx, &SSOProvider{Name: "okta"}, 7, []string{"keyorix-admins", "engineers"}))

	groups, err := ls.GetUserGroups(ctx, 7)
	require.NoError(t, err)
	ids := map[uint]bool{}
	for _, g := range groups {
		ids[g.ID] = true
	}
	assert.False(t, ids[1], "must NOT be added to the admin-conferring group via an IdP assertion")
	assert.True(t, ids[2], "the benign group still syncs")
}

func TestSyncSSORoles(t *testing.T) {
	t.Parallel()
	t.Run("authoritative over mapped roles only", func(t *testing.T) {
		c, store, key, p := ssoTestCore(t)
		p.GroupRoleMap = map[string]string{"keyorix-secrets-rw": "secrets_writer", "keyorix-auditors": "system_auditor"}
		// IdP asserts only keyorix-secrets-rw → secrets_writer desired; system_auditor
		// (mapped, not asserted) must be removed; system_viewer (NOT mapped) left alone.
		raw := signToken(t, key, "kid-1", jwt.MapClaims{"groups": []string{"keyorix-secrets-rw"}})
		store.On("GetUserRoles", mock.Anything, uint(7)).Return([]*models.Role{
			{ID: 20, Name: "system_auditor"}, {ID: 30, Name: "system_viewer"},
		}, nil)
		store.On("GetRoleByName", mock.Anything, "secrets_writer").Return(&models.Role{ID: 10, Name: "secrets_writer"}, nil)
		store.On("GetRoleByName", mock.Anything, "system_auditor").Return(&models.Role{ID: 20, Name: "system_auditor"}, nil)
		// RemoveUserRole's last-global-admin guard (unrelated to this test's role, but
		// exercised on every removal) looks up every install-admin role name
		// (installAdminRoleNames: super_admin/admin/system_admin) to build the
		// admin-role-ID set.
		store.On("GetRoleByName", mock.Anything, "super_admin").Return(nil, assert.AnError)
		store.On("GetRoleByName", mock.Anything, "admin").Return(nil, assert.AnError)
		store.On("GetRoleByName", mock.Anything, "system_admin").Return(nil, assert.AnError)
		// The IdP-auto-grant escalation backstop (idpAutoGrantOfRoleIsEscalation) now
		// checks the mapped role's bypass flag and permissions before granting.
		// secrets_writer (id 10) is an ordinary role — no bypass, no roles.assign — so it
		// is NOT an escalation and must still be granted.
		store.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{10}).Return(false, nil)
		store.On("GetRolePermissions", mock.Anything, uint(10)).Return([]*models.Permission{{Name: "secrets.write"}}, nil)
		store.On("AssignRole", mock.Anything, uint(7), uint(10), mock.Anything).Return(nil)
		store.On("RemoveRole", mock.Anything, uint(7), uint(20), mock.Anything).Return(nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		// evictUserSessionCache: evicts the removed-role user's cached sessions.
		store.On("ListSessionTokenHashesForUser", mock.Anything, uint(7)).Return([]string{}, nil)

		require.NoError(t, c.syncSSORoles(context.Background(), p, 7, raw))

		store.AssertCalled(t, "AssignRole", mock.Anything, uint(7), uint(10), mock.Anything)    // secrets_writer granted
		store.AssertCalled(t, "RemoveRole", mock.Anything, uint(7), uint(20), mock.Anything)    // system_auditor revoked
		store.AssertNotCalled(t, "RemoveRole", mock.Anything, uint(7), uint(30), mock.Anything) // system_viewer (unmapped) untouched
	})

	// TestSyncSSORoles/refuses-to-grant-an-admin-tier-role pins #96: GroupRoleMap
	// mapped a group directly to an admin-tier role with no guard (unlike
	// reconcileSSOGroups's admin-conferring-GROUP check) — an IdP group that is
	// frequently self-service or governed by non-Keyorix-admins could grant global
	// admin to anyone who joins it. AssignRole must never be called for an
	// admin-tier mapped role.
	t.Run("refuses to grant an admin-tier role from a group mapping", func(t *testing.T) {
		c, store, key, p := ssoTestCore(t)
		p.GroupRoleMap = map[string]string{"keyorix-admins": "system_admin"}
		raw := signToken(t, key, "kid-1", jwt.MapClaims{"groups": []string{"keyorix-admins"}})
		store.On("GetUserRoles", mock.Anything, uint(7)).Return([]*models.Role{}, nil)
		store.On("GetRoleByName", mock.Anything, "system_admin").Return(&models.Role{ID: 10, Name: "system_admin"}, nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		require.NoError(t, c.syncSSORoles(context.Background(), p, 7, raw))

		store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("absent groups claim → no-op (never touches roles)", func(t *testing.T) {
		c, store, key, p := ssoTestCore(t)
		p.GroupRoleMap = map[string]string{"keyorix-admins": "system_admin"}
		raw := signToken(t, key, "kid-1", jwt.MapClaims{"sub": "okta|1"}) // no groups claim

		require.NoError(t, c.syncSSORoles(context.Background(), p, 7, raw))
		store.AssertNotCalled(t, "GetUserRoles", mock.Anything, mock.Anything)
		store.AssertNotCalled(t, "RemoveRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("unknown mapped role is skipped, login not failed", func(t *testing.T) {
		c, store, key, p := ssoTestCore(t)
		p.GroupRoleMap = map[string]string{"keyorix-admins": "does_not_exist"}
		raw := signToken(t, key, "kid-1", jwt.MapClaims{"groups": []string{"keyorix-admins"}})
		store.On("GetUserRoles", mock.Anything, uint(7)).Return([]*models.Role{}, nil)
		// Real GetRoleByName wraps storage.ErrRoleNotFound for a missing name
		// (#2903); a bare message is a lookup FAILURE, which now refuses the login.
		store.On("GetRoleByName", mock.Anything, "does_not_exist").Return((*models.Role)(nil),
			fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrRoleNotFound))

		require.NoError(t, c.syncSSORoles(context.Background(), p, 7, raw))
		store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

// SSO login-time role reconciliation grants/revokes a real role, so it must land in
// the RBAC audit trail with a structured RoleID like every other grant path — not
// just the coarse aggregate auth.sso_roles_synced count (#297). Uses real storage so
// ListRBACAuditLogs (reading the actual persisted rows) is exercised end to end.
func TestReconcileSSORoles_IsRBACAudited(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Role{}, &models.UserRole{}, &models.AuditEvent{}, &models.SoDPolicy{}, &models.Permission{}, &models.RolePermission{}))
	ls := store.NewLocalStorage(db)
	c := NewKeyorixCore(ls)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 7, Username: "alice"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "system_auditor"}).Error)
	p := &SSOProvider{Name: "okta", GroupRoleMap: map[string]string{"keyorix-auditors": "system_auditor"}}

	// IdP asserts keyorix-auditors → system_auditor should be granted.
	require.NoError(t, c.reconcileSSORoles(ctx, p, 7, []string{"keyorix-auditors"}))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	var assigned *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventRoleAssigned {
			assigned = e
		}
	}
	require.NotNil(t, assigned, "SSO-driven role grant must appear in the RBAC audit trail")
	require.NotNil(t, assigned.TargetUserID)
	assert.Equal(t, uint(7), *assigned.TargetUserID)
	require.NotNil(t, assigned.RoleID)
	assert.Equal(t, uint(10), *assigned.RoleID)

	// A later login with no group asserted must revoke system_admin, also audited.
	require.NoError(t, c.reconcileSSORoles(ctx, p, 7, nil))

	entries, _, err = c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	var removed *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventRoleRemoved {
			removed = e
		}
	}
	require.NotNil(t, removed, "SSO-driven role revoke must appear in the RBAC audit trail")
	require.NotNil(t, removed.TargetUserID)
	assert.Equal(t, uint(7), *removed.TargetUserID)
	require.NotNil(t, removed.RoleID)
	assert.Equal(t, uint(10), *removed.RoleID)
}

func TestBeginSSO_BuildsAuthURLWithStateAndNonce(t *testing.T) {
	t.Parallel()
	c, store, _, _ := ssoTestCore(t)
	var captured *models.SSOLoginState
	store.On("CreateSSOLoginState", mock.Anything, mock.MatchedBy(func(s *models.SSOLoginState) bool {
		captured = s
		return s.Provider == "okta" && s.State != "" && s.Nonce != ""
	})).Return(nil)

	raw, err := c.BeginSSO(context.Background(), "okta", "/secrets")
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, "idp.test", u.Host)
	q := u.Query()
	assert.Equal(t, captured.State, q.Get("state"))
	assert.Equal(t, captured.Nonce, q.Get("nonce"))
	assert.Equal(t, "client-1", q.Get("client_id"))
	assert.Equal(t, "/secrets", captured.ReturnTo)
}

func TestBeginSSO_UnknownProvider(t *testing.T) {
	t.Parallel()
	c, _, _, _ := ssoTestCore(t)
	_, err := c.BeginSSO(context.Background(), "nope", "")
	require.Error(t, err)
}

// TestBeginSSO_RejectsSAMLTypedProvider is the #320 regression: a provider configured
// with Type: "saml" has OAuth == nil (server/main.go only ever sets OAuth for OIDC
// providers), so the old code — which dereferenced p.OAuth.AuthCodeURL unconditionally
// — panicked on any GET /auth/sso/{name}/login for a SAML provider name, an
// unauthenticated, unlimited, automatable crash-and-recover reachable by anyone who'd
// enumerated the name via GET /auth/sso/providers. BeginSSO must instead return a
// clean error, and — since the old panic happened AFTER CreateSSOLoginState — must not
// leave an orphaned SSOLoginState row behind (asserted by AssertNotCalled).
func TestBeginSSO_RejectsSAMLTypedProvider(t *testing.T) {
	t.Parallel()
	stub := &stubSAML{redirect: "https://idp.example/sso", requestID: "req-1"}
	c, store := samlTestCore(stub)

	_, err := c.BeginSSO(context.Background(), "corp", "/secrets")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "nil pointer", "must be a clean error, not a recovered panic")
	store.AssertNotCalled(t, "CreateSSOLoginState", mock.Anything, mock.Anything)
}

// TestCompleteSSO_RejectsSAMLTypedProvider mirrors TestBeginSSO_RejectsSAMLTypedProvider
// for the callback side (#320): CompleteSSO dereferences p.OAuth.Exchange unconditionally
// too. Even though a real attacker can't reach this without first obtaining a valid,
// unexpired SSOLoginState row (the state token is never returned before BeginSSO's old
// panic), the guard must hold defensively — and must fire BEFORE touching storage, so a
// type-mismatched callback never even attempts to consume a login state.
func TestCompleteSSO_RejectsSAMLTypedProvider(t *testing.T) {
	t.Parallel()
	stub := &stubSAML{redirect: "https://idp.example/sso", requestID: "req-1"}
	c, store := samlTestCore(stub)

	_, _, _, err := c.CompleteSSO(context.Background(), "corp", "code", "some-state", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "nil pointer", "must be a clean error, not a recovered panic")
	store.AssertNotCalled(t, "ConsumeSSOLoginState", mock.Anything, mock.Anything)
}

// TestCompleteSSO_PasswordExpiredGateError covers the r123 expiry gate path in
// CompleteSSO: when an active user's password has expired and SetAccountState
// fails (storage error), the login must be refused before minting a session.
// The test uses an in-process httptest server as the OAuth2 token endpoint to
// avoid any real network dependency.
func TestCompleteSSO_PasswordExpiredGateError(t *testing.T) {
	t.Parallel()
	c, store, key, p := ssoTestCore(t)
	c.passwordPolicy = PasswordPolicy{MaxAgeDays: 1}

	const testNonce = "nonce-expiry-err"
	expiredUser := &models.User{ID: 55, IsActive: true, AccountState: "active", CreatedAt: time.Now().Add(-48 * time.Hour)}

	idToken := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss":            "https://idp.test",
		"aud":            "client-1",
		"sub":            "okta|55",
		"email":          "expired@x.io",
		"email_verified": true,
		"nonce":          testNonce,
		"exp":            time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	store.On("ConsumeSSOLoginState", mock.Anything, "state-exp").Return(
		&models.SSOLoginState{Provider: "okta", Nonce: testNonce, ReturnTo: "/dash", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|55").Return(expiredUser, nil)
	store.On("SetAccountState", mock.Anything, uint(55), AccountPasswordResetRequired, mock.Anything).
		Return(errors.New("db unavailable"))

	session, _, _, err := c.CompleteSSO(context.Background(), "okta", "auth-code", "state-exp", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.ErrorContains(t, err, "password expiry")
	assert.Nil(t, session)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// TestCompleteSSO_LockedAccountSkipsGroupRoleSync pins CORE-OIDC-04: a currently
// brute-force-locked account must not have its native group memberships / mapped
// role grants reconciled from the IdP assertion — and no reconciliation audit
// written — when the login is about to be refused for that lock anyway. Before the
// fix, group/role sync ran BEFORE the loginLocked check, so a locked account's
// state (and audit trail) was mutated on every SSO attempt even though the
// function went on to reject the login a few lines later. The id_token here
// asserts a brand-new group that WOULD be added if reconciliation ran.
func TestCompleteSSO_LockedAccountSkipsGroupRoleSync(t *testing.T) {
	t.Parallel()
	c, store, key, p := ssoTestCore(t)
	c.loginLockout = LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 5, Window: time.Hour,
		BaseCooldown: time.Minute, MaxCooldown: time.Hour,
	}
	p.GroupSync = true
	p.GroupRoleMap = map[string]string{"keyorix-admins": "system_admin"}

	lockedUntil := time.Now().Add(10 * time.Minute)
	lockedUser := &models.User{
		ID: 66, IsActive: true, AccountState: "active",
		LoginLockedUntil: &lockedUntil, LoginLockoutCount: 1,
	}

	const testNonce = "nonce-locked"
	idToken := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss":            "https://idp.test",
		"aud":            "client-1",
		"sub":            "okta|66",
		"email":          "locked@x.io",
		"email_verified": true,
		"nonce":          testNonce,
		"groups":         []string{"keyorix-admins"}, // would be added/mapped if reconciled
		"exp":            time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	store.On("ConsumeSSOLoginState", mock.Anything, "state-locked").Return(
		&models.SSOLoginState{Provider: "okta", Nonce: testNonce, ReturnTo: "/dash", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|66").Return(lockedUser, nil)

	session, _, _, err := c.CompleteSSO(context.Background(), "okta", "auth-code", "state-locked", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.ErrorContains(t, err, "temporarily locked")
	assert.Nil(t, session)

	// Group/role reconciliation must never even start (which also means no
	// AddUserToGroup/AssignRole/LogAuditEvent for the sync).
	store.AssertNotCalled(t, "ListGroups", mock.Anything)
	store.AssertNotCalled(t, "GetUserGroups", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "GetUserRoles", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "AddUserToGroup", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
	// The account's own lockout state must be left untouched too — the login was
	// refused, so nothing about the account (including its lock) should be cleared.
	assert.Equal(t, 1, lockedUser.LoginLockoutCount)
	assert.NotNil(t, lockedUser.LoginLockedUntil)
}

func TestSanitizeReturnTo(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "/secrets", sanitizeReturnTo("/secrets"))
	assert.Equal(t, "", sanitizeReturnTo("//evil.com"))
	assert.Equal(t, "", sanitizeReturnTo("https://evil.com"))
	assert.Equal(t, "", sanitizeReturnTo("evil"))
	// A backslash right after the leading slash is normalized to "/" by several
	// browsers, so "/\evil.com" is effectively "//evil.com" — a protocol-relative
	// open redirect to an external host. It must be rejected even though it starts
	// with a single "/" and contains no literal "//".
	assert.Equal(t, "", sanitizeReturnTo(`/\evil.com`))
	assert.Equal(t, "", sanitizeReturnTo(`/\/evil.com`))
	assert.Equal(t, "", sanitizeReturnTo(`/\\evil.com`))
	// A backslash anywhere else in the value is rejected too, not just right after
	// the leading slash.
	assert.Equal(t, "", sanitizeReturnTo(`/ok/\evil.com`))
	// A same-origin path with a subpath still passes.
	assert.Equal(t, "/secrets/view", sanitizeReturnTo("/secrets/view"))
}

// #2778 review: a concurrent first login through ANOTHER provider claims the
// account between this login's read and its conditional claim. The claim
// returns false and the re-read shows the other provider's id: this login must
// be refused, not completed onto an account bound elsewhere.
func TestResolveSSOUser_LostClaimToOtherProviderIsRefused(t *testing.T) {
	c, store, _, _ := ssoTestCore(t)
	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|123").Return((*models.User)(nil), fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound))
	store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return(&models.User{ID: 9, ExternalID: ""}, nil)
	store.On("ClaimUserExternalIDIfUnset", mock.Anything, uint(9), "sso:okta:okta|123", mock.Anything).Return(false, nil)
	store.On("GetUser", mock.Anything, uint(9)).Return(&models.User{ID: 9, ExternalID: "sso:azure:azure|999", IsActive: true, AccountState: AccountActive}, nil)
	u, err := c.resolveSSOUser(context.Background(), "okta", "okta|123", "ada@x.io", true)
	require.Error(t, err)
	assert.Nil(t, u)
}
