package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// staticResolver returns one fixed RSA public key for a known kid.
type staticResolver struct {
	kid string
	key any
}

func (s staticResolver) Key(_ context.Context, _, kid string) (any, error) {
	if kid == s.kid {
		return s.key, nil
	}
	return nil, errTestNoKey
}

var errTestNoKey = &noKeyErr{}

type noKeyErr struct{}

func (*noKeyErr) Error() string { return "no key" }

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func newTestVerifier(t *testing.T, key *rsa.PrivateKey) *OIDCVerifier {
	t.Helper()
	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{{Issuer: "https://k8s.local", Audiences: []string{"keyorix"}}},
		staticResolver{kid: "kid-1", key: &key.PublicKey},
	)
	require.NoError(t, err)
	return v
}

func TestNewOIDCVerifier_RequiresAudience(t *testing.T) {
	t.Parallel()
	_, err := NewOIDCVerifier([]OIDCTrustedIssuer{{Issuer: "https://x", Audiences: nil}}, staticResolver{})
	require.ErrorContains(t, err, "no audiences")
}

// TestNewOIDCVerifier_RejectsBlankOnlyAudiences guards #367: an operator
// supplying only empty-string audience entries (e.g. Audiences: [""]) must be
// rejected at startup with a clear error, not silently build an issuer entry
// that can never satisfy its own audience check (permanent fail-closed lockout).
func TestNewOIDCVerifier_RejectsBlankOnlyAudiences(t *testing.T) {
	t.Parallel()
	_, err := NewOIDCVerifier([]OIDCTrustedIssuer{{Issuer: "https://x", Audiences: []string{"", ""}}}, staticResolver{})
	require.Error(t, err)
	require.ErrorContains(t, err, "https://x")
	require.ErrorContains(t, err, "no usable audiences")
}

func TestOIDCVerify_Valid(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key)
	raw := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://k8s.local",
		"sub": "system:serviceaccount:ci:deployer",
		"aud": []string{"keyorix"},
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	iss, sub, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	require.Equal(t, "https://k8s.local", iss)
	require.Equal(t, "system:serviceaccount:ci:deployer", sub)
}

func TestOIDCVerify_Rejections(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key)
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "https://k8s.local", "sub": "sa", "aud": []string{"keyorix"},
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	t.Run("untrusted issuer", func(t *testing.T) {
		c := base()
		c["iss"] = "https://evil.local"
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.Error(t, err)
	})

	t.Run("wrong audience", func(t *testing.T) {
		c := base()
		c["aud"] = []string{"some-other-service"}
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.ErrorContains(t, err, "audience")
	})

	t.Run("expired", func(t *testing.T) {
		c := base()
		c["exp"] = time.Now().Add(-2 * time.Hour).Unix()
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.Error(t, err)
	})

	t.Run("signature by an unknown key", func(t *testing.T) {
		// Signed by `other` but presented with kid-1 → resolver returns the real
		// key, signature check fails.
		_, _, err := v.Verify(context.Background(), signToken(t, other, "kid-1", base()))
		require.Error(t, err)
	})

	t.Run("unknown kid", func(t *testing.T) {
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-unknown", base()))
		require.Error(t, err)
	})

	t.Run("no subject", func(t *testing.T) {
		c := base()
		delete(c, "sub")
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.ErrorContains(t, err, "subject")
	})

	t.Run("HMAC algorithm rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, base())
		tok.Header["kid"] = "kid-1"
		raw, err := tok.SignedString([]byte("secret"))
		require.NoError(t, err)
		_, _, err = v.Verify(context.Background(), raw)
		require.Error(t, err, "HMAC must be rejected (asymmetric only)")
	})

	// #102: exp alone doesn't bound how long ago a token was minted — a
	// far-future exp (misconfigured or malicious issuer) must not verify
	// indefinitely just because it hasn't expired yet.
	t.Run("missing iat rejected", func(t *testing.T) {
		c := base()
		delete(c, "iat")
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.ErrorContains(t, err, "iat")
	})

	t.Run("stale iat beyond max age rejected despite a still-valid, far-future exp", func(t *testing.T) {
		c := base()
		c["iat"] = time.Now().Add(-48 * time.Hour).Unix() // exceeds defaultOIDCMaxTokenAge (24h)
		c["exp"] = time.Now().Add(10 * 365 * 24 * time.Hour).Unix()
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.ErrorContains(t, err, "max age")
	})

	t.Run("iat within max age accepted", func(t *testing.T) {
		c := base()
		c["iat"] = time.Now().Add(-1 * time.Hour).Unix()
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.NoError(t, err)
	})

	// #102: a multi-audience token is ambiguous about its intended recipient —
	// azp must disambiguate and itself be trusted.
	t.Run("multiple audiences without azp rejected", func(t *testing.T) {
		c := base()
		c["aud"] = []string{"keyorix", "some-other-trusted-service"}
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.ErrorContains(t, err, "azp")
	})

	t.Run("multiple audiences with untrusted azp rejected", func(t *testing.T) {
		c := base()
		c["aud"] = []string{"keyorix", "some-other-trusted-service"}
		c["azp"] = "some-other-trusted-service" // matches an audience, but not the one we expect to be the RP here
		v2, err := NewOIDCVerifier(
			[]OIDCTrustedIssuer{{Issuer: "https://k8s.local", Audiences: []string{"keyorix"}}}, // azp not in this issuer's trusted set
			staticResolver{kid: "kid-1", key: &key.PublicKey},
		)
		require.NoError(t, err)
		_, _, err = v2.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.ErrorContains(t, err, "azp")
	})

	t.Run("multiple audiences with trusted azp accepted", func(t *testing.T) {
		c := base()
		c["aud"] = []string{"keyorix", "some-other-trusted-service"}
		c["azp"] = "keyorix"
		_, _, err := v.Verify(context.Background(), signToken(t, key, "kid-1", c))
		require.NoError(t, err)
	})
}

func TestValidateOIDCToken_ResolvesMachine(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := new(MockStorage)
	store.On("GetMachineByOIDCSubject", mock.Anything, "https://k8s.local", "sa").
		Return(&models.MachineIdentity{ID: 7, Name: "ci", State: MachineActive}, nil)
	store.On("GetMachineRoles", mock.Anything, uint(7)).
		Return([]*models.Role{{Name: "project_viewer"}}, nil)

	c := NewKeyorixCore(store)
	c.SetOIDCVerifier(newTestVerifier(t, key))

	raw := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://k8s.local", "sub": "sa", "aud": []string{"keyorix"},
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	m, roles, err := c.ValidateOIDCToken(context.Background(), raw)
	require.NoError(t, err)
	require.Equal(t, uint(7), m.ID)
	require.Equal(t, []string{"project_viewer"}, roles)
}

func TestValidateOIDCToken_DisabledAndSuspended(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://k8s.local", "sub": "sa", "aud": []string{"keyorix"},
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	// Disabled: no verifier set.
	c := NewKeyorixCore(new(MockStorage))
	_, _, err := c.ValidateOIDCToken(context.Background(), raw)
	require.ErrorContains(t, err, "not enabled")

	// Suspended machine → rejected even with a valid token + binding.
	store := new(MockStorage)
	store.On("GetMachineByOIDCSubject", mock.Anything, "https://k8s.local", "sa").
		Return(&models.MachineIdentity{ID: 7, State: MachineSuspended}, nil)
	c2 := NewKeyorixCore(store)
	c2.SetOIDCVerifier(newTestVerifier(t, key))
	_, _, err = c2.ValidateOIDCToken(context.Background(), raw)
	require.ErrorContains(t, err, "suspended")
}
