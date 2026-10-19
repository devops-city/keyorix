package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// issuerKeyResolver returns a distinct signing key per issuer — i.e. each trusted issuer's
// own JWKS. The verifier picks the key by the token's (configured) issuer, so a token can
// only ever be validated against its own issuer's key.
type issuerKeyResolver map[string]any

func (r issuerKeyResolver) Key(_ context.Context, issuer, _ string) (any, error) {
	if k, ok := r[issuer]; ok {
		return k, nil
	}
	return nil, errTestNoKey
}

// TestValidateOIDCToken_CrossIssuerBindingIsolation pins the federated-auth trust property
// (ADR-031): an OIDC machine binding is keyed by (issuer, subject) JOINTLY. A token validly
// signed by ONE trusted issuer must not authenticate as a machine bound to a DIFFERENT
// trusted issuer, even when the subject is identical. This is the multi-tenant / confused-
// deputy defense: a second trusted issuer (another K8s cluster or CI provider) must not be
// able to impersonate a machine bound to the first just by reusing the subject string.
// Verify() pins the signing key to the token's configured issuer, and the binding lookup is
// scoped by issuer, so a (issuer-B, subject) token resolves no (issuer-A, subject) binding.
func TestValidateOIDCToken_CrossIssuerBindingIsolation(t *testing.T) {
	t.Parallel()
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)
	const issA = "https://cluster-a.local"
	const issB = "https://cluster-b.local"
	const subject = "system:serviceaccount:ci:deployer"

	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{
			{Issuer: issA, Audiences: []string{"keyorix"}},
			{Issuer: issB, Audiences: []string{"keyorix"}},
		},
		issuerKeyResolver{issA: &keyA.PublicKey, issB: &keyB.PublicKey},
	)
	require.NoError(t, err)

	store := new(MockStorage)
	c := NewKeyorixCore(store)
	c.SetOIDCVerifier(v)
	ctx := context.Background()

	// A machine is bound to (issuer A, subject) only — that exact tuple resolves; the same
	// subject under issuer B resolves nothing.
	machine := &models.MachineIdentity{ID: 7, State: MachineActive}
	store.On("GetMachineByOIDCSubject", ctx, issA, subject).Return(machine, nil)
	store.On("GetMachineByOIDCSubject", ctx, issB, subject).Return(nil, fmt.Errorf("not found: %w", gorm.ErrRecordNotFound)) // the shape LocalStorage returns for "no binding"; any other error is a storage fault (ErrAuthStorageUnavailable)
	store.On("GetMachineRoles", ctx, uint(7)).Return([]*models.Role{{Name: "ci-deployer"}}, nil)

	claims := func(iss string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss": iss, "sub": subject, "aud": []string{"keyorix"},
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	// Control: the genuine token from issuer A authenticates as the bound machine.
	m, roles, _, err := c.ValidateOIDCToken(ctx, signToken(t, keyA, "kid-1", claims(issA)))
	require.NoError(t, err)
	require.Equal(t, uint(7), m.ID)
	require.Equal(t, []string{"ci-deployer"}, roles)

	// Attack: a VALID token from the OTHER trusted issuer, same subject, must NOT
	// authenticate as machine 7 — no binding exists for (issuer B, subject).
	_, _, _, err = c.ValidateOIDCToken(ctx, signToken(t, keyB, "kid-1", claims(issB)))
	require.Error(t, err, "a token from a different trusted issuer must not resolve another issuer's binding")
	require.Contains(t, err.Error(), "no machine identity bound")
	// The lookup was scoped by the TOKEN's issuer (B), not the bound issuer (A).
	store.AssertCalled(t, "GetMachineByOIDCSubject", ctx, issB, subject)
}
