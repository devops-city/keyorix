// sso_complete_success_test.go covers CompleteSSO's success tail (sso.go) at
// the HTTP-handler level -- every existing handler-level CompleteSSO test
// (auth_sso_s13_test.go and siblings) exercises a REJECTION path (unknown
// provider, IdP error param, missing code/state, core error). None reaches
// the success branch: setSessionCookies, the expires_at/absolute_expires_at/
// return_to fragment fields, and the #r125-H3 invariant that a successful
// login's session token never appears in the redirect fragment either.
//
// Drives the real HTTP flow: a real SQLite-backed core (BeginSSO persists a
// real SSOLoginState row and returns the IdP authorize URL carrying the real
// state+nonce), a real RSA-signed id_token verified against a static JWKS
// resolver, and an httptest OAuth token endpoint -- the same shape
// internal/core/sso_test.go's ssoTestCore uses, reimplemented here since that
// helper (and its unexported staticResolver type) lives in package core.
package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// staticJWKSResolver is a minimal core.JWKSResolver returning one fixed key
// regardless of (issuer, kid) -- sufficient for a test with a single signer.
type staticJWKSResolver struct{ key *rsa.PublicKey }

func (s staticJWKSResolver) Key(_ context.Context, _, _ string) (any, error) {
	return s.key, nil
}

func signSSOToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "kid-1"
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestCompleteSSO_Success_S1727(t *testing.T) {
	cs := freshCoreS12(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const providerName = "testoidc_success_1727"
	const completeURL = "https://app.example.com/sso/complete"
	p := &core.SSOProvider{
		Name: providerName, Issuer: "https://idp.test.example", ClientID: "test-client-id",
		CompleteURL: completeURL,
		OAuth: &oauth2.Config{
			ClientID:    "test-client-id",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test.example/authorize", TokenURL: "https://idp.test.example/token"},
			RedirectURL: fmt.Sprintf("https://app.example.com/auth/sso/%s/callback", providerName),
			Scopes:      []string{"openid", "email"},
		},
	}
	cs.SetSSOProviders(map[string]*core.SSOProvider{providerName: p}, staticJWKSResolver{key: &key.PublicKey})
	h := NewAuthHandler(cs, false)

	// Step 1: BeginSSO persists a real SSOLoginState row and returns the
	// authorize URL carrying the real state+nonce.
	beginReq := withChiParam(httptest.NewRequest(http.MethodGet, "/auth/sso/"+providerName+"/login", nil), "provider", providerName)
	beginW := httptest.NewRecorder()
	h.BeginSSO(beginW, beginReq)
	require.Equal(t, http.StatusFound, beginW.Code)
	authURL, err := url.Parse(beginW.Header().Get("Location"))
	require.NoError(t, err)
	state := authURL.Query().Get("state")
	nonce := authURL.Query().Get("nonce")
	require.NotEmpty(t, state)
	require.NotEmpty(t, nonce)

	// Step 2: a real OAuth token endpoint returning a real, correctly-signed
	// id_token for the state's nonce.
	idToken := signSSOToken(t, key, jwt.MapClaims{
		"iss": p.Issuer, "aud": "test-client-id", "sub": "idp-subject-1727",
		"email": "handler-success@x.io", "email_verified": true, "nonce": nonce,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	// The IdP-federated user must already exist for this to succeed without
	// also exercising JIT provisioning (covered separately at the core level).
	// resolveSSOUser matches it by verified email (ExternalID starts empty and
	// self-heals to this SSO identity on this very login).
	_, err = cs.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "handlersuccess", Email: "handler-success@x.io",
		DisplayName: "Handler Success", Password: "pw-Aa1!aaaa-longenough",
	})
	require.NoError(t, err)

	reqURL := fmt.Sprintf("/auth/sso/%s/callback?code=authcode&state=%s", providerName, url.QueryEscape(state))
	req := withChiParam(httptest.NewRequest(http.MethodGet, reqURL, nil), "provider", providerName)
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, completeURL)

	fragURL, err := url.Parse(loc)
	require.NoError(t, err)
	frag, err := url.ParseQuery(fragURL.Fragment)
	require.NoError(t, err)
	assert.NotEmpty(t, frag.Get("expires_at"))
	assert.NotContains(t, loc, "error=", "a successful login must not carry an error fragment")

	// #r125-H3: the session token is delivered via cookie, never the fragment.
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session_token" || c.Name == "kx_session" {
			sessionCookie = c
		}
	}
	require.NotNil(t, sessionCookie, "a successful login must set a session cookie")
	assert.NotContains(t, loc, sessionCookie.Value, "the session token must never appear in the redirect fragment")
}
