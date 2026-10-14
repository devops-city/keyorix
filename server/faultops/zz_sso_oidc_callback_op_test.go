// zz_sso_oidc_callback_op_test.go wires the OIDC callback into opCatalog (#2910):
// REST GET /auth/sso/{provider}/callback, the unauthenticated endpoint that
// consumes the login state, exchanges the authorization code, verifies the
// id_token, reconciles the user's groups/roles from its groups claim and mints a
// session (core.CompleteSSO).
//
// It is a GET that changes state. The inventory only ever walked
// POST/PUT/PATCH/DELETE (mutatingHTTPMethods), so it was invisible to the
// registry and to this fuzzer. stateChangingGETRoutes (dump_inventory_test.go)
// now names it and its two siblings explicitly.
//
// The world shape is an EXISTING SSO account whose IdP groups changed since
// its last login. It holds a native group and a mapped role the IdP no longer
// asserts (both revoked on this login), and the IdP asserts a group it does not
// hold yet (added, with its mapped role granted). That is the revocation case
// #2839/#2903/#2907 refuse the login over. The SAML op covers the JIT-provisioned
// shape.
//
// The IdP side is real, not stubbed: a package-level httptest token endpoint
// serves an RS256 id_token signed by a package-level key, and the core verifies
// it through a JWKS resolver holding that key. Only the network hop to a real IdP
// is replaced.
package faultops

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	fuzzOIDCProviderName = "fuzzoidc"
	fuzzOIDCIssuer       = "https://fuzz-oidc.invalid"
	fuzzOIDCClientID     = "fuzz-oidc-client"
	fuzzOIDCKID          = "fuzz-oidc-kid"

	fuzzOIDCGroupEngineers   = "fuzz-oidc-engineers"   // asserted, not held -> add
	fuzzOIDCGroupContractors = "fuzz-oidc-contractors" // held, not asserted -> remove
	fuzzOIDCRoleEngineer     = "fuzz_oidc_engineer"    // mapped from engineers -> grant
	fuzzOIDCRoleContractor   = "fuzz_oidc_contractor"  // mapped from contractors -> revoke
)

// fuzzOIDCIdP is the package-level fake IdP: one signing key and one token
// endpoint. Like fuzzSAMLFixtureShared it is iteration-independent and built
// once per test binary. Setup registers each run's id_token under a fresh
// authorization code (codes), and the token endpoint redeems it once.
var (
	fuzzOIDCIdPOnce sync.Once
	fuzzOIDCKey     *rsa.PrivateKey
	fuzzOIDCServer  *httptest.Server
	fuzzOIDCIdPErr  error
	fuzzOIDCCodes   sync.Map // code -> id_token
)

func fuzzOIDCIdP() (*rsa.PrivateKey, *httptest.Server, error) {
	fuzzOIDCIdPOnce.Do(func() {
		fuzzOIDCKey, fuzzOIDCIdPErr = rsa.GenerateKey(rand.Reader, 2048)
		if fuzzOIDCIdPErr != nil {
			return
		}
		// Never closed: shared by every world in this test binary, torn down at
		// process exit, like the SAML fixture's key.
		fuzzOIDCServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			tok, ok := fuzzOIDCCodes.LoadAndDelete(r.PostForm.Get("code"))
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "fuzz-at", "token_type": "Bearer", "id_token": tok.(string),
			})
		}))
	})
	return fuzzOIDCKey, fuzzOIDCServer, fuzzOIDCIdPErr
}

// fuzzOIDCJWKS resolves the fake IdP's one key, as core.JWKSResolver.
type fuzzOIDCJWKS struct{ key *rsa.PublicKey }

func (j fuzzOIDCJWKS) Key(_ context.Context, _, kid string) (any, error) {
	if kid != fuzzOIDCKID {
		return nil, errors.New("fuzz OIDC JWKS: unknown kid")
	}
	return j.key, nil
}

// fuzzOIDCProvider is the "fuzzoidc" provider wireSSOProviders registers next
// to "fuzzsaml", with group sync on and a GroupRoleMap that includes a
// revocation (fuzzOIDCGroupContractors -> fuzzOIDCRoleContractor).
func fuzzOIDCProvider() (*core.SSOProvider, core.JWKSResolver, error) {
	key, srv, err := fuzzOIDCIdP()
	if err != nil {
		return nil, nil, err
	}
	p := &core.SSOProvider{
		Name: fuzzOIDCProviderName, Issuer: fuzzOIDCIssuer, ClientID: fuzzOIDCClientID,
		OAuth: &oauth2.Config{
			ClientID: fuzzOIDCClientID,
			Endpoint: oauth2.Endpoint{
				AuthURL: fuzzOIDCIssuer + "/authorize", TokenURL: srv.URL + "/token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: "https://fuzz-world.invalid/auth/sso/fuzzoidc/callback",
			Scopes:      []string{"openid", "email"},
		},
		CompleteURL: "https://fuzz-world.invalid/sso/complete",
		GroupSync:   true,
		GroupRoleMap: map[string]string{
			fuzzOIDCGroupEngineers:   fuzzOIDCRoleEngineer,
			fuzzOIDCGroupContractors: fuzzOIDCRoleContractor,
		},
	}
	return p, fuzzOIDCJWKS{key: &key.PublicKey}, nil
}

// seedFuzzSSOGroup / seedFuzzSSORole create a native group / plain role by
// name, directly via the world's DB like the other Setup prerequisites
// (Setup runs unfaulted, so this is not under test).
func seedFuzzSSOGroup(w *faultWorld, name string) error {
	return w.db.Create(&models.Group{Name: name, NameFolded: strings.ToLower(name)}).Error
}

func seedFuzzSSORole(w *faultWorld, name string) error {
	return w.db.Create(&models.Role{Name: name, NameFolded: strings.ToLower(name), Description: "fuzz SSO mapped role"}).Error
}

type oidcFuzzState struct {
	code, state string
}

func init() {
	opCatalog = append(opCatalog, operation{
		Key: "REST GET /auth/sso/{provider}/callback",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			key, _, err := fuzzOIDCIdP()
			if err != nil {
				return nil, fmt.Errorf("setup fuzzOIDCIdP: %w", err)
			}
			// Every PERSISTED value is deterministic (subject, email, login-state
			// key and nonce): oracle (a) compares against an independently built
			// reference world, so a random persisted value would make every
			// faulted-but-successful run differ from it. See the SAML op's
			// identical note. Only the authorization code is random. It is never
			// persisted, and it keys the package-level token endpoint that the
			// reference and fault worlds share.
			const subject = "fuzz-oidc-user"
			const email = subject + "@fuzz-oidc.example"
			tag, err := randFuzzSAMLToken()
			if err != nil {
				return nil, fmt.Errorf("setup random code: %w", err)
			}

			// The existing account and its now-stale IdP-derived access.
			for _, g := range []string{fuzzOIDCGroupEngineers, fuzzOIDCGroupContractors} {
				if err := seedFuzzSSOGroup(w, g); err != nil {
					return nil, fmt.Errorf("setup seed group %s: %w", g, err)
				}
			}
			for _, r := range []string{fuzzOIDCRoleEngineer, fuzzOIDCRoleContractor} {
				if err := seedFuzzSSORole(w, r); err != nil {
					return nil, fmt.Errorf("setup seed role %s: %w", r, err)
				}
			}
			user := &models.User{
				Username: subject, UsernameFolded: subject, Email: email, EmailFolded: email,
				ExternalID: "sso:" + fuzzOIDCProviderName + ":" + subject,
				IsActive:   true, AccountState: core.AccountActive,
			}
			if err := w.db.Create(user).Error; err != nil {
				return nil, fmt.Errorf("setup create SSO user: %w", err)
			}
			var contractors models.Group
			if err := w.db.Where("name = ?", fuzzOIDCGroupContractors).First(&contractors).Error; err != nil {
				return nil, fmt.Errorf("setup read group: %w", err)
			}
			if err := w.db.Create(&models.UserGroup{UserID: user.ID, GroupID: contractors.ID}).Error; err != nil {
				return nil, fmt.Errorf("setup stale membership: %w", err)
			}
			var contractorRole models.Role
			if err := w.db.Where("name = ?", fuzzOIDCRoleContractor).First(&contractorRole).Error; err != nil {
				return nil, fmt.Errorf("setup read role: %w", err)
			}
			if err := w.db.Create(&models.UserRole{UserID: user.ID, RoleID: contractorRole.ID}).Error; err != nil {
				return nil, fmt.Errorf("setup stale role: %w", err)
			}

			// The login state BeginSSO would have stored, and the id_token the IdP
			// will hand back for this run's authorization code.
			const state, nonce = "fuzz-oidc-state", "fuzz-oidc-nonce"
			if err := w.db.Create(&models.SSOLoginState{
				State: state, Nonce: nonce, Provider: fuzzOIDCProviderName,
				ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
			}).Error; err != nil {
				return nil, fmt.Errorf("setup create SSOLoginState: %w", err)
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": fuzzOIDCIssuer, "aud": fuzzOIDCClientID, "sub": subject,
				"email": email, "email_verified": true, "nonce": nonce,
				"exp":    time.Now().Add(time.Hour).Unix(),
				"groups": []string{fuzzOIDCGroupEngineers},
			})
			tok.Header["kid"] = fuzzOIDCKID
			idToken, err := tok.SignedString(key)
			if err != nil {
				return nil, fmt.Errorf("setup sign id_token: %w", err)
			}
			code := "fuzz-oidc-code-" + tag
			fuzzOIDCCodes.Store(code, idToken)
			return oidcFuzzState{code: code, state: state}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			st := state.(oidcFuzzState)
			q := url.Values{"code": {st.code}, "state": {st.state}}.Encode()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				w.httpServer.URL+"/auth/sso/"+fuzzOIDCProviderName+"/callback?"+q, nil)
			if err != nil {
				return opResult{}, err
			}
			// Same reasoning as the SAML ACS op: CompleteSSO always 302s to the
			// (undialable) SPA completion page, with the outcome in the fragment.
			client := &http.Client{
				Timeout:       10 * time.Second,
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
			}
			resp, err := client.Do(req)
			if err != nil {
				return opResult{}, err
			}
			defer func() { _ = resp.Body.Close() }()
			loc := resp.Header.Get("Location")
			success := resp.StatusCode == http.StatusFound && loc != "" && !strings.Contains(loc, "error=")
			return opResult{Success: success, Detail: fmt.Sprintf("HTTP %d Location=%s", resp.StatusCode, loc)}, nil
		},
	})
}
