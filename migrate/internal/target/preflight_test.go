// Fast unit tests for Preflight against an httptest fake Keyorix — no live server needed.
// internal/e2e's tests cover the same generated-apiclient wire contract for the CRUD path;
// this file is Preflight's own decision-branch coverage (revoked, expired, wrong scope,
// insufficient scope, unidentifiable token), which needs finer control over the PAT list
// response than a shared e2e fixture would give cleanly.
package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/migrate/internal/apiclient"
)

// patToken is a minimal fixture for one entry in a fake GET /api/v1/auth/tokens response.
type patToken struct {
	Name             string     `json:"name"`
	TokenPrefix      string     `json:"token_prefix"`
	Revoked          bool       `json:"revoked"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	ProjectScope     int        `json:"project_scope,omitempty"`
	EnvironmentScope int        `json:"environment_scope,omitempty"`
	Scopes           []string   `json:"scopes,omitempty"`
}

func fakePATServer(t *testing.T, statusCode int, tokens []patToken) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if statusCode != http.StatusOK {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": tokens})
	}))
}

func newTestClient(t *testing.T, srv *httptest.Server, projectID, environmentID int) *Client {
	t.Helper()
	api, err := apiclient.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}
	return New(api, projectID, environmentID)
}

// rawTokenFor builds a raw token whose first 13 characters match tokenPrefix — mirroring
// internal/core/pat.go's own TokenPrefix construction (patPrefix + 6 chars).
func rawTokenFor(tokenPrefix string) string {
	return tokenPrefix + "rest-of-the-raw-token-not-inspected"
}

func TestPreflight_UnauthorizedIsInvalidToken(t *testing.T) {
	srv := fakePATServer(t, http.StatusUnauthorized, nil)
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd"))
	if err == nil {
		t.Fatal("Preflight with a 401 response returned no error")
	}
}

func TestPreflight_UnidentifiableTokenPassesWithoutScopeChecks(t *testing.T) {
	// The list succeeds (proving the token authenticates), but no entry's prefix matches --
	// e.g. a machine token, not a PAT. Preflight must not fail just because it can't identify
	// which entry is "this" token.
	srv := fakePATServer(t, http.StatusOK, []patToken{{Name: "someone-elses", TokenPrefix: "kx_pat_zzzzzz"}})
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	if err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd")); err != nil {
		t.Fatalf("Preflight with an unidentifiable token returned an error, want nil: %v", err)
	}
}

func TestPreflight_Revoked(t *testing.T) {
	srv := fakePATServer(t, http.StatusOK, []patToken{{Name: "migrate", TokenPrefix: "kx_pat_ab12cd", Revoked: true}})
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd"))
	if err == nil {
		t.Fatal("Preflight with a revoked token returned no error")
	}
}

func TestPreflight_ExpiresWithinOneHour(t *testing.T) {
	soon := time.Now().Add(30 * time.Minute)
	srv := fakePATServer(t, http.StatusOK, []patToken{{Name: "migrate", TokenPrefix: "kx_pat_ab12cd", ExpiresAt: &soon}})
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd"))
	if err == nil {
		t.Fatal("Preflight with a token expiring in 30 minutes returned no error")
	}
}

func TestPreflight_AlreadyExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	srv := fakePATServer(t, http.StatusOK, []patToken{{Name: "migrate", TokenPrefix: "kx_pat_ab12cd", ExpiresAt: &past}})
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd"))
	if err == nil {
		t.Fatal("Preflight with an already-expired token returned no error")
	}
}

func TestPreflight_ExpiresWellBeyondOneHourPasses(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	srv := fakePATServer(t, http.StatusOK, []patToken{{Name: "migrate", TokenPrefix: "kx_pat_ab12cd", ExpiresAt: &future}})
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	if err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd")); err != nil {
		t.Fatalf("Preflight with a token expiring in 24h returned an error: %v", err)
	}
}

func TestPreflight_WrongProjectScope(t *testing.T) {
	srv := fakePATServer(t, http.StatusOK, []patToken{{Name: "migrate", TokenPrefix: "kx_pat_ab12cd", ProjectScope: 99}})
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd"))
	if err == nil {
		t.Fatal("Preflight with a token scoped to a different project returned no error")
	}
}

func TestPreflight_WrongEnvironmentScope(t *testing.T) {
	srv := fakePATServer(t, http.StatusOK, []patToken{{Name: "migrate", TokenPrefix: "kx_pat_ab12cd", EnvironmentScope: 99}})
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd"))
	if err == nil {
		t.Fatal("Preflight with a token scoped to a different environment returned no error")
	}
}

func TestPreflight_ScopesExcludeSecretsWrite(t *testing.T) {
	srv := fakePATServer(t, http.StatusOK, []patToken{{Name: "migrate", TokenPrefix: "kx_pat_ab12cd", Scopes: []string{"secrets.read"}}})
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd"))
	if err == nil {
		t.Fatal("Preflight with a read-only-scoped token returned no error")
	}
}

func TestPreflight_EmptyScopesInheritsFullPermissions(t *testing.T) {
	// Per openapi.yaml's createPAT doc: "Omit/empty = inherit the owner's full permissions."
	srv := fakePATServer(t, http.StatusOK, []patToken{{Name: "migrate", TokenPrefix: "kx_pat_ab12cd"}})
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	if err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd")); err != nil {
		t.Fatalf("Preflight with empty scopes returned an error: %v", err)
	}
}

func TestPreflight_MatchingProjectEnvironmentAndWriteScopePasses(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	srv := fakePATServer(t, http.StatusOK, []patToken{{
		Name: "migrate", TokenPrefix: "kx_pat_ab12cd", ExpiresAt: &future,
		ProjectScope: 7, EnvironmentScope: 3, Scopes: []string{"secrets.write"},
	}})
	defer srv.Close()
	c := newTestClient(t, srv, 7, 3)

	if err := c.Preflight(context.Background(), rawTokenFor("kx_pat_ab12cd")); err != nil {
		t.Fatalf("Preflight with a correctly-scoped token returned an error: %v", err)
	}
}

func TestAnyScopeAllowsSecretWrite(t *testing.T) {
	cases := []struct {
		scopes []string
		want   bool
	}{
		{[]string{"secrets.write"}, true},
		{[]string{"secrets.*"}, true},
		{[]string{"*"}, true},
		{[]string{"secrets.read"}, false},
		{[]string{"projects.read", "secrets.read"}, false},
		{[]string{}, false},
	}
	for _, c := range cases {
		if got := anyScopeAllowsSecretWrite(c.scopes); got != c.want {
			t.Errorf("anyScopeAllowsSecretWrite(%v) = %v, want %v", c.scopes, got, c.want)
		}
	}
}
