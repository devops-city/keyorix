package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustClient builds a KeyorixClient for baseURL (an httptest.Server URL — always
// loopback, so validateKeyorixClientURL's http-allowed-for-localhost exception applies), failing
// the test immediately on any construction error.
func mustClient(t *testing.T, baseURL, token string) *KeyorixClient {
	t.Helper()
	c, err := NewKeyorixClient(baseURL, token)
	require.NoError(t, err)
	return c
}

func TestKeyorixClient_GetSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/value", r.URL.Path)
		assert.Equal(t, "app/prod/db", r.URL.Query().Get("ref"))
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"data":{"secret":{"Name":"db"},"value":"p4ss"}}`))
	}))
	defer srv.Close()

	v, err := mustClient(t, srv.URL, "tok").GetSecret(context.Background(), "app/prod/db")
	require.NoError(t, err)
	assert.Equal(t, "p4ss", v)
}

func TestKeyorixClient_GetSecretErrors(t *testing.T) {
	cases := map[int]string{
		http.StatusUnauthorized: "not authorized",
		http.StatusForbidden:    "not authorized",
		http.StatusNotFound:     "not found",
		http.StatusBadRequest:   "invalid request",
		http.StatusBadGateway:   "HTTP 502",
	}
	for status, want := range cases {
		t.Run(want, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			_, err := mustClient(t, srv.URL, "tok").GetSecret(context.Background(), "a/b/c")
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
		})
	}
}

// ERRMAP-1: a refused value read names the secret's state, not the token.
func TestKeyorixClient_GetSecretStateRefusals(t *testing.T) {
	for code, want := range map[string]string{
		"SecretAccessOutsideSchedule": "outside its access schedule",
		"SecretExpired":               "has expired",
		"SecretSuspended":             "is suspended",
		"SecretMaxReadsExhausted":     "maximum number of reads",
	} {
		t.Run(code, func(t *testing.T) {
			status := http.StatusConflict
			if code == "SecretAccessOutsideSchedule" {
				status = http.StatusForbidden
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = fmt.Fprintf(w, `{"success":false,"code":%d,"error":%q,"message":"server text"}`, status, code)
			}))
			defer srv.Close()
			_, err := mustClient(t, srv.URL, "tok").GetSecret(context.Background(), "a/b/c")
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
			assert.NotContains(t, err.Error(), "not authorized")
			assert.NotContains(t, err.Error(), "server text", "the server's text is never echoed")
		})
	}
}

func TestKeyorixClient_ListSecretsBuildsRefsAndFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		assert.Equal(t, "100", r.URL.Query().Get("page_size"))
		_, _ = w.Write([]byte(`{"data":{"secrets":[
			{"Name":"db","Type":"password","project_name":"app","environment_name":"production"},
			{"Name":"api","Type":"api_key","project_name":"app","environment_name":"staging"},
			{"Name":"orphan","project_name":"app"}
		]}}`))
	}))
	defer srv.Close()

	// No filter: the two complete entries map to refs; the entry missing an environment
	// is dropped (can't form an unambiguous ref).
	all, truncated, err := mustClient(t, srv.URL, "tok").ListSecrets(context.Background(), "")
	require.NoError(t, err)
	assert.False(t, truncated) // only 3 items returned — well below 100
	require.Len(t, all, 2)
	assert.Equal(t, "app/production/db", all[0].Ref)
	assert.Equal(t, "password", all[0].Type)
	assert.Equal(t, "app/staging/api", all[1].Ref)

	// Environment filter (case-insensitive) narrows to one.
	prod, _, err := mustClient(t, srv.URL, "tok").ListSecrets(context.Background(), "Production")
	require.NoError(t, err)
	require.Len(t, prod, 1)
	assert.Equal(t, "app/production/db", prod[0].Ref)
}

// #122: NewKeyorixClient must reject a non-https KEYORIX_URL (the bearer token and
// every secret value it reads travel in cleartext otherwise) UNLESS the host is
// loopback (local development against a Keyorix instance on the same machine).
func TestNewKeyorixClient_RequiresHTTPS(t *testing.T) {
	if _, err := NewKeyorixClient("http://keyorix.example.com", "tok"); err == nil {
		t.Fatal("cleartext http KEYORIX_URL must be rejected")
	}
	for _, u := range []string{"https://keyorix.example.com", "http://localhost:8080", "http://127.0.0.1:9000", "http://[::1]:9000"} {
		if _, err := NewKeyorixClient(u, "tok"); err != nil {
			t.Fatalf("%s should be allowed: %v", u, err)
		}
	}
}

// TestKeyorixClient_RefusesRedirect pins the fix for a bearer-token-leak-on-downgrade
// bug: Go's default http.Client only strips the Authorization header when a redirect's
// Host differs from the original — never when only the scheme changes, so a same-host
// https->http redirect would otherwise carry the bearer token (and the plaintext secret
// value in the response) over cleartext. validateKeyorixClientURL only guards the INITIAL
// request's scheme, not a mid-request redirect, so CheckRedirect must refuse every
// redirect outright.
func TestKeyorixClient_RefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Fail(t, "the client must never actually reach the redirect target", "Authorization=%q", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/secrets/value", http.StatusFound)
	}))
	defer redirector.Close()

	_, err := mustClient(t, redirector.URL, "tok").GetSecret(context.Background(), "a/b/c")
	require.Error(t, err, "a redirect must be refused, not silently followed")
	assert.Contains(t, err.Error(), "redirect")
}
