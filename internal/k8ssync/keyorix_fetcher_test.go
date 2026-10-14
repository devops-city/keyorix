package k8ssync

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRef(t *testing.T) {
	cases := []struct {
		ref, env, name string
		ok             bool
	}{
		{"production/db-password", "production", "db-password", true},
		{"prod/app/config/url", "prod", "app/config/url", true}, // name may contain slashes
		{"noslash", "", "", false},
		{"/leading", "", "", false},
		{"trailing/", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		env, name, err := parseRef(c.ref)
		if !c.ok {
			assert.Error(t, err, "ref %q should be rejected", c.ref)
			continue
		}
		require.NoError(t, err, "ref %q", c.ref)
		assert.Equal(t, c.env, env)
		assert.Equal(t, c.name, name)
	}
}

// TestRefuseRedirect verifies that the http.Client CheckRedirect hook always errors,
// so a 3xx from a compromised/misconfigured Keyorix server can never bounce the
// bearer-token-bearing request onward (CWE-918) — see refuseRedirect's doc comment.
func TestRefuseRedirect(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com/next", nil)
	require.NoError(t, err)

	err = refuseRedirect(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to follow redirect")
	assert.Contains(t, err.Error(), "http://example.com/next")
}

// TestValidateFetcherBaseURL covers every branch: a well-formed https URL (always
// allowed), a loopback http URL (allowed as a redundant runtime re-check for this
// package's own httptest-backed tests), a non-loopback http URL (rejected), and two
// distinct ways a raw string fails to be a well-formed absolute URL at all.
func TestValidateFetcherBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr string // "" means no error expected
	}{
		{"https always allowed", "https://example.com", ""},
		{"http loopback IP allowed", "http://127.0.0.1:8080", ""},
		{"http localhost allowed", "http://localhost:8080", ""},
		{"http non-loopback host rejected", "http://example.com", "must use https"},
		{"unparseable url rejected", "http://[::1", "invalid keyorix_url"},
		{"no host rejected", "not-a-url", "invalid keyorix_url"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateFetcherBaseURL(c.raw)
			if c.wantErr == "" {
				assert.NoError(t, err, "raw %q", c.raw)
				return
			}
			require.Error(t, err, "raw %q", c.raw)
			assert.Contains(t, err.Error(), c.wantErr)
		})
	}
}

// TestIsLoopbackHostname covers all three ways a host can be recognized (or not) as
// loopback: the literal "localhost", a loopback IP literal, and a non-loopback host
// (by name or by IP) which must return false.
func TestIsLoopbackHostname(t *testing.T) {
	assert.True(t, isLoopbackHostname("localhost"))
	assert.True(t, isLoopbackHostname("127.0.0.1"))
	assert.True(t, isLoopbackHostname("::1"))
	assert.False(t, isLoopbackHostname("example.com"))
	assert.False(t, isLoopbackHostname("8.8.8.8"))
}

// TestKeyorixFetcher_InvalidBaseURLRejectedAtRequestTime exercises getJSON's runtime
// re-validation of f.baseURL: a fetcher built (NewKeyorixFetcher never itself
// validates baseURL) with an http URL to a non-loopback host must have every request
// refused at request time, before any network call is attempted.
func TestKeyorixFetcher_InvalidBaseURLRejectedAtRequestTime(t *testing.T) {
	f := NewKeyorixFetcher("http://example.com", "tok", 1)
	_, err := f.Fetch(context.Background(), "production/db-password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use https")
}

// TestKeyorixFetcher_ResolveID_ListSecretsError exercises resolveID's error path when
// the environment resolves fine but the subsequent, environment-scoped secrets-list
// call itself fails (a transient 5xx here, distinct from the "not found" case already
// covered by TestKeyorixFetcher_NotFound).
func TestKeyorixFetcher_ResolveID_ListSecretsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/environments"):
			_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":5,"Name":"production"}]}}`))
		case r.URL.Path == "/api/v1/secrets":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok", 1)

	_, err := f.Fetch(context.Background(), "production/db-password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list secrets in project")
	assert.Contains(t, err.Error(), "HTTP 500")
}

// stubSecret is one entry the fake secrets-list endpoint serves.
type stubSecret struct {
	ID   uint
	Name string
}

// keyorixStub serves the endpoints the fetcher uses: the project's environment list
// (GET /api/v1/projects/{projectID}/environments), the environment+project-scoped,
// paginated secrets list (GET /api/v1/secrets), and the value read
// (GET /api/v1/secrets/{id}). environments maps environment name -> id; secretsByEnv
// maps environment id -> the secrets "in" that environment (used to build both the
// list response, respecting project_id/environment_id/page/page_size, and to serve
// each secret's value).
func keyorixStub(t *testing.T, wantToken string, projectID uint, environments map[string]uint, secretsByEnv map[uint][]stubSecret) *httptest.Server {
	t.Helper()
	// id -> value, derived so /secrets/{id}?include_value=true can answer directly.
	valueByID := make(map[uint]string)
	for _, secrets := range secretsByEnv {
		for _, s := range secrets {
			valueByID[s.ID] = fmt.Sprintf("value-of-%d", s.ID)
		}
	}
	projPrefix := fmt.Sprintf("/api/v1/projects/%d/environments", projectID)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == projPrefix:
			var buf string
			buf = `{"data":{"environments":[`
			first := true
			for name, id := range environments {
				if !first {
					buf += ","
				}
				first = false
				buf += fmt.Sprintf(`{"ID":%d,"Name":%q}`, id, name)
			}
			buf += `]}}`
			_, _ = w.Write([]byte(buf))

		case r.URL.Path == "/api/v1/secrets":
			gotProject := r.URL.Query().Get("project_id")
			gotEnv := r.URL.Query().Get("environment_id")
			if gotProject != strconv.FormatUint(uint64(projectID), 10) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			envID, err := strconv.ParseUint(gotEnv, 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			all := secretsByEnv[uint(envID)]

			page := 1
			if p := r.URL.Query().Get("page"); p != "" {
				page, _ = strconv.Atoi(p)
			}
			pageSize := 100
			if ps := r.URL.Query().Get("page_size"); ps != "" {
				if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
					pageSize = v
				} else {
					pageSize = 20 // server's silent fallback for an out-of-range page_size
				}
			}
			totalPages := (len(all) + pageSize - 1) / pageSize
			if totalPages == 0 {
				totalPages = 1
			}
			start := (page - 1) * pageSize
			end := start + pageSize
			if start > len(all) {
				start = len(all)
			}
			if end > len(all) {
				end = len(all)
			}
			pageItems := all[start:end]

			buf := fmt.Sprintf(`{"data":{"total_pages":%d,"secrets":[`, totalPages)
			for i, s := range pageItems {
				if i > 0 {
					buf += ","
				}
				buf += fmt.Sprintf(`{"ID":%d,"Name":%q}`, s.ID, s.Name)
			}
			buf += `]}}`
			_, _ = w.Write([]byte(buf))

		case r.URL.Query().Get("include_value") == "true":
			var id uint
			_, _ = fmt.Sscanf(r.URL.Path, "/api/v1/secrets/%d", &id)
			val, ok := valueByID[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"value":%q}}`, val)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestKeyorixFetcher_Fetch(t *testing.T) {
	srv := keyorixStub(t, "tok", 1,
		map[string]uint{"production": 5},
		map[uint][]stubSecret{5: {{ID: 7, Name: "db-password"}, {ID: 9, Name: "api-key"}}},
	)
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok", 1)

	val, err := f.Fetch(context.Background(), "production/db-password")
	require.NoError(t, err)
	assert.Equal(t, []byte("value-of-7"), val)
}

func TestKeyorixFetcher_NotFound(t *testing.T) {
	srv := keyorixStub(t, "tok", 1,
		map[string]uint{"production": 5},
		map[uint][]stubSecret{5: {{ID: 7, Name: "db-password"}}},
	)
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok", 1)

	_, err := f.Fetch(context.Background(), "production/missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	assert.ErrorIs(t, err, ErrUpstreamGone)
}

func TestKeyorixFetcher_Unauthorized(t *testing.T) {
	srv := keyorixStub(t, "tok", 1,
		map[string]uint{"production": 5},
		map[uint][]stubSecret{5: {{ID: 7, Name: "db-password"}}},
	)
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "wrong-token", 1)

	_, err := f.Fetch(context.Background(), "production/db-password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

// TestKeyorixFetcher_EnvCacheExpiresAfterTTL pins the fix for the stale-cache
// finding: a renamed-then-reused environment name must eventually resolve to
// the NEW id, not the id cached before the TTL. environments is a live map
// reference the stub server's handler closes over, so mutating it here after
// the server starts simulates the server-side rename mid-test.
func TestKeyorixFetcher_EnvCacheExpiresAfterTTL(t *testing.T) {
	environments := map[string]uint{"production": 5}
	srv := keyorixStub(t, "tok", 1,
		environments,
		map[uint][]stubSecret{
			5: {{ID: 7, Name: "db-password"}},
			9: {{ID: 11, Name: "db-password"}},
		},
	)
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok", 1)

	now := time.Now()
	f.now = func() time.Time { return now }

	val, err := f.Fetch(context.Background(), "production/db-password")
	require.NoError(t, err)
	assert.Equal(t, []byte("value-of-7"), val, "first resolution: production -> env 5")

	// Simulate env 5 being renamed away and a NEW environment reusing the name
	// "production" with id 9 — the same map the running stub server reads from.
	delete(environments, "production")
	environments["production"] = 9

	// Still within the TTL: the cached (now-stale) mapping is still used —
	// this is the existing, intentional "don't hit the network on every call"
	// behavior, unchanged by this fix.
	val, err = f.Fetch(context.Background(), "production/db-password")
	require.NoError(t, err)
	assert.Equal(t, []byte("value-of-7"), val, "within TTL: still resolves to the stale cached env 5")

	// Advance past the TTL: resolveEnvironmentID must now force a fresh lookup
	// and pick up the renamed environment's new id.
	now = now.Add(envCacheTTL + time.Second)

	val, err = f.Fetch(context.Background(), "production/db-password")
	require.NoError(t, err)
	assert.Equal(t, []byte("value-of-11"), val, "after TTL: re-resolves to the new env 9")
}

func TestKeyorixFetcher_BadRef(t *testing.T) {
	f := NewKeyorixFetcher("http://example.invalid", "tok", 1)
	_, err := f.Fetch(context.Background(), "noslash")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ref")
}

// TestKeyorixFetcher_EnvironmentNotFound verifies that an environment name absent
// from this fetcher's project resolves to an ErrUpstreamGone "not found", rather than
// e.g. panicking or silently matching some other project's environment (there is no
// other project reachable from a single fetcher instance at all — see Bug1 tests
// below for the same-name-different-environment case).
func TestKeyorixFetcher_EnvironmentNotFound(t *testing.T) {
	srv := keyorixStub(t, "tok", 1,
		map[string]uint{"production": 5},
		map[uint][]stubSecret{5: {{ID: 7, Name: "db-password"}}},
	)
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok", 1)

	_, err := f.Fetch(context.Background(), "staging/db-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUpstreamGone)
	assert.Contains(t, err.Error(), "environment")
}

// TestKeyorixFetcher_SameNameDifferentEnvironment_Bug1 proves the fix for Bug1: two
// environments in the SAME project each have a secret named "db-password" with a
// DIFFERENT id. Resolving "production/db-password" must return production's secret
// (id 7) and its value — never staging's (id 77) — because the list call is scoped
// server-side by BOTH project_id and the resolved environment_id, not by an
// unscoped, name-only search across every environment the token can see.
func TestKeyorixFetcher_SameNameDifferentEnvironment_Bug1(t *testing.T) {
	srv := keyorixStub(t, "tok", 1,
		map[string]uint{"production": 5, "staging": 6},
		map[uint][]stubSecret{
			5: {{ID: 7, Name: "db-password"}},
			6: {{ID: 77, Name: "db-password"}},
		},
	)
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok", 1)

	val, err := f.Fetch(context.Background(), "production/db-password")
	require.NoError(t, err)
	assert.Equal(t, []byte("value-of-7"), val, "must resolve production's secret, not staging's same-named one")

	val, err = f.Fetch(context.Background(), "staging/db-password")
	require.NoError(t, err)
	assert.Equal(t, []byte("value-of-77"), val, "must resolve staging's secret, not production's same-named one")
}

// TestKeyorixFetcher_ExactCaseMatch_Bug3 proves the fix for Bug3: within ONE
// environment, a secret named "DB-Password" (a differently-cased duplicate, e.g.
// created by a lower-privileged co-tenant) must never shadow "db-password" — the
// match is exact, not case-insensitive.
func TestKeyorixFetcher_ExactCaseMatch_Bug3(t *testing.T) {
	srv := keyorixStub(t, "tok", 1,
		map[string]uint{"production": 5},
		map[uint][]stubSecret{5: {
			{ID: 99, Name: "DB-Password"}, // impostor: listed FIRST, wrong case
			{ID: 7, Name: "db-password"},  // the intended secret
		}},
	)
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok", 1)

	val, err := f.Fetch(context.Background(), "production/db-password")
	require.NoError(t, err)
	assert.Equal(t, []byte("value-of-7"), val, "must resolve the exact-case match, not the differently-cased impostor")
}

// TestKeyorixFetcher_PaginatesPastServerDefault_Bug2 proves the fix for Bug2: the
// target secret is ranked past position 100 (the server's actual page_size cap) —
// it would never be found on page 1 alone (nor within the server's silent 20-item
// default fallback) — but resolveID must still paginate through to find it rather
// than reporting it "not found" (which, in the real sync loop, would cause a
// mistaken delete of the previously-synced Kubernetes Secret).
func TestKeyorixFetcher_PaginatesPastServerDefault_Bug2(t *testing.T) {
	secrets := make([]stubSecret, 0, 250)
	for i := range 250 {
		secrets = append(secrets, stubSecret{ID: uint(1000 + i), Name: fmt.Sprintf("filler-%d", i)})
	}
	// The target is the very last entry — on page 3 at page_size=100.
	secrets = append(secrets, stubSecret{ID: 42, Name: "db-password"})

	srv := keyorixStub(t, "tok", 1,
		map[string]uint{"production": 5},
		map[uint][]stubSecret{5: secrets},
	)
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok", 1)

	val, err := f.Fetch(context.Background(), "production/db-password")
	require.NoError(t, err)
	assert.Equal(t, []byte("value-of-42"), val)
}

// TestKeyorixFetcher_CachesEnvironmentList verifies that resolving two mappings in
// the same environment only fetches the environment list once (the second Fetch call
// hits the cache), by counting requests to the environments endpoint.
func TestKeyorixFetcher_CachesEnvironmentList(t *testing.T) {
	var envCalls int
	envPath := "/api/v1/projects/1/environments"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == envPath:
			envCalls++
			_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":5,"Name":"production"}]}}`))
		case r.URL.Path == "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"total_pages":1,"secrets":[{"ID":7,"Name":"db-password"},{"ID":9,"Name":"api-key"}]}}`))
		case r.URL.Query().Get("include_value") == "true":
			_, _ = w.Write([]byte(`{"data":{"value":"x"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	f := NewKeyorixFetcher(srv.URL, "tok", 1)
	_, err := f.Fetch(context.Background(), "production/db-password")
	require.NoError(t, err)
	_, err = f.Fetch(context.Background(), "production/api-key")
	require.NoError(t, err)

	assert.Equal(t, 1, envCalls, "the environment list should be fetched once and cached")
}
