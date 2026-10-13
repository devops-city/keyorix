package keyorix

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_FetchValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/value", r.URL.Path)
		assert.Equal(t, "app/production/db", r.URL.Query().Get("ref"))
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"data":{"secret":{"Name":"db"},"value":"p4ss"}}`))
	}))
	defer srv.Close()

	v, err := New(srv.URL, "tok").FetchValue(context.Background(), "app/production/db")
	require.NoError(t, err)
	assert.Equal(t, []byte("p4ss"), v)
}

// TestClient_FetchValueMissingDataValueErrors pins the fix for finding
// operator-keyorix.json#0: a 200 response whose body omits data.value entirely (a
// malformed/unexpected response shape, a partial response, or an upstream API contract
// change) must return an explicit error, never a silent ("", nil) success that would
// materialize an empty Kubernetes Secret value in place of a real one.
func TestClient_FetchValueMissingDataValueErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No "value" key in data at all -- distinct from an explicit "value":"".
		_, _ = w.Write([]byte(`{"data":{"secret":{"Name":"db"}}}`))
	}))
	defer srv.Close()

	v, err := New(srv.URL, "tok").FetchValue(context.Background(), "app/production/db")
	require.Error(t, err, "a 200 response missing data.value must not silently succeed")
	assert.Nil(t, v)
	assert.Contains(t, err.Error(), "missing data.value")
}

// TestClient_FetchValueExplicitEmptyValueSucceeds pins the other half of the same fix:
// a response that explicitly sets data.value to "" is a deliberate, well-formed answer
// (the wire contract doesn't forbid it, even though today's server-side validation never
// produces one in practice) and must be returned as a real empty value, not treated as
// the same failure as an outright missing field.
func TestClient_FetchValueExplicitEmptyValueSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secret":{"Name":"db"},"value":""}}`))
	}))
	defer srv.Close()

	v, err := New(srv.URL, "tok").FetchValue(context.Background(), "app/production/db")
	require.NoError(t, err)
	assert.Equal(t, []byte(""), v)
}

func TestClient_FetchValueErrors(t *testing.T) {
	cases := map[int]string{
		http.StatusUnauthorized:        "not authorized",
		http.StatusForbidden:           "forbidden",
		http.StatusNotFound:            "not found",
		http.StatusBadRequest:          "invalid reference",
		http.StatusInternalServerError: "HTTP 500",
	}
	for status, want := range cases {
		t.Run(want, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
		})
	}
}

// TestClient_FetchValueErrorGoneClassification pins the 404/403-vs-everything-else
// distinction the operator controller relies on (#428): a 404 or 403 must wrap
// ErrSecretGone so the controller can treat it as "the secret is confirmed gone" and
// wipe the stale target Secret, while every other failure (401, 400, 5xx, network)
// must NOT wrap it — those are ambiguous or transient and must never trigger a
// destructive action against a previously synced Secret.
func TestClient_FetchValueErrorGoneClassification(t *testing.T) {
	cases := []struct {
		status   int
		wantGone bool
	}{
		{http.StatusNotFound, true},
		{http.StatusForbidden, true},
		{http.StatusUnauthorized, false},
		{http.StatusBadRequest, false},
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusServiceUnavailable, false},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
			require.Error(t, err)
			assert.Equal(t, tc.wantGone, errors.Is(err, ErrSecretGone),
				"HTTP %d: errors.Is(err, ErrSecretGone) = %v, want %v", tc.status, errors.Is(err, ErrSecretGone), tc.wantGone)
		})
	}
}

// A genuine network failure (no HTTP response at all — connection refused here) must
// never be classified as ErrSecretGone: it says nothing about whether the secret
// still exists, only that this attempt to reach the server failed transiently.
func TestClient_FetchValueNetworkErrorIsNotGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	unreachable := srv.URL
	srv.Close() // closed before use: connections to this URL are refused

	_, err := New(unreachable, "tok").FetchValue(context.Background(), "a/b/c")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSecretGone), "a connection-refused error must not be classified as ErrSecretGone")
}

// TestClient_FetchValueUnauthorizedWrapsErrUnauthorized pins the 401 classification the
// operator controller relies on: a 401 must wrap ErrUnauthorized (distinct from
// ErrSecretGone, which stays reserved for a confirmed 404/403) so the controller keeps
// the target Secret and reports KeyorixAuthFailed instead of wiping it.
func TestClient_FetchValueUnauthorizedWrapsErrUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized), "a 401 must wrap ErrUnauthorized")
	assert.False(t, errors.Is(err, ErrSecretGone), "a 401 must NOT wrap ErrSecretGone — it says nothing about the referenced secret's own fate")
}

// TestClient_StatusDecidesClassification: the 401 / 403 / 404 split comes from the HTTP
// status alone, never from message text. A 401 whose body says "not found" is still
// ErrUnauthorized; a 404 or 403 whose body says "unauthorized" is still ErrSecretGone.
func TestClient_StatusDecidesClassification(t *testing.T) {
	cases := []struct {
		status   int
		body     string
		wantAuth bool
		wantGone bool
	}{
		{http.StatusUnauthorized, `{"error":"not found","message":"secret revoked, access forbidden"}`, true, false},
		{http.StatusNotFound, `{"error":"unauthorized","message":"bearer token rejected"}`, false, true},
		{http.StatusForbidden, `{"error":"unauthorized","message":"401 invalid token"}`, false, true},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
		srv.Close()
		require.Error(t, err)
		assert.Equal(t, tc.wantAuth, errors.Is(err, ErrUnauthorized), "status %d", tc.status)
		assert.Equal(t, tc.wantGone, errors.Is(err, ErrSecretGone), "status %d", tc.status)
	}
}

// TestClient_CouldNotAnswerClassification: connection refused, a timed-out request and a
// 5xx are classified ErrUnreachable / ErrTimeout / ErrServerError from the transport error
// and the status alone, each exclusive of the others and never gone/unauthorized. A
// cancelled context and a plain 4xx are none of them.
func TestClient_CouldNotAnswerClassification(t *testing.T) {
	sentinels := []error{ErrUnreachable, ErrTimeout, ErrServerError}
	check := func(t *testing.T, err error, want error) {
		t.Helper()
		require.Error(t, err)
		for _, s := range sentinels {
			assert.Equal(t, s == want, errors.Is(err, s), "%v vs %v", err, s)
		}
		assert.False(t, errors.Is(err, ErrSecretGone))
		assert.False(t, errors.Is(err, ErrUnauthorized))
	}

	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()
		_, err := New(url, "tok").FetchValue(context.Background(), "a/b/c")
		check(t, err, ErrUnreachable)
	})

	t.Run("client timeout", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		defer srv.Close()
		defer close(release)
		c := New(srv.URL, "tok")
		c.hc.Timeout = 50 * time.Millisecond
		_, err := c.FetchValue(context.Background(), "a/b/c")
		check(t, err, ErrTimeout)
	})

	t.Run("context deadline", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		defer srv.Close()
		defer close(release)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := New(srv.URL, "tok").FetchValue(ctx, "a/b/c")
		check(t, err, ErrTimeout)
	})

	for _, status := range []int{500, 502, 503, 504} {
		t.Run(fmt.Sprintf("http %d", status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"not found","message":"unauthorized"}`))
			}))
			defer srv.Close()
			_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
			check(t, err, ErrServerError)
		})
	}

	t.Run("plain 4xx is none of them", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()
		_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
		check(t, err, nil)
	})

	t.Run("cancelled context is none of them", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		defer srv.Close()
		defer close(release)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := New(srv.URL, "tok").FetchValue(ctx, "a/b/c")
		check(t, err, nil)
	})
}

// TestClient_RefusesRedirect pins the fix for a bearer-token-leak-on-downgrade bug: Go's
// default http.Client only strips the Authorization header when a redirect's Host
// differs from the original — never when only the scheme changes, so a same-host
// https->http redirect would otherwise carry the bearer token (and the plaintext secret
// value in the response) over cleartext. This client has no legitimate reason to follow
// any redirect, so CheckRedirect must refuse every one outright.
func TestClient_RefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If a redirect were followed, the Authorization header would land here.
		assert.Fail(t, "the client must never actually reach the redirect target", "Authorization=%q", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/secrets/value", http.StatusFound)
	}))
	defer redirector.Close()

	_, err := New(redirector.URL, "tok").FetchValue(context.Background(), "a/b/c")
	require.Error(t, err, "a redirect must be refused, not silently followed")
	assert.Contains(t, err.Error(), "redirect")
}

// TestClient_FetchValueMalformedJSONBodyErrors pins that a 200 response whose body is
// not valid JSON at all (a proxy/gateway mangling the body, a non-JSON error page
// mistakenly served with a 200 status, etc.) surfaces as a decode error rather than a
// panic or a silently empty value.
func TestClient_FetchValueMalformedJSONBodyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	v, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
	require.Error(t, err)
	assert.Nil(t, v)
	assert.Contains(t, err.Error(), "decode response")
}

// TestClient_FetchValueRejectsInvalidBaseURL pins that FetchValue itself re-validates
// c.baseURL (not just at construction time) before ever issuing a request — see the
// validateClientBaseURL doc comment on why this direct read of c.baseURL matters for
// static analysis. A Client built with a non-https, non-loopback base URL must fail
// closed instead of sending the bearer token anywhere.
func TestClient_FetchValueRejectsInvalidBaseURL(t *testing.T) {
	c := &Client{baseURL: "ftp://example.com", token: "tok", hc: &http.Client{Timeout: time.Second}}
	v, err := c.FetchValue(context.Background(), "a/b/c")
	require.Error(t, err)
	assert.Nil(t, v)
	assert.Contains(t, err.Error(), "must use https")
}

// TestValidateClientBaseURL exercises every branch of validateClientBaseURL directly:
// unparseable URLs, missing hosts, the https-always-ok path, the http-loopback-only
// exception, and rejection of both non-loopback http and non-http/https schemes.
func TestValidateClientBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr string // substring; empty means no error
	}{
		{"unparseable URL", "http://example.com/%zz", "invalid base URL"},
		{"missing host", "not-a-url", "missing a host"},
		{"missing host, scheme only", "http://", "missing a host"},
		{"https any host accepted", "https://example.com", ""},
		{"http loopback hostname accepted", "http://localhost:8080", ""},
		{"http loopback IP accepted", "http://127.0.0.1:8080", ""},
		{"http non-loopback host rejected", "http://example.com", "must use https"},
		{"non-http/https scheme rejected", "ftp://localhost", "must use https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateClientBaseURL(tc.raw)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestIsLoopbackHost exercises every branch of isLoopbackHost: the literal "localhost"
// shortcut, IPv4/IPv6 loopback addresses, a parseable-but-non-loopback IP, and a
// non-IP, non-"localhost" hostname.
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			assert.Equal(t, tc.want, isLoopbackHost(tc.host))
		})
	}
}

// ERRMAP-1: the server names a secret-state refusal with a code. None of them is an
// access-cut signal: outside the access schedule and max-reads exhausted are
// ErrSecretUnavailable, suspended is ErrSecretSuspended and expired is ErrSecretExpired
// (FIX-3175B: the controller retains the target Secret for all of them and never wipes).
// A bare 403 without a code stays ErrSecretGone, and an unrelated 409 is none of them.
func TestClient_FetchValueSecretStateRefusals(t *testing.T) {
	cases := []struct {
		status                                int
		code                                  string
		gone, unavailable, suspended, expired bool
	}{
		{http.StatusForbidden, "SecretAccessOutsideSchedule", false, true, false, false},
		{http.StatusConflict, "SecretMaxReadsExhausted", false, true, false, false},
		{http.StatusConflict, "SecretSuspended", false, false, true, false},
		{http.StatusConflict, "SecretExpired", false, false, false, true},
		{http.StatusForbidden, "Forbidden", true, false, false, false},
		{http.StatusConflict, "ConflictError", false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprintf(w, `{"success":false,"code":%d,"error":%q,"message":"refused"}`, tc.status, tc.code)
			}))
			defer srv.Close()
			_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
			require.Error(t, err)
			assert.Equal(t, tc.gone, errors.Is(err, ErrSecretGone), "ErrSecretGone for %d %s: %v", tc.status, tc.code, err)
			assert.Equal(t, tc.unavailable, errors.Is(err, ErrSecretUnavailable), "ErrSecretUnavailable for %d %s: %v", tc.status, tc.code, err)
			assert.Equal(t, tc.suspended, errors.Is(err, ErrSecretSuspended), "ErrSecretSuspended for %d %s: %v", tc.status, tc.code, err)
			assert.Equal(t, tc.expired, errors.Is(err, ErrSecretExpired), "ErrSecretExpired for %d %s: %v", tc.status, tc.code, err)
		})
	}
}

// FetchValueInfo reports the source secret's expiration alongside the value.
func TestClient_FetchValueInfo_Expiration(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantExp    string
	}{
		{"with expiration", `{"data":{"value":"v","secret":{"expiration":"2030-01-02T03:04:05Z"}}}`, "2030-01-02T03:04:05Z"},
		{"null expiration", `{"data":{"value":"v","secret":{"expiration":null}}}`, ""},
		{"no secret block", `{"data":{"value":"v"}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			v, err := New(srv.URL, "tok").FetchValueInfo(context.Background(), "a/b/c")
			require.NoError(t, err)
			assert.Equal(t, "v", string(v.Data))
			if tc.wantExp == "" {
				assert.Nil(t, v.Expiration)
				return
			}
			require.NotNil(t, v.Expiration)
			assert.Equal(t, tc.wantExp, v.Expiration.UTC().Format("2006-01-02T15:04:05Z"))
		})
	}
}
