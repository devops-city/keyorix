package k8ssync

// A 401 from Keyorix means the agent's OWN credential was rejected (invalid, expired or
// rotated). Policy (Andrei, 2026-10-13): never wipe on it, whatever prune_on_revoke says;
// keep every synced Secret, report it (auth_failed + a log line), back off, and sync
// normally once the credential is fixed. 403/404 are unchanged (see sync_test.go).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authFetcher serves values; refs in unauthorized fail like a 401, refs in revoked like a
// 403/404 (ErrUpstreamGone).
type authFetcher struct {
	values       map[string][]byte
	unauthorized bool
	revoked      map[string]bool
}

func (f *authFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	if f.unauthorized {
		return nil, fmt.Errorf("not authorized (HTTP 401): %w", ErrUnauthorized)
	}
	if f.revoked[ref] {
		return nil, fmt.Errorf("secret %q gone: %w", ref, ErrUpstreamGone)
	}
	return f.values[ref], nil
}

// TestFetcher_StatusDecidesClassification: the split comes from the HTTP status only, never
// from message text. A 401 whose body says "not found" is ErrUnauthorized, not Gone; a
// 403/404 whose body says "unauthorized" is Gone, not ErrUnauthorized.
func TestFetcher_StatusDecidesClassification(t *testing.T) {
	cases := []struct {
		status   int
		body     string
		wantAuth bool
		wantGone bool
	}{
		{http.StatusUnauthorized, `{"error":"not found","message":"secret revoked, access forbidden"}`, true, false},
		{http.StatusForbidden, `{"error":"unauthorized","message":"401 invalid token"}`, false, true},
		{http.StatusNotFound, `{"error":"unauthorized","message":"bearer token rejected"}`, false, true},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		f := NewKeyorixFetcher(srv.URL, "tok", 1)
		_, err := f.Fetch(context.Background(), "prod/secret")
		srv.Close()
		require.Error(t, err)
		assert.Equal(t, tc.wantAuth, errors.Is(err, ErrUnauthorized), "status %d", tc.status)
		assert.Equal(t, tc.wantGone, errors.Is(err, ErrUpstreamGone), "status %d", tc.status)
	}
}

// TestReconcile_Unauthorized_KeepsSecretsThenRecovers drives the real engine: after a
// good sync the token is rejected; with prune_on_revoke at its default (true) nothing is
// wiped or rewritten, the pass reports auth_failed + failed, and when the credential is
// fixed the next pass syncs the rotated value.
func TestReconcile_Unauthorized_KeepsSecretsThenRecovers(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"prune_on_revoke default", nil},
		{"prune_on_revoke false", []Option{WithKeepOnRevoke()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &authFetcher{values: map[string][]byte{"prod/db": []byte("p4ss"), "prod/api": []byte("k3y")}}
			s := newFakeSink()
			e := NewEngine(f, s, tc.opts...)
			maps := []SecretMapping{
				{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
				{Ref: "prod/api", Namespace: "app", Name: "other", Key: "API_KEY"},
			}
			res, err := e.Reconcile(context.Background(), maps)
			require.NoError(t, err)
			require.Equal(t, 2, res.Created)

			f.unauthorized = true
			for i := 0; i < 2; i++ {
				res, err = e.Reconcile(context.Background(), maps)
				require.NoError(t, err)
				assert.Equal(t, 2, res.AuthFailed)
				assert.Equal(t, 2, res.Failed, "counted as failed so the loop backs off")
				assert.Zero(t, res.Revoked)
				assert.Zero(t, res.Suspected)
				assert.Zero(t, res.Deleted)
				assert.Empty(t, s.deleted, "a 401 never deletes")
				assert.Equal(t, []byte("p4ss"), s.existing["app/creds"]["DB_PASSWORD"])
				assert.Equal(t, []byte("k3y"), s.existing["app/other"]["API_KEY"])
				require.NotEmpty(t, res.Errors)
				assert.Contains(t, res.Errors[0], "KeyorixAuthFailed")
			}

			// Credential fixed (and the value rotated meanwhile): normal sync resumes.
			f.unauthorized = false
			f.values["prod/db"] = []byte("n3w")
			res, err = e.Reconcile(context.Background(), maps)
			require.NoError(t, err)
			assert.Zero(t, res.AuthFailed)
			assert.Zero(t, res.Failed)
			assert.Equal(t, 1, res.Updated)
			assert.Equal(t, []byte("n3w"), s.existing["app/creds"]["DB_PASSWORD"])
		})
	}
}

// TestReconcile_Unauthorized_OneKeyOfMultiKeySecretKeepsWholeSecret: a 401 on any mapping
// of a target skips the whole target; no key is trimmed.
func TestReconcile_Unauthorized_OneKeyOfMultiKeySecretKeepsWholeSecret(t *testing.T) {
	f := &authFetcher{values: map[string][]byte{"prod/db": []byte("p4ss"), "prod/api": []byte("k3y")}}
	s := newFakeSink()
	e := NewEngine(f, s)
	maps := []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
		{Ref: "prod/api", Namespace: "app", Name: "creds", Key: "API_KEY"},
	}
	_, err := e.Reconcile(context.Background(), maps)
	require.NoError(t, err)
	f.unauthorized = true
	res, err := e.Reconcile(context.Background(), maps)
	require.NoError(t, err)
	assert.Equal(t, 1, res.AuthFailed)
	assert.Equal(t, map[string][]byte{"DB_PASSWORD": []byte("p4ss"), "API_KEY": []byte("k3y")}, s.existing["app/creds"])
}

// TestReconcile_Forbidden_StillWipesAsBefore: control for the same engine, mapping and
// sink: a 403/404 (ErrUpstreamGone) removes the Secret exactly as before, and is not
// counted as auth_failed.
func TestReconcile_Forbidden_StillWipesAsBefore(t *testing.T) {
	f := &authFetcher{values: map[string][]byte{"prod/db": []byte("p4ss")}, revoked: map[string]bool{}}
	s := newFakeSink()
	e := NewEngine(f, s)
	maps := []SecretMapping{{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"}}
	_, err := e.Reconcile(context.Background(), maps)
	require.NoError(t, err)
	f.revoked["prod/db"] = true
	res, err := e.Reconcile(context.Background(), maps)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Revoked)
	assert.Zero(t, res.AuthFailed)
	assert.Contains(t, s.deleted, "app/creds")
}

// TestStatus_ReportsAuthFailed: /status and /metrics expose the new outcome.
func TestStatus_ReportsAuthFailed(t *testing.T) {
	st := NewStatus()
	st.Record(Result{Failed: 2, AuthFailed: 2})
	m := st.metrics()
	assert.Contains(t, m, `keyorix_k8s_sync_secrets_total{outcome="auth_failed"} 2`)
	assert.Contains(t, m, `keyorix_k8s_sync_secrets_total{outcome="revoked"} 0`)
}

// TestRun_UnauthorizedBacksOffAndLogs: the loop treats a 401 pass as unhealthy (backoff)
// and the one-line summary and per-target error name KeyorixAuthFailed.
func TestRun_UnauthorizedBacksOffAndLogs(t *testing.T) {
	f := &authFetcher{unauthorized: true}
	s := newFakeSink()
	s.existing["app/creds"] = map[string][]byte{"DB_PASSWORD": []byte("kept")}
	s.owned["app/creds"] = true
	e := NewEngine(f, s)
	var lines []string
	logf := func(format string, args ...interface{}) { lines = append(lines, fmt.Sprintf(format, args...)) }
	res := Sync(context.Background(), e, []SecretMapping{{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"}}, logf)
	assert.Equal(t, 1, res.AuthFailed)
	joined := strings.Join(lines, "\n")
	assert.Contains(t, joined, "auth_failed=1")
	assert.Contains(t, joined, "KeyorixAuthFailed")
	assert.Equal(t, []byte("kept"), s.existing["app/creds"]["DB_PASSWORD"])
	// Failed > 0 engages the existing failure backoff (see run).
	assert.Greater(t, nextDelay(time.Minute, 1, func() float64 { return 0.5 }), time.Minute)
}
