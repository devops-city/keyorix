package k8ssync

// Keyorix could not answer (no response, timeout, 5xx): the agent keeps every synced
// Secret, counts the target failed AND keyorix_unreachable, names KeyorixUnreachable and
// the reason in the pass log (the operator's counterpart is KeyorixUnreachable +
// keyorix_operator_fetch_errors_total{reason}), backs off, and syncs normally once Keyorix
// answers again.

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

// TestFetcher_CouldNotAnswerClassification: classification comes from the transport error
// and the status only, never from body text; sentinels are mutually exclusive and never
// gone/unauthorized. A plain 4xx and a cancelled context are none of them.
func TestFetcher_CouldNotAnswerClassification(t *testing.T) {
	sentinels := []error{ErrUnreachable, ErrTimeout, ErrServerError}
	check := func(t *testing.T, err error, want error) {
		t.Helper()
		require.Error(t, err)
		for _, s := range sentinels {
			assert.Equal(t, s == want, errors.Is(err, s), "%v vs %v", err, s)
		}
		assert.False(t, errors.Is(err, ErrUpstreamGone))
		assert.False(t, errors.Is(err, ErrUnauthorized))
	}

	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()
		_, err := NewKeyorixFetcher(url, "tok", 1).Fetch(context.Background(), "prod/secret")
		check(t, err, ErrUnreachable)
		assert.Equal(t, "unreachable", fetchUnavailableReason(err))
	})

	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		defer srv.Close()
		defer close(release)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := NewKeyorixFetcher(srv.URL, "tok", 1).Fetch(ctx, "prod/secret")
		check(t, err, ErrTimeout)
		assert.Equal(t, "timeout", fetchUnavailableReason(err))
	})

	for _, status := range []int{500, 502, 503, 504} {
		t.Run(fmt.Sprintf("http %d", status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"not found","message":"unauthorized"}`))
			}))
			defer srv.Close()
			_, err := NewKeyorixFetcher(srv.URL, "tok", 1).Fetch(context.Background(), "prod/secret")
			check(t, err, ErrServerError)
			assert.Equal(t, "server_error", fetchUnavailableReason(err))
		})
	}

	t.Run("plain 4xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()
		_, err := NewKeyorixFetcher(srv.URL, "tok", 1).Fetch(context.Background(), "prod/secret")
		check(t, err, nil)
		assert.Empty(t, fetchUnavailableReason(err))
	})

	t.Run("cancelled context", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		defer srv.Close()
		defer close(release)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := NewKeyorixFetcher(srv.URL, "tok", 1).Fetch(ctx, "prod/secret")
		check(t, err, nil)
	})
}

// downFetcher fails every fetch with err while down is set.
type downFetcher struct {
	values map[string][]byte
	err    error
}

func (f *downFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.values[ref], nil
}

// TestReconcile_FetchUnavailable_KeepsSecretsThenRecovers drives the real engine for each
// could-not-answer kind: nothing is deleted or rewritten, the pass reports
// keyorix_unreachable + failed (not auth_failed, not revoked), and the next healthy pass
// syncs the rotated value.
func TestReconcile_FetchUnavailable_KeepsSecretsThenRecovers(t *testing.T) {
	for _, tc := range []struct {
		reason string
		err    error
	}{
		{"unreachable", fmt.Errorf("request failed: connection refused: %w", ErrUnreachable)},
		{"timeout", fmt.Errorf("request failed: deadline exceeded: %w", ErrTimeout)},
		{"server_error", fmt.Errorf("server returned HTTP 503: %w", ErrServerError)},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			f := &downFetcher{values: map[string][]byte{"prod/db": []byte("p4ss"), "prod/api": []byte("k3y")}}
			s := newFakeSink()
			e := NewEngine(f, s)
			maps := []SecretMapping{
				{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
				{Ref: "prod/api", Namespace: "app", Name: "other", Key: "API_KEY"},
			}
			res, err := e.Reconcile(context.Background(), maps)
			require.NoError(t, err)
			require.Equal(t, 2, res.Created)

			f.err = tc.err
			for range 2 {
				res, err = e.Reconcile(context.Background(), maps)
				require.NoError(t, err)
				assert.Equal(t, 2, res.KeyorixUnreachable)
				assert.Equal(t, 2, res.Failed, "counted as failed so the loop backs off")
				assert.Zero(t, res.AuthFailed)
				assert.Zero(t, res.Revoked)
				assert.Zero(t, res.Deleted)
				assert.Empty(t, s.deleted)
				assert.Equal(t, []byte("p4ss"), s.existing["app/creds"]["DB_PASSWORD"])
				assert.Equal(t, []byte("k3y"), s.existing["app/other"]["API_KEY"])
				require.NotEmpty(t, res.Errors)
				assert.Contains(t, res.Errors[0], "KeyorixUnreachable ("+tc.reason+")")
			}

			f.err = nil
			f.values["prod/db"] = []byte("n3w")
			res, err = e.Reconcile(context.Background(), maps)
			require.NoError(t, err)
			assert.Zero(t, res.KeyorixUnreachable)
			assert.Zero(t, res.Failed)
			assert.Equal(t, 1, res.Updated)
			assert.Equal(t, []byte("n3w"), s.existing["app/creds"]["DB_PASSWORD"])
		})
	}
}

// TestStatus_ReportsKeyorixUnreachable: /status and /metrics expose the outcome.
func TestStatus_ReportsKeyorixUnreachable(t *testing.T) {
	st := NewStatus()
	st.Record(Result{Failed: 3, KeyorixUnreachable: 3})
	m := st.metrics()
	assert.Contains(t, m, `keyorix_k8s_sync_secrets_total{outcome="keyorix_unreachable"} 3`)
	assert.Contains(t, m, `keyorix_k8s_sync_secrets_total{outcome="auth_failed"} 0`)
	assert.Contains(t, m, `keyorix_k8s_sync_secrets_total{outcome="failed"} 3`)
}

// TestRun_FetchUnavailableBacksOffAndLogs: the summary line and the per-target error name
// KeyorixUnreachable and the loop backs off.
func TestRun_FetchUnavailableBacksOffAndLogs(t *testing.T) {
	f := &downFetcher{err: fmt.Errorf("server returned HTTP 502: %w", ErrServerError)}
	s := newFakeSink()
	s.existing["app/creds"] = map[string][]byte{"DB_PASSWORD": []byte("kept")}
	s.owned["app/creds"] = true
	e := NewEngine(f, s)
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	res := Sync(context.Background(), e, []SecretMapping{{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"}}, logf)
	assert.Equal(t, 1, res.KeyorixUnreachable)
	joined := strings.Join(lines, "\n")
	assert.Contains(t, joined, "keyorix_unreachable=1")
	assert.Contains(t, joined, "KeyorixUnreachable (server_error)")
	assert.Equal(t, []byte("kept"), s.existing["app/creds"]["DB_PASSWORD"])
	assert.Greater(t, nextDelay(time.Minute, 1, func() float64 { return 0.5 }), time.Minute)
}
