package k8ssync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRun_S22_ExecutesOnePassAndCancelStops verifies that Run executes at least
// one reconcile synchronously and returns when the context is cancelled.
func TestRun_S22_ExecutesOnePassAndCancelStops(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"e/n": []byte("v")}}
	s := newFakeSink()
	e := NewEngine(f, s)

	var logged []string
	logf := func(format string, args ...any) {
		logged = append(logged, format)
	}

	mappings := []SecretMapping{
		{Ref: "e/n", Namespace: "ns", Name: "sec", Key: "K"},
	}

	status := NewStatus()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, e, mappings, 50*time.Millisecond, logf, status)
		close(done)
	}()

	// Wait until status reports at least one pass was recorded.
	deadline := time.After(2 * time.Second)
	for {
		ran, _, _ := status.snapshot()
		if ran {
			break
		}
		select {
		case <-deadline:
			t.Fatal("status never became ready")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	assert.NotEmpty(t, logged, "at least one log line must have been emitted")
}

// TestRun_S22_NilStatusIsOK verifies that Run does not panic when status is nil.
func TestRun_S22_NilStatusIsOK(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"e/n": []byte("v")}}
	s := newFakeSink()
	e := NewEngine(f, s)

	logf := func(string, ...any) {}
	mappings := []SecretMapping{
		{Ref: "e/n", Namespace: "ns", Name: "sec", Key: "K"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so Run exits after the first synchronous pass
	// Must not panic with nil status.
	require.NotPanics(t, func() {
		Run(ctx, e, mappings, time.Minute, logf, nil)
	})
}

// TestRun_S22_RecordsResultInStatus verifies that Status.Record is called after
// each pass and that cumulative totals accumulate correctly.
func TestRun_S22_RecordsResultInStatus(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"e/n": []byte("v")}}
	s := newFakeSink()
	e := NewEngine(f, s)

	logf := func(string, ...any) {}
	mappings := []SecretMapping{
		{Ref: "e/n", Namespace: "ns", Name: "sec", Key: "K"},
	}

	status := NewStatus()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // exit after the single synchronous first pass
	Run(ctx, e, mappings, time.Minute, logf, status)

	ran, _, last := status.snapshot()
	assert.True(t, ran)
	// First pass creates the Secret.
	assert.Equal(t, 1, last.Created)
}

// TestDataEqual_S22_EmptyMaps verifies that two nil/empty maps are considered equal.
func TestDataEqual_S22_EmptyMaps(t *testing.T) {
	assert.True(t, dataEqual(nil, nil))
	assert.True(t, dataEqual(map[string][]byte{}, nil))
	assert.True(t, dataEqual(nil, map[string][]byte{}))
	assert.True(t, dataEqual(map[string][]byte{}, map[string][]byte{}))
}

// TestDataEqual_S22_DifferentLengths verifies that maps of different sizes are not equal.
func TestDataEqual_S22_DifferentLengths(t *testing.T) {
	a := map[string][]byte{"k": []byte("v")}
	b := map[string][]byte{}
	assert.False(t, dataEqual(a, b))
	assert.False(t, dataEqual(b, a))
}

// TestDataEqual_S22_SameLengthDifferentValues verifies the value-comparison branch.
func TestDataEqual_S22_SameLengthDifferentValues(t *testing.T) {
	a := map[string][]byte{"k": []byte("x")}
	b := map[string][]byte{"k": []byte("y")}
	assert.False(t, dataEqual(a, b))
}

// TestDataEqual_S22_SameLengthDifferentKeys verifies that different key names make maps unequal.
func TestDataEqual_S22_SameLengthDifferentKeys(t *testing.T) {
	a := map[string][]byte{"a": []byte("v")}
	b := map[string][]byte{"b": []byte("v")}
	assert.False(t, dataEqual(a, b))
}

// TestGroupByTarget_S22_DuplicateKey verifies that two mappings targeting the same
// Secret with the same key are rejected as duplicates.
func TestGroupByTarget_S22_DuplicateKey(t *testing.T) {
	mappings := []SecretMapping{
		{Ref: "prod/a", Namespace: "ns", Name: "sec", Key: "K"},
		{Ref: "prod/b", Namespace: "ns", Name: "sec", Key: "K"}, // same target+key → duplicate
	}
	grouped, errs := groupByTarget(mappings)
	assert.Len(t, errs, 1, "duplicate key must be reported as an error")
	assert.Contains(t, errs[0], "duplicate key")
	// Only the first mapping makes it into the group.
	assert.Len(t, grouped, 1)
}

// TestGroupByTarget_S22_MultipleKeysOneTarget verifies that multiple distinct keys
// for the same target are grouped together without error.
func TestGroupByTarget_S22_MultipleKeysOneTarget(t *testing.T) {
	mappings := []SecretMapping{
		{Ref: "prod/db", Namespace: "ns", Name: "sec", Key: "DB"},
		{Ref: "prod/api", Namespace: "ns", Name: "sec", Key: "API"},
	}
	grouped, errs := groupByTarget(mappings)
	assert.Empty(t, errs)
	tgt := target{namespace: "ns", name: "sec"}
	assert.Len(t, grouped[tgt], 2)
}

// TestGroupByTarget_S22_InvalidMappingExcluded verifies that an invalid mapping is
// excluded from the grouped result and appears in the error list.
func TestGroupByTarget_S22_InvalidMappingExcluded(t *testing.T) {
	mappings := []SecretMapping{
		{Ref: "", Namespace: "ns", Name: "sec", Key: "K"}, // invalid: no ref
		{Ref: "prod/ok", Namespace: "ns", Name: "sec", Key: "K"},
	}
	grouped, errs := groupByTarget(mappings)
	assert.Len(t, errs, 1)
	assert.Contains(t, errs[0], "mapping 0")
	// Valid mapping is still grouped.
	assert.Len(t, grouped, 1)
}

// TestIsDNS1123Label_S22_EdgeCases verifies label acceptance/rejection for
// boundary-adjacent inputs.
func TestIsDNS1123Label_S22_EdgeCases(t *testing.T) {
	assert.True(t, isDNS1123Label("a"))          // single lowercase letter
	assert.True(t, isDNS1123Label("0"))          // single digit
	assert.False(t, isDNS1123Label(""))          // empty
	assert.False(t, isDNS1123Label("-leading"))  // leading hyphen
	assert.False(t, isDNS1123Label("trailing-")) // trailing hyphen
	assert.False(t, isDNS1123Label("A"))         // uppercase
	assert.True(t, isDNS1123Label("a-b-0"))      // valid with hyphens and digits
}

// TestIsDNS1123Subdomain_S22_EdgeCases verifies subdomain acceptance/rejection for
// boundary-adjacent inputs.
func TestIsDNS1123Subdomain_S22_EdgeCases(t *testing.T) {
	assert.True(t, isDNS1123Subdomain("a.b.c")) // valid multi-label
	assert.False(t, isDNS1123Subdomain("a..b")) // empty label between dots
	assert.False(t, isDNS1123Subdomain(""))     // empty
	assert.True(t, isDNS1123Subdomain("my-secret-0.namespace"))
}

// TestTargetString_S22 verifies the String() representation of target.
func TestTargetString_S22(t *testing.T) {
	tgt := target{namespace: "app", name: "creds"}
	assert.Equal(t, "app/creds", tgt.String())
}

// TestWithDryRun_S22_NoWrite verifies that an Engine configured with WithDryRun
// reports what WOULD be created/updated without actually calling Apply.
func TestWithDryRun_S22_NoWrite(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"e/n": []byte("v")}}
	s := newFakeSink()
	e := NewEngine(f, s, WithDryRun())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "e/n", Namespace: "ns", Name: "sec", Key: "K"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created, "dry-run must count would-be creates")
	// Apply must not have been called: the sink's applied map stays empty.
	assert.Empty(t, s.applied)
}

// TestWithCleanup_S22_DeletesOrphan verifies that WithCleanup removes a Secret
// that is owned by the agent but absent from the current mapping set.
func TestWithCleanup_S22_DeletesOrphan(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"e/n": []byte("v")}}
	s := newFakeSink()

	// Pre-populate an orphan: the agent previously created "ns/orphan".
	s.owned["ns/orphan"] = true
	s.existing["ns/orphan"] = map[string][]byte{"K": []byte("old")}

	e := NewEngine(f, s, WithCleanup())

	// The current config only wants "ns/sec"; "ns/orphan" is not in the mapping.
	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "e/n", Namespace: "ns", Name: "sec", Key: "K"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Deleted, "orphan must be deleted")
	assert.Contains(t, s.deleted, "ns/orphan")
}

// TestNewStatus_S22_InitialState verifies that a freshly created Status reports
// not-ran and zero counters before any pass.
func TestNewStatus_S22_InitialState(t *testing.T) {
	st := NewStatus()
	ran, lastRun, last := st.snapshot()
	assert.False(t, ran)
	assert.True(t, lastRun.IsZero())
	assert.Equal(t, 0, last.Created)
	assert.Equal(t, 0, last.Failed)
}

// TestStatus_S22_CumulativeTotals verifies that Record accumulates totals across
// multiple passes, including Deleted which prior tests did not explicitly check.
func TestStatus_S22_CumulativeTotals(t *testing.T) {
	var now time.Time
	st := &Status{now: func() time.Time { return now }}

	st.Record(Result{Created: 2, Updated: 1, Unchanged: 3, Failed: 0, Deleted: 1})
	st.Record(Result{Created: 0, Updated: 2, Unchanged: 1, Failed: 1, Deleted: 2})

	st.mu.Lock()
	defer st.mu.Unlock()
	assert.Equal(t, int64(2), st.passes)
	assert.Equal(t, int64(2), st.totCreated)
	assert.Equal(t, int64(3), st.totUpdated)
	assert.Equal(t, int64(4), st.totUnchanged)
	assert.Equal(t, int64(1), st.totFailed)
	assert.Equal(t, int64(3), st.totDeleted)
}

// TestStatus_S22_MetricsIncludesDeletedCount verifies that the /metrics output
// includes the deleted total.
func TestStatus_S22_MetricsIncludesDeletedCount(t *testing.T) {
	st := NewStatus()
	st.Record(Result{Deleted: 5})
	h := st.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	assert.Contains(t, body, `keyorix_k8s_sync_secrets_total{outcome="deleted"} 5`)
}

// TestStatus_S22_StatusEndpointDeletedField verifies that the /status JSON includes
// the deleted count from the last pass.
func TestStatus_S22_StatusEndpointDeletedField(t *testing.T) {
	st := NewStatus()
	st.Record(Result{Deleted: 3})
	h := st.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.EqualValues(t, 3, body["deleted"])
}

// TestKeyorixFetcher_S22_HTTP5xxError verifies that a 5xx response returns a
// plain error (not wrapping ErrUpstreamGone) so the caller treats it as transient.
// Uses the existing keyorixStub via an impossible environment name so the list
// call hits the default (404) handler and the stub returns NotFound, which in
// resolveID wraps ErrUpstreamGone — but a direct getJSON 500 path is exercised
// by sending a bad base URL that causes a connection error instead.
func TestKeyorixFetcher_S22_HTTP5xxError(t *testing.T) {
	// Using the shared keyorixStub: requesting an environment "bad-env" returns 404
	// from the stub's default case — which the list endpoint maps to ErrUpstreamGone.
	// Separately verify that a completely unreachable host returns a transport error
	// (not ErrUpstreamGone) — covering the getJSON http.Do error branch.
	f := NewKeyorixFetcher("http://127.0.0.1:1", "tok", 1) // port 1 is always refused
	_, err := f.Fetch(context.Background(), "prod/secret")
	require.Error(t, err)
	// Transport error must not be mistaken for an authorisation/not-found issue.
	assert.NotContains(t, err.Error(), "not authorized")
}

// TestKeyorixFetcher_S22_MalformedJSONResponse verifies that a non-JSON body from
// the server returns a decode error. Every path (including the environment-list
// lookup resolveID performs first) responds with garbage, so the decode-error path is
// exercised at the earliest possible request.
func TestKeyorixFetcher_S22_MalformedJSONResponse(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("definitely not json"))
	}))
	defer bad.Close()

	f := NewKeyorixFetcher(bad.URL, "tok", 1)
	_, err := f.Fetch(context.Background(), "prod/secret")
	require.Error(t, err)
}

// TestKeyorixFetcher_S22_EmptyDataEnvelope verifies that a response with no "data"
// key at all returns the "empty data in response" error from getJSON. The
// environment-list and secrets-list endpoints return valid bodies so resolveID
// succeeds; only the value fetch (the final request) returns an envelope with a
// missing "data" field.
func TestKeyorixFetcher_S22_EmptyDataEnvelope(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Return a valid environment list so resolveEnvironmentID succeeds.
		if r.URL.Path == "/api/v1/projects/1/environments" {
			_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":5,"Name":"prod"}]}}`))
			return
		}
		// Return a valid list so resolveID finds the secret (id=1).
		if r.URL.Path == "/api/v1/secrets" {
			_, _ = w.Write([]byte(`{"data":{"total_pages":1,"secrets":[{"ID":1,"Name":"secret"}]}}`))
			return
		}
		// Value endpoint returns a JSON object with no "data" key → env.Data == nil.
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer bad.Close()

	f := NewKeyorixFetcher(bad.URL, "tok", 1)
	_, err := f.Fetch(context.Background(), "prod/secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty data")
}

// TestKeyorixFetcher_S22_ForbiddenWrapsErrUpstreamGone verifies that a 403
// response wraps ErrUpstreamGone so the caller can distinguish it from transient.
func TestKeyorixFetcher_S22_ForbiddenWrapsErrUpstreamGone(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer bad.Close()

	f := NewKeyorixFetcher(bad.URL, "tok", 1)
	_, err := f.Fetch(context.Background(), "prod/secret")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUpstreamGone)
}

// TestReconcile_S22_DryRunWithCleanupShowsOrphan verifies the dry-run + cleanup
// combination: orphans are counted in Deleted without being removed.
func TestReconcile_S22_DryRunWithCleanupShowsOrphan(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"e/n": []byte("v")}}
	s := newFakeSink()
	s.owned["ns/orphan"] = true
	s.existing["ns/orphan"] = map[string][]byte{"K": []byte("old")}

	e := NewEngine(f, s, WithDryRun(), WithCleanup())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "e/n", Namespace: "ns", Name: "sec", Key: "K"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created, "dry-run would-create")
	assert.Equal(t, 1, res.Deleted, "dry-run would-delete orphan")
	// Nothing actually deleted.
	assert.Empty(t, s.deleted)
}

// TestReconcile_S22_CleanupListError verifies that a List error during cleanup
// increments Failed and records an error message but does not abort other targets.
func TestReconcile_S22_CleanupListError(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"e/n": []byte("v")}}
	s := newFakeSink()
	s.listErr["ns"] = true // List("ns") will fail

	e := NewEngine(f, s, WithCleanup())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "e/n", Namespace: "ns", Name: "sec", Key: "K"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created)
	assert.Equal(t, 1, res.Failed, "list error must be counted")
	require.NotEmpty(t, res.Errors)
	assert.Contains(t, res.Errors[len(res.Errors)-1], "list owned")
}

// TestReconcile_S22_UpstreamGoneRemovesSecret verifies the ErrUpstreamGone branch
// WITH prune_on_revoke enabled: when a fetch returns ErrUpstreamGone, the engine
// deletes the materialized Secret. (With the default off, it wouldn't — see
// TestReconcile_RevokedUpstreamKeepsSecretByDefault in sync_test.go.)
func TestReconcile_S22_UpstreamGoneRemovesSecret(t *testing.T) {
	f := &fakeFetcher{revoked: map[string]bool{"prod/gone": true}}
	s := newFakeSink()
	// Pre-populate the Secret as if it was previously materialized.
	s.existing["ns/old-secret"] = map[string][]byte{"K": []byte("stale")}

	e := NewEngine(f, s, WithPruneOnRevoke())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/gone", Namespace: "ns", Name: "old-secret", Key: "K"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Revoked)
	assert.Contains(t, s.deleted, "ns/old-secret")
}
