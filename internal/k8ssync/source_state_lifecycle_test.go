package k8ssync

// FIX-3175B: what k8s-sync does when a source secret is suspended or expires, what it
// says about it, and what happens on reactivation. Driven end to end through the real
// KeyorixFetcher and the real RESTSink against two stateful fakes: a Keyorix server that
// refuses reads in a given state, and a Kubernetes API that stores Secrets.
//
// Policy (Andrei, 2026-10-13): fetch failures never touch the target; an expired source
// is retained; a suspended one is retained by default (on_suspend retain) or has its key
// emptied (clear), never the Secret deleted; reactivation restores the data on the next
// pass in every mode; each state is logged and counted, and is not a failure.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeKubeSecret struct {
	Labels map[string]string
	Data   map[string]string // key -> base64
}

// fakeKubeAPI is the slice of the Kubernetes Secrets API RESTSink uses.
type fakeKubeAPI struct {
	mu      sync.Mutex
	secrets map[string]*fakeKubeSecret // "ns/name"
}

func newFakeKubeAPI() *fakeKubeAPI { return &fakeKubeAPI{secrets: map[string]*fakeKubeSecret{}} }

func (k *fakeKubeAPI) put(key string, s fakeKubeSecret) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.secrets[key] = &s
}

func (k *fakeKubeAPI) snapshot(key string) (fakeKubeSecret, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, ok := k.secrets[key]
	if !ok {
		return fakeKubeSecret{}, false
	}
	cp := fakeKubeSecret{Labels: map[string]string{}, Data: map[string]string{}}
	for a, b := range s.Labels {
		cp.Labels[a] = b
	}
	for a, b := range s.Data {
		cp.Data[a] = b
	}
	return cp, true
}

func (k *fakeKubeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	// /api/v1/namespaces/{ns}/secrets[/{name}]
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[2] != "namespaces" || parts[4] != "secrets" {
		http.NotFound(w, r)
		return
	}
	ns := parts[3]
	var name string
	if len(parts) > 5 {
		name = parts[5]
	}
	key := ns + "/" + name
	body, _ := io.ReadAll(r.Body)
	var in struct {
		Metadata struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	_ = json.Unmarshal(body, &in)
	switch r.Method {
	case http.MethodGet:
		s, ok := k.secrets[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"metadata": map[string]interface{}{"uid": "u-" + name, "resourceVersion": "1", "labels": s.Labels},
			"data":     s.Data,
		})
	case http.MethodPost:
		k.secrets[ns+"/"+in.Metadata.Name] = &fakeKubeSecret{Labels: in.Metadata.Labels, Data: in.Data}
		w.WriteHeader(http.StatusCreated)
	case http.MethodPatch:
		s, ok := k.secrets[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.Labels, s.Data = in.Metadata.Labels, in.Data
	case http.MethodDelete:
		delete(k.secrets, key)
	}
}

// fakeKeyorix serves one secret (prod/db, id 7) whose read state the test flips.
type fakeKeyorix struct {
	mu         sync.Mutex
	state      string // "", "SecretSuspended", "SecretExpired", "unavailable" (HTTP 503)
	value      string
	expiration *time.Time
	// clearRequested adds details.clear_synced_copies=true to a SecretSuspended refusal
	// (SUSPEND-PURGE-1); details is a different shape when detailsRaw is set.
	clearRequested bool
	detailsRaw     string
}

func (f *fakeKeyorix) set(state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = state
}

func (f *fakeKeyorix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	state, value, exp := f.state, f.value, f.expiration
	details := ""
	switch {
	case f.detailsRaw != "":
		details = `,"details":` + f.detailsRaw
	case f.clearRequested:
		details = `,"details":{"clear_synced_copies":true}`
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v1/projects/1/environments":
		_, _ = io.WriteString(w, `{"data":{"environments":[{"ID":3,"Name":"prod"}]}}`)
	case "/api/v1/secrets":
		_, _ = io.WriteString(w, `{"data":{"secrets":[{"ID":7,"Name":"db"}],"total_pages":1}}`)
	case "/api/v1/secrets/7":
		switch state {
		case "unavailable":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"value": value, "secret": map[string]interface{}{"expiration": exp},
			}})
		default:
			w.WriteHeader(http.StatusConflict)
			// The server carries the marker on a SecretExpired refusal too, when the
			// secret is also suspended with it (#3215).
			if state != "SecretSuspended" && state != "SecretExpired" {
				details = ""
			}
			_, _ = fmt.Fprintf(w, `{"success":false,"code":409,"error":%q,"message":"refused"%s}`, state, details)
		}
	default:
		http.NotFound(w, r)
	}
}

type lifecycleWorld struct {
	kx   *fakeKeyorix
	kube *fakeKubeAPI
	eng  *Engine
	maps []SecretMapping
	now  time.Time
}

func newLifecycleWorld(t *testing.T, opts ...Option) *lifecycleWorld {
	t.Helper()
	w := &lifecycleWorld{
		kx:   &fakeKeyorix{value: "s3cr3t-value"},
		kube: newFakeKubeAPI(),
		maps: []SecretMapping{{Ref: "prod/db", Namespace: "app", Name: "db-creds", Key: "password"}},
		now:  time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
	}
	kxSrv := httptest.NewServer(w.kx)
	t.Cleanup(kxSrv.Close)
	kubeSrv := httptest.NewServer(w.kube)
	t.Cleanup(kubeSrv.Close)
	w.eng = NewEngine(NewKeyorixFetcher(kxSrv.URL, "tok", 1), testSink(kubeSrv), opts...)
	w.eng.now = func() time.Time { return w.now }
	return w
}

func (w *lifecycleWorld) pass(t *testing.T) (Result, []string) {
	t.Helper()
	var logged []string
	res := Sync(context.Background(), w.eng, w.maps, func(f string, a ...interface{}) { logged = append(logged, fmt.Sprintf(f, a...)) })
	return res, logged
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

const managedLabelKey = "app.kubernetes.io/managed-by"

func TestSourceStateLifecycle_ExpiredIsRetained(t *testing.T) {
	w := newLifecycleWorld(t)
	res, _ := w.pass(t)
	require.Equal(t, 1, res.Created, "%+v", res)
	original, _ := w.kube.snapshot("app/db-creds")

	w.kx.value = "rotated-while-expired"
	w.kx.set("SecretExpired")
	status := NewStatus()
	res, logged := w.pass(t)
	status.Record(res)
	got, ok := w.kube.snapshot("app/db-creds")
	require.True(t, ok, "an expired source must NOT delete the target Secret")
	assert.Equal(t, original, got, "nor change it")
	assert.Equal(t, 1, res.SourceExpired)
	assert.Zero(t, res.Failed+res.Revoked+res.Suspected, "not a failure / revocation: no backoff")
	assert.Contains(t, strings.Join(logged, "\n"), "SourceSecretExpired")
	assert.Contains(t, status.metrics(), `keyorix_k8s_sync_secrets_total{outcome="source_expired"} 1`)

	// Same state next pass: counted again, but the line is logged only on change.
	res, logged = w.pass(t)
	assert.Equal(t, 1, res.SourceExpired)
	assert.NotContains(t, strings.Join(logged, "\n"), "WARNING")

	// Recovered: the new value is synced and the recovery is logged.
	w.kx.set("")
	res, logged = w.pass(t)
	assert.Equal(t, 1, res.Updated, "%+v", res)
	got, _ = w.kube.snapshot("app/db-creds")
	assert.Equal(t, b64("rotated-while-expired"), got.Data["password"])
	assert.Contains(t, strings.Join(logged, "\n"), "readable again")
}

func TestSourceStateLifecycle_Suspended(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts  []Option
		clear bool
	}{
		{"retain (default)", nil, false},
		{"clear", []Option{WithClearOnSuspend()}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newLifecycleWorld(t, tc.opts...)
			res, _ := w.pass(t)
			require.Equal(t, 1, res.Created, "%+v", res)
			original, _ := w.kube.snapshot("app/db-creds")
			require.Equal(t, map[string]string{managedLabelKey: "keyorix-sync"}, original.Labels)
			require.Equal(t, b64("s3cr3t-value"), original.Data["password"])

			w.kx.set("SecretSuspended")
			status := NewStatus()
			res, logged := w.pass(t)
			status.Record(res)
			got, ok := w.kube.snapshot("app/db-creds")
			require.True(t, ok, "a suspended source never deletes the Secret")
			if tc.clear {
				assert.Empty(t, got.Data, "clear empties the managed keys")
				assert.Equal(t, original.Labels, got.Labels)
			} else {
				assert.Equal(t, original, got, "retain leaves it exactly as it was")
			}
			assert.Equal(t, 1, res.SourceSuspended)
			assert.Zero(t, res.Failed+res.Revoked+res.Suspected)
			assert.Contains(t, strings.Join(logged, "\n"), "SourceSecretSuspended")
			assert.Contains(t, status.metrics(), `keyorix_k8s_sync_secrets_total{outcome="source_suspended"} 1`)

			// Still suspended: nothing changes, no repeated warning line.
			res, logged = w.pass(t)
			again, _ := w.kube.snapshot("app/db-creds")
			assert.Equal(t, got, again)
			assert.Zero(t, res.Failed)
			assert.NotContains(t, strings.Join(logged, "\n"), "WARNING")

			// Resumed: the very next pass restores the same Secret (name, labels, data).
			w.kx.set("")
			res, _ = w.pass(t)
			restored, ok := w.kube.snapshot("app/db-creds")
			require.True(t, ok)
			assert.Equal(t, original, restored, "same name, labels and data as before the suspension")
			if tc.clear {
				assert.Equal(t, 1, res.Updated, "%+v", res)
			} else {
				assert.Equal(t, 1, res.Unchanged, "%+v", res)
			}
		})
	}
}

// Clear never touches a Secret the agent does not own and never creates an empty one.
func TestSourceStateLifecycle_ClearLeavesUnownedAndAbsentAlone(t *testing.T) {
	t.Run("unowned", func(t *testing.T) {
		w := newLifecycleWorld(t, WithClearOnSuspend())
		w.kube.put("app/db-creds", fakeKubeSecret{Labels: map[string]string{}, Data: map[string]string{"THEIRS": b64("keep")}})
		w.kx.set("SecretSuspended")
		res, _ := w.pass(t)
		got, _ := w.kube.snapshot("app/db-creds")
		assert.Equal(t, map[string]string{"THEIRS": b64("keep")}, got.Data, "an unmanaged Secret is not touched")
		assert.Equal(t, 1, res.Failed, "reported (not-managed refusal), not applied")
	})
	t.Run("absent", func(t *testing.T) {
		w := newLifecycleWorld(t, WithClearOnSuspend())
		w.kx.set("SecretSuspended")
		w.pass(t)
		_, ok := w.kube.snapshot("app/db-creds")
		assert.False(t, ok, "no empty Secret is created")
	})
}

// A fetch that fails for any other reason (server unreachable / 5xx) never modifies the
// target, in either mode; it is a failure that is retried.
func TestSourceStateLifecycle_FetchErrorsNeverTouchTheTarget(t *testing.T) {
	for _, opts := range [][]Option{nil, {WithClearOnSuspend()}} {
		w := newLifecycleWorld(t, opts...)
		res, _ := w.pass(t)
		require.Equal(t, 1, res.Created)
		original, _ := w.kube.snapshot("app/db-creds")

		w.kx.set("unavailable")
		res, _ = w.pass(t)
		got, ok := w.kube.snapshot("app/db-creds")
		require.True(t, ok)
		assert.Equal(t, original, got)
		assert.Equal(t, 1, res.Failed)
		assert.Zero(t, res.SourceSuspended+res.SourceExpired)
	}
}

// Ahead of an expiry the line is logged when the secret first comes within 30 days, then
// 7, then 1, and not again within a window; the target keeps syncing meanwhile.
func TestSourceStateLifecycle_ExpiryWarnings(t *testing.T) {
	w := newLifecycleWorld(t)
	expiry := w.now.Add(60 * 24 * time.Hour)
	w.kx.expiration = &expiry

	at := func(d time.Duration) (Result, string) {
		w.now = expiry.Add(d)
		res, logged := w.pass(t)
		return res, strings.Join(logged, "\n")
	}
	res, logs := at(-59 * 24 * time.Hour)
	assert.Zero(t, res.SourceExpiring)
	assert.NotContains(t, logs, "WARNING")

	res, logs = at(-29 * 24 * time.Hour)
	assert.Equal(t, 1, res.SourceExpiring)
	assert.Contains(t, logs, "SourceSecretExpiring")
	assert.Contains(t, logs, "within 30d")

	_, logs = at(-20 * 24 * time.Hour)
	assert.NotContains(t, logs, "WARNING", "same window: no repeat")

	_, logs = at(-6 * 24 * time.Hour)
	assert.Contains(t, logs, "within 7d")

	res, logs = at(-12 * time.Hour)
	assert.Contains(t, logs, "within 1d")
	assert.Equal(t, 1, res.SourceExpiring)

	// Still syncs: warning is not a hold.
	got, _ := w.kube.snapshot("app/db-creds")
	assert.Equal(t, b64("s3cr3t-value"), got.Data["password"])

	// Extended on the server: the warning clears.
	later := expiry.Add(400 * 24 * time.Hour)
	w.kx.mu.Lock()
	w.kx.expiration = &later
	w.kx.mu.Unlock()
	res, logs = at(-6 * time.Hour)
	assert.Zero(t, res.SourceExpiring)
	assert.Contains(t, logs, "readable again")
}

// Neither state engages the loop's failure backoff: reactivation is picked up in a plain
// interval.
func TestSourceStateLifecycle_DoesNotEngageFailureBackoff(t *testing.T) {
	for _, state := range []string{"SecretSuspended", "SecretExpired"} {
		w := newLifecycleWorld(t)
		w.pass(t)
		w.kx.set(state)
		res, _ := w.pass(t)
		unhealthy := res.Failed > 0 || res.Revoked > 0 || res.Suspected > 0
		assert.False(t, unhealthy, "%s must not count as an unhealthy pass (see run)", state)
	}
}

// A target with a revoked ref AND a retained (suspended) one still takes the revoked path,
// and the retained key keeps its current value instead of being pruned.
func TestSourceState_RevokedAndRetainedTogether(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/ok": []byte("v")}, revoked: map[string]bool{"prod/gone": true}}
	sink := newFakeSink()
	sink.existing["app/s"] = map[string][]byte{"ok": []byte("old"), "held": []byte("held-value"), "gone": []byte("stale")}
	sink.owned["app/s"] = true
	eng := NewEngine(&suspendingFetcher{fakeFetcher: f, suspended: map[string]bool{"prod/held": true}}, sink)
	res, err := eng.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/ok", Namespace: "app", Name: "s", Key: "ok"},
		{Ref: "prod/held", Namespace: "app", Name: "s", Key: "held"},
		{Ref: "prod/gone", Namespace: "app", Name: "s", Key: "gone"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.SourceSuspended)
	assert.Equal(t, map[string][]byte{"ok": []byte("v"), "held": []byte("held-value")}, sink.applied["app/s"],
		"revoked key dropped, retained key carried over, readable key refreshed")
}

type suspendingFetcher struct {
	*fakeFetcher
	suspended map[string]bool
}

func (s *suspendingFetcher) Fetch(ctx context.Context, ref string) ([]byte, error) {
	if s.suspended[ref] {
		return nil, fmt.Errorf("%q: %w", ref, ErrSourceSuspended)
	}
	return s.fakeFetcher.Fetch(ctx, ref)
}

func TestConfig_OnSuspend(t *testing.T) {
	base := func(v string) *Config {
		return &Config{KeyorixURL: "https://k.example", ProjectID: 1, OnSuspend: v,
			Mappings: []SecretMapping{{Ref: "prod/db", Namespace: "app", Name: "s", Key: "k"}}}
	}
	for _, v := range []string{"", "retain", "clear", "Clear", " RETAIN "} {
		require.NoError(t, base(v).validate(), v)
	}
	assert.Equal(t, OnSuspendRetain, base("").GetOnSuspend())
	assert.Equal(t, OnSuspendClear, base("Clear").GetOnSuspend())
	err := base("delete").validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "on_suspend")
}
