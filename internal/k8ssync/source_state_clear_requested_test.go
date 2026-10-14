package k8ssync

// SUSPEND-PURGE-1: a suspension that asks (details.clear_synced_copies on the 409
// SecretSuspended) for the synced copies to be cleared is treated as on_suspend: clear
// for that mapping, over on_suspend: retain. Same clear semantics as FIX-3175B: only the
// key the agent manages is emptied, an unowned Secret is never touched and none is created,
// the Secret object stays, and resuming restores the data on the next pass. Driven through
// the real KeyorixFetcher and RESTSink (see source_state_lifecycle_test.go).

import (
	"context"
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

func TestSourceStateClearRequested_OverridesRetain_ThenRestores(t *testing.T) {
	w := newLifecycleWorld(t) // on_suspend: retain (the default)
	res, _ := w.pass(t)
	require.Equal(t, 1, res.Created, "%+v", res)
	original, _ := w.kube.snapshot("app/db-creds")
	require.Equal(t, b64("s3cr3t-value"), original.Data["password"])

	w.kx.clearRequested = true
	w.kx.set("SecretSuspended")
	status := NewStatus()
	res, logged := w.pass(t)
	status.Record(res)
	got, ok := w.kube.snapshot("app/db-creds")
	require.True(t, ok, "the Secret object is never deleted")
	assert.Empty(t, got.Data, "the suspension's request beats on_suspend: retain")
	assert.Equal(t, original.Labels, got.Labels)
	assert.Equal(t, 1, res.SourceSuspended)
	assert.Equal(t, 1, res.Updated, "%+v", res)
	assert.Zero(t, res.Failed+res.Revoked+res.Suspected, "not a failure: no backoff")
	assert.Contains(t, strings.Join(logged, "\n"), "SourceSecretSuspended")
	assert.Contains(t, strings.Join(logged, "\n"), "requests clearing the synced copies")
	assert.Contains(t, status.metrics(), `keyorix_k8s_sync_secrets_total{outcome="source_suspended"} 1`)

	// Still suspended: nothing changes, no repeated warning line.
	res, logged = w.pass(t)
	again, _ := w.kube.snapshot("app/db-creds")
	assert.Equal(t, got, again)
	assert.Zero(t, res.Failed)
	assert.NotContains(t, strings.Join(logged, "\n"), "WARNING")

	// Resumed (the request goes with the suspension): the next pass restores everything.
	w.kx.clearRequested = false
	w.kx.set("")
	res, _ = w.pass(t)
	restored, ok := w.kube.snapshot("app/db-creds")
	require.True(t, ok)
	assert.Equal(t, original, restored, "same name, labels and data as before the suspension")
	assert.Equal(t, 1, res.Updated, "%+v", res)
}

// The override is per suspension: without the request, retain still retains.
func TestSourceStateClearRequested_PlainSuspendStillRetained(t *testing.T) {
	w := newLifecycleWorld(t)
	w.pass(t)
	original, _ := w.kube.snapshot("app/db-creds")
	w.kx.set("SecretSuspended")
	w.pass(t)
	got, _ := w.kube.snapshot("app/db-creds")
	assert.Equal(t, original, got)
}

// Details of a shape the agent does not know drop only the request marker: the refusal is
// still classified suspended (no failure, nothing wiped) and on_suspend decides.
func TestSourceStateClearRequested_UnknownDetailsShapeIsPlainSuspend(t *testing.T) {
	for _, raw := range []string{`"clear_synced_copies"`, `{"clear_synced_copies":false}`, `[true]`, `null`} {
		t.Run(raw, func(t *testing.T) {
			w := newLifecycleWorld(t)
			w.pass(t)
			original, _ := w.kube.snapshot("app/db-creds")
			w.kx.detailsRaw = raw
			w.kx.set("SecretSuspended")
			res, _ := w.pass(t)
			got, _ := w.kube.snapshot("app/db-creds")
			assert.Equal(t, original, got, "retain applies when the request marker is absent or unreadable")
			assert.Equal(t, 1, res.SourceSuspended, "%+v", res)
			assert.Zero(t, res.Failed, "%+v", res)
		})
	}
}

// #3215: the server judges expiry first, so a secret that is expired AND suspended with the
// request answers SecretExpired carrying the marker. The copies are cleared (the user was
// told they would be), with the usual Clear semantics, and restored on resume.
func TestSourceStateClearRequested_HonouredOnExpiredWhenSuspendedWithRequest(t *testing.T) {
	w := newLifecycleWorld(t) // on_suspend: retain
	w.pass(t)
	original, _ := w.kube.snapshot("app/db-creds")
	require.Equal(t, b64("s3cr3t-value"), original.Data["password"])
	w.kx.clearRequested = true
	w.kx.set("SecretExpired")
	res, _ := w.pass(t)
	got, ok := w.kube.snapshot("app/db-creds")
	require.True(t, ok, "the Secret object is never deleted")
	assert.Empty(t, got.Data, "expired + suspended + request: copies cleared")
	assert.Equal(t, original.Labels, got.Labels)
	assert.Zero(t, res.Failed+res.Revoked+res.Suspected, "%+v", res)

	w.kx.clearRequested = false
	w.kx.set("")
	w.pass(t)
	restored, _ := w.kube.snapshot("app/db-creds")
	assert.Equal(t, original, restored)
}

// An expired secret that is NOT suspended with the request keeps its copies (keep + warn).
func TestSourceStateClearRequested_ExpiredOnlyStillRetained(t *testing.T) {
	w := newLifecycleWorld(t)
	w.pass(t)
	original, _ := w.kube.snapshot("app/db-creds")
	w.kx.set("SecretExpired")
	res, _ := w.pass(t)
	got, _ := w.kube.snapshot("app/db-creds")
	assert.Equal(t, original, got)
	assert.Equal(t, 1, res.SourceExpired, "%+v", res)
}

// Expired + request keeps the Clear guard rails: unowned Secrets untouched, none created.
func TestSourceStateClearRequested_ExpiredLeavesUnownedAndAbsentAlone(t *testing.T) {
	t.Run("unowned", func(t *testing.T) {
		w := newLifecycleWorld(t)
		w.kube.put("app/db-creds", fakeKubeSecret{Labels: map[string]string{}, Data: map[string]string{"THEIRS": b64("keep")}})
		w.kx.clearRequested = true
		w.kx.set("SecretExpired")
		w.pass(t)
		got, _ := w.kube.snapshot("app/db-creds")
		assert.Equal(t, map[string]string{"THEIRS": b64("keep")}, got.Data)
	})
	t.Run("absent", func(t *testing.T) {
		w := newLifecycleWorld(t)
		w.kx.clearRequested = true
		w.kx.set("SecretExpired")
		w.pass(t)
		_, ok := w.kube.snapshot("app/db-creds")
		assert.False(t, ok, "no empty Secret is created")
	})
}

// Clear semantics are exactly FIX-3175B's.
func TestSourceStateClearRequested_LeavesUnownedAndAbsentAlone(t *testing.T) {
	t.Run("unowned", func(t *testing.T) {
		w := newLifecycleWorld(t)
		w.kube.put("app/db-creds", fakeKubeSecret{Labels: map[string]string{}, Data: map[string]string{"THEIRS": b64("keep")}})
		w.kx.clearRequested = true
		w.kx.set("SecretSuspended")
		res, _ := w.pass(t)
		got, _ := w.kube.snapshot("app/db-creds")
		assert.Equal(t, map[string]string{"THEIRS": b64("keep")}, got.Data, "an unmanaged Secret is not touched")
		assert.Equal(t, 1, res.Failed, "reported (not-managed refusal), not applied")
	})
	t.Run("absent", func(t *testing.T) {
		w := newLifecycleWorld(t)
		w.kx.clearRequested = true
		w.kx.set("SecretSuspended")
		w.pass(t)
		_, ok := w.kube.snapshot("app/db-creds")
		assert.False(t, ok, "no empty Secret is created")
	})
}

// With several keys in one target, only the mapping whose suspension made the request is
// emptied; a sibling that is merely suspended keeps its value under retain.
func TestSourceStateClearRequested_OnlyTheRequestingMappingIsCleared(t *testing.T) {
	unit := newPerRefWorld(t)
	unit.pass(t)
	before, _ := unit.kube.snapshot("app/db-creds")
	require.Len(t, before.Data, 2)

	unit.setSuspended(map[string]bool{"db": true, "api": true}, map[string]bool{"db": true})
	unit.pass(t)
	got, _ := unit.kube.snapshot("app/db-creds")
	assert.NotContains(t, got.Data, "password", "the compromised secret's copy is gone")
	assert.Equal(t, before.Data["token"], got.Data["token"], "a plainly suspended sibling is retained")

	unit.setSuspended(nil, nil)
	unit.pass(t)
	restored, _ := unit.kube.snapshot("app/db-creds")
	assert.Equal(t, before, restored)
}

// perRefWorld serves two secrets (prod/db id 7, prod/api id 8) into ONE target Secret, each
// with its own suspended / clear-requested state.
type perRefWorld struct {
	mu        sync.Mutex
	suspended map[string]bool // by secret name
	clearReq  map[string]bool
	kube      *fakeKubeAPI
	eng       *Engine
	maps      []SecretMapping
}

func newPerRefWorld(t *testing.T) *perRefWorld {
	t.Helper()
	w := &perRefWorld{
		kube: newFakeKubeAPI(),
		maps: []SecretMapping{
			{Ref: "prod/db", Namespace: "app", Name: "db-creds", Key: "password"},
			{Ref: "prod/api", Namespace: "app", Name: "db-creds", Key: "token"},
		},
	}
	kx := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		names := map[string]string{"/api/v1/secrets/7": "db", "/api/v1/secrets/8": "api"}
		switch name, byID := names[r.URL.Path], names[r.URL.Path] != ""; {
		case r.URL.Path == "/api/v1/projects/1/environments":
			_, _ = io.WriteString(rw, `{"data":{"environments":[{"ID":3,"Name":"prod"}]}}`)
		case r.URL.Path == "/api/v1/secrets":
			_, _ = io.WriteString(rw, `{"data":{"secrets":[{"ID":7,"Name":"db"},{"ID":8,"Name":"api"}],"total_pages":1}}`)
		case byID:
			w.mu.Lock()
			susp, clr := w.suspended[name], w.clearReq[name]
			w.mu.Unlock()
			if !susp {
				_, _ = fmt.Fprintf(rw, `{"data":{"value":"value-of-%s","secret":{}}}`, name)
				return
			}
			details := ""
			if clr {
				details = `,"details":{"clear_synced_copies":true}`
			}
			rw.WriteHeader(http.StatusConflict)
			_, _ = fmt.Fprintf(rw, `{"success":false,"code":409,"error":"SecretSuspended","message":"refused"%s}`, details)
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(kx.Close)
	kubeSrv := httptest.NewServer(w.kube)
	t.Cleanup(kubeSrv.Close)
	w.eng = NewEngine(NewKeyorixFetcher(kx.URL, "tok", 1), testSink(kubeSrv))
	w.eng.now = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }
	return w
}

func (w *perRefWorld) setSuspended(suspended, clearReq map[string]bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.suspended, w.clearReq = suspended, clearReq
}

func (w *perRefWorld) pass(t *testing.T) Result {
	t.Helper()
	return Sync(context.Background(), w.eng, w.maps, func(string, ...any) {})
}
