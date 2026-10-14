package siem

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// eventually polls cond until true or a deadline, for asserting on async delivery
// without racing the retry backoff.
func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

func sampleEvent() *models.AuditEvent {
	t := true
	uid, pid := uint(7), uint(3)
	return &models.AuditEvent{
		ID: 42, EventType: "secret.updated", UserID: &uid, ProjectID: &pid,
		Description: "User alice updated secret db-password", IPAddress: "10.0.0.5",
		Success: &t, EventTime: time.Date(2026, 6, 4, 10, 0, 0, 0, time.UTC),
		Diff:      `{"value":{"changed":true}}`,
		PrevHash:  "prevhash-abc",
		EntryHash: "entryhash-xyz",
	}
}

// capture spins up a one-shot server recording the request it receives.
type capture struct {
	mu      sync.Mutex
	headers http.Header
	body    []byte
	hits    int
}

func newCaptureServer(t *testing.T, status int) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.headers = r.Header.Clone()
		c.body = b
		c.hits++
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func TestNew_DisabledReturnsNil(t *testing.T) {
	f, err := New(Config{Enabled: false})
	if err != nil || f != nil {
		t.Fatalf("disabled forwarder should be (nil,nil), got (%v,%v)", f, err)
	}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	if _, err := New(Config{Enabled: true, Provider: ProviderSplunk}); err == nil {
		t.Error("expected error when endpoint missing")
	}
	if _, err := New(Config{Enabled: true, Endpoint: "http://x", Provider: "nope"}); err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestSend_SplunkFormat(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK)
	f, err := New(Config{Enabled: true, Provider: ProviderSplunk, Endpoint: srv.URL, Token: "hec-tok"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)

	if _, err := f.send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := cap.headers.Get("Authorization"); got != "Splunk hec-tok" {
		t.Errorf("Splunk auth header = %q", got)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(cap.body, &envelope); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if _, ok := envelope["event"]; !ok {
		t.Errorf("Splunk body missing event envelope: %s", cap.body)
	}
	if string(cap.body) == "" {
		t.Error("empty body")
	}
	// The plaintext value must never appear anywhere in the forwarded payload.
	if containsValueLeak(cap.body) {
		t.Errorf("payload appears to leak a value before/after: %s", cap.body)
	}
}

func TestSend_DatadogHeader(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusAccepted)
	f, _ := New(Config{Enabled: true, Provider: ProviderDatadog, Endpoint: srv.URL, Token: "dd-key"})
	t.Cleanup(f.Close)

	if _, err := f.send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := cap.headers.Get("DD-API-KEY"); got != "dd-key" {
		t.Errorf("Datadog API key header = %q", got)
	}
}

func TestSend_WebhookBearer(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK)
	f, _ := New(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL, Token: "bear"})
	t.Cleanup(f.Close)

	if _, err := f.send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := cap.headers.Get("Authorization"); got != "Bearer bear" {
		t.Errorf("webhook auth header = %q", got)
	}
	var p eventPayload
	if err := json.Unmarshal(cap.body, &p); err != nil {
		t.Fatalf("webhook body not the payload shape: %v", err)
	}
	if p.ID != 42 || p.EventType != "secret.updated" {
		t.Errorf("unexpected payload: %+v", p)
	}
	// The chain links must be exported so a downstream SIEM can detect a dropped or
	// forged event (a gap shows as a prev_hash that doesn't match the prior entry_hash).
	if p.EntryHash != "entryhash-xyz" || p.PrevHash != "prevhash-abc" {
		t.Errorf("missing tamper-evidence chain links: entry=%q prev=%q", p.EntryHash, p.PrevHash)
	}
}

// A cross-host redirect from the configured SIEM endpoint must be refused, so the
// custom auth header (DD-API-KEY) — which Go does NOT strip across hosts — can't be
// exfiltrated to an attacker-controlled redirect target.
func TestSend_RefusesCrossHostRedirect(t *testing.T) {
	evil, evilCap := newCaptureServer(t, http.StatusOK)
	// Primary endpoint 302-redirects to the evil host.
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, evil.URL, http.StatusFound)
	}))
	t.Cleanup(primary.Close)

	f, _ := New(Config{Enabled: true, Provider: ProviderDatadog, Endpoint: primary.URL, Token: "dd-key"})
	t.Cleanup(f.Close)

	_, err := f.send(context.Background(), sampleEvent())
	if err == nil {
		t.Fatal("expected an error when the endpoint redirects cross-host")
	}
	evilCap.mu.Lock()
	hits, leaked := evilCap.hits, evilCap.headers.Get("DD-API-KEY")
	evilCap.mu.Unlock()
	if hits != 0 {
		t.Errorf("redirect target was reached %d time(s); it must not be followed", hits)
	}
	if leaked != "" {
		t.Errorf("DD-API-KEY leaked to redirect target: %q", leaked)
	}
}

func TestSend_Non2xxIsError(t *testing.T) {
	srv, _ := newCaptureServer(t, http.StatusInternalServerError)
	f, _ := New(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL})
	t.Cleanup(f.Close)
	if _, err := f.send(context.Background(), sampleEvent()); err == nil {
		t.Error("expected an error on a 500 response")
	}
}

func TestForward_AsyncDeliversThenClose(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK)
	f, _ := New(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL})

	f.Forward(sampleEvent())
	f.Forward(sampleEvent())
	f.Close() // drains the queue

	cap.mu.Lock()
	hits := cap.hits
	cap.mu.Unlock()
	if hits != 2 {
		t.Errorf("expected 2 delivered events, got %d", hits)
	}
}

func TestForward_RetriesTransientThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // transient — retried
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	delivBefore := testutil.ToFloat64(siemForwards.WithLabelValues(outcomeDelivered))
	retryBefore := testutil.ToFloat64(siemRetries)

	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Forward(sampleEvent())

	eventually(t, func() bool {
		return testutil.ToFloat64(siemForwards.WithLabelValues(outcomeDelivered))-delivBefore == 1
	})
	if got := hits.Load(); got != 3 {
		t.Errorf("hits = %d, want 3 (two retries then success)", got)
	}
	if got := testutil.ToFloat64(siemRetries) - retryBefore; got != 2 {
		t.Errorf("retries = %v, want 2", got)
	}
}

func TestForward_PermanentErrorNotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest) // 4xx — permanent
	}))
	defer srv.Close()

	failedBefore := testutil.ToFloat64(siemForwards.WithLabelValues(outcomeFailed))
	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	f.Forward(sampleEvent())
	f.Close() // no retry backoff for a permanent error, so Close cleanly drains it

	if got := hits.Load(); got != 1 {
		t.Errorf("hits = %d, want 1 (a 4xx must not be retried)", got)
	}
	if got := testutil.ToFloat64(siemForwards.WithLabelValues(outcomeFailed)) - failedBefore; got != 1 {
		t.Errorf("failed delta = %v, want 1", got)
	}
}

func TestForward_DropsAndCountsWhenQueueFull(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // wedge the worker so the queue backs up
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	droppedBefore := testutil.ToFloat64(siemForwards.WithLabelValues(outcomeDropped))
	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for range queueSize + 5 {
		f.Forward(sampleEvent())
	}
	if got := testutil.ToFloat64(siemForwards.WithLabelValues(outcomeDropped)) - droppedBefore; got < 1 {
		t.Errorf("dropped delta = %v, want >= 1 (events past queue capacity are dropped)", got)
	}
	close(release)
	f.Close()
}

// #199: a single strictly-serial worker meant an ordinary SLOW (not down) SIEM
// throttled the whole system's audit-forward throughput to ~one event per round
// trip. Proves delivery now happens with real concurrency (a bounded worker pool),
// not one event at a time.
func TestForward_DeliversWithBoundedConcurrency(t *testing.T) {
	var inFlight, maxInFlight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		for {
			old := maxInFlight.Load()
			if n <= old || maxInFlight.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond) // hold the request open long enough for others to overlap
		inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for range numWorkers * 3 {
		f.Forward(sampleEvent())
	}
	f.Close()

	if got := maxInFlight.Load(); got <= 1 {
		t.Errorf("max concurrent SIEM deliveries = %d, want > 1 (a single serial worker throttles throughput behind one slow endpoint)", got)
	}
}

// #199: the queue-full drop path must log enough to identify the specific lost
// event for forensic backfill from the durable DB audit trail — not just a
// running counter.
func TestForward_DropLogIncludesEventIdentity(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // wedge every worker so the queue backs up
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	var logBuf syncBuffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	for range queueSize + numWorkers + 5 {
		f.Forward(sampleEvent()) // sampleEvent has ID 42, EventType "secret.updated"
	}

	out := logBuf.String()
	if !strings.Contains(out, "dropped event 42") {
		t.Errorf("drop log missing the event ID for forensic backfill; got: %s", out)
	}
	if !strings.Contains(out, `"secret.updated"`) {
		t.Errorf("drop log missing the event type for forensic backfill; got: %s", out)
	}

	// Release the wedged workers so Close (which waits for them) doesn't deadlock —
	// must happen BEFORE Close, not deferred after it (defers run LIFO).
	close(release)
	f.Close()
}

// syncBuffer is a goroutine-safe io.Writer for capturing concurrently-written log output.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// containsValueLeak reports whether the JSON appears to carry a plaintext value
// before/after under the value diff (which must never be forwarded).
func containsValueLeak(body []byte) bool {
	s := string(body)
	return strings.Contains(s, `"value":{"before"`) || strings.Contains(s, `"value":{"after"`)
}
